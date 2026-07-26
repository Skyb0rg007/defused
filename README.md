<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# defused - a setuid-less fusermount implementation

The Linux kernel's implementation of [Filesystem in Userspace][FUSE-Wikipedia]
requires root permissions, despite its use in unprivileged programs.
This has normally been solved via [libfuse][]'s setuid helper program
`fusermount`/`fusermount3`.

This does means that certain kinds of security policies cannot be applied,
specifically [`no_new_privileges`][NoNewPrivileges] process flag.

```sh
$ mkdir _lower _mnt
$ # Without no_new_privileges
$ fuse-overlayfs -o lowerdir=_lower _mnt
$ fusermount3 -u _mnt
$ # With no_new_privileges
$ setpriv --no-new-privs -- fuse-overlayfs -o lowerdir=_lower _mnt
/usr/bin/fusermount3: mount failed: Operation not permitted
fuse-overlayfs: cannot mount: Operation not permitted
```

The `no_new_privileges` flag is important for proper application sandboxing,
as Linux features such as [landlock][] and [seccomp-bpf][] can only be used
after a call to `prctl(PR_SET_NO_NEW_PRIVS, 1)`.

Using Unix domain sockets like defused does also means that the FUSE-mounting
capability can be granted to applications by allow-listing the socket in the
application's AppArmor or Landlock configuration.
Doing so with `fusermount3` is much more challenging, as it is not compatible
with Landlock.

## Requirements

Defused requires Linux 6.13 or later: the service authorizes unmounts by
resolving a client's pidfd to its pid via the `PIDFD_GET_INFO` ioctl, which
was added in 6.13. Support for older kernels is possible by falling back to
parsing `/proc/self/fdinfo/<pidfd>`'s `Pid:` line, but that fallback is not
currently implemented.

## Project structure

This project provides the following:

- A system service that listens on `/run/defused/defused.sock`.
- A replacement `fusermount3` binary to communicate with the service.

The system service is written to use systemd socket activation with
`Accept=yes`.
For testing or on systems without systemd, `defused --daemon` can be used
to create the Varlink socket and fork off child processes to handle
accepted connections.

Root callers are delegated directly to libfuse's `fusermount3`, since they do
not need the unprivileged service path.
This means libfuse's `fusermount3` should still be installed, just not in
`/usr/bin` (ex. `/usr/lib/fuse3/fusermount3`).

## Mountpoint ownership model

Defused uses a different mountpoint ownership model than libfuse's setuid
`fusermount3`.
For non-root mounts, the mountpoint must be a directory or regular file owned
by the caller.
It must be writable by that caller, and directories must also be searchable.

This means defused rejects mounts on writable shared directories owned by
another user, even when libfuse's setuid helper would allow them because the
directory is not sticky.
The stricter rule keeps the privileged service's authorization decision tied
to the mountpoint file descriptor it receives, instead of trying to reproduce
libfuse's path-based `access(W_OK)` check across the client/service protocol.

This does lead to some additional mounting possibilities, all due to other
filesystem restrictions.
If a given file path is owned by the user, but the process is unable to write
to the path due to POSIX ACLs, LSMs like SELinux, AppArmor, or Landlock,
libfuse's setuid implementation will deny the mount while this implementation
will still perform it.
I do not believe this is an issue, however, as sandboxed applications should
deny access to `/dev/fuse` or `/run/defused/defused.sock`.

See [protocol.md](./doc/protocol.md) for more information on how defused
works.

## Installation

### Nix

`flake.nix` exposes a `defused` package and a NixOS module
(`nixosModules.defused`) that sets up the systemd socket/service natively.
Add this repository as a flake input and, for NixOS, enable
`services.defused`.

I am using cachix as a binary cache:

```
# Add to nix.conf
extra-substituters = https://defused.cachix.org
extra-trusted-public-keys = defused.cachix.org-1:/YD+2Bmle49JSliBhGRqTKpLYhvruoFyMPPU071YCAY=
```

### .deb / .rpm

Every `v*` tag is built into `.deb` and `.rpm` packages for x86_64 and
aarch64, published as assets on the corresponding [GitHub
release](https://github.com/Skyb0rg007/defused/releases). These are built
natively per-distro (`debhelper`/`dpkg-buildpackage` for `.deb`, `rpmbuild`
for `.rpm`, see `debian/` and `packaging/defused.spec`) rather than with Nix,
so they're linked against the target distro's own glibc/libseccomp/libsystemd
instead of nixpkgs'.

Note that defused's Varlink usage currently needs **libsystemd >= 258**
(both packages declare this explicitly as a runtime dependency --
`libsystemd0 (>= 258)` for `.deb`, `systemd-libs >= 258` for `.rpm` -- rather
than relying solely on the auto-detected shared-library version, since it's
a meaningfully high floor). As of this writing that means:

- Fedora: works on current releases (Fedora 44 ships systemd 259).
- Debian: does **not** work on Debian 12 (bookworm) or 13 (trixie, current
  stable) -- trixie's systemd 257 is still one major version short.
- Ubuntu: does **not** work on 24.04 LTS (systemd 255) or earlier; needs
  26.04 LTS (systemd 259) or newer.

If you're on a distribution that doesn't ship a new enough systemd yet, use
the Nix package instead (see above), which carries its own libsystemd.

Install with your distribution's package manager, e.g.:

```sh
# Debian/Ubuntu
$ sudo apt install ./defused_<version>_amd64.deb
# Fedora
$ sudo dnf install ./defused-<version>-1.x86_64.rpm
```

This installs the `defused@.service`/`defused.socket` units and the polkit
action, but doesn't enable or start the socket for you:

```sh
$ sudo systemctl enable --now defused.socket
```

See [protocol.md](./doc/protocol.md) for the default (interactive-only)
polkit policy, and `packaging/polkit/examples/50-defused-mount-policy.rules`
(installed under `/usr/share/doc/defused/examples`) for a less strict
example rule.

These packages can also be built locally:

```sh
# .deb, from the repo root
$ dpkg-buildpackage -us -uc -b

# .rpm: set up an rpmbuild tree, generate the source tarball
# packaging/defused.spec expects, then build
$ rpmdev-setuptree
$ git archive --prefix=defused-0.1/ -o ~/rpmbuild/SOURCES/defused-0.1.tar.gz HEAD
$ rpmbuild -ba packaging/defused.spec
```

## Contributing

See [contributing.md](./doc/contributing.md).

## Licensing

This project copies a some helpers from libfuse in [util.h](./src/util.h),
which are either GPL-2.0-only or LGPL-2.1-only
(marked via SPDX snippets in [util.c](./src/util.c)).
All of my code is licensed under GPL-2.0-or-later, but the resulting binary
will be GPL-2.0-only.

[FUSE-Wikipedia]: https://en.wikipedia.org/wiki/Filesystem_in_Userspace
[FUSE]: https://www.kernel.org/doc/html/next/filesystems/fuse.html
[libfuse]: https://github.com/libfuse/libfuse
[NoNewPrivileges]: https://docs.kernel.org/userspace-api/no_new_privs.html
[seccomp-bpf]: https://docs.kernel.org/userspace-api/seccomp_filter.html
[landlock]: https://docs.kernel.org/userspace-api/landlock.html
