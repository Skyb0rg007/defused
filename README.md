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

Defused requires Linux 6.5 or later, for `SO_PEERPIDFD`. To authorize
unmounts, the service resolves a client's pidfd to its pid with the
`PIDFD_GET_INFO` ioctl on Linux 6.13 or later, and falls back to the `Pid:`
line of `/proc/self/fdinfo/<pidfd>` on older kernels.
Privileged callers (see below) have neither requirement.

Building needs libsystemd 258 or later, for the sd-varlink file descriptor
passing API. Debian 13 (systemd 257) and Ubuntu 24.04 (255) are too old.

## Project structure

This project provides the following:

- A system service that listens on `/run/defused/defused.sock`.
- A replacement `fusermount3` and `fusermount` binary to communicate with
  the service.

The system service is written to use systemd socket activation with
`Accept=yes`.
For testing or on systems without systemd, `defused --daemon` can be used
to create the Varlink socket and fork off child processes to handle
accepted connections.

## Mount policy

Command-line options decide who may mount and unmount at all; see
[protocol.md](./doc/protocol.md):

| Option | Meaning | Default |
| --- | --- | --- |
| `--max-mounts=N` | Refuse a mount once N FUSE filesystems are mounted (libfuse's `mount_max`) | 100 |
| `--allow-groups=GROUP[,GROUP...]` | Only members of these groups (names or gids, supplementary included) may mount and unmount | any user |
| `--allow-other` | Let callers set the `allow_other` mount option (libfuse's `user_allow_other`) | refused |

The ownership checks below always apply as well.
The installed `defused@.service` takes these from environment variables, so
changing them is a drop-in:

```
# systemctl edit defused@.service
[Service]
Environment=DEFUSED_ALLOW_GROUPS=fuse
```

`DEFUSED_MAX_MOUNTS` works the same way. `DEFUSED_EXTRA_ARGS` is split on
whitespace and appended to the command line, which is how a flag-only option
like `--allow-other` is passed:

```
# systemctl edit defused@.service
[Service]
Environment=DEFUSED_EXTRA_ARGS=--allow-other
```

A caller that is root or holds `CAP_SYS_ADMIN` does not need the service:
`fusermount3` instead spawns `defused --child`, which performs the request
with the caller's own privileges and none of the service's policy (no mount
limit, no mountpoint ownership rule, no filesystem-type allowlist), and honors
the `suid`, `dev` and `blkdev` options like libfuse's `fusermount3` does for
root.
libfuse's own `fusermount3` is therefore not needed at all.

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

## NixOS

```nix
{
  imports = [ inputs.defused.nixosModules.defused ];
  services.defused.enable = true;
}
```

This replaces `/run/wrappers/bin/fusermount3` and `/run/wrappers/bin/fusermount`
with defused's, so every FUSE program uses it, libfuse2 and libfuse3 alike.
`services.defused.replaceFusermount3` and `replaceFusermount` turn either
takeover off.
`services.defused.maxMounts`, `allowGroups` and `allowOther` configure the
policy.
See `services.defused.*` for the options.

## Nix binary cache

I am using cachix as a binary cache:

```
# Add to nix.conf
extra-substituters = https://defused.cachix.org
extra-trusted-public-keys = defused.cachix.org-1:/YD+2Bmle49JSliBhGRqTKpLYhvruoFyMPPU071YCAY=
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
