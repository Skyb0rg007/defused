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

Using Unix domain sockets like defused does also means that privileges can be
granted or denied by bind-mounting the sockets into the application's
namespace. Doing so with `/usr/bin` is much more challenging.

## Project structure

This project provides the following:

- A system service that listens on `/run/defused/defused.sock`.
- A replacement `fusermount3` binary to communicate with the service.

The system service is written to use systemd socket activation with
`Accept=yes`.
On systems without systemd as service manager or and for testing,
you can run the service with `systemd-socket-activate`.

## Mountpoint ownership model

Defused uses a different mountpoint ownership model than libfuse's setuid
`fusermount3`.
For non-root mounts, the mountpoint must be a directory or regular file owned
by the caller.
It must be writable by that caller; directories must also be searchable.

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

## Nix binary cache

I am using cachix as a binary cache:

```
# Add to nix.conf
extra-substituters = https://defused.cachix.org
extra-trusted-public-keys = defused.cachix.org-1:/YD+2Bmle49JSliBhGRqTKpLYhvruoFyMPPU071YCAY=
```

## Polkit authorization

Owning the mountpoint answers "is this file the caller's to use", not
"is this caller allowed to create FUSE mounts at all".
For the latter, defused asks polkit (`website.soss.defused.mount`) before
creating a mount, so that policy can be configured system-wide (see
`data/website.soss.defused.policy`) or per-client with a
`/etc/polkit-1/rules.d/*.rules` script, independently of who owns the
mountpoint.
The shipped default is `auth_admin_keep`, and defused fails closed if
polkit can't be reached at all -- see `doc/protocol.md` for the full
reasoning.
Unmounting isn't gated by polkit, since the existing ownership check (only
the mount's own creator may tear it down) is already a complete answer for
that operation.

defused has no config file or options beyond `--help`.
The caller's current FUSE mount count and whether `-o allow_other` was
requested are passed to polkit as details on every `CheckAuthorization`
call, so that policy can be expressed per client in a rule.
`examples/50-defused-mount-policy.rules` is a complete, installable
example.

## Licensing

This project copies a lot of helpers from libfuse, which are either
GPL-2.0-only or LGPL-2.1-only.
All of my code is licensed under GPL-2.0-or-later.

[FUSE-Wikipedia]: https://en.wikipedia.org/wiki/Filesystem_in_Userspace
[FUSE]: https://www.kernel.org/doc/html/next/filesystems/fuse.html
[libfuse]: https://github.com/libfuse/libfuse
[NoNewPrivileges]: https://docs.kernel.org/userspace-api/no_new_privs.html
[seccomp-bpf]: https://docs.kernel.org/userspace-api/seccomp_filter.html
[landlock]: https://docs.kernel.org/userspace-api/landlock.html
