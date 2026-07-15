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

Defused intentionally uses a stricter mountpoint ownership model than
libfuse's setuid `fusermount3`.
For non-root mounts, the mountpoint must be a directory or regular file owned
by the caller.
It must be writable by that caller; directories must also be searchable.

This means defused rejects mounts on writable shared directories owned by
another user, even when libfuse's setuid helper would allow them because the
directory is not sticky.
The stricter rule keeps the privileged service's authorization decision tied
to the mountpoint file descriptor it receives, instead of trying to reproduce
libfuse's path-based `access(W_OK)` check across the client/service protocol.

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
