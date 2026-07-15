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

The `no_new_privileges` flag is important for proper application sandboxing.
Using Unix domain sockets like defused does means that privileges can be
granted or denied by bind-mounting the sockets into the application's
namespace.
Doing so with `/usr/bin` is much more challenging.

## Project structure

This project provides the following:

- A system service that listens on `/run/defused/defused.sock`.
- A replacement `fusermount3` binary to communicate with the service.

The system service is written to use systemd socket activation with
`Accept=yes`.
On systems without systemd as service manager or and for testing,
you can run the service with `systemd-socket-activate`.

## Licensing

This project copies a lot of helpers from libfuse, which are either
GPL-2.0-only or LGPL-2.1-only.
All of my code is licensed under GPL-2.0-or-later.

[FUSE-Wikipedia]: https://en.wikipedia.org/wiki/Filesystem_in_Userspace
[FUSE]: https://www.kernel.org/doc/html/next/filesystems/fuse.html
[libfuse]: https://github.com/libfuse/libfuse
[NoNewPrivileges]: https://docs.kernel.org/userspace-api/no_new_privs.html
