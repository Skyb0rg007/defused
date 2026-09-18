<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# The defused wire protocol

This document describes the protocol spoken between the unprivileged
`fusermount3` replacement (the *client*) and the privileged `defused` system
service.

The authoritative constants are in `src/defused_proto.h`; the Varlink
interface is defined in `src/defused-varlink.c`.

## Transport

The service listens on an `AF_UNIX` `SOCK_STREAM` socket and speaks Varlink
using libsystemd's `sd-varlink` implementation.
It must be started as root.

- **Socket path**: `/run/defused/defused.sock` (`DEFUSED_SOCKET_PATH`).
- **Socket type**: `SOCK_STREAM`.
- **Server-side activation**: the service socket unit uses `Accept=yes`,
  and `defused` receives the already-`accept()`-ed connection through the
  standard systemd `$LISTEN_PID`/`$LISTEN_FDS` protocol (`sd_listen_fds(3)`).
  The socket is created by systemd at its default `SocketMode=`, 0666.
- **`--daemon` activation**: for systems without systemd as service
  manager, `defused --daemon` creates and binds the Varlink socket itself
  (still at `DEFUSED_SOCKET_PATH` by default, also mode 0666), then forks
  a child per accepted connection to run the same one-call-per-connection
  handling as the `Accept=yes` path.
- **Discovery**: the socket inode is tagged with the extended attribute
  `user.varlink=entrypoint` as recommended by the [Varlink UAPI Spec][].
  This only works on Linux 7.0 and above.

The service handles one Varlink method call and exits when the connection goes
idle.

## Interface

The interface name is:

```varlink
interface website.soss.defused
```

### Mount

```varlink
method Mount(
  fuseFileDescriptor: int,
  mountpointFileDescriptor: int,
  mountFlags: int,
  maxRead: int,
  blockSize: int,
  fsName: string,
  subtype: string
) -> ()
```

The client attaches exactly two fds to the Varlink call:

1. A file descriptor for `/dev/fuse`.
2. A file descriptor for the mountpoint.

`fuseFileDescriptor` and `mountpointFileDescriptor` are indices into the fd
array associated with the call. `fusermount3` sends `0` and `1`, respectively.

`mountFlags` is the final option bitmask requested by the client. The empty
bitmask is the fusermount3-compatible unprivileged default: `nosuid` and
`nodev` are enforced unless the client explicitly sets
`DEFUSED_MOUNT_ALLOW_DEV`.

Policy applied before the mount is attempted:

- The mountpoint must be a directory or regular file
  (`MalformedRequest` otherwise).
- The FUSE device fd must really name `/dev/fuse` and be open read/write
  (`MalformedRequest` otherwise).
- The mountpoint fd must name a caller-owned writable mountpoint on a backing
  filesystem type that libfuse permits for unprivileged mounts
  (`NotAllowed` otherwise). Directories must also be searchable by
  the caller.
- The service asks polkit (`org.freedesktop.PolicyKit1.Authority
  .CheckAuthorization`) whether the caller may create this mount
  (`website.soss.defused.mount`), providing the privileged options that the
  request asks for via the `privileged-flags` detail, and the total number
  of FUSE mounts via `current-mounts`.

On success, the service creates the mount with Linux's file-descriptor-based
mount API (`fsopen()`/`fsconfig()`/`fsmount()`), attaches it to the received
mountpoint fd with `move_mount()`, and replies with an empty object.

### Unmount

```varlink
method Unmount(
  parentFileDescriptor: int,
  name: string,
  lazy: bool
) -> ()
```

The client attaches a file descriptor for the mountpoint's parent directory.
`parentFileDescriptor` is the index of that fd, normally `0`.
`name` is the mountpoint's basename within that directory.

The service opens `name` under the parent fd with `O_PATH | O_NOFOLLOW`,
reads the target's `mnt_id` from its `fdinfo`, compares that with the parent
fd's `mnt_id`, and closes the target fd again.
The target must be a mountpoint under the parent, not just a regular directory
inside the same mount, so the target and parent mount IDs must differ.
From here on the `mnt_id` is what identifies the target.

The service then ensures via polkit that the caller is permitted to call
`website.soss.defused.unmount`, failing otherwise.
The polkit check only answers whether the caller may use unmount at all,
and thus the default policy is to always allow.
The service then reads the caller's `/proc/<pid>/mountinfo` (the pid comes
from the socket peer's pidfd) and checks that the target's `mnt_id` identifies
a FUSE mount whose `user_id=` superblock option matches the caller's uid.

Finally, a sandboxed child joins the caller's mount namespace, changes
directory to the parent fd, re-opens `name` with `O_PATH | O_NOFOLLOW`, and
checks through the service's trusted procfs that its `mnt_id` is still the
one that was authorized.
It closes that fd again and calls `umount2(name, UMOUNT_NOFOLLOW)`, adding
`MNT_DETACH` if `lazy` is true.
No defused process holds an fd on the mount at that point, since any such
reference would make a non-lazy unmount fail with `EBUSY`.

## Errors

A method that succeeds replies with an empty object; a failure is one of:

```varlink
error MalformedRequest(errno: int)
error BadMountOption()
error NotAllowed()
error NotAFuseMount()
error MountFailed(errno: int)
error UnmountFailed(errno: int)
```

| Error | Meaning |
| --- | --- |
| `MalformedRequest` | Request-level validation failure after Varlink parsing and fd binding; `errno` says what was wrong with it |
| `BadMountOption` | `mountFlags` outside its allowed mask |
| `NotAllowed` | The mountpoint/mount is not the caller's to use, or polkit denied the operation |
| `NotAFuseMount` | Unmount target is not a FUSE mount |
| `MountFailed` | Mount setup, joining the caller's mount namespace, or attachment failed, or polkit could not be reached |
| `UnmountFailed` | Joining the caller's mount namespace or `umount2(2)` failed, or polkit could not be reached |

`errno` is the Linux error number behind the failure, following the
`io.systemd.System` convention.
Which function produced it is a debugging detail the service keeps to its own
log rather than putting on the wire.

Varlink protocol-level problems, such as missing fields, wrong field types, bad
fd indices, or wrong fd count, are returned as standard Varlink errors by
libsystemd instead.

## Why Varlink

Varlink gives defused a typed, introspectable request protocol without a custom
binary parser.
The service uses libsystemd for the JSON parser, method dispatcher, fd passing
bookkeeping, and reply framing.
The only values defused interprets itself are already-typed integers, booleans,
and strings delivered by `sd_varlink_dispatch()`.

## Why the service resolves the mount namespace from the socket peer

Mount attachment and `umount2(2)` only ever act on the calling process's
*current* mount namespace, so a request from a client in a container -- which
may have had only the socket bind-mounted into it -- has to be serviced from
within that client's mount namespace, not the host's.

The service uses `SO_PEERPIDFD` on the accepted socket to identify the
connecting process and joins that process's mount namespace before the
mount/umount operation.

The main service process never enters the client-controlled namespace.
After validating and authorizing the request, it forks a short-lived child that
installs an enforcing seccomp filter and then joins the namespace.
For mounts, the parent creates a detached FUSE mount first, leaving the child
only `setns()` and `move_mount()`.
For unmounts, the child can additionally open `name` under the parent
directory, read its `fdinfo` through the trusted procfs file descriptor opened
by the parent, close it, and call `umount2()`.
The post-`setns()` code uses explicit syscall wrappers so the filter's
allowlist fully describes its possible kernel interface.

## Why unmount passes a parent-directory fd

Passing an fd on the mountpoint itself makes non-lazy `umount2()` see an
additional open reference and return `EBUSY`.
The same applies to fds the service opens: the `O_PATH` fd it uses to read the
target's `mnt_id` is closed before `umount2()` runs, and the final call names
the target as `name` relative to the parent directory, mirroring libfuse's own
`fusermount3` flow.

That parent-relative lookup is what the sandboxed child re-checks right before
`umount2()`: `name` must still resolve to the authorized `mnt_id`, so a rename
or replacement of `name` after authorization is caught instead of redirecting
the unmount to a different mount.
The kernel also refuses to rename a mountpoint, or over one, within the
caller's mount namespace, so what remains is a window of two syscalls in which
only the mount table itself could change under the same directory entry.

## Why defused asks polkit

Because defused runs as a system service, it is unable to use process-specific
information when making filesystem access decisions such as those enforced via
LSMs.
It may also be desirable to set different mount limits for different users and
groups, or to allow some privileged FUSE options after interactive
authentication.
defused uses polkit to implement these features.

By default, defused is installed with a policy that requires `AUTH_ADMIN_KEEP`
for all mount requests.
This is likely overly restrictive.
The project provides an example polkit rules file to allow unprivileged FUSE
options to all users, and to only require authentication as admin for possibly
insecure options such as `ALLOW_OTHER`.

The mount action includes additional information that should be queried when
writing polkit rules:

| Key | Value |
| --- | --- |
| `current-mounts` | The caller's live FUSE mount count, decimal. A rule wanting a mount-count limit implements it entirely from this. |
| `privileged-flags` | Comma-separated names of the privileged mount options (see `privileged_mount_flags[]` in `defused.c`; currently just `allow_other`) the request actually sets. Omitted entirely when the request sets none. |

Both values are strings, so a rule comparing `current-mounts` numerically needs
to call `parseInt()` first, and one inspecting `privileged-flags` needs to call
`.split(",")` on it.
`packaging/polkit/examples/50-defused-mount-policy.rules` is a complete,
installable rule using both: it grants ordinary mounts (fewer than 100 open,
requesting no privileged option the rule doesn't explicitly allowlist) without
prompting, and falls back to `AUTH_ADMIN_KEEP` for anything past that limit or
outside the allowlist.

### Why `privileged-flags` is a name list

Flags like `ALLOW_OTHER` grant the caller additional privileges that need to be
individually allow-listed.
If each option was a separate polkit detail, a new release could result in a
policy becoming insecure.
By using a comma-separated list the polkit rule can simply require auth for
every option it doesn't recognize: see
`packaging/polkit/examples/50-defused-mount-policy.rules` for an example.

### Why unmount's default policy differs from mount's

The permissions on the mount functionality is gated behind `AUTH_ADMIN_KEEP`,
but `website.soss.defused.unmount`'s default is `YES`.
This is because the ownership check that follows the polkit check (that the
mount's `user_id=` must match the caller) is a sufficient answer to "is this
caller allowed to tear down this specific mount".
A deployment that wants to log unmounts or needs to prevent a specific pid from
unmounting FUSE mounts owned by its uid can do so by modifying
`website.soss.defused.unmount`'s policy.

[Varlink UAPI Spec]: https://uapi-group.org/specifications/specs/varlink/
