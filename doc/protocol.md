<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# The defused wire protocol

This document describes the protocol spoken between the unprivileged
`fusermount3` replacement (the *client*) and the privileged `defused` system
service.

The client is installed under both of libfuse's helper names, `fusermount3`
and libfuse2's `fusermount`: one binary, one wire protocol. libfuse2's
command line and `-o` option set are a subset of libfuse3's, so nothing below
depends on which name the client was invoked under.

The authoritative constants are in `src/defused_proto.h`; the Varlink
interface is defined in `src/defused-varlink.c`.

## Transport

The service listens on an `AF_UNIX` `SOCK_STREAM` socket and speaks Varlink
using libsystemd's `sd-varlink` implementation.
It must be started as root.

- **Socket path**: `/run/defused/defused.sock` (`DEFUSED_SOCKET_PATH`).
- **Socket type**: `SOCK_STREAM`.
- **Server-side activation**: the socket unit uses `Accept=yes` and
  `FileDescriptorName=varlink`, so `defused` receives the
  already-`accept()`-ed connection as the one `$LISTEN_FDS` fd and checks
  for it with `sd_varlink_invocation(3)`, like systemd's own `Accept=yes`
  Varlink services. The socket is created by systemd at its default
  `SocketMode=`, 0666, with `MaxConnections=64` (the default) and
  `MaxConnectionsPerSource=16`.
- **`defused-activate`**: for systems without systemd as service manager.
  It binds the Varlink socket itself (`DEFUSED_SOCKET_PATH` by default,
  also mode 0666) and spawns one `defused` per accepted connection with
  the same handoff and the same two connection limits.
  `systemd-socket-activate(1)` is not usable in its place: it binds
  `AF_UNIX` sockets 0644 with no way to change that, it does not tag the
  socket for discovery, and it takes over a socket another process is
  still serving.
- **Discovery**: the socket inode is tagged with the extended attribute
  `user.varlink=entrypoint` as recommended by the [Varlink UAPI Spec][].
  This only works on Linux 7.0 and above.
- **`--child`**: the same handoff, but spawned by `fusermount3` via
  `sd_varlink_connect_exec(3)`; see [Privileged callers](#privileged-callers).

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
`nodev` are enforced unless a privileged caller explicitly sets
`DEFUSED_MOUNT_ALLOW_SUID` or `DEFUSED_MOUNT_ALLOW_DEV`.

Policy applied before the mount is attempted:

- The mountpoint must be a directory or regular file
  (`MalformedRequest` otherwise).
- The FUSE device fd must really name `/dev/fuse` and be open read/write
  (`MalformedRequest` otherwise).
- The mountpoint fd must name a caller-owned writable mountpoint on a backing
  filesystem type that libfuse permits for unprivileged mounts
  (`NotAllowed` otherwise). Directories must also be searchable by
  the caller.
- The service asks its policy whether the caller may create this mount at
  all -- see [The mount policy](#the-mount-policy) (`NotAllowed` otherwise).

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

The service reads the `mnt_id` of `name` under the parent fd with
`name_to_handle_at()` and compares it with the parent fd's own.
The target must be a mountpoint under the parent, not just a regular directory
inside the same mount, so the target and parent mount IDs must differ.
From here on the `mnt_id` is what identifies the target.

The service then asks its policy whether the caller may unmount at all (the
`--allow-groups` check), failing otherwise.
The check only answers whether the caller may use unmount at all, and thus
the default policy is to always allow.
The service then asks `statmount()` about the target, naming the caller's
mount namespace (found from the socket peer's pidfd) so that nothing has to
be entered, and checks that the mount is a `fuse` or `fuseblk` one whose
`user_id=` superblock option matches the caller's uid.

Finally, a sandboxed child joins the caller's mount namespace, changes
directory to the parent fd, and asks `name_to_handle_at()` about `name`
again to check that its `mnt_id` is still the one that was authorized.
It then calls `umount2(name, UMOUNT_NOFOLLOW)`, adding `MNT_DETACH` if `lazy`
is true.
No defused process holds an fd on the mount at that point, since any such
reference would make a non-lazy unmount fail with `EBUSY`.

## Privileged callers

A `fusermount3` caller that is root or holds `CAP_SYS_ADMIN` does not use the
service: it spawns `defused --child` with `sd_varlink_connect_exec(3)` and
speaks the same protocol to it.
The child validates the request for shape, skips the ownership rule, the
filesystem-type allowlist, the policy, and the unmount `user_id=` check, and
calls `move_mount()` or `umount2()` directly in the caller's mount namespace.
Like root's `umount`, it unmounts any mount below the parent directory.

It is also the only path that accepts `DEFUSED_MOUNT_ALLOW_SUID` (`suid`),
`DEFUSED_MOUNT_ALLOW_DEV` (`dev`) and `DEFUSED_MOUNT_BLKDEV` (`blkdev`: a
`fuseblk` mount whose `fsName` is the block device path, so it may contain
slashes here), as libfuse's `fusermount3` does for root: `suid` and `dev` are
the two options its own table marks unsafe.
The service answers `BadMountOption` to all three rather than consulting its
policy, since granting `suid` or `dev` would let a user's FUSE server hand out
setuid-root binaries or device nodes.

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
| `BadMountOption` | `mountFlags` outside its allowed mask, or a privileged-only flag sent to the service |
| `NotAllowed` | The mountpoint/mount is not the caller's to use, or policy denied the operation |
| `NotAFuseMount` | Unmount target is not a FUSE mount |
| `MountFailed` | Mount setup, joining the caller's mount namespace, or attachment failed |
| `UnmountFailed` | Joining the caller's mount namespace or `umount2(2)` failed |

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
For unmounts, the child can additionally `fchdir()` to the parent directory,
`name_to_handle_at()` `name` under it, and call `umount2()`.
Both may `write()` their result back and exit.

The filter pins every argument of all of those, not just the syscall numbers:
each rule is an equality test against the exact descriptor, pointer and flag
word the child is about to pass.
seccomp-bpf cannot dereference pointers, so the child first copies its one
path argument into an anonymous mapping and `mprotect()`s it read-only, and
takes the kernel's output buffers from a second mapping.
`mprotect()` is not on the allowlist, so those addresses are fixed for the
child's life, and comparing them by value is as good as comparing the strings.
The post-`setns()` code uses explicit syscall wrappers so the filter's
allowlist fully describes its possible kernel interface.

## Why unmount passes a parent-directory fd

Passing an fd on the mountpoint itself makes non-lazy `umount2()` see an
additional open reference and return `EBUSY`.
The same applies to fds the service would open, which is why the `mnt_id`
checks take no fd at all, and why the final call names the target as `name`
relative to the parent directory, mirroring libfuse's own `fusermount3` flow.

Those mount-id reads use `name_to_handle_at()` rather than `statx()`, which
would be the obvious choice.
`statx()` calls the filesystem's `getattr()`, and `fuse_getattr()` answers
`EACCES` to any non-empty request from a process that is neither the mount's
`user_id` nor covered by `allow_other` -- running as root is no help.
It would therefore refuse exactly the mounts this service exists to unmount.
`name_to_handle_at()` never calls `getattr()`; `AT_HANDLE_FID` asks for a
handle that need not be decodable, which every filesystem can produce, and
`AT_HANDLE_MNT_ID_UNIQUE` returns the 64-bit mount id the kernel never
reuses, so an id recycled inside the window cannot pass for the mount that
was authorized.

That parent-relative lookup is what the sandboxed child re-checks right before
`umount2()`: `name` must still resolve to the authorized `mnt_id`, so a rename
or replacement of `name` after authorization is caught instead of redirecting
the unmount to a different mount.
The kernel also refuses to rename a mountpoint, or over one, within the
caller's mount namespace, so what remains is a window of two syscalls in which
only the mount table itself could change under the same directory entry.

## The mount policy

Because defused runs as a system service, it is unable to use process-specific
information when making filesystem access decisions such as those enforced via
LSMs.
What it can decide is who may use the service at all, and how much: a policy
like "one group may create up to 100 mounts, with no privileged options".
The service takes that policy from its command line, applies it to every
request from an unprivileged caller, and logs the reason for every denial:

| Option | Meaning | Default |
| --- | --- | --- |
| `--max-mounts=N` | Refuse a mount once N FUSE filesystems are mounted in the caller's mount namespace | 100 |
| `--allow-groups=GROUP[,GROUP...]` | Only members of these groups (names or gids, supplementary groups included via `SO_PEERGROUPS`) may mount and unmount | any user |
| `--allow-other` | Let callers set the `allow_other` mount option | refused |

A refused request is answered with `NotAllowed`.
Nothing can be asked interactively: a caller either satisfies the policy or is
refused.
For unmount only the group check applies, for the reason given below.

### Why unmount's policy differs from mount's

Unmount is subject to the group check but not to `--max-mounts` or the
`--allow-other` check, neither of which describes a teardown.
The ownership check that follows (that the mount's `user_id=` must match the
caller) is a sufficient answer to "is this caller allowed to tear down this
specific mount".

[Varlink UAPI Spec]: https://uapi-group.org/specifications/specs/varlink/
