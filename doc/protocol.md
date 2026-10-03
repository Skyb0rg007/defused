<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# The defused wire protocol

This document describes the protocol spoken between the unprivileged
`fusermount3` replacement (the *client*) and the privileged `defused` system
service.

The client is installed under both of libfuse's helper names, `fusermount3`
and libfuse2's `fusermount`.
libfuse2's command line and `-o` option set are a subset of libfuse3's so
nothing below depends on which name the client was invoked under.

The authoritative definition of the wire protocol is `src/defused-proto.h`.

## Transport

The service listens on an `AF_UNIX` `SOCK_SEQPACKET` socket.
It must be started as root.

- **Socket path**: `/run/defused/defused.sock` (`DEFUSED_SOCKET_PATH`).
- **Socket type**: `SOCK_SEQPACKET`, so that one `sendmsg()` is exactly one
  `recvmsg()`.
- **Server-side activation**: the service socket unit uses `Accept=yes`,
  and `defused` receives the already-`accept()`-ed connection as fd 3,
  announced through `$LISTEN_PID`/`$LISTEN_FDS` (the `sd_listen_fds(3)`
  protocol).
- **`--daemon` activation**: `defused --daemon` creates and binds the socket
  itself (at `DEFUSED_SOCKET_PATH` by default, mode 0666), then forks a child
  per accepted connection to run the same one-request-per-connection handler.

A connection lasts for exactly one request and one reply; the service exits
after answering.

## Messages

Both messages are fixed-size and use native endian encoding.
There is no version negotiation, but the first 4 bytes of a message are fixed
to catch version mismatches.

### Request

```c
struct defused_request {
    uint32_t magic;       /* DEFUSED_MAGIC */
    uint32_t op;          /* DEFUSED_OP_MOUNT or DEFUSED_OP_UNMOUNT */
    uint32_t mount_flags; /* mount: enum defused_mount_flag */
    uint32_t max_read;    /* mount: 0 for unset */
    uint32_t blksize;     /* mount: 0 for unset */
    uint32_t lazy;        /* unmount: add MNT_DETACH */
    char fsname[4096];    /* mount */
    char subtype[32];     /* mount */
    char name[256];       /* unmount: the mountpoint basename */
};
```

To simplify the protocol, both mount and unmount operations use the same
struct.
The string fields are fixed-length and NUL-terminated.

The descriptors a request carries are decided by its op:

| Op | Descriptors, in order |
| --- | --- |
| `DEFUSED_OP_MOUNT` | `/dev/fuse`, then the mountpoint |
| `DEFUSED_OP_UNMOUNT` | the mountpoint's *parent* directory |

An invalid request will get the response `DEFUSED_ERR_MALFORMED` and `EBADMSG`.

### Reply

```c
struct defused_reply {
    uint32_t magic;    /* DEFUSED_MAGIC */
    uint32_t code;     /* enum defused_error_code; 0 is success */
    int32_t sys_errno; /* Linux error code, or 0 if not relevant */
};
```

Replies are also fixed size, but will not carry file descriptors.
The `code` field describes the high-level issue:

| `code` | Meaning |
| --- | --- |
| `DEFUSED_OK` | The mount or unmount was performed |
| `DEFUSED_ERR_MALFORMED` | Request-level validation failure; `sys_errno` says what was wrong with it |
| `DEFUSED_ERR_BAD_OPTION` | `mount_flags` outside its allowed mask, or a privileged-only flag sent to the service |
| `DEFUSED_ERR_NOT_ALLOWED` | The mountpoint/mount is not the caller's, or policy denied the operation |
| `DEFUSED_ERR_NOT_A_FUSE_MOUNT` | Unmount target is not a FUSE mount |
| `DEFUSED_ERR_MOUNT_FAILED` | Mount setup, joining the caller's mount namespace, or attachment failed |
| `DEFUSED_ERR_UNMOUNT_FAILED` | Joining the caller's mount namespace or `umount2(2)` failed |

`sys_errno` is set to the error code that a syscall returned.

## Mount

`mount_flags` is the final option bitmask requested by the client.
The empty bitmask is the fusermount3-compatible unprivileged default:
`nosuid` and `nodev` are enforced unless a privileged caller explicitly sets
`DEFUSED_MOUNT_ALLOW_SUID` or `DEFUSED_MOUNT_ALLOW_DEV`.

Policy applied before the mount is attempted:

- The mountpoint must be a directory or regular file
  (`DEFUSED_ERR_MALFORMED` otherwise).
- The FUSE device fd must really name `/dev/fuse` and be open read/write
  (`DEFUSED_ERR_MALFORMED` otherwise).
- The mountpoint fd must name a caller-owned writable mountpoint on a backing
  filesystem type that libfuse permits for unprivileged mounts
  (`DEFUSED_ERR_NOT_ALLOWED` otherwise). Directories must also be searchable by
  the caller.
- The service asks its policy whether the caller may create this mount at
  all -- see [The mount policy](#the-mount-policy)
  (`DEFUSED_ERR_NOT_ALLOWED` otherwise).

On success, the service creates the mount with Linux's file-descriptor-based
mount API (`fsopen()`/`fsconfig()`/`fsmount()`), attaches it to the received
mountpoint fd with `move_mount()`, and replies `DEFUSED_OK`.

## Unmount

`name` is the mountpoint's basename. The parent directory is sent via file
descriptor.

The service reads the `mnt_id` of `name` under the parent fd with
`name_to_handle_at()` and compares it with the parent fd's own.
The target must be a mountpoint under the parent, not just a regular directory
inside the same mount, so the target and parent mount IDs must differ.
From here on the `mnt_id` is what identifies the target.

The service then asks its policy whether the caller may unmount at all (the
`--allow-groups` check), failing otherwise.
The check only answers whether the caller may use unmount at all, and thus
the default policy is to always allow.
The service then asks `statmount()` about the target within the caller's mount
namespace (found via the socket peer's pidfd) and checks that the mount is a
`fuse` or `fuseblk` mount whose `user_id=` superblock option matches the
caller's uid.

Finally, the service loads its seccomp filter and joins the caller's mount
namespace.
It then changes directory to the parent fd, and asks `name_to_handle_at()`
about `name` again to check that its `mnt_id` is still the one that was
authorized
It then calls `umount2(name, UMOUNT_NOFOLLOW)`, adding `MNT_DETACH` if `lazy`
is set.
No defused process holds an fd on the mount at that point, since any such
reference would make a non-lazy unmount fail with `EBUSY`.

## Privileged callers

A `fusermount3` caller that is root or holds `CAP_SYS_ADMIN` does not contact
the defused socket.
It already has the privilege to perform the mount itself, so it will call
`defused_perform()` directly to do the work in its own process.
By doing so, it also skips all of the policy checks.

The privileged code path also accepts `DEFUSED_MOUNT_ALLOW_SUID` (`suid`),
`DEFUSED_MOUNT_ALLOW_DEV` (`dev`) and `DEFUSED_MOUNT_BLKDEV` (`blkdev`: a
`fuseblk` mount whose `fsname` is the block device path, so it may contain
slashes here)
Those options are unsafe to let unprivileged users set, so the service responds
with `DEFUSED_ERR_BAD_OPTION` to all three.

## Why the service resolves the mount namespace from the socket peer

Mount attachment and `umount2(2)` only ever act on the calling process's
*current* mount namespace, so a request from a client in a container -- which
may have had only the socket bind-mounted into it -- has to be serviced from
within that client's mount namespace, not the host's.

The service uses `SO_PEERPIDFD` on the accepted socket to identify the
connecting process and joins that process's mount namespace before the
mount/umount operation.

The service enters the client-controlled namespace only under an enforcing
seccomp filter.
The service tries to do as much as possible before setting it up:
for mounts, it leaves only `setns()` and `move_mount()` for after the filter.
For unmounts, it can additionally `fchdir()` to the parent directory,
`name_to_handle_at()` `name` under it, and call `umount2()`.
Either way it may then `sendto()` the reply to the client, write to stderr,
and exit.

The seccomp filter guards against libc opening files in the client's filesystem
(such as `/etc/nsswitch.conf`).
Each syscall that operates on a path or descriptor has that argument pinned.
For dynamic string arguments (ex. for `umount2()`), the string is first copied
into an anonymous mapping which is made read-only with `mprotect()`.
The post-`setns()` operations use explicit syscall wrappers to make sure there
are no libc-wrapper-specific issues.

## Why unmount passes a parent-directory fd

Passing an fd on the mountpoint itself makes non-lazy `umount2()` see an
additional open reference and return `EBUSY`.
The same applies to fds the service would open, which is why the `mnt_id`
checks take no fd at all, and why the final call names the target as `name`
relative to the parent directory.

Those mount-id reads use `name_to_handle_at()` rather than `statx()`, which
would be the obvious choice.
`statx()` calls the filesystem's `getattr()`, and `fuse_getattr()` answers
`EACCES` to any non-empty request from a process that is neither the mount's
`user_id` nor covered by `allow_other` -- running as root is no help.
`name_to_handle_at()` never calls `getattr()`;
`AT_HANDLE_FID` asks for a handle that need not be decodable, which every
filesystem can produce, and `AT_HANDLE_MNT_ID_UNIQUE` returns the 64-bit mount
id the kernel never reuses, so an id recycled inside the window cannot pass for
the mount that was authorized.

The sandboxed process re-checks the fd-relative lookup right before
`umount2()` to make sure `name` must still resolve to the authorized `mnt_id`.
The kernel refuses to rename a mountpoint, or over one, within the
caller's mount namespace, so what remains is a window of two syscalls in which
only the mount table itself could change under the same directory entry.

## The mount policy

Because defused runs as a system service, it is unable to use process-specific
information when making filesystem access decisions such as those enforced via
LSMs.
What it can decide is who may use the service at all, and how much: a policy
like "one group may create up to 100 mounts, with no privileged options".
The service takes that policy from its command line and applies it to every
request from an unprivileged caller:

| Option | Meaning | Default |
| --- | --- | --- |
| `--max-mounts=N` | Refuse a mount once N FUSE filesystems are mounted in the caller's mount namespace | 100 |
| `--allow-groups=GROUP[,GROUP...]` | Only members of these groups (names or gids) may mount and unmount | any user |
| `--allow-other` | Let callers set the `allow_other` mount option | refused |

A refused request is answered with `DEFUSED_ERR_NOT_ALLOWED`.
For unmount only the group check applies, for the reason given below.

### Why unmount's policy differs from mount's

Unmount is subject to the group check but not to `--max-mounts` or the
`--allow-other` check.
The ownership check that follows (that the mount's `user_id=` must match the
caller) is a sufficient answer to "is this caller allowed to tear down this
specific mount".
