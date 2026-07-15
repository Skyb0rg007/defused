<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# The defused wire protocol

This document describes the protocol spoken between the unprivileged
`fusermount3` replacement (the *client*) and the privileged `defused` system
service.
The authoritative definition is the shared header `src/defused.h`.

## Transport

The service listens on a `SOCK_SEQPACKET` `AF_UNIX` socket.
A client's interaction with the protocol is always:
connect, send one request, receive one response, disconnect.

- **Socket path**: `/run/defused/defused.sock` (`DEFUSED_SOCKET_PATH`).
- **Socket type**: `SOCK_SEQPACKET`.
  Every `sendmsg()`/`recvmsg()` call transfers exactly one datagram-like
  message, so there is no length prefixing or partial-read/partial-write loop
  anywhere in the protocol.
- **Server-side activation**: the service socket unit uses `Accept=yes`,
  and `defused` receives the already-`accept()`-ed connection through the
  standard systemd `$LISTEN_PID`/`$LISTEN_FDS` protocol (`sd_listen_fds(3)`)
  rather than on any of its standard file descriptors.

## Message framing

Every request and every response begins with the same 12-byte header:

```c
struct defused_hdr {
  uint32_t magic;    /* DEFUSED_PROTO_MAGIC   = 0x44465531 ("DFU1") */
  uint32_t version;  /* DEFUSED_PROTO_VERSION = 1 */
  uint32_t op;       /* enum defused_op */
};
```

All fields are host byte order.

There is no explicit length field since `SOCK_SEQPACKET` provides the
framing.
The service will send a response with `DEFUSED_ERR_MALFORMED` if the
magic, version, or message size don't exactly match a known request shape.

## Ancillary file descriptors

Requests carry operation-specific ancillary file descriptors via
`SCM_RIGHTS`: mount requests carry two fds and unmount requests carry one.

The service will resolve the connecting process's mount namespace from
`SO_PEERPIDFD` on the socket itself and joins that namespace when needed.
That ties the namespace to the kernel-verified peer on this connection.

Responses carry no ancillary fds.

## Operations

### `DEFUSED_OP_MOUNT`

Request:

```c
struct defused_mount_req {
  struct defused_hdr hdr;         /* op = DEFUSED_OP_MOUNT */
  uint32_t mount_flags;           /* enum defused_mount_flag bits */
  uint32_t max_read;              /* -o max_read=N, 0 = unset */
  uint32_t blksize;               /* -o blksize=N, 0 = unset */
  char fsname[DEFUSED_MAX_NAME];  /* -o fsname=, may be empty; no '/' */
  char subtype[DEFUSED_MAX_NAME]; /* -o subtype=, may be empty; no '/' */
};
```

`DEFUSED_MAX_NAME` is 32 bytes.
The mount request carries exactly two ancillary fds, in order:

1. A file descriptor for `/dev/fuse`.
2. A file descriptor for the mountpoint.

The service validates the `/dev/fuse` fd before using it, but does not open the
device itself and never changes uid or gid.
That preserves device-node access policy: a client that cannot open `/dev/fuse`
cannot ask the service to do it on its behalf.
The service validates the mountpoint fd with `fstat()`, including that it names
a directory or regular file.
The detached mount is attached to that fd with `move_mount(..., MOVE_MOUNT_T_EMPTY_PATH)`.

`mount_flags` is the final option bitmask requested by the client.
The empty bitmask is the fusermount3-compatible unprivileged default:
`nosuid` and `nodev` are enforced unless the client explicitly sets
`DEFUSED_MOUNT_ALLOW_DEV`.

Policy applied before the mount is attempted:

- `ALLOW_OTHER` requires the service to have been started with
  `--user-allow-other`, else `DEFUSED_ERR_NOT_ALLOWED`.
- The mountpoint must be a directory or regular file
  (`DEFUSED_ERR_MALFORMED` otherwise).
- The mountpoint fd must name a caller-owned writable mountpoint
  on a backing filesystem type that libfuse permits for unprivileged mounts
  (`DEFUSED_ERR_NOT_ALLOWED` otherwise).
  Directories must also be searchable by the caller.
  This is an intentional policy difference from libfuse's setuid
  `fusermount3`: libfuse allows writable non-sticky shared directories owned
  by another user, while defused requires caller ownership so the privileged
  service can authorize the received mountpoint fd directly.
- If `--mount-max` (default 1000, `-1` disables it) is already reached, the
  mount is refused (`DEFUSED_ERR_TOO_MANY_MOUNTS`).

On success, the service creates the mount with the Linux new mount API
(`fsopen()`/`fsconfig()`/`fsmount()`), attaches it to the received
mountpoint fd with `move_mount()`, and replies `DEFUSED_OK`.
The client keeps the `/dev/fuse` fd it opened and sent in the request, and
hands that same fd to libfuse.

### `DEFUSED_OP_UNMOUNT`

Request:

```c
struct defused_umount_req {
  struct defused_hdr hdr;          /* op = DEFUSED_OP_UNMOUNT */
  uint32_t lazy;                   /* nonzero => MNT_DETACH */
  char name[DEFUSED_MAX_FILENAME]; /* basename of the mountpoint; no '/' allowed */
};
```

`DEFUSED_MAX_FILENAME` is 256 bytes (`NAME_MAX + 1`).

The ancillary fd is a file descriptor for the mountpoint's **parent** directory.
`name` is the mountpoint's basename within that directory.
Providing an invalid name results in `DEFUSED_ERR_MALFORMED`.

The service opens `name` under the parent fd to identify the target via its
`fdinfo` `mnt_id`, compare that with the parent fd's `mnt_id`, and look up the
matching `/proc/self/mountinfo` line, then closes the target fd before doing
anything further.
The target must be a mountpoint under the parent, not just a regular directory
inside the same mount, so the target and parent mount IDs must differ.
The target lookup must also show the mount as a FUSE mount
(`DEFUSED_ERR_NOT_A_FUSE_MOUNT` otherwise), and its `user_id=` superblock
option must match the caller's uid (`DEFUSED_ERR_NOT_ALLOWED` otherwise).

The actual `umount2()` call is made by path, as
`/proc/self/fd/<parent fd>/<name>`, with `UMOUNT_NOFOLLOW`.
On success/failure it replies `DEFUSED_OK`/`DEFUSED_ERR_UNMOUNT_FAILED`.

## Response

```c
struct defused_resp {
  struct defused_hdr hdr; /* op = DEFUSED_OP_RESPONSE */
  uint32_t status;   /* enum defused_status */
  int32_t sys_errno; /* errno from mount setup/umount2()/setns(), when relevant */
};
```

`status` is one of:

| Value | Name | Meaning |
|---|---|---|
| 0 | `DEFUSED_OK` | Success |
| 1 | `DEFUSED_ERR_MALFORMED` | Bad magic/version/op/size, wrong fd count, or a request-level validation failure (e.g. a bad `name`) |
| 2 | `DEFUSED_ERR_BAD_OPTION` | `mount_flags` outside its allowed mask |
| 3 | `DEFUSED_ERR_NOT_ALLOWED` | A privileged option used without privilege, or the mountpoint/mount isn't the caller's to use |
| 4 | `DEFUSED_ERR_TOO_MANY_MOUNTS` | `--mount-max` reached |
| 5 | `DEFUSED_ERR_NOT_A_FUSE_MOUNT` | Unmount target isn't a FUSE mount |
| 6 | `DEFUSED_ERR_MOUNT_FAILED` | Mount setup or attachment failed; see `sys_errno` |
| 7 | `DEFUSED_ERR_UNMOUNT_FAILED` | `umount2(2)` failed; see `sys_errno` |
| 8 | `DEFUSED_ERR_SETNS_FAILED` | Couldn't join the caller's mount namespace; see `sys_errno` |

A client should treat any response it cannot parse (wrong size, bad magic,
unexpected version) the same as a transport failure, not as a status code.

## Implementation decisions

This section records the reasoning behind choices above, for future
maintainers deciding whether to change them.

### Why `SOCK_SEQPACKET`

`SOCK_SEQPACKET` preserves message boundaries and delivers each message
atomically (`SOCK_DGRAM` semantics with `SOCK_STREAM`'s reliability and
ordering guarantees).
One `recvmsg()` call always yields exactly one complete request or response and
its ancillary fds, so there is no need to re-implement framing.

### Why one process per connection, spawned by `Accept=yes`

The use of `setns()` means that the service must `fork()` before handling
a request anyways.
By using the systemd `Accept=yes` mode, the service manager performs that
`fork()` for us.

### Why a typed binary protocol instead of an `-o`-style option string

We control both sides of the protocol, so we can make sure that all of the
error-prone string parsing code is done by the unprivileged helper.
This can also make it easier to implement new frontends to defused.

### Why the service resolves the mount namespace from the socket peer

Mount attachment and `umount2(2)` only ever act on the calling process's
*current* mount namespace, so a request from a client in a container --
which may have had only the socket bind-mounted into it -- has to be
serviced from within *that* client's mount namespace, not the host's.

### Why unmount passes a parent-directory fd, not an fd on the mount itself

One possible thought would be to pass a file descriptor to the mountpoint
itself, and call `umount2()` via `/proc/self/fd/N`.
This doesn't work for non-lazy unmounts, as that file descriptor is considered
an additional open file descriptor, so `umount2()` will return `EBUSY`.

This mirrors the libfuse `fusermount3`'s own `chdir_to_parent()` + by-name
`umount2(..., UMOUNT_NOFOLLOW)`:
name the target without ever holding a reference to it.
And exactly like libfuse, defused checks that the mount ID is okay to unmount
but closes the file descriptor before calling `umount2()` to avoid the `EBUSY`
issue.

Even though this looks like a TOCTOU issue, mountpoints are not able to
be renamed, and the unmount cannot be misdirected via symlink due to
`UMOUNT_NOFOLLOW`.
This is also what libfuse has done forever.

### Versioning

`DEFUSED_PROTO_MAGIC` ensures that the client is not confused about what
they're requesting when they send a message.
`DEFUSED_PROTO_VERSION` is used to allow for future protocol changes, to
enable backwards-compatibility.
