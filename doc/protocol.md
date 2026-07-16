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

- **Socket path**: `/run/defused/defused.sock` (`DEFUSED_SOCKET_PATH`).
- **Socket type**: `SOCK_STREAM`.
- **Server-side activation**: the service socket unit uses `Accept=yes`,
  and `defused` receives the already-`accept()`-ed connection through the
  standard systemd `$LISTEN_PID`/`$LISTEN_FDS` protocol (`sd_listen_fds(3)`).

The service handles one Varlink method call and exits when the connection goes
idle. Message framing, JSON parsing, method dispatch, parameter type checking,
and file-descriptor association are delegated to libsystemd.

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
) -> (status: int, sysErrno: int)
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
  (`DEFUSED_ERR_MALFORMED` otherwise).
- The FUSE device fd must really name `/dev/fuse` and be open read/write
  (`DEFUSED_ERR_MALFORMED` otherwise).
- The mountpoint fd must name a caller-owned writable mountpoint on a backing
  filesystem type that libfuse permits for unprivileged mounts
  (`DEFUSED_ERR_NOT_ALLOWED` otherwise). Directories must also be searchable by
  the caller. This is an intentional policy difference from libfuse's setuid
  `fusermount3`: libfuse allows writable non-sticky shared directories owned by
  another user, while defused requires caller ownership so the privileged
  service can authorize the received mountpoint fd directly.
- The service asks polkit (`org.freedesktop.PolicyKit1.Authority
  .CheckAuthorization`) whether the caller may create this mount at all
  (`website.soss.defused.mount`), telling it which privileged options
  (currently just `ALLOW_OTHER`) the request actually sets via the
  `privileged-flags` detail -- see "Why defused asks polkit" below. A
  denial or challenge maps to `DEFUSED_ERR_NOT_ALLOWED`; being unable to
  reach polkit at all (not installed, not running, D-Bus unreachable)
  fails closed as `DEFUSED_ERR_MOUNT_FAILED` rather than silently falling
  back to the ownership check alone.

On success, the service creates the mount with the Linux new mount API
(`fsopen()`/`fsconfig()`/`fsmount()`), attaches it to the received mountpoint fd
with `move_mount()`, and replies `DEFUSED_OK`.

### Unmount

```varlink
method Unmount(
  parentFileDescriptor: int,
  name: string,
  lazy: bool
) -> (status: int, sysErrno: int)
```

The client attaches exactly one fd: a file descriptor for the mountpoint's
parent directory. `parentFileDescriptor` is the index of that fd, normally `0`.
`name` is the mountpoint's basename within that directory.

The service opens `name` under the parent fd to identify the target via its
`fdinfo` `mnt_id`, compare that with the parent fd's `mnt_id`, and look up the
matching `/proc/self/mountinfo` line, then closes the target fd before doing
anything further. The target must be a mountpoint under the parent, not just a
regular directory inside the same mount, so the target and parent mount IDs must
differ (`DEFUSED_ERR_NOT_A_FUSE_MOUNT` otherwise).

The service then asks polkit whether the caller may use
`website.soss.defused.unmount` at all -- see "Why defused asks polkit" below; a
denial maps to `DEFUSED_ERR_NOT_ALLOWED`, being unable to reach polkit at all
fails closed as `DEFUSED_ERR_UNMOUNT_FAILED`. After joining the caller's mount
namespace, the target lookup must also show the mount as a FUSE mount
(`DEFUSED_ERR_NOT_A_FUSE_MOUNT` otherwise), and its `user_id=` superblock
option must match the caller's uid (`DEFUSED_ERR_NOT_ALLOWED` otherwise).

If `lazy` is true, the service uses `MNT_DETACH`; otherwise it performs a
non-lazy unmount.

## Response Status

Every successful Varlink method reply contains:

```varlink
status: int
sysErrno: int
```

`status` uses `enum defused_status`:

| Value | Name | Meaning |
| --- | --- | --- |
| 0 | `DEFUSED_OK` | Success |
| 1 | `DEFUSED_ERR_MALFORMED` | Bad Varlink fd indices, wrong fd count, or a request-level validation failure |
| 2 | `DEFUSED_ERR_BAD_OPTION` | `mountFlags` outside its allowed mask |
| 3 | `DEFUSED_ERR_NOT_ALLOWED` | The mountpoint/mount is not the caller's to use, or polkit denied the operation |
| 4 | `DEFUSED_ERR_NOT_A_FUSE_MOUNT` | Unmount target is not a FUSE mount |
| 5 | `DEFUSED_ERR_MOUNT_FAILED` | Mount setup or attachment failed, or polkit could not be reached; see `sysErrno` |
| 6 | `DEFUSED_ERR_UNMOUNT_FAILED` | `umount2(2)` failed, or polkit could not be reached; see `sysErrno` |
| 7 | `DEFUSED_ERR_SETNS_FAILED` | Could not join the caller's mount namespace; see `sysErrno` |

Varlink protocol-level problems, such as missing fields or wrong field types,
are returned as standard Varlink errors by libsystemd rather than as a
`defused_status`.

## Why Varlink

Varlink gives defused a typed, introspectable request protocol without a custom
binary parser. The service uses libsystemd for the JSON parser, method
dispatcher, fd passing bookkeeping, and reply framing. The only values defused
interprets itself are already-typed integers, booleans, and strings delivered
by `sd_varlink_dispatch()`.

## Why the service resolves the mount namespace from the socket peer

Mount attachment and `umount2(2)` only ever act on the calling process's
*current* mount namespace, so a request from a client in a container -- which
may have had only the socket bind-mounted into it -- has to be serviced from
within that client's mount namespace, not the host's.

The service uses `SO_PEERPIDFD` on the accepted socket to identify the
connecting process and joins that process's mount namespace before the
mount/umount operation.

## Why unmount passes a parent-directory fd

Passing an fd on the mountpoint itself makes non-lazy `umount2()` see an
additional open reference and return `EBUSY`. Passing the parent directory plus
the mountpoint basename mirrors libfuse's own `fusermount3` flow while still
letting defused validate the target before closing the target fd and calling
`umount2(..., UMOUNT_NOFOLLOW)`.

## Why defused asks polkit

The mountpoint ownership check is intentionally narrow: it answers whether the
caller may act on this particular file. Polkit is the broader system policy
gate that answers whether the caller may use defused at all, and whether
privileged capabilities such as `allow_other` are acceptable.

A rule already has the caller's uid, pid, and group membership from the
subject polkit itself constructs -- `subject.uid`, `subject.pid`,
`subject.groups` (and `subject.user` for the resolved username) -- so
`details` only needs to carry what a rule genuinely can't get any other
way. For the mount action that's:

| Key | Value |
| --- | --- |
| `current-mounts` | The caller's live FUSE mount count, decimal. A rule wanting a mount-count limit implements it entirely from this. |
| `privileged-flags` | Comma-separated names of the privileged mount options (see `privileged_mount_flags[]` in `defused.c`; currently just `allow_other`) the request actually sets. Omitted entirely when the request sets none. |

Both values are strings (`a{ss}`, as the `CheckAuthorization` signature
requires), so a rule comparing `current-mounts` numerically needs to
`parseInt()` it first, and one inspecting `privileged-flags` needs to
`.split(",")` it.
`examples/50-defused-mount-policy.rules` is a complete, installable rule
using both: it grants ordinary mounts (fewer than 100 open, requesting no
privileged option the rule doesn't explicitly allowlist) without
prompting, and falls back to the shipped `AUTH_ADMIN_KEEP` default --
interactive administrator authentication -- for anything past that limit
or outside the allowlist.

polkit only lets a *trusted* caller of `CheckAuthorization` pass a non-empty
`details` dict at all -- uid 0, or the uid named by the action's
`org.freedesktop.policykit.owner` annotation. This is a non-issue for defused's
actual deployment, but it means a `defused` binary run manually as a non-root
user for testing will have every request fail closed at this step.

The subject sent to polkit is a `unix-process` identified by a `pidfd` obtained
from this connection's `SO_PEERPIDFD` plus `uid`, not the older
`pid`+`start-time` pair. A bare pid can be recycled onto an unrelated process
between the credential check and whenever polkit gets around to resolving it,
while a pidfd keeps pinning the exact process the whole time.

Unlike the mount namespace join, this check is *not* something defused can opt
out of by construction if polkit is missing: if
`org.freedesktop.PolicyKit1` has no owner on the system bus at all, or the
`CheckAuthorization` call otherwise fails, the operation is refused
(`DEFUSED_ERR_MOUNT_FAILED`/`DEFUSED_ERR_UNMOUNT_FAILED`) rather than treated
as "polkit is not configured, so allow it".

### Why `privileged-flags` is a name list

`ALLOW_OTHER` lets *other* users access the mount, which is a materially
different risk than an ordinary self-only mount -- and more capabilities
in the same category are planned (e.g. `suid`, `cuse`, `blkdev`), so
`privileged-flags` carries every privileged capability name a request
sets, not just a single fixed boolean. That lets a rule allowlist
capabilities by name and fail closed (`AUTH_ADMIN_KEEP`) on any name it
doesn't recognize -- exactly what
`examples/50-defused-mount-policy.rules` does. A rule that ignores
`privileged-flags` entirely -- like `nixos/tests/common.nix`'s shared
node, deliberately, since it exists to test mount plumbing rather than
policy -- does not get this property; the safety here lives in the rule,
not the protocol.

### Why unmount's default policy differs from mount's

Both mount and every privileged mount capability default to `AUTH_ADMIN_KEEP`,
but `website.soss.defused.unmount`'s shipped default is plain `yes`. The
ownership check that follows it (the mount's `user_id=` must match the caller)
is already the complete answer to "is this caller allowed to tear down this
specific mount", since nobody but its owner should be able to unmount it. The
polkit gate only answers the coarser "is this caller allowed to use unmount at
all" question, so making everyone wait on interactive authentication for it by
default would add friction without a correspondingly clearer security win.
