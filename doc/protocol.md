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

The authoritative definition is `src/defused-proto.h`; `src/defused-proto.c`
is the whole implementation of putting a message on the wire and taking it
off again.

## Transport

The service listens on an `AF_UNIX` `SOCK_SEQPACKET` socket.
It must be started as root.

- **Socket path**: `/run/defused/defused.sock` (`DEFUSED_SOCKET_PATH`).
- **Socket type**: `SOCK_SEQPACKET`, so that one `sendmsg()` is exactly one
  `recvmsg()`. A message therefore needs no length prefix and no
  reassembly, and the file descriptors attached to it cannot arrive with a
  different one.
- **Server-side activation**: the service socket unit uses `Accept=yes`,
  and `defused` receives the already-`accept()`-ed connection as fd 3,
  announced through `$LISTEN_PID`/`$LISTEN_FDS` (the `sd_listen_fds(3)`
  protocol, which defused implements itself in ~20 lines rather than
  linking libsystemd for it).
  The socket is created by systemd at its default `SocketMode=`, 0666.
- **`--daemon` activation**: for systems without systemd as service
  manager, `defused --daemon` creates and binds the socket itself (still at
  `DEFUSED_SOCKET_PATH` by default, also mode 0666), then forks a child per
  accepted connection to run the same one-request-per-connection handling
  as the `Accept=yes` path.

A connection carries exactly one request and one reply, and the service
exits when it has answered.

## Messages

Both messages are fixed-layout C structs, exchanged as they sit in memory.
The client and the service are always installed together from the same
build, so there is no serialization, no versioning and nothing to parse:
reading a request is a `recvmsg()` followed by a handful of comparisons.

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

Every field is present whatever the op; the ones the op does not use are
zero. Strings are fixed-width and NUL-terminated, which is the only thing
about them the transport checks.

`magic` guards against a peer that is not defused and against a client and
a service from different builds. It is bumped whenever the layout changes;
nothing tries to stay compatible across that, since the two binaries ship
together.

The descriptors a request carries are decided by its op, so the service is
never told how many to expect:

| Op | Descriptors, in order |
| --- | --- |
| `DEFUSED_OP_MOUNT` | `/dev/fuse`, then the mountpoint |
| `DEFUSED_OP_UNMOUNT` | the mountpoint's *parent* directory |

Anything else -- a short message, a wrong `magic`, an unknown op, the wrong
number of descriptors, an unterminated string -- is answered with
`DEFUSED_ERR_MALFORMED` and `EBADMSG`, with whatever descriptors did arrive
closed.

### Reply

```c
struct defused_reply {
    uint32_t magic;    /* DEFUSED_MAGIC */
    uint32_t code;     /* enum defused_error_code; 0 is success */
    int32_t sys_errno; /* the Linux error behind it, 0 if it has none */
};
```

Twelve bytes and no descriptors. The client switches on `code`; it never
compares a string to decide what happened.

| `code` | Meaning |
| --- | --- |
| `DEFUSED_OK` | The mount or unmount was performed |
| `DEFUSED_ERR_MALFORMED` | Request-level validation failure; `sys_errno` says what was wrong with it |
| `DEFUSED_ERR_BAD_OPTION` | `mount_flags` outside its allowed mask, or a privileged-only flag sent to the service |
| `DEFUSED_ERR_NOT_ALLOWED` | The mountpoint/mount is not the caller's to use, or policy denied the operation |
| `DEFUSED_ERR_NOT_A_FUSE_MOUNT` | Unmount target is not a FUSE mount |
| `DEFUSED_ERR_MOUNT_FAILED` | Mount setup, joining the caller's mount namespace, or attachment failed |
| `DEFUSED_ERR_UNMOUNT_FAILED` | Joining the caller's mount namespace or `umount2(2)` failed |

`sys_errno` is the Linux error number behind the failure. Which function
produced it is a debugging detail the service keeps to its own log, along
with a short description of the code (`not allowed` and friends, from
`defused_error_description()`) and a sentence saying what went wrong.

## Mount

`mount_flags` is the final option bitmask requested by the client. The empty
bitmask is the fusermount3-compatible unprivileged default: `nosuid` and
`nodev` are enforced unless a privileged caller explicitly sets
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

`name` is the mountpoint's basename within the parent directory whose
descriptor the request carries.

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
is set.
No defused process holds an fd on the mount at that point, since any such
reference would make a non-lazy unmount fail with `EBUSY`.

## Privileged callers

A `fusermount3` caller that is root or holds `CAP_SYS_ADMIN` speaks no
protocol at all. It already holds the privilege the service exists to lend
out, and it is already in the mount namespace the mount belongs in, so
there is nothing to ask anyone for and nothing to enter: it calls
`defused_perform()` (`src/defused-mount.c`) and does the work in its own
process.

That path validates the request for shape and then calls `move_mount()` or
`umount2()` directly. It applies no policy, no mountpoint ownership rule,
no filesystem-type allowlist and no unmount `user_id=` check.
Like root's `umount`, it unmounts any mount below the parent directory.

Both binaries link `src/defused-mount.c`, so the shape checks and the
superblock construction are the same code either way. Only what surrounds
them differs: the service puts its authorization between the steps, and
hands the finished mount to a sandboxed child rather than attaching it
itself.

Two things follow from the privileged path no longer being the service:

- `defused` has no branch that skips an authorization step, because it
  has no caller that would need one.
- `fusermount3` needs neither the socket nor the `defused` binary
  installed.

It is also the only path that accepts `DEFUSED_MOUNT_ALLOW_SUID` (`suid`),
`DEFUSED_MOUNT_ALLOW_DEV` (`dev`) and `DEFUSED_MOUNT_BLKDEV` (`blkdev`: a
`fuseblk` mount whose `fsname` is the block device path, so it may contain
slashes here), as libfuse's `fusermount3` does for root: `suid` and `dev` are
the two options its own table marks unsafe.
The service answers `DEFUSED_ERR_BAD_OPTION` to all three rather than
consulting its policy, since granting `suid` or `dev` would let a user's
FUSE server hand out setuid-root binaries or device nodes.

## Why a fixed binary layout

defused previously spoke [Varlink][], which gave it a typed, introspectable,
versioned request protocol for free. Almost none of that turned out to
apply here: the connection is between two binaries from the same build, it
is never long-lived, it carries several `SCM_RIGHTS` descriptors per call
and a bitmask that no Varlink type describes, and there is nothing useful
for a third party to discover on it -- bind-mounting the socket into a
container grants the *capability*, not an API worth exploring.

What is left is the cost: a JSON parser, a dispatcher, fd-index bookkeeping,
and error identities that only exist as strings to be compared. A struct
over `SOCK_SEQPACKET` removes all of it. The service's entire input handling
is one `recvmsg()`, a `magic` comparison, a descriptor count, and three
`memchr()`s for NUL terminators; the only strings it then looks at are ones
it has to interpret anyway (`fsname` and `subtype` go into `fsconfig()`,
`name` into `umount2()`).

It also drops libsystemd, and with it the systemd 258 build requirement that
kept defused off Debian 13 and Ubuntu 24.04. The one thing defused still
wanted from it, `sd_listen_fds(3)`, is two environment variables and three
`getsockopt()` calls.

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

A refused request is answered with `DEFUSED_ERR_NOT_ALLOWED`.
Nothing can be asked interactively: a caller either satisfies the policy or is
refused.
For unmount only the group check applies, for the reason given below.

### Why unmount's policy differs from mount's

Unmount is subject to the group check but not to `--max-mounts` or the
`--allow-other` check, neither of which describes a teardown.
The ownership check that follows (that the mount's `user_id=` must match the
caller) is a sufficient answer to "is this caller allowed to tear down this
specific mount".

[Varlink]: https://uapi-group.org/specifications/specs/varlink/
