/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The wire protocol between fusermount3 and the defused service: one
 * fixed-layout request plus its file descriptors, one fixed-layout reply,
 * over an AF_UNIX SOCK_SEQPACKET socket. See doc/protocol.md.
 */

#ifndef DEFUSED_PROTO_H
#define DEFUSED_PROTO_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define DEFUSED_SOCKET_PATH "/run/defused/defused.sock"

/* One sendmsg() is one recvmsg(): no length prefix, no reassembly, and a
 * message's descriptors cannot arrive attached to another. */
#define DEFUSED_SOCKET_TYPE SOCK_SEQPACKET

/* Catches a peer that is not defused, or one from a different build. Bump
 * it whenever anything below changes; both sides ship together, so there
 * is nothing to stay compatible with. */
#define DEFUSED_MAGIC 0xdef05ed1u

#define DEFUSED_MAX_SUBTYPE 32   /* subtype= */
#define DEFUSED_MAX_FSNAME 4096  /* fsname= (a device path for blkdev) */
#define DEFUSED_MAX_FILENAME 256 /* NAME_MAX + 1: a mountpoint basename */
#define DEFUSED_MAX_FDS 2        /* a mount's two; an unmount sends one */

enum defused_op {
    DEFUSED_OP_MOUNT = 1,
    DEFUSED_OP_UNMOUNT = 2,
};

enum defused_mount_flag {
    DEFUSED_MOUNT_RDONLY = 1u << 0,
    DEFUSED_MOUNT_ALLOW_DEV = 1u << 1, /* privileged */
    DEFUSED_MOUNT_NOEXEC = 1u << 2,
    DEFUSED_MOUNT_NOATIME = 1u << 3,
    DEFUSED_MOUNT_NODIRATIME = 1u << 4,
    DEFUSED_MOUNT_NOSYMFOLLOW = 1u << 5,
    DEFUSED_MOUNT_SYNCHRONOUS = 1u << 6,
    DEFUSED_MOUNT_DIRSYNC = 1u << 7,
    DEFUSED_FUSE_ALLOW_OTHER = 1u << 8,
    DEFUSED_FUSE_DEFAULT_PERMISSIONS = 1u << 9,
    DEFUSED_MOUNT_ALLOW_SUID = 1u << 10, /* privileged */
    DEFUSED_MOUNT_BLKDEV = 1u << 11,     /* privileged: fuseblk on fsname */
};
#define DEFUSED_MOUNT_PRIVILEGED_FLAGS                                         \
    (DEFUSED_MOUNT_ALLOW_SUID | DEFUSED_MOUNT_ALLOW_DEV | DEFUSED_MOUNT_BLKDEV)
#define DEFUSED_MOUNT_FLAGS_MASK ((1u << 12) - 1)

/* Fields the op does not use are zero; strings are NUL-terminated. A
 * mount carries /dev/fuse and the mountpoint, an unmount the mountpoint's
 * parent -- an fd on the mount itself would make a non-lazy umount2()
 * fail with EBUSY. */
struct defused_request {
    uint32_t magic;                    /* DEFUSED_MAGIC */
    uint32_t op;                       /* enum defused_op */
    uint32_t mount_flags;              /* mount: enum defused_mount_flag */
    uint32_t max_read;                 /* mount: 0 for unset */
    uint32_t blksize;                  /* mount: 0 for unset */
    uint32_t lazy;                     /* unmount: add MNT_DETACH */
    char fsname[DEFUSED_MAX_FSNAME];   /* mount */
    char subtype[DEFUSED_MAX_SUBTYPE]; /* mount */
    char name[DEFUSED_MAX_FILENAME];   /* unmount: the mountpoint basename */
};

enum defused_error_code {
    DEFUSED_OK = 0,
    DEFUSED_ERR_MALFORMED, /* carries errno */
    DEFUSED_ERR_BAD_OPTION,
    DEFUSED_ERR_NOT_ALLOWED,
    DEFUSED_ERR_NOT_A_FUSE_MOUNT,
    DEFUSED_ERR_MOUNT_FAILED,   /* carries errno */
    DEFUSED_ERR_UNMOUNT_FAILED, /* carries errno */
    DEFUSED_ERR_COUNT
};

struct defused_reply {
    uint32_t magic;
    uint32_t code;     /* enum defused_error_code */
    int32_t sys_errno; /* 0 if the code carries none */
};

/* How a reply leaves: MSG_NOSIGNAL, so a client that hung up cannot raise
 * SIGPIPE in the service. The sandbox's seccomp filter pins this value, so
 * the sender and that rule read it from here. */
#define DEFUSED_REPLY_SEND_FLAGS MSG_NOSIGNAL

/* Only code and sys_errno reach the client; detail stays in the log. */
struct defused_error {
    uint32_t code;
    int32_t sys_errno;
    char detail[160];
};

/* Both return -sys_errno, so a caller can `return defused_error_set(...)`.
 * A NULL detail means "". */
static inline int defused_error_set(struct defused_error *err, uint32_t code,
                                    int sys_errno, const char *detail) {
    err->code = code;
    err->sys_errno = sys_errno;
    strncpy(err->detail, detail ? detail : "", sizeof(err->detail) - 1);
    err->detail[sizeof(err->detail) - 1] = '\0';
    return -sys_errno;
}

__attribute__((__format__(__printf__, 4, 5))) static inline int
defused_error_setf(struct defused_error *err, uint32_t code, int sys_errno,
                   const char *fmt, ...) {
    defused_error_set(err, code, sys_errno, NULL);
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err->detail, sizeof(err->detail), fmt, ap);
    va_end(ap);
    return -sys_errno;
}

/* "not allowed" and friends, for messages only: nothing parses these. */
const char *defused_error_description(uint32_t code);

/* 0 for an op that is not one of enum defused_op. */
size_t defused_op_n_fds(uint32_t op);

/* Client side. A negative return means the exchange failed; 0 means the
 * service answered, and *err says what it answered. */
int defused_call(int sock, const struct defused_request *req, const int *fds,
                 struct defused_error *err);

/* Service side. recv answers -EBADMSG for anything that is not a
 * well-formed request, having closed whatever descriptors did arrive. */
int defused_recv_request(int sock, struct defused_request *req, int *fds,
                         size_t *n_fds);
int defused_send_reply(int sock, const struct defused_error *err);

#endif /* DEFUSED_PROTO_H */
