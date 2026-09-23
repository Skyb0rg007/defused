/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Putting a message on the wire and taking it off again: a
 * sendmsg()/recvmsg() pair plus the SCM_RIGHTS bookkeeping, and a plain
 * sendto() for the reply. Nothing here inspects a request beyond checking
 * that it is one.
 */
#define _GNU_SOURCE
#include "defused-proto.h"
#include "common.h"
#include "defused-syscall.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

const char *defused_error_description(uint32_t code) {
    static const char *const descriptions[DEFUSED_ERR_COUNT] = {
        [DEFUSED_OK] = "success",
        [DEFUSED_ERR_MALFORMED] = "malformed request",
        [DEFUSED_ERR_BAD_OPTION] = "bad mount option",
        [DEFUSED_ERR_NOT_ALLOWED] = "not allowed",
        [DEFUSED_ERR_NOT_A_FUSE_MOUNT] = "not a FUSE mount",
        [DEFUSED_ERR_MOUNT_FAILED] = "mount failed",
        [DEFUSED_ERR_UNMOUNT_FAILED] = "unmount failed",
    };
    return code < ARRAY_SIZE(descriptions) ? descriptions[code]
                                           : "unknown error";
}

size_t defused_op_n_fds(uint32_t op) {
    switch (op) {
    case DEFUSED_OP_MOUNT:
        return 2;
    case DEFUSED_OP_UNMOUNT:
        return 1;
    default:
        return 0;
    }
}

union control_buf {
    struct cmsghdr align;
    char bytes[CMSG_SPACE(DEFUSED_MAX_FDS * sizeof(int))];
};

static int send_msg(int sock, const void *msg, size_t size, const int *fds,
                    size_t n_fds) {
    struct iovec iov = {.iov_base = (void *)msg, .iov_len = size};
    union control_buf control = {};
    struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1};
    if (n_fds > 0) {
        mh.msg_control = control.bytes;
        mh.msg_controllen = CMSG_SPACE(n_fds * sizeof(int));
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(n_fds * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds, n_fds * sizeof(int));
    }
    ssize_t n;
    do
        n = sendmsg(sock, &mh, MSG_NOSIGNAL);
    while (n < 0 && errno == EINTR);
    if (n < 0)
        return -errno;
    /* Seqpacket delivers a message whole or not at all. */
    return n == (ssize_t)size ? 0 : -EIO;
}

/* *n_fds is the room in fds going in and the count coming out; on any
 * error it is 0 and nothing is left open. fds needs DEFUSED_MAX_FDS
 * entries whatever the caller expects, so surplus descriptors can be seen
 * and closed rather than leaked. */
static int recv_msg(int sock, void *msg, size_t size, int *fds, size_t *n_fds) {
    struct iovec iov = {.iov_base = msg, .iov_len = size};
    union control_buf control;
    struct msghdr mh = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    ssize_t n;
    do
        n = recvmsg(sock, &mh, MSG_CMSG_CLOEXEC);
    while (n < 0 && errno == EINTR);
    if (n < 0) {
        *n_fds = 0;
        return -errno;
    }

    size_t got = 0;
    int received[DEFUSED_MAX_FDS];
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&mh, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
            continue;
        size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < count && got < ARRAY_SIZE(received); i++)
            memcpy(&received[got++], CMSG_DATA(cmsg) + i * sizeof(int),
                   sizeof(int));
    }

    int ret = 0;
    if (n == 0) {
        ret = -ECONNRESET; /* every message has a body: the peer hung up */
    } else if (n != (ssize_t)size ||
               (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || got > *n_fds) {
        /* Not one whole message, so not this protocol. */
        ret = -EBADMSG;
    }
    if (ret < 0) {
        for (size_t i = 0; i < got; i++)
            safe_close(received[i]);
        *n_fds = 0;
        return ret;
    }
    memcpy(fds, received, got * sizeof(int));
    *n_fds = got;
    return 0;
}

static bool terminated(const char *s, size_t size) {
    return memchr(s, '\0', size) != NULL;
}

int defused_call(int sock, const struct defused_request *req, const int *fds,
                 struct defused_error *err) {
    int ret = send_msg(sock, req, sizeof(*req), fds, defused_op_n_fds(req->op));
    if (ret < 0)
        return ret;

    struct defused_reply reply;
    size_t n_fds = 0;
    int unexpected[DEFUSED_MAX_FDS];
    ret = recv_msg(sock, &reply, sizeof(reply), unexpected, &n_fds);
    if (ret < 0)
        return ret;
    if (reply.magic != DEFUSED_MAGIC || reply.code >= DEFUSED_ERR_COUNT)
        return -EBADMSG;
    err->code = reply.code;
    err->sys_errno = reply.sys_errno;
    err->detail[0] = '\0';
    return 0;
}

int defused_recv_request(int sock, struct defused_request *req, int *fds,
                         size_t *n_fds) {
    *n_fds = DEFUSED_MAX_FDS;
    int ret = recv_msg(sock, req, sizeof(*req), fds, n_fds);
    if (ret < 0)
        return ret;
    /* A count of 0 would also mean an op that is not one of ours. */
    if (req->magic == DEFUSED_MAGIC && *n_fds > 0 &&
        *n_fds == defused_op_n_fds(req->op) &&
        terminated(req->fsname, sizeof(req->fsname)) &&
        terminated(req->subtype, sizeof(req->subtype)) &&
        terminated(req->name, sizeof(req->name)))
        return 0;
    for (size_t i = 0; i < *n_fds; i++)
        safe_close(fds[i]);
    *n_fds = 0;
    return -EBADMSG;
}

/* sendto(), not the sendmsg() above: a reply carries no descriptors, and
 * the service sends it from inside its seccomp sandbox, whose allowlist
 * has to name one entry point. */
int defused_send_reply(int sock, const struct defused_error *err) {
    struct defused_reply reply = {
        .magic = DEFUSED_MAGIC,
        .code = err->code,
        .sys_errno = err->sys_errno,
    };
    ssize_t n;
    do
        n = sys_sendto(sock, &reply, sizeof(reply), DEFUSED_REPLY_SEND_FLAGS,
                       NULL, 0);
    while (n < 0 && errno == EINTR);
    if (n < 0)
        return -errno;
    /* Seqpacket delivers a message whole or not at all. */
    return n == (ssize_t)sizeof(reply) ? 0 : -EIO;
}
