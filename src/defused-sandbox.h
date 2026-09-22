/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_SANDBOX_H
#define DEFUSED_SANDBOX_H

#include "defused-proto.h"

#include <stdint.h>
#include <sys/types.h>

/* Scratch memory the sandboxed process hands the kernel, pinned where its
 * seccomp filter expects it. Only defused-sandbox.c looks inside. */
struct sandbox_buf;

/* One operation to run inside the client's mount namespace. Every syscall
 * argument the process will pass is here before the filter is built. */
struct sandbox_job {
    enum defused_op op;
    int pidfd, sock;
    int mountfd, mnt_fd;         /* mount */
    int parent_fd, umount_flags; /* unmount */
    uint64_t mnt_id;             /* unmount; never reused */
    /* The one path argument: a basename for an unmount, the empty path for
     * a mount. Read-only memory after pin_job_memory(). */
    const char *path;
    struct sandbox_buf *buf;
};

/* The client's mount namespace is entered only under a seccomp allowlist,
 * which these load on the calling process and never lift. Once one
 * returns the process can reply on sock, log to stderr and exit, and
 * nothing else; the connection handler is one process per request, so
 * that is all it had left to do. */
int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd, int sock,
                          struct defused_error *err);
int defused_sandbox_unmount(int pidfd, int parent_fd, const char *name,
                            bool lazy, uint64_t mnt_id, uid_t uid, int sock,
                            struct defused_error *err);

/* Answers the client: through the pinned buffer once a filter is loaded,
 * otherwise like defused_send_reply(). */
int defused_sandbox_reply(int sock, const struct defused_error *err);

/* The mount namespace pidfd's process is in, to aim statmount() and
 * listmount() at it. */
int defused_peer_mnt_ns_id(int pidfd, uint64_t *out_id);

/* 1 if mnt_id names a FUSE mount in namespace mnt_ns_id (0 for the
 * caller's own), 0 for any other mount, or a negative errno. The optional
 * out_blkdev distinguishes "fuseblk"; the optional out_uid gets user_id=,
 * and asking for it makes a FUSE mount without one an error. */
int defused_is_fuse_mount(uint64_t mnt_ns_id, uint64_t mnt_id, bool *out_blkdev,
                          uid_t *out_uid);

#ifdef DEFUSED_TEST
/* What the process does before setns(). A test pins without installing,
 * to see what the kernel alone answers. */
int defused_test_pin_job(struct sandbox_job *job);
int defused_test_install_seccomp(const struct sandbox_job *job);
/* The buffers pinning handed the filter: the handle, the mount id, and the
 * reply the process answers with, whose length the filter pins too. */
const void *defused_test_handle_buf(const struct sandbox_job *job);
const void *defused_test_handle_id(const struct sandbox_job *job);
const void *defused_test_reply_buf(const struct sandbox_job *job, size_t *size);
int defused_test_mount_opts_owner(const char *opts, uid_t *out_uid);
pid_t defused_test_fdinfo_pid(const char *text);
#endif

#endif /* DEFUSED_SANDBOX_H */
