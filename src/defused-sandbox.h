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
 * returns the process can answer on sock, log to stderr and exit, and
 * nothing else. */
int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd, int sock,
                          struct defused_error *err);
int defused_sandbox_unmount(int pidfd, int parent_fd, const char *name,
                            bool lazy, uint64_t mnt_id, uid_t uid, int sock,
                            struct defused_error *err);

/* The mount namespace pidfd's process is in, to aim statmount() and
 * listmount() at it. */
int defused_peer_mnt_ns_id(int pidfd, uint64_t *out_id);

#ifdef DEFUSED_TEST
/* What the process does before setns(). A test pins without installing,
 * to see what the kernel alone answers. */
int defused_test_pin_job(struct sandbox_job *job);
int defused_test_install_seccomp(const struct sandbox_job *job);
/* The buffers pinning handed the filter: the handle and the mount id. */
const void *defused_test_handle_buf(const struct sandbox_job *job);
const void *defused_test_handle_id(const struct sandbox_job *job);
pid_t defused_test_fdinfo_pid(const char *text);
#endif

#endif /* DEFUSED_SANDBOX_H */
