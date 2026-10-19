/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Implements a strict seccomp sandbox.
 * Entering into an untrusted mount namespace as root is extremely risky,
 * so we make sure to first lockdown the process with seccomp.
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"
#include "common.h"
#include "defused-mount.h"
#include "defused-syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unistd.h>

/* MOVE_MOUNT_*, struct mnt_id_req, struct statmount, NS_GET_MNTNS_ID
 * Needed for musl */
#include <linux/mount.h>
#include <linux/nsfs.h>

/* AT_HANDLE_FID, AT_HANDLE_MNT_ID_UNIQUE, PIDFD_GET_MNT_NAMESPACE */
#define _ASM_GENERIC_FCNTL_H
#include <linux/fcntl.h>
#include <linux/pidfd.h>

DEFINE_TRIVIAL_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);

/* The writable pinned memory, kept out of the strings' mapping so that one
 * can stay read-only. */
struct sandbox_buf {
    struct defused_handle handle;
    uint64_t mnt_id;
};

/* A fixed-address empty string for use in seccomp filters */
static const char sandbox_empty[] = "";

/* Will hold the unmount path, to be marked read-only by mprotect. */
struct sandbox_strings {
    char path[DEFUSED_MAX_FILENAME];
};

/* Maps the path read-only and the scratch writable, at the addresses
 * install_seccomp() pins. */
static int pin_job_memory(struct sandbox_job *job) {
    if (job->path != sandbox_empty) {
        struct sandbox_strings *s =
            mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (s == MAP_FAILED)
            return -errno;
        size_t len = strlen(job->path);
        if (len >= sizeof(s->path))
            return -ENAMETOOLONG;
        memcpy(s->path, job->path, len + 1);
        /* mprotect() rounds up to the whole page mmap() handed out. */
        if (mprotect(s, sizeof(*s), PROT_READ) == -1)
            return -errno;
        job->path = s->path;
    }

    void *buf = mmap(NULL, sizeof(*job->buf), PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        return -errno;
    job->buf = buf;
    return 0;
}

#define ARG(n, v) {(n), SCMP_CMP_EQ, (scmp_datum_t)(long)(v), 0}

/* This filter keeps libc away from the client's filesystem. */
static int install_seccomp(const struct sandbox_job *job) {
    const struct sandbox_buf *buf = job->buf;
    const struct {
        int nr;
        int only; /* 0: both operations */
        unsigned int nargs;
        struct scmp_arg_cmp args[6];
    } rules[] = {
        {SCMP_SYS(rt_sigreturn), 0, 0, {{0}}},
        {SCMP_SYS(exit), 0, 0, {{0}}},
        {SCMP_SYS(exit_group), 0, 0, {{0}}},
        {SCMP_SYS(write), 0, 1, {ARG(0, STDERR_FILENO)}},
        {SCMP_SYS(writev), 0, 1, {ARG(0, STDERR_FILENO)}},
        /* The reply: one message of its exact size, to the client and
         * nowhere else. A null address keeps it on that connection. */
        {SCMP_SYS(sendto),
         0,
         4,
         {ARG(0, job->sock), ARG(2, sizeof(struct defused_reply)),
          ARG(3, DEFUSED_REPLY_SEND_FLAGS), ARG(4, NULL)}},
        {SCMP_SYS(setns), 0, 2, {ARG(0, job->pidfd), ARG(1, CLONE_NEWNS)}},
        {SCMP_SYS(move_mount),
         DEFUSED_OP_MOUNT,
         5,
         {ARG(0, job->mountfd), ARG(1, job->path), ARG(2, job->mnt_fd),
          ARG(3, job->path), ARG(4, DEFUSED_MOVE_MOUNT_FLAGS)}},
        {SCMP_SYS(fchdir), DEFUSED_OP_UNMOUNT, 1, {ARG(0, job->parent_fd)}},
        {SCMP_SYS(name_to_handle_at),
         DEFUSED_OP_UNMOUNT,
         5,
         {ARG(0, job->parent_fd), ARG(1, job->path), ARG(2, &buf->handle),
          ARG(3, &buf->mnt_id), ARG(4, DEFUSED_HANDLE_FLAGS)}},
        {SCMP_SYS(umount2),
         DEFUSED_OP_UNMOUNT,
         2,
         {ARG(0, job->path), ARG(1, job->umount_flags)}},
    };
    _cleanup_(seccomp_releasep) scmp_filter_ctx ctx =
        seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
        return -ENOMEM;
    for (size_t i = 0; i < ARRAY_SIZE(rules); i++) {
        if (rules[i].only && rules[i].only != (int)job->op)
            continue;
        int ret = seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, rules[i].nr,
                                         rules[i].nargs, rules[i].args);
        if (ret < 0)
            return ret;
    }
    return seccomp_load(ctx);
}

/* By id, not by fd: an fd of 0 in mnt_id_req silently means "my own".
 * PIDFD_GET_MNT_NAMESPACE (Linux 6.11+) makes the same PTRACE_MODE_READ
 * check as opening /proc/<pid>/ns/mnt, without going through a pid that
 * could have been recycled, and fails with ESRCH once the process has
 * exited. */
int defused_peer_mnt_ns_id(int pidfd, uint64_t *out_id) {
    _cleanup_close_ int ns_fd = sys_ioctl(pidfd, PIDFD_GET_MNT_NAMESPACE, NULL);
    if (ns_fd < 0)
        return -errno;
    return sys_ioctl(ns_fd, NS_GET_MNTNS_ID, out_id) == -1 ? -errno : 0;
}

/* statmount() takes a mount namespace parameter, so it can be called before
 * setns() and thus before the seccomp filter is installed. */
static int peer_fuse_mount_owner(int pidfd, uint64_t mnt_id, uid_t *out_uid) {
    uint64_t ns_id;
    int ret = defused_peer_mnt_ns_id(pidfd, &ns_id);
    if (ret < 0)
        return ret;
    ret = defused_is_fuse_mount(ns_id, mnt_id, NULL, NULL, out_uid);
    if (ret == -ENOENT)
        return 1;
    return ret < 0 ? ret : !ret;
}

/* The rest runs after setns(). */
static int sandbox_do_mount(const struct sandbox_job *job,
                            struct defused_error *err) {
    if (sys_move_mount(job->mountfd, job->path, job->mnt_fd, job->path,
                       DEFUSED_MOVE_MOUNT_FLAGS) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
                                  "move_mount() onto the mountpoint in the "
                                  "client's mount namespace failed");
    return 0;
}

static int sandbox_do_unmount(const struct sandbox_job *job,
                              struct defused_error *err) {
    if (sys_fchdir(job->parent_fd) == -1)
        return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, errno,
                                  "fchdir() to the parent directory in the "
                                  "client's mount namespace failed");
    /* name must still be the mount the parent authorized. The filter pins
     * both name_to_handle_at() out-pointers to job->buf. */
    int ret = defused_mnt_id_into(job->parent_fd, job->path, &job->buf->handle,
                                  &job->buf->mnt_id);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, -ret,
                                  "reading the mountpoint's mnt_id in the "
                                  "client's mount namespace failed");
    uint64_t id = job->buf->mnt_id;
    if (id != job->mnt_id)
        return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, ESTALE,
                                  "the mountpoint changed between the "
                                  "authorization check and the unmount: "
                                  "mnt_id %llu, expected %llu",
                                  (unsigned long long)id,
                                  (unsigned long long)job->mnt_id);
    if (sys_umount2(job->path, job->umount_flags) == -1)
        return defused_error_setf(
            err, DEFUSED_ERR_UNMOUNT_FAILED, errno, "umount2(\"%s\"%s) failed",
            job->path, job->umount_flags & MNT_DETACH ? ", MNT_DETACH" : "");
    return 0;
}

/* Pins, loads the filter, joins the namespace and runs the operation.
 * Remember that on return the seccomp filter will still be loaded. */
static int run_sandboxed(struct sandbox_job *job, struct defused_error *err) {
    uint32_t fail_code = job->op == DEFUSED_OP_MOUNT
                             ? DEFUSED_ERR_MOUNT_FAILED
                             : DEFUSED_ERR_UNMOUNT_FAILED;
    int ret = pin_job_memory(job);
    if (ret < 0)
        return defused_error_setf(err, fail_code, -ret,
                                  "pinning the sandbox's memory failed");
    ret = install_seccomp(job);
    if (ret < 0)
        return defused_error_setf(err, fail_code, -ret,
                                  "installing the sandbox seccomp filter "
                                  "failed");
    if (sys_setns(job->pidfd, CLONE_NEWNS) == -1)
        return defused_error_setf(err, fail_code, errno,
                                  "setns() into the client's mount namespace "
                                  "failed");
    return job->op == DEFUSED_OP_MOUNT ? sandbox_do_mount(job, err)
                                       : sandbox_do_unmount(job, err);
}

int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd, int sock,
                          struct defused_error *err) {
    struct sandbox_job job = {.op = DEFUSED_OP_MOUNT,
                              .pidfd = pidfd,
                              .sock = sock,
                              .mountfd = mountfd,
                              .mnt_fd = mnt_fd,
                              .path = sandbox_empty};
    return run_sandboxed(&job, err);
}

int defused_sandbox_unmount(int pidfd, int parent_fd, const char *name,
                            bool lazy, uint64_t mnt_id, uid_t uid, int sock,
                            struct defused_error *err) {
    uid_t owner = (uid_t)-1;
    int ret = peer_fuse_mount_owner(pidfd, mnt_id, &owner);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, -ret,
                                  "reading mnt_id %llu in the caller's mount "
                                  "namespace failed",
                                  (unsigned long long)mnt_id);
    if (ret > 0) {
        defused_error_setf(err, DEFUSED_ERR_NOT_A_FUSE_MOUNT, 0,
                           "mnt_id %llu is not a FUSE mount in the caller's "
                           "mount namespace",
                           (unsigned long long)mnt_id);
        return -EINVAL;
    }
    if (owner != uid) {
        defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
                           "the FUSE mount with mnt_id %llu belongs to uid "
                           "%u, not the caller's uid %u",
                           (unsigned long long)mnt_id, (unsigned)owner,
                           (unsigned)uid);
        return -EPERM;
    }

    struct sandbox_job job = {
        .op = DEFUSED_OP_UNMOUNT,
        .pidfd = pidfd,
        .sock = sock,
        .parent_fd = parent_fd,
        .umount_flags = UMOUNT_NOFOLLOW | (lazy ? MNT_DETACH : 0),
        .path = name,
        .mnt_id = mnt_id,
    };
    return run_sandboxed(&job, err);
}

#ifdef DEFUSED_TEST
int defused_test_pin_job(struct sandbox_job *job) {
    return pin_job_memory(job);
}

int defused_test_install_seccomp(const struct sandbox_job *job) {
    return install_seccomp(job);
}

const void *defused_test_handle_buf(const struct sandbox_job *job) {
    return &job->buf->handle;
}

const void *defused_test_handle_id(const struct sandbox_job *job) {
    return &job->buf->mnt_id;
}
#endif
