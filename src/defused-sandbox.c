/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Joining a client's mount namespace under a seccomp allowlist, and the
 * unmount ownership check that gates it.
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"
#include "common.h"
#include "defused-mount.h"
#include "defused-syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* MOVE_MOUNT_*, struct mnt_id_req, struct statmount, NS_GET_MNTNS_ID:
 * musl declares none of them. */
#include <linux/mount.h>
#include <linux/nsfs.h>

/* AT_HANDLE_FID, AT_HANDLE_MNT_ID_UNIQUE and PIDFD_GET_INFO. The define
 * skips <asm-generic/fcntl.h>, which would clash with <fcntl.h> above. */
#define _ASM_GENERIC_FCNTL_H
#include <linux/fcntl.h>
#include <linux/pidfd.h>

DEFINE_TRIVIAL_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);

/* AT_EMPTY_PATH asks about a directory fd itself. Without
 * AT_SYMLINK_FOLLOW a final symlink is never followed. */
#define SANDBOX_HANDLE_FLAGS                                                   \
    (AT_EMPTY_PATH | AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE)
#define SANDBOX_MOVE_MOUNT_FLAGS                                               \
    (MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)

/* struct file_handle ends in a flexible array member, so it cannot be a
 * member of anything else. The same layout, at the largest size. */
struct sandbox_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[MAX_HANDLE_SZ];
};
_Static_assert(offsetof(struct sandbox_handle, f_handle) ==
                   sizeof(struct file_handle),
               "struct sandbox_handle must match struct file_handle");

/* The writable pinned memory, kept out of the strings' mapping so that one
 * can stay read-only. */
struct sandbox_buf {
    struct sandbox_handle handle;
    uint64_t mnt_id;
};

/* move_mount()'s empty path: one const object, so it sits in .rodata at a
 * fixed address and the filter rule and the call site cannot differ. */
static const char sandbox_empty[] = "";

/* The read-only mapping a request-supplied path needs; sandbox_empty
 * needs none. */
struct sandbox_strings {
    char path[DEFUSED_MAX_FILENAME];
};

/* statx() would call fuse_getattr(), which refuses a non-empty request
 * from anyone but the mount's user_id, root included. AT_HANDLE_FID
 * encodes on any filesystem; buf is the pinned scratch. */
static int sandbox_mnt_id(int dir_fd, const char *name, struct sandbox_buf *buf,
                          uint64_t *out_id) {
    buf->handle.handle_bytes = MAX_HANDLE_SZ;
    if (sys_name_to_handle_at(dir_fd, name, &buf->handle, &buf->mnt_id,
                              SANDBOX_HANDLE_FLAGS) == -1)
        return -errno;
    *out_id = buf->mnt_id;
    return 0;
}

/* Maps the path read-only and the scratch writable, at the addresses
 * install_seccomp() pins. mprotect() is not allowed, so the path cannot be
 * rewritten once the filter is up. */
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

/* The filter is here to keep libc away from the client's filesystem, so
 * what it scrutinizes is anything that names a file: a rule for such a
 * call pins every argument, and the call cannot be aimed elsewhere.
 * A call that only acts on a descriptor already opened needs no such
 * care, so the reply and the log line are pinned by descriptor alone,
 * whatever buffer libc hands them. Anything else is EPERM. */
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
          ARG(3, job->path), ARG(4, SANDBOX_MOVE_MOUNT_FLAGS)}},
        {SCMP_SYS(fchdir), DEFUSED_OP_UNMOUNT, 1, {ARG(0, job->parent_fd)}},
        {SCMP_SYS(name_to_handle_at),
         DEFUSED_OP_UNMOUNT,
         5,
         {ARG(0, job->parent_fd), ARG(1, job->path), ARG(2, &buf->handle),
          ARG(3, &buf->mnt_id), ARG(4, SANDBOX_HANDLE_FLAGS)}},
        {SCMP_SYS(umount2),
         DEFUSED_OP_UNMOUNT,
         2,
         {ARG(0, job->path), ARG(1, job->umount_flags)}},
    };
    /* The kernel keeps its own copy of a loaded filter. */
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

/* Linux 6.13+. ENODATA, not EINVAL, for a useless reply: EINVAL means the
 * kernel lacks the ioctl. */
static pid_t pidfd_to_pid_ioctl(int pidfd) {
    struct pidfd_info info = {0};
    if (sys_ioctl(pidfd, PIDFD_GET_INFO, &info) == -1)
        return -errno;
    if (!(info.mask & PIDFD_INFO_PID) || info.pid == 0 ||
        info.pid > (unsigned int)INT_MAX)
        return -ENODATA;
    return (pid_t)info.pid;
}

/* A "Pid:" of -1 (not visible from this pid namespace) or 0 (exited) means
 * there is no process to look up. */
static pid_t fdinfo_pid(FILE *f) {
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Pid:", 4) != 0)
            continue;
        char *end;
        errno = 0;
        long pid = strtol(line + 4, &end, 10);
        if (end == line + 4 || errno != 0 || pid > INT_MAX ||
            (*end != '\n' && *end != '\0'))
            return -EINVAL;
        return pid > 0 ? (pid_t)pid : -ESRCH;
    }
    return -ENODATA;
}

/* Kernels before 6.13 fail PIDFD_GET_INFO with ENOTTY (no pidfd_ioctl()) or
 * EINVAL (6.11/6.12 reject any ioctl with an argument). The fallback, Linux
 * 5.2+'s fdinfo "Pid:", is reported in the reader's pid namespace, the one
 * /proc/<pid>/mountinfo is opened from. */
static pid_t pidfd_to_pid(int pidfd) {
    pid_t pid = pidfd_to_pid_ioctl(pidfd);
    if (pid != -ENOTTY && pid != -EINVAL)
        return pid;
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
    _cleanup_fclose_ FILE *f = fopen(path, "re");
    return f ? fdinfo_pid(f) : -errno;
}

/* A pidfd polls readable once its process has exited. Unlike a
 * pidfd_send_signal() probe this needs no CAP_KILL, which the hardened
 * service unit doesn't grant. */
static int pidfd_alive(int pidfd) {
    struct pollfd pfd = {.fd = pidfd, .events = POLLIN};
    int n;
    do
        n = poll(&pfd, 1, 0);
    while (n == -1 && errno == EINTR);
    return n == -1 ? -errno : n == 0 ? 0 : -ESRCH;
}

/* By id, not by fd: an fd of 0 in mnt_id_req silently means "my own". */
int defused_peer_mnt_ns_id(int pidfd, uint64_t *out_id) {
    pid_t pid = pidfd_to_pid(pidfd);
    if (pid < 0)
        return (int)pid;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", (int)pid);
    _cleanup_close_ int ns_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0)
        return -errno;
    /* Checked after the open(): the pid wasn't recycled to another task. */
    int ret = pidfd_alive(pidfd);
    if (ret < 0)
        return ret;
    return sys_ioctl(ns_fd, NS_GET_MNTNS_ID, out_id) == -1 ? -errno : 0;
}

/* statmount() is told which namespace to look in, so this needs neither
 * the filter nor setns(). */
static int peer_fuse_mount_owner(int pidfd, uint64_t mnt_id, uid_t *out_uid) {
    uint64_t ns_id;
    int ret = defused_peer_mnt_ns_id(pidfd, &ns_id);
    if (ret < 0)
        return ret;
    ret = defused_is_fuse_mount(ns_id, mnt_id, NULL, NULL, out_uid);
    return ret < 0 ? ret : ret == 0 ? -EINVAL : 0;
}

/* The rest runs after setns(). */
static int sandbox_do_mount(const struct sandbox_job *job,
                            struct defused_error *err) {
    if (sys_move_mount(job->mountfd, job->path, job->mnt_fd, job->path,
                       SANDBOX_MOVE_MOUNT_FLAGS) == -1)
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
    /* name must still be the mount the parent authorized.
     * name_to_handle_at() holds no reference, so it cannot make the
     * non-lazy umount2() below fail with EBUSY. */
    uint64_t id = 0;
    int ret = sandbox_mnt_id(job->parent_fd, job->path, job->buf, &id);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, -ret,
                                  "reading the mountpoint's mnt_id in the "
                                  "client's mount namespace failed");
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

/* Pins, loads the filter, joins the namespace and runs the operation, all
 * in this process. The filter stays loaded on return: the caller answers
 * the client, logs, and exits. */
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
    /* Before the filter, so an unauthorized caller's namespace is never
     * entered. GCC cannot see that owner is set whenever this returns 0,
     * hence the initializer. */
    uid_t owner = (uid_t)-1;
    int ret = peer_fuse_mount_owner(pidfd, mnt_id, &owner);
    if (ret < 0) {
        defused_error_setf(
            err, DEFUSED_ERR_NOT_A_FUSE_MOUNT, 0, "mnt_id %llu %s (%s)",
            (unsigned long long)mnt_id,
            ret == -ENOENT   ? "is not in the caller's mountinfo"
            : ret == -EINVAL ? "is not a FUSE mount with a user_id= option"
                             : "could not be read from the caller's mountinfo",
            strerror(-ret));
        return ret;
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

pid_t defused_test_fdinfo_pid(const char *text) {
    _cleanup_fclose_ FILE *f = fmemopen((void *)text, strlen(text), "r");
    return f ? fdinfo_pid(f) : -errno;
}
#endif
