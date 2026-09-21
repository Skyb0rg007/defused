/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The sandboxed child that joins a client's mount namespace, and the
 * unmount ownership check that gates it.
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

/* AT_EMPTY_PATH asks about a directory fd itself. Without
 * AT_SYMLINK_FOLLOW a final symlink is never followed. */
#define SANDBOX_HANDLE_FLAGS                                                   \
    (AT_EMPTY_PATH | AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE)

DEFINE_TRIVIAL_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);

/* After setns() the filesystem is the client's; this is loaded before it.
 * Anything else fails with EPERM. */
static int install_seccomp(enum defused_op op) {
    static const struct {
        int nr;
        int only; /* 0: both operations */
    } rules[] = {
        {SCMP_SYS(write), 0},
        {SCMP_SYS(exit), 0},
        {SCMP_SYS(exit_group), 0},
        {SCMP_SYS(setns), 0},
        {SCMP_SYS(rt_sigreturn), 0},
        {SCMP_SYS(move_mount), DEFUSED_OP_MOUNT},
        {SCMP_SYS(fchdir), DEFUSED_OP_UNMOUNT},
        {SCMP_SYS(name_to_handle_at), DEFUSED_OP_UNMOUNT},
        {SCMP_SYS(umount2), DEFUSED_OP_UNMOUNT},
    };
    /* The kernel keeps its own copy of a loaded filter. */
    _cleanup_(seccomp_releasep) scmp_filter_ctx ctx =
        seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
        return -ENOMEM;
    for (size_t i = 0; i < ARRAY_SIZE(rules); i++) {
        if (rules[i].only && rules[i].only != (int)op)
            continue;
        int ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, rules[i].nr, 0);
        if (ret < 0)
            return ret;
    }
    return seccomp_load(ctx);
}

/*
 * Everything that can run after setns() uses these: syscall() has exactly
 * the kernel entry named here, unlike a libc function whose implementation
 * may change underneath the allowlist.
 */
static int sandbox_setns(int fd, int nstype) {
    return (int)syscall(SYS_setns, fd, nstype);
}

static ssize_t sandbox_write(int fd, const void *buf, size_t count) {
    return (ssize_t)syscall(SYS_write, fd, buf, count);
}

static int sandbox_fchdir(int fd) { return (int)syscall(SYS_fchdir, fd); }

/* musl prototypes ioctl()'s request as int, which the _IO* constants do
 * not fit. The kernel takes an unsigned int, so pass the number itself. */
static int raw_ioctl(int fd, unsigned long request, void *arg) {
    return (int)syscall(SYS_ioctl, (long)fd, (long)request, arg);
}

static __attribute__((__noreturn__)) void sandbox_exit(int status) {
    (void)syscall(SYS_exit_group, status);
    for (;;)
        (void)syscall(SYS_exit, status);
}

/* Linux 6.13+. ENODATA, not EINVAL, for a useless reply: EINVAL means the
 * kernel lacks the ioctl. */
static pid_t pidfd_to_pid_ioctl(int pidfd) {
    struct pidfd_info info = {0};
    if (raw_ioctl(pidfd, PIDFD_GET_INFO, &info) == -1)
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

/* One statmount() reply. An over-long string fails with EOVERFLOW rather
 * than truncating. */
union sandbox_statmount {
    struct statmount sm;
    char raw[4096];
};

/* FUSE's user_id= among the comma-separated options. Matched only at an
 * option start, so a value ending in "user_id=" cannot pass for one. */
static int mount_opts_owner(const char *opts, uid_t *out_uid) {
    for (const char *p = opts;; p++) {
        if (strncmp(p, "user_id=", 8) == 0 && p[8] >= '0' && p[8] <= '9') {
            char *end;
            errno = 0;
            unsigned long uid = strtoul(p + 8, &end, 10);
            if (errno != 0 || uid > (uid_t)-1 || (*end != ',' && *end != '\0'))
                return -EINVAL;
            *out_uid = (uid_t)uid;
            return 0;
        }
        p += strcspn(p, ",");
        if (*p != ',')
            return -EINVAL;
    }
}

int defused_is_fuse_mount(uint64_t mnt_ns_id, uint64_t mnt_id, bool *out_blkdev,
                          uid_t *out_uid) {
    struct mnt_id_req req = {
        .size = MNT_ID_REQ_SIZE_VER1,
        .mnt_id = mnt_id,
        .param = STATMOUNT_FS_TYPE | (out_uid ? STATMOUNT_MNT_OPTS : 0),
        .mnt_ns_id = mnt_ns_id,
    };
    union sandbox_statmount buf;
    if (syscall(SYS_statmount, &req, &buf.sm, (long)sizeof(buf), 0L) == -1)
        return -errno;
    if (!(buf.sm.mask & STATMOUNT_FS_TYPE))
        return -EINVAL;
    /* A "fuse.sshfs" mount reports its subtype separately, so these are the
     * only two spellings. */
    const char *fstype = buf.sm.str + buf.sm.fs_type;
    bool blkdev = strcmp(fstype, "fuseblk") == 0;
    if (!blkdev && strcmp(fstype, "fuse") != 0)
        return 0;
    if (out_blkdev)
        *out_blkdev = blkdev;
    if (!out_uid)
        return 1;
    if (!(buf.sm.mask & STATMOUNT_MNT_OPTS))
        return -EINVAL;
    int ret = mount_opts_owner(buf.sm.str + buf.sm.mnt_opts, out_uid);
    return ret < 0 ? ret : 1;
}

/* By id, not by fd: an fd of 0 in mnt_id_req silently means "my own". */
static int peer_mnt_ns_id(int pidfd, uint64_t *out_id) {
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
    return raw_ioctl(ns_fd, NS_GET_MNTNS_ID, out_id) == -1 ? -errno : 0;
}

/* statmount() is told which namespace to look in, so this needs neither
 * the fork nor setns(). */
static int peer_fuse_mount_owner(int pidfd, uint64_t mnt_id, uid_t *out_uid) {
    uint64_t ns_id;
    int ret = peer_mnt_ns_id(pidfd, &ns_id);
    if (ret < 0)
        return ret;
    ret = defused_is_fuse_mount(ns_id, mnt_id, NULL, out_uid);
    return ret < 0 ? ret : ret == 0 ? -EINVAL : 0;
}

/* Finds the "mnt_id:" line of a /proc/self/fdinfo/<fd> text. */
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

/* statx() would call fuse_getattr(), which refuses a non-empty request
 * from anyone but the mount's user_id, root included. AT_HANDLE_FID
 * encodes on any filesystem. */
int defused_mnt_id(int dir_fd, const char *name, uint64_t *out_id) {
    struct sandbox_handle h = {.handle_bytes = MAX_HANDLE_SZ};
    uint64_t id = 0;
    if (syscall(SYS_name_to_handle_at, (long)dir_fd, name, &h, &id,
                (long)SANDBOX_HANDLE_FLAGS) == -1)
        return -errno;
    *out_id = id;
    return 0;
}

struct sandbox_job {
    enum defused_op op;
    int mountfd, mnt_fd;         /* mount */
    int parent_fd, umount_flags; /* unmount */
    const char *name;
    uint64_t mnt_id;
};

/* The rest runs after setns(). detail must be a fixed string: the child
 * cannot format one. */
static int sandbox_do_mount(const struct sandbox_job *job,
                            const char **detail) {
    if (syscall(SYS_move_mount, job->mountfd, "", job->mnt_fd, "",
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == 0)
        return 0;
    *detail = "move_mount() onto the mountpoint in the client's mount "
              "namespace failed";
    return -errno;
}

static int sandbox_do_unmount(const struct sandbox_job *job,
                              const char **detail) {
    if (sandbox_fchdir(job->parent_fd) == -1) {
        *detail = "fchdir() to the parent directory in the client's mount "
                  "namespace failed";
        return -errno;
    }
    /* name must still be the mount the parent authorized.
     * name_to_handle_at() holds no reference, so it cannot make the
     * non-lazy umount2() below fail with EBUSY. */
    uint64_t id = 0;
    int ret = defused_mnt_id(job->parent_fd, job->name, &id);
    if (ret < 0) {
        *detail = "reading the mountpoint's mnt_id in the client's mount "
                  "namespace failed";
        return ret;
    }
    if (id != job->mnt_id) {
        *detail = "the mountpoint changed between the authorization check "
                  "and the unmount";
        return -ESTALE;
    }
    if (syscall(SYS_umount2, job->name, UMOUNT_NOFOLLOW | job->umount_flags) ==
        -1) {
        *detail = job->umount_flags & MNT_DETACH
                      ? "umount2(MNT_DETACH) failed"
                      : "umount2() failed -- still busy?";
        return -errno;
    }
    return 0;
}

struct sandbox_result {
    struct defused_error err;
    int32_t ret;
};

/* Forks the sandboxed child and returns what it reported. */
static int run_sandboxed(const struct sandbox_job *job, int pidfd,
                         struct defused_error *err) {
    const char *fail_id = job->op == DEFUSED_OP_MOUNT
                              ? DEFUSED_ERROR_MOUNT_FAILED
                              : DEFUSED_ERROR_UNMOUNT_FAILED;
    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return defused_error_setf(err, fail_id, errno,
                                  "pipe2() for the sandboxed helper failed");
    pid_t pid = fork();
    if (pid == -1)
        return defused_error_setf(err, fail_id, errno,
                                  "fork() of the sandboxed helper failed");
    if (pid == 0) {
        const char *detail = "installing the sandbox seccomp filter failed";
        int ret = install_seccomp(job->op);
        if (ret == 0) {
            detail = "setns() into the client's mount namespace failed";
            ret = sandbox_setns(pidfd, CLONE_NEWNS) == -1 ? -errno : 0;
        }
        if (ret == 0)
            ret = job->op == DEFUSED_OP_MOUNT
                      ? sandbox_do_mount(job, &detail)
                      : sandbox_do_unmount(job, &detail);
        struct sandbox_result result = {.ret = ret};
        if (ret < 0)
            defused_error_set(&result.err, fail_id, -ret, detail);
        /* Under PIPE_BUF, so it arrives whole or not at all. */
        (void)sandbox_write(pipefd[1], &result, sizeof(result));
        sandbox_exit(ret == 0 ? 0 : 1);
    }
    pipefd[1] = safe_close(pipefd[1]);

    struct sandbox_result result;
    ssize_t n;
    do
        n = read(pipefd[0], &result, sizeof(result));
    while (n < 0 && errno == EINTR);
    int read_errno = n < 0 ? errno : EPIPE, status = 0;
    while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
        ;
    if (n == (ssize_t)sizeof(result)) {
        *err = result.err;
        return result.ret;
    }
    /* SIGSYS here means the seccomp filter refused a syscall. */
    if (WIFSIGNALED(status))
        return defused_error_setf(
            err, fail_id, read_errno,
            "the sandboxed helper was killed by signal %d%s before reporting "
            "a result",
            WTERMSIG(status), WTERMSIG(status) == SIGSYS ? " (seccomp)" : "");
    return defused_error_setf(err, fail_id, read_errno,
                              "the sandboxed helper exited with status %d "
                              "without reporting a result",
                              WEXITSTATUS(status));
}

int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd,
                          struct defused_error *err) {
    struct sandbox_job job = {
        .op = DEFUSED_OP_MOUNT, .mountfd = mountfd, .mnt_fd = mnt_fd};
    return run_sandboxed(&job, pidfd, err);
}

int defused_sandbox_unmount(int pidfd, int parent_fd, const char *name,
                            bool lazy, uint64_t mnt_id, uid_t uid,
                            struct defused_error *err) {
    /* Before forking, so an unauthorized caller's namespace is never
     * entered. GCC cannot see that owner is set whenever this returns 0,
     * hence the initializer. */
    uid_t owner = (uid_t)-1;
    int ret = peer_fuse_mount_owner(pidfd, mnt_id, &owner);
    if (ret < 0) {
        defused_error_setf(
            err, DEFUSED_ERROR_NOT_A_FUSE_MOUNT, 0, "mnt_id %llu %s (%s)",
            (unsigned long long)mnt_id,
            ret == -ENOENT   ? "is not in the caller's mount namespace"
            : ret == -EINVAL ? "is not a FUSE mount with a user_id= option"
                             : "could not be looked up",
            strerror(-ret));
        return ret;
    }
    if (owner != uid) {
        defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                           "the FUSE mount with mnt_id %llu belongs to uid "
                           "%u, not the caller's uid %u",
                           (unsigned long long)mnt_id, (unsigned)owner,
                           (unsigned)uid);
        return -EPERM;
    }

    struct sandbox_job job = {
        .op = DEFUSED_OP_UNMOUNT,
        .parent_fd = parent_fd,
        .umount_flags = lazy ? MNT_DETACH : 0,
        .name = name,
        .mnt_id = mnt_id,
    };
    return run_sandboxed(&job, pidfd, err);
}

#ifdef DEFUSED_TEST
int defused_test_install_seccomp(enum defused_op op) {
    return install_seccomp(op);
}

int defused_test_mount_opts_owner(const char *opts, uid_t *out_uid) {
    return mount_opts_owner(opts, out_uid);
}

pid_t defused_test_fdinfo_pid(const char *text) {
    _cleanup_fclose_ FILE *f = fmemopen((void *)text, strlen(text), "r");
    return f ? fdinfo_pid(f) : -errno;
}
#endif
