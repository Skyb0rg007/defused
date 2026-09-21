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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* MOVE_MOUNT_*, which musl does not declare. */
#include <linux/mount.h>

/* Skips <linux/fcntl.h>'s struct redefinitions, which otherwise clash with
 * <fcntl.h> above. */
#define _ASM_GENERIC_FCNTL_H
#include <linux/pidfd.h>

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
        {SCMP_SYS(openat), DEFUSED_OP_UNMOUNT},
        {SCMP_SYS(read), DEFUSED_OP_UNMOUNT},
        {SCMP_SYS(close), DEFUSED_OP_UNMOUNT},
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

static int sandbox_openat(int dirfd, const char *path, int flags) {
    return (int)syscall(SYS_openat, dirfd, path, flags, 0);
}

static ssize_t sandbox_read(int fd, void *buf, size_t count) {
    return (ssize_t)syscall(SYS_read, fd, buf, count);
}

static void sandbox_closep(int *fd) {
    if (*fd >= 0)
        (void)syscall(SYS_close, *fd);
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
    if (ioctl(pidfd, PIDFD_GET_INFO, &info) == -1)
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

static bool is_fuse_fstype(const char *s) {
    if (strncmp(s, "fuseblk", 7) == 0)
        s += 7;
    else if (strncmp(s, "fuse", 4) == 0)
        s += 4;
    else
        return false;
    return *s == ' ' || *s == '.';
}

/* One mountinfo line: "ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTS [TAG]... -
 * FSTYPE SOURCE SUPEROPTS". Returns 0 and the user_id= super option if it is
 * mnt_id's FUSE mount, -ENOENT if it is some other mount, and -EINVAL if it
 * is mnt_id but not a FUSE mount with a user_id=. */
static int mountinfo_line_owner(const char *line, long mnt_id, uid_t *out_uid) {
    char *end;
    errno = 0;
    long id = strtol(line, &end, 10);
    if (end == line || *end != ' ' || errno != 0 || id != mnt_id)
        return -ENOENT;

    /* Paths have their spaces escaped, so " - " only ever separates. */
    const char *p = strstr(end, " - ");
    if (p == NULL || !is_fuse_fstype(p + 3))
        return -EINVAL;
    for (int field = 0; field < 3; field++) { /* skip "-", FSTYPE, SOURCE */
        p += strcspn(p + 1, " \n") + 1;
        if (*p != ' ')
            return -EINVAL;
    }
    for (p++;; p++) {
        if (strncmp(p, "user_id=", 8) == 0 && p[8] >= '0' && p[8] <= '9') {
            errno = 0;
            unsigned long uid = strtoul(p + 8, &end, 10);
            if (errno != 0 || uid > (uid_t)-1 ||
                (*end != ',' && *end != ' ' && *end != '\n' && *end != '\0'))
                return -EINVAL;
            *out_uid = (uid_t)uid;
            return 0;
        }
        p += strcspn(p, ", \n");
        if (*p != ',')
            return -EINVAL;
    }
}

/* mountinfo reflects its owning process's namespace regardless of the
 * reader's, so no setns() is needed. */
static int peer_fuse_mount_owner(int pidfd, long mnt_id, uid_t *out_uid) {
    pid_t pid = pidfd_to_pid(pidfd);
    if (pid < 0)
        return (int)pid;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", (int)pid);
    _cleanup_fclose_ FILE *f = fopen(path, "re");
    if (!f)
        return -errno;
    /* Checked after the open(): the pid wasn't recycled to another task. */
    int ret = pidfd_alive(pidfd);
    if (ret < 0)
        return ret;

    _cleanup_free_ char *line = NULL;
    size_t cap = 0;
    ret = -ENOENT;
    while (ret == -ENOENT && getline(&line, &cap, f) >= 0)
        ret = mountinfo_line_owner(line, mnt_id, out_uid);
    return ret;
}

/* Finds the "mnt_id:" line of a /proc/self/fdinfo/<fd> text. */
static int parse_fdinfo_mnt_id(const char *text, long *out_id) {
    for (const char *line = text; *line;
         line += strcspn(line, "\n"), line += *line == '\n') {
        if (strncmp(line, "mnt_id:", 7) != 0)
            continue;
        const char *p = line + 7;
        while (*p == ' ' || *p == '\t')
            p++;
        long id = 0;
        bool have_digit = false;
        for (; *p >= '0' && *p <= '9'; p++, have_digit = true) {
            if (id > (LONG_MAX - (*p - '0')) / 10)
                return -EOVERFLOW;
            id = id * 10 + (*p - '0');
        }
        if (!have_digit || (*p != '\n' && *p != '\0'))
            return -EINVAL;
        *out_id = id;
        return 0;
    }
    return -ENODATA;
}

/* "self/fdinfo/<fd>" without snprintf(), for the sandboxed child. */
static void format_fdinfo_path(char out[32], int fd) {
    char *p = stpcpy(out, "self/fdinfo/");
    char digits[3 * sizeof(int)];
    int n = 0;
    do
        digits[n++] = (char)('0' + fd % 10);
    while ((fd /= 10) > 0);
    while (n > 0)
        *p++ = digits[--n];
    *p = '\0';
}

int defused_fd_mnt_id(int proc_fd, int fd, long *out_id) {
    char path[32];
    format_fdinfo_path(path, fd);
    _cleanup_(sandbox_closep) int info_fd =
        sandbox_openat(proc_fd, path, O_RDONLY | O_CLOEXEC);
    if (info_fd == -1)
        return -errno;

    /* An O_PATH fd's fdinfo is a few short lines; a full buffer means the
     * mnt_id line might have been cut in half. */
    char buf[1024];
    size_t len = 0;
    for (;;) {
        ssize_t n = sandbox_read(info_fd, buf + len, sizeof(buf) - 1 - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return -errno;
        if (n == 0)
            break;
        len += (size_t)n;
        if (len == sizeof(buf) - 1)
            return -E2BIG;
    }
    buf[len] = '\0';
    return parse_fdinfo_mnt_id(buf, out_id);
}

struct sandbox_job {
    enum defused_op op;
    int mountfd, mnt_fd;                  /* mount */
    int proc_fd, parent_fd, umount_flags; /* unmount */
    const char *name;
    long mnt_id;
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
    /* name, relative to parent_fd, must still be the mount the parent
     * authorized. Its own block so the O_PATH fd is closed before umount2():
     * an open reference makes a non-lazy unmount fail with EBUSY. */
    {
        _cleanup_(sandbox_closep) int fd = sandbox_openat(
            job->parent_fd, job->name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd == -1) {
            *detail = "reopening the mountpoint in the client's mount "
                      "namespace failed";
            return -errno;
        }
        long id = -1;
        int ret = defused_fd_mnt_id(job->proc_fd, fd, &id);
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

int defused_sandbox_unmount(int pidfd, int proc_fd, int parent_fd,
                            const char *name, bool lazy, long mnt_id, uid_t uid,
                            struct defused_error *err) {
    /* Before forking, so an unauthorized caller's namespace is never
     * entered. GCC cannot see that owner is set whenever this returns 0,
     * hence the initializer. */
    uid_t owner = (uid_t)-1;
    int ret = peer_fuse_mount_owner(pidfd, mnt_id, &owner);
    if (ret < 0) {
        defused_error_setf(
            err, DEFUSED_ERROR_NOT_A_FUSE_MOUNT, 0, "mnt_id %ld %s (%s)",
            mnt_id,
            ret == -ENOENT   ? "is not in the caller's mountinfo"
            : ret == -EINVAL ? "is not a FUSE mount with a user_id= option"
                             : "could not be read from the caller's mountinfo",
            strerror(-ret));
        return ret;
    }
    if (owner != uid) {
        defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                           "the FUSE mount with mnt_id %ld belongs to uid %u, "
                           "not the caller's uid %u",
                           mnt_id, (unsigned)owner, (unsigned)uid);
        return -EPERM;
    }

    struct sandbox_job job = {
        .op = DEFUSED_OP_UNMOUNT,
        .proc_fd = proc_fd,
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

int defused_test_mountinfo_owner(const char *line, long mnt_id,
                                 uid_t *out_uid) {
    return mountinfo_line_owner(line, mnt_id, out_uid);
}

pid_t defused_test_fdinfo_pid(const char *text) {
    _cleanup_fclose_ FILE *f = fmemopen((void *)text, strlen(text), "r");
    return f ? fdinfo_pid(f) : -errno;
}

int defused_test_fdinfo_mnt_id(const char *text, long *out_id) {
    return parse_fdinfo_mnt_id(text, out_id);
}
#endif
