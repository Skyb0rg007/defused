/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Skips <linux/fcntl.h>'s struct redefinitions, which otherwise clash with
 * glibc's <fcntl.h> above. */
#define _ASM_GENERIC_FCNTL_H
#include <linux/pidfd.h>

struct sandbox_result {
    struct defused_error err;
    int32_t ret;
};

DEFINE_TRIVIAL_CLEANUP_FUNC(scmp_filter_ctx, seccomp_release);

static int add_rules(scmp_filter_ctx ctx, const int *syscalls, size_t count) {
    for (size_t i = 0; i < count; i++) {
        int ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0);
        if (ret < 0)
            return ret;
    }
    return 0;
}

/* After setns(), the filesystem will be controlled by the client.
 * Restrict ourselves before that to make sure nothing bad happens. */
static int install_seccomp(enum defused_op op) {
    static const int allowed_syscalls[] = {
        SCMP_SYS(write), SCMP_SYS(exit),         SCMP_SYS(exit_group),
        SCMP_SYS(setns), SCMP_SYS(rt_sigreturn),
    };
    static const int mount_syscalls[] = {
        SCMP_SYS(move_mount),
    };
    static const int unmount_syscalls[] = {
        SCMP_SYS(fchdir), SCMP_SYS(openat),  SCMP_SYS(read),
        SCMP_SYS(close),  SCMP_SYS(umount2),
    };

    /* The kernel keeps its own copy of a loaded filter, so ctx is released
     * on success as well. */
    _cleanup_(seccomp_releasep) scmp_filter_ctx ctx =
        seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
        return -ENOMEM;

    int ret = add_rules(ctx, allowed_syscalls,
                        sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]));
    if (ret < 0)
        return ret;

    switch (op) {
    case DEFUSED_OP_MOUNT:
        ret = add_rules(ctx, mount_syscalls,
                        sizeof(mount_syscalls) / sizeof(mount_syscalls[0]));
        break;
    case DEFUSED_OP_UNMOUNT:
        ret = add_rules(ctx, unmount_syscalls,
                        sizeof(unmount_syscalls) / sizeof(unmount_syscalls[0]));
        break;
    default:
        ret = -EINVAL;
        break;
    }
    if (ret < 0)
        return ret;

    ret = seccomp_load(ctx);
    return ret < 0 ? ret : 0;
}

/*
 * Everything below install_seccomp() that can run after setns() uses these
 * wrappers. syscall() has exactly the kernel entry named here, unlike a libc
 * convenience function whose implementation may change underneath the
 * seccomp allowlist.
 */
static int sandbox_setns(int fd, int nstype) {
    return (int)syscall(SYS_setns, fd, nstype);
}

static int sandbox_move_mount(int from_fd, const char *from_path, int to_fd,
                              const char *to_path, unsigned int flags) {
    return (int)syscall(SYS_move_mount, from_fd, from_path, to_fd, to_path,
                        flags);
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

static int sandbox_close(int fd) { return (int)syscall(SYS_close, fd); }

/* _cleanup_ handler for fds owned by the sandboxed child, where libc's
 * close() may not be what the seccomp filter allows. */
static void sandbox_closep(int *fd) {
    if (*fd >= 0)
        (void)sandbox_close(*fd);
}

static int sandbox_umount2(const char *path, int flags) {
    return (int)syscall(SYS_umount2, path, flags);
}

static __attribute__((__noreturn__)) void sandbox_exit(int status) {
    (void)syscall(SYS_exit_group, status);
    for (;;)
        (void)syscall(SYS_exit, status);
}

/* Sends the sandboxed child's result back to the parent over out_fd and
 * exits; sys_errno is taken as given rather than derived from
 * ret, since a refusal deliberately surfaces no syscall errno. */
static __attribute__((__noreturn__)) void
sandbox_done(int out_fd, const char *error_id, int sys_errno, int ret) {
    struct sandbox_result result = {.ret = ret};
    defused_error_set(&result.err, error_id, sys_errno);
    const char *p = (const char *)&result;
    size_t left = sizeof(result);

    while (left > 0) {
        ssize_t n = sandbox_write(out_fd, p, left);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        p += (size_t)n;
        left -= (size_t)n;
    }

    sandbox_exit(ret == 0 ? 0 : 1);
}

enum mountinfo_state {
    MOUNTINFO_ID,
    MOUNTINFO_SKIP_LINE,
    MOUNTINFO_BEFORE_SEPARATOR,
    MOUNTINFO_FSTYPE,
    MOUNTINFO_SOURCE,
    MOUNTINFO_SUPER_OPTIONS,
};

/* The super-options key whose value names the FUSE mount's owning uid. */
static const char uid_prefix[] = "user_id=";

struct mountinfo_parser {
    enum mountinfo_state state;
    long target_id;
    unsigned long number;
    bool have_number;
    bool number_overflow;
    unsigned int separator_progress;
    char fstype_prefix[8];
    size_t fstype_length;
    size_t option_index;
    bool option_matches_uid;
    bool option_has_uid_digit;
    bool option_uid_overflow;
    unsigned long option_uid;
    uid_t *out_uid;
};

static void mountinfo_reset_line(struct mountinfo_parser *parser) {
    parser->state = MOUNTINFO_ID;
    parser->number = 0;
    parser->have_number = false;
    parser->number_overflow = false;
    parser->separator_progress = 0;
}

static void mountinfo_reset_option(struct mountinfo_parser *parser) {
    parser->option_index = 0;
    parser->option_matches_uid = true;
    parser->option_has_uid_digit = false;
    parser->option_uid_overflow = false;
    parser->option_uid = 0;
}

static bool mountinfo_fstype_is_fuse(const struct mountinfo_parser *parser) {
    const char *s = parser->fstype_prefix;
    size_t len = parser->fstype_length;

    if (len == 4 && memcmp(s, "fuse", 4) == 0)
        return true;
    if (len >= 5 && memcmp(s, "fuse.", 5) == 0)
        return true;
    if (len == 7 && memcmp(s, "fuseblk", 7) == 0)
        return true;
    return len >= 8 && memcmp(s, "fuseblk.", 8) == 0;
}

static int mountinfo_finish_option(struct mountinfo_parser *parser) {
    if (parser->option_matches_uid &&
        parser->option_index > sizeof(uid_prefix) - 1 &&
        parser->option_has_uid_digit && !parser->option_uid_overflow &&
        parser->option_uid <= (unsigned long)((uid_t)-1)) {
        *parser->out_uid = (uid_t)parser->option_uid;
        return 1;
    }

    mountinfo_reset_option(parser);
    return 0;
}

/*
 * Consume one byte of mountinfo. This is deliberately streaming: mount paths
 * and option lists are not bounded by this program, and truncating a line
 * could turn a valid FUSE mount into a false authorization result.
 *
 * Returns 1 when the requested owner was found, 0 to continue, or -EINVAL
 * when the requested mount exists but is not a well-formed FUSE entry.
 */
static int mountinfo_feed(struct mountinfo_parser *parser, char ch) {
    switch (parser->state) {
    case MOUNTINFO_ID:
        if (ch >= '0' && ch <= '9') {
            unsigned int digit = (unsigned int)(ch - '0');
            parser->have_number = true;
            if (parser->number > (ULONG_MAX - digit) / 10)
                parser->number_overflow = true;
            else
                parser->number = parser->number * 10 + digit;
            return 0;
        }
        if (ch == ' ' && parser->have_number && !parser->number_overflow &&
            parser->number == (unsigned long)parser->target_id)
            parser->state = MOUNTINFO_BEFORE_SEPARATOR;
        else if (ch == '\n')
            mountinfo_reset_line(parser);
        else
            parser->state = MOUNTINFO_SKIP_LINE;
        return 0;

    case MOUNTINFO_SKIP_LINE:
        if (ch == '\n')
            mountinfo_reset_line(parser);
        return 0;

    case MOUNTINFO_BEFORE_SEPARATOR:
        if (ch == '\n')
            return -EINVAL;
        if (parser->separator_progress == 0)
            parser->separator_progress = ch == ' ' ? 1 : 0;
        else if (parser->separator_progress == 1)
            parser->separator_progress = ch == '-' ? 2 : (ch == ' ' ? 1 : 0);
        else if (ch == ' ') {
            parser->state = MOUNTINFO_FSTYPE;
            parser->fstype_length = 0;
        } else
            parser->separator_progress = 0;
        return 0;

    case MOUNTINFO_FSTYPE:
        if (ch == '\n')
            return -EINVAL;
        if (ch == ' ') {
            if (!mountinfo_fstype_is_fuse(parser))
                return -EINVAL;
            parser->state = MOUNTINFO_SOURCE;
            return 0;
        }
        if (parser->fstype_length < sizeof(parser->fstype_prefix))
            parser->fstype_prefix[parser->fstype_length] = ch;
        parser->fstype_length++;
        return 0;

    case MOUNTINFO_SOURCE:
        if (ch == '\n')
            return -EINVAL;
        if (ch == ' ') {
            parser->state = MOUNTINFO_SUPER_OPTIONS;
            mountinfo_reset_option(parser);
        }
        return 0;

    case MOUNTINFO_SUPER_OPTIONS:
        if (ch == ',' || ch == ' ' || ch == '\n') {
            int ret = mountinfo_finish_option(parser);
            if (ret != 0)
                return ret;
            return ch == ',' ? 0 : -EINVAL;
        }

        if (parser->option_index < sizeof(uid_prefix) - 1) {
            if (ch != uid_prefix[parser->option_index])
                parser->option_matches_uid = false;
        } else if (ch >= '0' && ch <= '9') {
            unsigned int digit = (unsigned int)(ch - '0');
            parser->option_has_uid_digit = true;
            if (parser->option_uid > (ULONG_MAX - digit) / 10)
                parser->option_uid_overflow = true;
            else
                parser->option_uid = parser->option_uid * 10 + digit;
        } else
            parser->option_matches_uid = false;
        parser->option_index++;
        return 0;
    }

    return -EINVAL;
}

/* Linux 6.13+. ENODATA, not EINVAL, for a useless reply: EINVAL means the
 * kernel lacks the ioctl (see pidfd_to_pid()). */
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

/* Linux 5.2+: "Pid:" is reported in the reader's pid namespace, which is the
 * one /proc/<pid>/mountinfo is opened from below. Runs in the parent before
 * the seccomp filter exists, so stdio is fine here. */
static pid_t pidfd_to_pid_fdinfo(int pidfd) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
    _cleanup_fclose_ FILE *f = fopen(path, "re");
    if (!f)
        return -errno;
    return fdinfo_pid(f);
}

/* Kernels before 6.13 fail PIDFD_GET_INFO with ENOTTY (no pidfd_ioctl()) or
 * EINVAL (6.11/6.12 reject any ioctl with an argument outright).
 * open_peer_mountinfo() below closes the pid-recycling race this alone
 * doesn't. */
static pid_t pidfd_to_pid(int pidfd) {
    pid_t pid = pidfd_to_pid_ioctl(pidfd);
    if (pid == -ENOTTY || pid == -EINVAL)
        pid = pidfd_to_pid_fdinfo(pidfd);
    return pid;
}

/* A pidfd polls readable once its process has exited. Unlike a
 * pidfd_send_signal() probe this needs no CAP_KILL, which the hardened
 * service unit doesn't grant. */
static int pidfd_alive(int pidfd) {
    struct pollfd pfd = {.fd = pidfd, .events = POLLIN};
    for (;;) {
        int n = poll(&pfd, 1, 0);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        return n == 0 ? 0 : -ESRCH;
    }
}

/* The liveness check after open() proves the pid wasn't recycled to another
 * task in between. */
static int open_peer_mountinfo(int pidfd, int *out_fd) {
    pid_t pid = pidfd_to_pid(pidfd);
    if (pid < 0)
        return (int)pid;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", (int)pid);

    _cleanup_close_ int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return -errno;

    int ret = pidfd_alive(pidfd);
    if (ret < 0)
        return ret;

    *out_fd = TAKE_FD(fd);
    return 0;
}

/* mountinfo reflects its owning process's namespace regardless of the reader's,
 * so no setns() is needed. */
static int peer_fuse_mount_owner(int pidfd, long mnt_id, uid_t *out_uid) {
    _cleanup_close_ int fd = -EBADF;
    int ret = open_peer_mountinfo(pidfd, &fd);
    if (ret < 0)
        return ret;

    struct mountinfo_parser parser = {
        .target_id = mnt_id,
        .out_uid = out_uid,
    };
    mountinfo_reset_line(&parser);

    char buf[4096];
    ret = -ENOENT;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ret = -errno;
            break;
        }
        if (n == 0)
            break;

        for (ssize_t i = 0; i < n; i++) {
            ret = mountinfo_feed(&parser, buf[i]);
            if (ret != 0)
                return ret > 0 ? 0 : ret;
        }
    }

    if (ret == -ENOENT && parser.state != MOUNTINFO_ID) {
        ret = mountinfo_feed(&parser, '\n');
        if (ret > 0)
            ret = 0;
    }

    return ret;
}

/* Finds the "mnt_id:" line of a /proc/self/fdinfo/<fd> buffer. Works on a
 * plain buffer so the sandboxed child can use it without stdio. */
static int parse_fdinfo_mnt_id(const char *buf, size_t len, long *out_id) {
    static const char key[] = "mnt_id:";
    size_t i = 0;

    while (i < len) {
        size_t line_end = i;
        while (line_end < len && buf[line_end] != '\n')
            line_end++;

        if (line_end - i > sizeof(key) - 1 &&
            memcmp(buf + i, key, sizeof(key) - 1) == 0) {
            size_t p = i + sizeof(key) - 1;
            while (p < line_end && (buf[p] == ' ' || buf[p] == '\t'))
                p++;

            long id = 0;
            bool have_digit = false;
            for (; p < line_end; p++) {
                if (buf[p] < '0' || buf[p] > '9')
                    return -EINVAL;
                unsigned int digit = (unsigned int)(buf[p] - '0');
                if (id > (LONG_MAX - (long)digit) / 10)
                    return -EOVERFLOW;
                id = id * 10 + (long)digit;
                have_digit = true;
            }
            if (!have_digit)
                return -EINVAL;
            *out_id = id;
            return 0;
        }

        i = line_end + 1;
    }

    return -ENODATA;
}

/* snprintf()-free "self/fdinfo/<fd>" for the sandboxed child. */
static void format_fdinfo_path(char out[32], int fd) {
    static const char prefix[] = "self/fdinfo/";
    char digits[3 * sizeof(int)];
    size_t n = 0;
    unsigned int v = (unsigned int)fd;

    do {
        digits[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);

    memcpy(out, prefix, sizeof(prefix) - 1);
    size_t pos = sizeof(prefix) - 1;
    while (n > 0)
        out[pos++] = digits[--n];
    out[pos] = '\0';
}

/* Post-setns() counterpart of defused.c's fd_mnt_id(): reads fd's fdinfo from
 * the service's trusted procfs with raw syscalls only. */
static int sandbox_fd_mnt_id(int proc_fd, int fd, long *out_id) {
    char path[32];
    format_fdinfo_path(path, fd);

    _cleanup_(sandbox_closep) int info_fd =
        sandbox_openat(proc_fd, path, O_RDONLY | O_CLOEXEC);
    if (info_fd == -1)
        return -errno;

    char buf[1024];
    size_t len = 0;
    while (len < sizeof(buf)) {
        ssize_t n = sandbox_read(info_fd, buf + len, sizeof(buf) - len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }
    /* An O_PATH fd's fdinfo is a few short lines; a full buffer means the
     * mnt_id line might have been cut in half. */
    if (len == sizeof(buf))
        return -E2BIG;
    return parse_fdinfo_mnt_id(buf, len, out_id);
}

/* Runs after setns(). Checks that name, relative to parent_fd, still resolves
 * to the mount the parent authorized. Its own function so the O_PATH fd is
 * closed on return, before the caller's umount2(): an open reference to the
 * mount makes a non-lazy unmount fail with EBUSY. */
static int sandbox_check_mnt_id(int proc_fd, int parent_fd, const char *name,
                                long mnt_id) {
    _cleanup_(sandbox_closep) int fd =
        sandbox_openat(parent_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1)
        return -errno;
    long id = -1;
    int ret = sandbox_fd_mnt_id(proc_fd, fd, &id);
    if (ret < 0)
        return ret;
    return id == mnt_id ? 0 : -ESTALE;
}

/* Runs after setns(). Unmounts name, relative to parent_fd, once
 * sandbox_check_mnt_id() confirms it is still the mount the parent
 * authorized. */
static int sandbox_unmount_verified(int proc_fd, int parent_fd,
                                    const char *name, long mnt_id, int flags) {
    if (sandbox_fchdir(parent_fd) == -1)
        return -errno;

    int ret = sandbox_check_mnt_id(proc_fd, parent_fd, name, mnt_id);
    if (ret < 0)
        return ret;

    if (sandbox_umount2(name, UMOUNT_NOFOLLOW | flags) == -1)
        return -errno;
    return 0;
}

static int read_sandbox_result(int fd, struct sandbox_result *result) {
    char *p = (char *)result;
    size_t left = sizeof(*result);

    while (left > 0) {
        ssize_t n = read(fd, p, left);
        if (n == 0)
            return -EPIPE;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        p += (size_t)n;
        left -= (size_t)n;
    }

    return 0;
}

static int wait_sandbox(pid_t pid) {
    int status;
    for (;;) {
        if (waitpid(pid, &status, 0) >= 0)
            return status;
        if (errno != EINTR)
            return -errno;
    }
}

/* Creates a CLOEXEC pipe into the caller's _cleanup_close_pair_ pipefd and
 * forks. Returns the child's pid to the parent, 0 to the child, or a
 * negative errno if pipe2()/fork() itself failed. */
static pid_t fork_with_pipe(int pipefd[2]) {
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;

    pid_t pid = fork();
    if (pid == -1)
        return -errno;
    return pid;
}

/* Reads the child's sandbox_result off pipefd_read and waits for pid.
 * fail_id is reported when no result arrived; once one has, it is the answer
 * whatever the wait says, since the child writes it immediately before
 * exiting and something else may already have reaped the child. */
static int reap_sandbox(int pipefd_read, pid_t pid, const char *fail_id,
                        struct defused_error *err) {
    struct sandbox_result result;
    int ret = read_sandbox_result(pipefd_read, &result);
    (void)wait_sandbox(pid);
    if (ret < 0) {
        defused_error_set(err, fail_id, -ret);
        return ret;
    }

    *err = result.err;
    return result.ret;
}

int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd,
                          struct defused_error *err) {
    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    pid_t pid = fork_with_pipe(pipefd);
    if (pid < 0)
        return (int)pid;

    if (pid == 0) {
        pipefd[0] = safe_close(pipefd[0]);

        int ret = install_seccomp(DEFUSED_OP_MOUNT);
        if (ret < 0)
            sandbox_done(pipefd[1], DEFUSED_VARLINK_ERROR_MOUNT_FAILED, -ret,
                         ret);

        if (sandbox_setns(pidfd, CLONE_NEWNS) == -1) {
            ret = -errno;
            sandbox_done(pipefd[1], DEFUSED_VARLINK_ERROR_MOUNT_FAILED, -ret,
                         ret);
        }

        ret = sandbox_move_mount(mountfd, "", mnt_fd, "",
                                 MOVE_MOUNT_F_EMPTY_PATH |
                                     MOVE_MOUNT_T_EMPTY_PATH) == -1
                  ? -errno
                  : 0;
        sandbox_done(pipefd[1],
                     ret < 0 ? DEFUSED_VARLINK_ERROR_MOUNT_FAILED : NULL,
                     ret < 0 ? -ret : 0, ret);
    }

    pipefd[1] = safe_close(pipefd[1]);
    return reap_sandbox(pipefd[0], pid, DEFUSED_VARLINK_ERROR_MOUNT_FAILED,
                        err);
}

int defused_sandbox_unmount(int pidfd, int proc_fd, int parent_fd,
                            const char *name, bool lazy, long mnt_id, uid_t uid,
                            struct defused_error *err) {
    /* Checked here, before forking, so an unauthorized caller never touches the
     * client's namespace. */
    uid_t owner;
    int ret = peer_fuse_mount_owner(pidfd, mnt_id, &owner);
    if (ret < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_A_FUSE_MOUNT, 0);
        return ret;
    }
    if (owner != uid) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_ALLOWED, 0);
        return -EPERM;
    }

    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    pid_t pid = fork_with_pipe(pipefd);
    if (pid < 0)
        return (int)pid;

    if (pid == 0) {
        pipefd[0] = safe_close(pipefd[0]);

        int child_ret = install_seccomp(DEFUSED_OP_UNMOUNT);
        if (child_ret < 0)
            sandbox_done(pipefd[1], DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED,
                         -child_ret, child_ret);

        if (sandbox_setns(pidfd, CLONE_NEWNS) == -1) {
            child_ret = -errno;
            sandbox_done(pipefd[1], DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED,
                         -child_ret, child_ret);
        }

        child_ret = sandbox_unmount_verified(proc_fd, parent_fd, name, mnt_id,
                                             lazy ? MNT_DETACH : 0);
        sandbox_done(pipefd[1],
                     child_ret < 0 ? DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED
                                   : NULL,
                     child_ret < 0 ? -child_ret : 0, child_ret);
    }

    pipefd[1] = safe_close(pipefd[1]);
    return reap_sandbox(pipefd[0], pid, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED,
                        err);
}

#ifdef DEFUSED_TEST
int defused_test_install_seccomp(enum defused_op op) {
    return install_seccomp(op);
}

int defused_test_mountinfo_owner(const char *line, long mnt_id,
                                 uid_t *out_uid) {
    struct mountinfo_parser parser = {
        .target_id = mnt_id,
        .out_uid = out_uid,
    };
    mountinfo_reset_line(&parser);

    for (const char *p = line; *p; p++) {
        int ret = mountinfo_feed(&parser, *p);
        if (ret != 0)
            return ret > 0 ? 0 : ret;
    }

    int ret = mountinfo_feed(&parser, '\n');
    return ret > 0 ? 0 : ret == 0 ? -ENOENT : ret;
}

pid_t defused_test_fdinfo_pid(const char *text) {
    _cleanup_fclose_ FILE *f = fmemopen((void *)text, strlen(text), "r");
    if (!f)
        return -errno;
    return fdinfo_pid(f);
}

int defused_test_fdinfo_mnt_id(const char *buf, size_t len, long *out_id) {
    return parse_fdinfo_mnt_id(buf, len, out_id);
}
#endif
