/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdio.h>
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
    uint32_t status;
    int32_t sys_errno;
    int32_t ret;
};

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
        SCMP_SYS(fchdir),
        SCMP_SYS(umount2),
    };

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
        return -ENOMEM;

    int ret = add_rules(ctx, allowed_syscalls,
                        sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]));
    if (ret < 0)
        goto out;

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
        seccomp_release(ctx);
        return -EINVAL;
    }
    if (ret < 0)
        goto out;

    ret = seccomp_load(ctx);
    if (ret >= 0)
        return 0;
out:
    seccomp_release(ctx);
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

static int sandbox_umount2(const char *path, int flags) {
    return (int)syscall(SYS_umount2, path, flags);
}

static __attribute__((__noreturn__)) void sandbox_exit(int status) {
    (void)syscall(SYS_exit_group, status);
    for (;;)
        (void)syscall(SYS_exit, status);
}

/* Sends the sandboxed child's result back to the parent over out_fd and
 * exits; sys_errno is taken as given rather than derived from ret, since
 * some statuses (e.g. DEFUSED_ERR_NOT_ALLOWED) deliberately don't surface a
 * syscall errno. */
static __attribute__((__noreturn__)) void
sandbox_done(int out_fd, uint32_t status, int sys_errno, int ret) {
    struct sandbox_result result = {
        .status = status,
        .sys_errno = sys_errno,
        .ret = ret,
    };
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
    if (parser->option_matches_uid && parser->option_index > 8 &&
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
    static const char uid_prefix[] = "user_id=";

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

/* Requires Linux 6.13; open_peer_mountinfo() below closes the pid-recycling
 * race this alone doesn't. Older kernels could fall back to parsing
 * /proc/self/fdinfo/<pidfd>'s "Pid:" line instead, but that isn't done here. */
static pid_t pidfd_to_pid(int pidfd) {
    struct pidfd_info info = {0};
    if (ioctl(pidfd, PIDFD_GET_INFO, &info) == -1)
        return -errno;
    if (!(info.mask & PIDFD_INFO_PID) || info.pid == 0 ||
        info.pid > (unsigned int)INT_MAX)
        return -EINVAL;
    return (pid_t)info.pid;
}

/* The pidfd_send_signal() after open() proves the pid wasn't recycled to
 * another task in between. */
static int open_peer_mountinfo(int pidfd, int *out_fd) {
    pid_t pid = pidfd_to_pid(pidfd);
    if (pid < 0)
        return (int)pid;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mountinfo", (int)pid);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return -errno;

    if (syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) == -1) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }

    *out_fd = fd;
    return 0;
}

/* mountinfo reflects its owning process's namespace regardless of the reader's,
 * so no setns() is needed. */
static int peer_fuse_mount_owner(int pidfd, long mnt_id, uid_t *out_uid) {
    int fd;
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
            if (ret != 0) {
                if (ret > 0)
                    ret = 0;
                goto out;
            }
        }
    }

    if (ret == -ENOENT && parser.state != MOUNTINFO_ID) {
        ret = mountinfo_feed(&parser, '\n');
        if (ret > 0)
            ret = 0;
    }

out:
    close(fd);
    return ret;
}

static int sandbox_umount_by_proc_path(int proc_fd, const char *proc_path,
                                       int flags) {
    if (sandbox_fchdir(proc_fd) == -1)
        return -errno;

    if (sandbox_umount2(proc_path, flags) == -1)
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

/* Creates a CLOEXEC pipe and forks. Returns the child's pid to the parent,
 * 0 to the child, or a negative errno if pipe2()/fork() itself failed (both
 * pipe ends are already closed in that case). */
static pid_t fork_with_pipe(int pipefd[2]) {
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;

    pid_t pid = fork();
    if (pid == -1) {
        int saved_errno = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        return -saved_errno;
    }
    return pid;
}

/* Reads the child's sandbox_result off pipefd_read and waits for pid,
 * folding a pipe-read failure or an abnormal exit into the result so the
 * caller doesn't have to special-case them. fail_status is reported if the
 * child never got to send a result at all. */
static int reap_sandbox(int pipefd_read, pid_t pid, uint32_t fail_status,
                        uint32_t *status, int *sys_errno) {
    struct sandbox_result result = {
        .status = fail_status,
        .sys_errno = EIO,
        .ret = -EIO,
    };
    int ret = read_sandbox_result(pipefd_read, &result);
    close(pipefd_read);
    int wait_status = wait_sandbox(pid);
    if (ret < 0) {
        result.sys_errno = -ret;
        result.ret = ret;
    } else if (wait_status < 0) {
        result.sys_errno = -wait_status;
        result.ret = wait_status;
    } else if (!WIFEXITED(wait_status)) {
        result.sys_errno = EIO;
        result.ret = -EIO;
    }

    *status = result.status;
    *sys_errno = result.sys_errno;
    return result.ret;
}

int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd, uint32_t *status,
                          int *sys_errno) {
    int pipefd[2];
    pid_t pid = fork_with_pipe(pipefd);
    if (pid < 0)
        return (int)pid;

    if (pid == 0) {
        close(pipefd[0]);

        int ret = install_seccomp(DEFUSED_OP_MOUNT);
        if (ret < 0)
            sandbox_done(pipefd[1], DEFUSED_ERR_MOUNT_FAILED, -ret, ret);

        if (sandbox_setns(pidfd, CLONE_NEWNS) == -1) {
            ret = -errno;
            sandbox_done(pipefd[1], DEFUSED_ERR_SETNS_FAILED, -ret, ret);
        }

        ret = sandbox_move_mount(mountfd, "", mnt_fd, "",
                                 MOVE_MOUNT_F_EMPTY_PATH |
                                     MOVE_MOUNT_T_EMPTY_PATH) == -1
                  ? -errno
                  : 0;
        sandbox_done(pipefd[1], ret < 0 ? DEFUSED_ERR_MOUNT_FAILED : DEFUSED_OK,
                     ret < 0 ? -ret : 0, ret);
    }

    close(pipefd[1]);
    return reap_sandbox(pipefd[0], pid, DEFUSED_ERR_MOUNT_FAILED, status,
                        sys_errno);
}

int defused_sandbox_unmount(int pidfd, int proc_fd, int mnt_fd, bool lazy,
                            long mnt_id, uid_t uid, uint32_t *status,
                            int *sys_errno) {
    /* Checked here, before forking, so an unauthorized caller never touches the
     * client's namespace. */
    uid_t owner;
    int ret = peer_fuse_mount_owner(pidfd, mnt_id, &owner);
    if (ret < 0) {
        *status = DEFUSED_ERR_NOT_A_FUSE_MOUNT;
        *sys_errno = 0;
        return ret;
    }
    if (owner != uid) {
        *status = DEFUSED_ERR_NOT_ALLOWED;
        *sys_errno = 0;
        return -EPERM;
    }

    char proc_path[32];
    snprintf(proc_path, sizeof(proc_path), "self/fd/%d", mnt_fd);

    int pipefd[2];
    pid_t pid = fork_with_pipe(pipefd);
    if (pid < 0)
        return (int)pid;

    if (pid == 0) {
        close(pipefd[0]);

        int child_ret = install_seccomp(DEFUSED_OP_UNMOUNT);
        if (child_ret < 0)
            sandbox_done(pipefd[1], DEFUSED_ERR_UNMOUNT_FAILED, -child_ret,
                         child_ret);

        if (sandbox_setns(pidfd, CLONE_NEWNS) == -1) {
            child_ret = -errno;
            sandbox_done(pipefd[1], DEFUSED_ERR_SETNS_FAILED, -child_ret,
                         child_ret);
        }

        /*
         * Resolve the mount through the O_PATH fd that supplied mnt_id above,
         * rather than looking up the client-controlled parent/name pair
         * again after authorization. proc_fd refers to the service's trusted
         * procfs, so following this magic link cannot redirect the unmount to
         * a different client-selected path.
         */
        child_ret = sandbox_umount_by_proc_path(proc_fd, proc_path,
                                                lazy ? MNT_DETACH : 0);
        sandbox_done(pipefd[1],
                     child_ret < 0 ? DEFUSED_ERR_UNMOUNT_FAILED : DEFUSED_OK,
                     child_ret < 0 ? -child_ret : 0, child_ret);
    }

    close(pipefd[1]);
    return reap_sandbox(pipefd[0], pid, DEFUSED_ERR_UNMOUNT_FAILED, status,
                        sys_errno);
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
#endif
