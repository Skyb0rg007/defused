/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct sandbox_result {
    uint32_t status;
    int32_t sys_errno;
    int32_t ret;
};

/* After setns(), the filesystem will be controlled by the client.
 * Restrict ourselves before that to make sure nothing bad happens. */
static int install_seccomp(enum defused_op op) {
    static const int allowed_syscalls[] = {
        SCMP_SYS(read),         SCMP_SYS(write),      SCMP_SYS(close),
        SCMP_SYS(exit),         SCMP_SYS(exit_group), SCMP_SYS(setns),
        SCMP_SYS(rt_sigreturn),
    };
    static const int mount_syscalls[] = {
        SCMP_SYS(move_mount),
    };
    static const int unmount_syscalls[] = {
        SCMP_SYS(fchdir),
        SCMP_SYS(umount2),
        SCMP_SYS(openat),
    };

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
        return -ENOMEM;

    int ret = 0;
    for (size_t i = 0;
         i < sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]); i++) {
        ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed_syscalls[i], 0);
        if (ret < 0)
            goto out;
    }

    switch (op) {
    case DEFUSED_OP_MOUNT:
        for (size_t i = 0;
             i < sizeof(mount_syscalls) / sizeof(mount_syscalls[0]); i++) {
            ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, mount_syscalls[i], 0);
            if (ret < 0)
                goto out;
        }
        break;
    case DEFUSED_OP_UNMOUNT:
        for (size_t i = 0;
             i < sizeof(unmount_syscalls) / sizeof(unmount_syscalls[0]); i++) {
            ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, unmount_syscalls[i], 0);
            if (ret < 0)
                goto out;
        }
        break;
    default:
        return -EINVAL;
    }

    ret = seccomp_load(ctx);
    if (ret >= 0)
        return 0;
out:
    seccomp_release(ctx);
    return ret < 0 ? ret : 0;
}

static int neg_errno(void) { return -errno; }

static void sandbox_exit(int status) {
    (void)syscall(SYS_exit_group, status);
    for (;;)
        (void)syscall(SYS_exit, status);
}

static void sandbox_finish(int out_fd, struct sandbox_result result) {
    const char *p = (const char *)&result;
    size_t left = sizeof(result);

    while (left > 0) {
        ssize_t n = write(out_fd, p, left);
        if (n <= 0)
            break;
        p += (size_t)n;
        left -= (size_t)n;
    }

    sandbox_exit(result.ret == 0 ? 0 : 1);
}

static int sandbox_prefix(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s != *prefix)
            return 0;
        s++;
        prefix++;
    }
    return 1;
}

static int sandbox_parse_ulong(const char **p, unsigned long *out) {
    const char *s = *p;
    unsigned long v = 0;

    if (*s < '0' || *s > '9')
        return -EINVAL;

    do {
        v = v * 10 + (unsigned long)(*s - '0');
        s++;
    } while (*s >= '0' && *s <= '9');

    *p = s;
    *out = v;
    return 0;
}

static const char *sandbox_find_sep(const char *line) {
    for (const char *p = line; p[0] && p[1] && p[2]; p++)
        if (p[0] == ' ' && p[1] == '-' && p[2] == ' ')
            return p;
    return NULL;
}

static int sandbox_fstype_is_fuse(const char *p) {
    if (sandbox_prefix(p, "fuse") &&
        (p[4] == ' ' || p[4] == '.' || p[4] == '\0'))
        return 1;
    if (sandbox_prefix(p, "fuseblk") &&
        (p[7] == ' ' || p[7] == '.' || p[7] == '\0'))
        return 1;
    return 0;
}

static int sandbox_mountinfo_owner_line(const char *line, long mnt_id,
                                        uid_t *out_uid) {
    const char *p = line;
    unsigned long id;
    if (sandbox_parse_ulong(&p, &id) < 0 || (long)id != mnt_id)
        return -ENOENT;

    const char *sep = sandbox_find_sep(line);
    if (!sep)
        return -ENOENT;
    p = sep + 3;
    if (!sandbox_fstype_is_fuse(p))
        return -EINVAL;

    for (; *p; p++) {
        if (!sandbox_prefix(p, "user_id="))
            continue;
        p += 8;
        unsigned long uid;
        if (sandbox_parse_ulong(&p, &uid) < 0)
            return -EINVAL;
        *out_uid = (uid_t)uid;
        return 0;
    }

    return -EINVAL;
}

static int sandbox_fuse_mount_owner(int proc_fd, long mnt_id, uid_t *out_uid) {
    int fd = openat(proc_fd, "self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return neg_errno();

    char buf[1024];
    char line[1024];
    size_t line_len = 0;
    int ret = -ENOENT;

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            ret = neg_errno();
            break;
        }
        if (n == 0)
            break;

        for (long i = 0; i < n; i++) {
            char ch = buf[i];
            if (ch != '\n' && line_len + 1 < sizeof(line)) {
                line[line_len++] = ch;
                continue;
            }

            line[line_len] = '\0';
            ret = sandbox_mountinfo_owner_line(line, mnt_id, out_uid);
            if (ret != -ENOENT)
                goto out;
            line_len = 0;
        }
    }

    if (ret == -ENOENT && line_len > 0) {
        line[line_len] = '\0';
        ret = sandbox_mountinfo_owner_line(line, mnt_id, out_uid);
    }

out:
    close(fd);
    return ret;
}

static int sandbox_umount_by_proc_path(int proc_fd, const char *proc_path,
                                       int flags) {
    if (fchdir(proc_fd) == -1)
        return neg_errno();

    if (umount2(proc_path, flags) == -1)
        return neg_errno();
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

int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd, uint32_t *status,
                          int *sys_errno) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;

    pid_t pid = fork();
    if (pid == -1) {
        int saved_errno = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        return -saved_errno;
    }

    if (pid == 0) {
        close(pipefd[0]);

        int ret = install_seccomp(DEFUSED_OP_MOUNT);
        if (ret < 0) {
            struct sandbox_result result = {
                .status = DEFUSED_ERR_MOUNT_FAILED,
                .sys_errno = -ret,
                .ret = ret,
            };
            sandbox_finish(pipefd[1], result);
        }

        if (setns(pidfd, CLONE_NEWNS) == -1) {
            ret = neg_errno();
            struct sandbox_result result = {
                .status = DEFUSED_ERR_SETNS_FAILED,
                .sys_errno = -ret,
                .ret = ret,
            };
            sandbox_finish(pipefd[1], result);
        }

        if (move_mount(mountfd, "", mnt_fd, "",
                       MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == -1)
            ret = neg_errno();
        else
            ret = 0;
        struct sandbox_result result = {
            .status = ret < 0 ? DEFUSED_ERR_MOUNT_FAILED : DEFUSED_OK,
            .sys_errno = ret < 0 ? -ret : 0,
            .ret = ret,
        };
        sandbox_finish(pipefd[1], result);
    }

    close(pipefd[1]);
    struct sandbox_result result = {
        .status = DEFUSED_ERR_MOUNT_FAILED,
        .sys_errno = EIO,
        .ret = -EIO,
    };
    int ret = read_sandbox_result(pipefd[0], &result);
    close(pipefd[0]);
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

int defused_sandbox_unmount(int pidfd, int proc_fd, int parent_fd,
                            const struct defused_umount_req *req, long mnt_id,
                            uid_t uid, uint32_t *status, int *sys_errno) {
    char proc_path[32 + DEFUSED_MAX_FILENAME];
    snprintf(proc_path, sizeof(proc_path), "self/fd/%d/%s", parent_fd,
             req->name);

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;

    pid_t pid = fork();
    if (pid == -1) {
        int saved_errno = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        return -saved_errno;
    }

    if (pid == 0) {
        close(pipefd[0]);

        int ret = install_seccomp(DEFUSED_OP_UNMOUNT);
        if (ret < 0) {
            struct sandbox_result result = {
                .status = DEFUSED_ERR_UNMOUNT_FAILED,
                .sys_errno = -ret,
                .ret = ret,
            };
            sandbox_finish(pipefd[1], result);
        }

        if (setns(pidfd, CLONE_NEWNS) == -1) {
            ret = neg_errno();
            struct sandbox_result result = {
                .status = DEFUSED_ERR_SETNS_FAILED,
                .sys_errno = -ret,
                .ret = ret,
            };
            sandbox_finish(pipefd[1], result);
        }

        uid_t owner;
        ret = sandbox_fuse_mount_owner(proc_fd, mnt_id, &owner);
        if (ret < 0) {
            struct sandbox_result result = {
                .status = DEFUSED_ERR_NOT_A_FUSE_MOUNT,
                .sys_errno = 0,
                .ret = ret,
            };
            sandbox_finish(pipefd[1], result);
        }

        if (owner != uid) {
            struct sandbox_result result = {
                .status = DEFUSED_ERR_NOT_ALLOWED,
                .sys_errno = 0,
                .ret = -EPERM,
            };
            sandbox_finish(pipefd[1], result);
        }

        ret = sandbox_umount_by_proc_path(
            proc_fd, proc_path, (req->lazy ? MNT_DETACH : 0) | UMOUNT_NOFOLLOW);
        struct sandbox_result result = {
            .status = ret < 0 ? DEFUSED_ERR_UNMOUNT_FAILED : DEFUSED_OK,
            .sys_errno = ret < 0 ? -ret : 0,
            .ret = ret,
        };
        sandbox_finish(pipefd[1], result);
    }

    close(pipefd[1]);
    struct sandbox_result result = {
        .status = DEFUSED_ERR_UNMOUNT_FAILED,
        .sys_errno = EIO,
        .ret = -EIO,
    };
    int ret = read_sandbox_result(pipefd[0], &result);
    close(pipefd[0]);
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
