/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

struct filter_result {
    int install_ret;
    long syscall_ret;
    int sys_errno;
};

static int read_full(int fd, void *buf, size_t size) {
    char *p = buf;
    while (size > 0) {
        ssize_t n = read(fd, p, size);
        if (n == 0)
            return -EPIPE;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        p += (size_t)n;
        size -= (size_t)n;
    }
    return 0;
}

static void test_filter_syscall(enum defused_op op, long syscall_number,
                                int expected_errno) {
    int pipefd[2];
    int ret = pipe2(pipefd, O_CLOEXEC);
    CHECK(ret == 0);
    if (ret < 0)
        return;

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        close(pipefd[0]);
        struct filter_result result = {
            .install_ret = defused_test_install_seccomp(op),
        };
        errno = 0;
        result.syscall_ret = syscall(syscall_number, -1, NULL, 0, 0, 0, 0);
        result.sys_errno = errno;
        (void)syscall(SYS_write, pipefd[1], &result, sizeof(result));
        (void)syscall(SYS_exit_group, 0);
        for (;;)
            (void)syscall(SYS_exit, 1);
    }

    close(pipefd[1]);
    struct filter_result result = {};
    CHECK(read_full(pipefd[0], &result, sizeof(result)) == 0);
    close(pipefd[0]);

    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(result.install_ret == 0);
    CHECK(result.syscall_ret == -1);
    CHECK(result.sys_errno == expected_errno);
}

static void test_mountinfo_parser(void) {
    uid_t uid = 0;
    const char *line = "42 35 0:50 / /mnt rw,nosuid - fuse.sshfs user_id=123 "
                       "rw,nosuid,user_id=1000,group_id=1000";
    CHECK(defused_test_mountinfo_owner(line, 42, &uid) == 0);
    CHECK(uid == 1000);

    uid = 0;
    line = "43 35 0:51 / /mnt rw - fuse source "
           "rw,xuser_id=123,user_id=1001,group_id=1001";
    CHECK(defused_test_mountinfo_owner(line, 43, &uid) == 0);
    CHECK(uid == 1001);

    uid = 0;
    line = "44 35 0:52 / /mnt rw - fuseblk source "
           "rw,user_id=1002,group_id=1002";
    CHECK(defused_test_mountinfo_owner(line, 44, &uid) == 0);
    CHECK(uid == 1002);

    line = "45 35 0:53 / /mnt rw - ext4 source rw,user_id=1003";
    CHECK(defused_test_mountinfo_owner(line, 45, &uid) == -EINVAL);

    line = "46 35 0:54 / /mnt rw - fuse source rw,group_id=1004";
    CHECK(defused_test_mountinfo_owner(line, 99, &uid) == -ENOENT);
    CHECK(defused_test_mountinfo_owner(line, 46, &uid) == -EINVAL);

    line = "47 35 0:55 / /mnt rw - fuse user_id=1005 rw,group_id=1005";
    CHECK(defused_test_mountinfo_owner(line, 47, &uid) == -EINVAL);

    line = "48 35 0:56 / /mnt rw - fuseevil source rw,user_id=1006";
    CHECK(defused_test_mountinfo_owner(line, 48, &uid) == -EINVAL);
}

static void test_long_mountinfo_line(void) {
    char line[8192];
    int n = snprintf(line, sizeof(line), "49 35 0:57 / /mnt rw ");
    CHECK(n > 0);
    if (n <= 0)
        return;

    size_t len = (size_t)n;
    while (len < 6000)
        line[len++] = 'x';

    const char *suffix = " - fuse source rw,user_id=4242,group_id=4242";
    size_t suffix_len = strlen(suffix);
    CHECK(len + suffix_len + 1 < sizeof(line));
    if (len + suffix_len + 1 >= sizeof(line))
        return;
    memcpy(line + len, suffix, suffix_len + 1);

    uid_t uid = 0;
    CHECK(defused_test_mountinfo_owner(line, 49, &uid) == 0);
    CHECK(uid == 4242);
}

int main(void) {
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_getpid, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_getpid, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_read, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_close, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_read, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_close, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_fchdir, EBADF);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_umount2, EFAULT);
    test_mountinfo_parser();
    test_long_mountinfo_line();
    return failures ? 1 : 0;
}
