/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include "common.h"
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

/* Meson reads 77 as a skip. */
#define MESON_EXIT_SKIP 77

/* Probes in a child so the filter never lands on the test process. */
static int seccomp_available(void) {
    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;

    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid == 0) {
        pipefd[0] = safe_close(pipefd[0]);
        int install_ret = defused_test_install_seccomp(DEFUSED_OP_MOUNT);
        (void)syscall(SYS_write, pipefd[1], &install_ret, sizeof(install_ret));
        (void)syscall(SYS_exit_group, 0);
        for (;;)
            (void)syscall(SYS_exit, 1);
    }

    pipefd[1] = safe_close(pipefd[1]);
    int install_ret = 0;
    int ret = read_full(pipefd[0], &install_ret, sizeof(install_ret));
    if (waitpid(pid, NULL, 0) != pid)
        return -ECHILD;
    return ret < 0 ? ret : install_ret;
}

static void test_filter_syscall(enum defused_op op, long syscall_number,
                                int expected_errno) {
    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    int ret = pipe2(pipefd, O_CLOEXEC);
    CHECK(ret == 0);
    if (ret < 0)
        return;

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0)
        return;

    if (pid == 0) {
        pipefd[0] = safe_close(pipefd[0]);
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

    pipefd[1] = safe_close(pipefd[1]);
    struct filter_result result = {};
    CHECK(read_full(pipefd[0], &result, sizeof(result)) == 0);

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

static void test_fdinfo_pid(void) {
    CHECK(
        defused_test_fdinfo_pid("pos:\t0\nflags:\t02\nmnt_id:\t14\nino:\t1234\n"
                                "Pid:\t4242\nNSpid:\t4242\t1\n") == 4242);
    CHECK(defused_test_fdinfo_pid("Pid:\t7") == 7);
    CHECK(defused_test_fdinfo_pid("pos:\t0\nNSpid:\t1\nPPid:\t1\n") ==
          -ENODATA);
    CHECK(defused_test_fdinfo_pid("Pid:\t-1\nNSpid:\t-1\n") == -ESRCH);
    CHECK(defused_test_fdinfo_pid("Pid:\t0\n") == -ESRCH);
    CHECK(defused_test_fdinfo_pid("Pid:\t\n") == -EINVAL);
    CHECK(defused_test_fdinfo_pid("Pid:\t2147483648\n") == -EINVAL);
    CHECK(defused_test_fdinfo_pid("Pid:\t4242 junk\n") == -EINVAL);
}

static void test_fdinfo_parser(void) {
    long id = -1;
    const char *info = "pos:\t0\nflags:\t012100000\nmnt_id:\t31\nino:\t4242\n";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == 0);
    CHECK(id == 31);

    id = -1;
    info = "pos:\t0\nflags:\t0\nmnt_id:\t7";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == 0);
    CHECK(id == 7);

    info = "pos:\t0\nflags:\t0\nino:\t31\n";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == -ENODATA);

    info = "pos:\t0\nxmnt_id:\t31\n";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == -ENODATA);

    info = "mnt_id:\t\n";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == -EINVAL);

    info = "mnt_id:\t3x\n";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == -EINVAL);

    info = "mnt_id:\t99999999999999999999999\n";
    CHECK(defused_test_fdinfo_mnt_id(info, strlen(info), &id) == -EOVERFLOW);
}

int main(void) {
    int ret = seccomp_available();
    if (ret < 0) {
        fprintf(stderr,
                "SKIP: seccomp filters cannot be installed here (%s); this "
                "test needs to load the real filters\n",
                strerror(-ret));
        return MESON_EXIT_SKIP;
    }

    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_getpid, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_getpid, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_read, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_close, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_openat, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_fchdir, EPERM);
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_umount2, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_move_mount, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_read, EBADF);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_close, EBADF);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_openat, EFAULT);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_fchdir, EBADF);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_umount2, EFAULT);
    test_mountinfo_parser();
    test_long_mountinfo_line();
    test_fdinfo_pid();
    test_fdinfo_parser();
    return failures ? 1 : 0;
}
