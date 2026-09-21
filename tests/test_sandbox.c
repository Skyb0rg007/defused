/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-sandbox.h"
#include "test_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

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

/* statmount() strips the leading comma; FUSE always emits user_id= and
 * group_id=. */
static void test_mount_opts_parser(void) {
    uid_t uid = 0;
    CHECK(defused_test_mount_opts_owner("user_id=1000,group_id=1000", &uid) ==
          0);
    CHECK(uid == 1000);

    uid = 0;
    CHECK(defused_test_mount_opts_owner("rw,nosuid,user_id=1001,group_id=2",
                                        &uid) == 0);
    CHECK(uid == 1001);

    /* Only the start of an option counts, so this is not a user_id=. */
    uid = 0;
    CHECK(defused_test_mount_opts_owner("xuser_id=1,user_id=1002", &uid) == 0);
    CHECK(uid == 1002);

    uid = 0;
    CHECK(defused_test_mount_opts_owner("allow_other,user_id=0", &uid) == 0);
    CHECK(uid == 0);

    CHECK(defused_test_mount_opts_owner("rw,group_id=5", &uid) == -EINVAL);
    CHECK(defused_test_mount_opts_owner("", &uid) == -EINVAL);
    CHECK(defused_test_mount_opts_owner("user_id=", &uid) == -EINVAL);
    CHECK(defused_test_mount_opts_owner("user_id=-1", &uid) == -EINVAL);
    CHECK(defused_test_mount_opts_owner("user_id=1x,group_id=1", &uid) ==
          -EINVAL);
    CHECK(defused_test_mount_opts_owner("user_id=99999999999999999999", &uid) ==
          -EINVAL);
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

int main(void) {
    test_set_timeout();

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
    test_filter_syscall(DEFUSED_OP_MOUNT, SYS_name_to_handle_at, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_move_mount, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_read, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_close, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_openat, EPERM);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_fchdir, EBADF);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_umount2, EFAULT);
    test_filter_syscall(DEFUSED_OP_UNMOUNT, SYS_name_to_handle_at, EFAULT);
    test_mount_opts_parser();
    test_fdinfo_pid();
    return failures ? 1 : 0;
}
