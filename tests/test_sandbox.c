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
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/mount.h>

/* AT_HANDLE_FID and AT_HANDLE_MNT_ID_UNIQUE. The define skips
 * <asm-generic/fcntl.h>, which would clash with <fcntl.h> above. */
#define _ASM_GENERIC_FCNTL_H
#include <linux/fcntl.h>

/* Closed, so a call the filter lets through fails with EBADF instead of
 * acting, and distinct, so swapping two in a rule shows up. */
#define FD_PIDFD 900
#define FD_PIPE 901
#define FD_MOUNTFD 902
#define FD_MNTFD 903
#define FD_PARENT 904

/* No such name here, so a umount2() the filter lets through hits ENOENT. */
#define PROBE_NAME "defused-seccomp-probe-no-such-mountpoint"

/* Spelled out, not shared with defused-sandbox.c, so changing one side
 * without the other fails. */
#define PROBE_HANDLE_FLAGS                                                     \
    (AT_EMPTY_PATH | AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE)
#define PROBE_MOVE_FLAGS (MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)

/* Pointer arguments exist only once the child has pinned them, so a probe
 * names one. The values sit far above any literal a probe passes. */
enum {
    ARG_PATH = 0x10000, /* the pinned path, and an unpinned copy of it */
    ARG_PATH_COPY,
    ARG_HANDLE, /* the pinned file handle, and an unpinned buffer */
    ARG_HANDLE_COPY,
    ARG_HANDLE_ID, /* the pinned mount-id out-parameter */
    ARG_RESULT,    /* the pinned result buffer, and its pinned length */
    ARG_RESULT_LEN,
};

static long probe_arg(long v, const struct sandbox_job *job) {
    /* Filled at run time, so it is a distinct object whatever the compiler
     * does with identical literals. */
    static char path_copy[DEFUSED_MAX_FILENAME];
    static char handle_copy[512];
    switch (v) {
    case ARG_PATH:
        return (long)job->path;
    case ARG_PATH_COPY:
        /* The same text as the pinned path, at a different address. */
        strcpy(path_copy, job->path);
        return (long)path_copy;
    case ARG_HANDLE:
        return (long)defused_test_handle_buf(job);
    case ARG_HANDLE_ID:
        return (long)defused_test_handle_id(job);
    case ARG_HANDLE_COPY:
        return (long)handle_copy;
    case ARG_RESULT:
    case ARG_RESULT_LEN: {
        size_t len;
        const void *buf = defused_test_result_buf(job, &len);
        return v == ARG_RESULT ? (long)buf : (long)len;
    }
    default:
        return v;
    }
}

/* ALLOW: the filter must answer as the kernel alone would. DENY: it must
 * turn the call into EPERM. */
enum probe_verdict { DENY, ALLOW };

/* A compound literal: a short initializer for a struct field draws
 * -Wmissing-field-initializers on newer compilers. */
#define ARGS(...) ((const long[5]){__VA_ARGS__})

struct probe {
    const char *what;
    enum probe_verdict verdict;
    long nr;
    const long *args;
};

static const struct probe mount_probes[] = {
    {"move_mount as the child makes it", ALLOW, SYS_move_mount,
     ARGS(FD_MOUNTFD, ARG_PATH, FD_MNTFD, ARG_PATH, PROBE_MOVE_FLAGS)},
    {"move_mount with the two mount fds swapped", DENY, SYS_move_mount,
     ARGS(FD_MNTFD, ARG_PATH, FD_MOUNTFD, ARG_PATH, PROBE_MOVE_FLAGS)},
    {"move_mount off an unpinned empty path", DENY, SYS_move_mount,
     ARGS(FD_MOUNTFD, ARG_PATH_COPY, FD_MNTFD, ARG_PATH, PROBE_MOVE_FLAGS)},
    {"move_mount onto an unpinned empty path", DENY, SYS_move_mount,
     ARGS(FD_MOUNTFD, ARG_PATH, FD_MNTFD, ARG_PATH_COPY, PROBE_MOVE_FLAGS)},
    {"move_mount without the empty-path flags", DENY, SYS_move_mount,
     ARGS(FD_MOUNTFD, ARG_PATH, FD_MNTFD, ARG_PATH, 0)},
    {"write as the child reports with", ALLOW, SYS_write,
     ARGS(FD_PIPE, ARG_RESULT, ARG_RESULT_LEN)},
    {"write to another descriptor", DENY, SYS_write,
     ARGS(FD_PARENT, ARG_RESULT, ARG_RESULT_LEN)},
    {"write from an unpinned buffer", DENY, SYS_write,
     ARGS(FD_PIPE, ARG_HANDLE_COPY, ARG_RESULT_LEN)},
    {"write of a different length", DENY, SYS_write,
     ARGS(FD_PIPE, ARG_RESULT, 1)},
    {"setns as the child makes it", ALLOW, SYS_setns,
     ARGS(FD_PIDFD, CLONE_NEWNS)},
    {"setns into another namespace type", DENY, SYS_setns,
     ARGS(FD_PIDFD, CLONE_NEWUSER)},
    {"setns on another descriptor", DENY, SYS_setns,
     ARGS(FD_MOUNTFD, CLONE_NEWNS)},
    {"getpid, which the child never makes", DENY, SYS_getpid, ARGS(0)},
    {"fchdir, which only unmount makes", DENY, SYS_fchdir, ARGS(FD_PARENT)},
    {"umount2, which only unmount makes", DENY, SYS_umount2,
     ARGS(ARG_PATH, UMOUNT_NOFOLLOW)},
    {"openat, which the child never makes", DENY, SYS_openat,
     ARGS(FD_PARENT, ARG_PATH, O_RDONLY)},
};

static const struct probe unmount_probes[] = {
    {"fchdir as the child makes it", ALLOW, SYS_fchdir, ARGS(FD_PARENT)},
    {"fchdir on another descriptor", DENY, SYS_fchdir, ARGS(FD_PIDFD)},
    {"name_to_handle_at as the child makes it", ALLOW, SYS_name_to_handle_at,
     ARGS(FD_PARENT, ARG_PATH, ARG_HANDLE, ARG_HANDLE_ID, PROBE_HANDLE_FLAGS)},
    {"name_to_handle_at on another descriptor", DENY, SYS_name_to_handle_at,
     ARGS(FD_PIDFD, ARG_PATH, ARG_HANDLE, ARG_HANDLE_ID, PROBE_HANDLE_FLAGS)},
    {"name_to_handle_at on an unpinned copy of the same name", DENY,
     SYS_name_to_handle_at,
     ARGS(FD_PARENT, ARG_PATH_COPY, ARG_HANDLE, ARG_HANDLE_ID,
          PROBE_HANDLE_FLAGS)},
    {"name_to_handle_at into an unpinned handle", DENY, SYS_name_to_handle_at,
     ARGS(FD_PARENT, ARG_PATH, ARG_HANDLE_COPY, ARG_HANDLE_ID,
          PROBE_HANDLE_FLAGS)},
    {"name_to_handle_at into an unpinned mount id", DENY, SYS_name_to_handle_at,
     ARGS(FD_PARENT, ARG_PATH, ARG_HANDLE, ARG_HANDLE_COPY,
          PROBE_HANDLE_FLAGS)},
    {"name_to_handle_at settling for the reusable mount id", DENY,
     SYS_name_to_handle_at,
     ARGS(FD_PARENT, ARG_PATH, ARG_HANDLE, ARG_HANDLE_ID,
          AT_EMPTY_PATH | AT_HANDLE_FID)},
    {"name_to_handle_at following symlinks", DENY, SYS_name_to_handle_at,
     ARGS(FD_PARENT, ARG_PATH, ARG_HANDLE, ARG_HANDLE_ID,
          PROBE_HANDLE_FLAGS | AT_SYMLINK_FOLLOW)},
    {"umount2 as the child makes it", ALLOW, SYS_umount2,
     ARGS(ARG_PATH, UMOUNT_NOFOLLOW)},
    {"umount2 on an unpinned copy of the same name", DENY, SYS_umount2,
     ARGS(ARG_PATH_COPY, UMOUNT_NOFOLLOW)},
    {"umount2 with flags the job did not ask for", DENY, SYS_umount2,
     ARGS(ARG_PATH, UMOUNT_NOFOLLOW | MNT_DETACH)},
    {"write as the child reports with", ALLOW, SYS_write,
     ARGS(FD_PIPE, ARG_RESULT, ARG_RESULT_LEN)},
    {"setns as the child makes it", ALLOW, SYS_setns,
     ARGS(FD_PIDFD, CLONE_NEWNS)},
    {"getpid, which the child never makes", DENY, SYS_getpid, ARGS(0)},
    {"move_mount, which only mount makes", DENY, SYS_move_mount,
     ARGS(FD_MOUNTFD, ARG_PATH, FD_MNTFD, ARG_PATH, PROBE_MOVE_FLAGS)},
    {"openat, which the child never makes", DENY, SYS_openat,
     ARGS(FD_PARENT, ARG_PATH, O_RDONLY)},
    {"read, which the child never makes", DENY, SYS_read,
     ARGS(FD_PARENT, ARG_HANDLE_COPY, 1)},
    {"close, which the child never makes", DENY, SYS_close, ARGS(FD_PARENT)},
};

static struct sandbox_job probe_job(enum defused_op op) {
    struct sandbox_job job = {
        .op = op,
        .pidfd = FD_PIDFD,
        .pipe_fd = FD_PIPE,
        .mountfd = FD_MOUNTFD,
        .mnt_fd = FD_MNTFD,
        .parent_fd = FD_PARENT,
        .umount_flags = UMOUNT_NOFOLLOW,
        .mnt_id = 1,
    };
    job.path = op == DEFUSED_OP_UNMOUNT ? PROBE_NAME : "";
    return job;
}

/* The filter leaves only the real child's write(), so a probe reports
 * through its exit status: 0 for success, otherwise its errno. */
#define PROBE_SETUP_FAILED 255

/* Makes the call in a forked child, with or without the filter. The
 * unfiltered run is the expectation for a call the filter must leave
 * alone. */
static int run_probe(const struct probe *p, enum defused_op op, bool filtered) {
    struct sandbox_job job = probe_job(op);
    fflush(NULL);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* move_mount() and umount2() want CAP_SYS_ADMIN before they look at
         * their arguments. Both runs try for it alike; where it is refused
         * both see EPERM and the probe is inconclusive. */
        (void)unshare(CLONE_NEWUSER | CLONE_NEWNS);
        if (defused_test_pin_job(&job) != 0 ||
            (filtered && defused_test_install_seccomp(&job) != 0))
            _exit(PROBE_SETUP_FAILED);
        long a[5];
        for (size_t i = 0; i < ARRAY_SIZE(a); i++)
            a[i] = probe_arg(p->args[i], &job);
        errno = 0;
        long ret = syscall(p->nr, a[0], a[1], a[2], a[3], a[4]);
        _exit(ret == -1 ? errno & 0xff : 0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status));
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_probes(const struct probe *probes, size_t n,
                      enum defused_op op) {
    int skipped = 0;
    for (size_t i = 0; i < n; i++) {
        int bare = run_probe(&probes[i], op, false);
        int got = run_probe(&probes[i], op, true);
        if (bare < 0 || got < 0)
            continue; /* fork or wait failed; already counted */
        if (bare == PROBE_SETUP_FAILED || got == PROBE_SETUP_FAILED) {
            fprintf(stderr, "FAIL %s: the filter would not load\n",
                    probes[i].what);
            failures++;
            continue;
        }
        /* The kernel refuses this anyway; the filter's EPERM would look
         * the same. */
        if (bare == EPERM) {
            skipped++;
            continue;
        }
        int want = probes[i].verdict == ALLOW ? bare : EPERM;
        if (got == want)
            continue;
        fprintf(stderr, "FAIL %s: expected %s, got %s\n", probes[i].what,
                strerror(want), strerror(got));
        failures++;
    }
    return skipped;
}

static void test_filter(void) {
    int skipped =
        run_probes(mount_probes, ARRAY_SIZE(mount_probes), DEFUSED_OP_MOUNT) +
        run_probes(unmount_probes, ARRAY_SIZE(unmount_probes),
                   DEFUSED_OP_UNMOUNT);
    if (skipped)
        fprintf(stderr,
                "note: %d probe(s) inconclusive, because this system already "
                "refuses the call they make with EPERM\n",
                skipped);
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

/* Probes in a child, so the filter never lands on the test process. One
 * that fails to build is never loaded, so the child can report why. */
static int seccomp_available(void) {
    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;

    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid == 0) {
        struct sandbox_job job = probe_job(DEFUSED_OP_MOUNT);
        int ret = defused_test_pin_job(&job);
        if (ret == 0)
            ret = defused_test_install_seccomp(&job);
        if (ret != 0)
            (void)!write(pipefd[1], &ret, sizeof(ret));
        _exit(0);
    }

    pipefd[1] = safe_close(pipefd[1]);
    int install_ret = 0;
    ssize_t n = read(pipefd[0], &install_ret, sizeof(install_ret));
    if (waitpid(pid, NULL, 0) != pid)
        return -ECHILD;
    return n == (ssize_t)sizeof(install_ret) ? install_ret : n < 0 ? -errno : 0;
}

int main(void) {
    test_set_timeout();

    /* The probes rely on these being closed. */
    for (int fd = FD_PIDFD; fd <= FD_PARENT; fd++)
        (void)close(fd);

    int ret = seccomp_available();
    if (ret < 0) {
        fprintf(stderr,
                "SKIP: seccomp filters cannot be installed here (%s); this "
                "test needs to load the real filters\n",
                strerror(-ret));
        return MESON_EXIT_SKIP;
    }

    test_filter();
    test_mount_opts_parser();
    test_fdinfo_pid();
    return failures ? 1 : 0;
}
