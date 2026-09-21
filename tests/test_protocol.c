/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Exercises the defused-proto.h wire protocol against a real `defused`
 * process without requiring root or CAP_SYS_ADMIN. The requests intentionally
 * stop before the real mount(2) call, since that's the one part of request
 * handling that needs privilege to succeed.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-proto.h"
#include "test_util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* No-ops while the resource is unset, so it can be declared early. */
static void rmdirp(const char **dir) {
    if (*dir)
        rmdir(*dir);
}

static void sigterm_waitp(pid_t *pid) {
    if (*pid > 0) {
        kill(*pid, SIGTERM);
        waitpid(*pid, NULL, 0);
    }
}

/* A scratch directory and the socket path inside it, both removed with
 * the scope. */
struct daemon_scratch {
    char dir[sizeof("/tmp/defused-daemon-XXXXXX")];
    char sock_path[sizeof("/tmp/defused-daemon-XXXXXX/defused.sock")];
};

static void daemon_scratch_done(struct daemon_scratch *s) {
    if (s->dir[0] != '\0') {
        unlink(s->sock_path);
        rmdir(s->dir);
    }
}

static int daemon_scratch_create(struct daemon_scratch *s) {
    strcpy(s->dir, "/tmp/defused-daemon-XXXXXX");
    if (mkdtemp(s->dir) == NULL) {
        perror("mkdtemp");
        s->dir[0] = '\0';
        return -errno;
    }
    snprintf(s->sock_path, sizeof(s->sock_path), "%s/defused.sock", s->dir);
    return 0;
}

/* why names the case in the failure message. */
static int check_err(const struct defused_error *err, uint32_t expect_code,
                     const char *why) {
    if (err->code == expect_code)
        return 0;
    fprintf(stderr, "FAIL: %s: expected %s, got %s\n", why,
            defused_error_description(expect_code),
            defused_error_description(err->code));
    return -EINVAL;
}

/* extra_args: NULL-terminated service arguments, or NULL. */
static int spawn_defused(const char *defused_path,
                         const char *const *extra_args, int *client_sock,
                         pid_t *out_pid) {
    _cleanup_close_pair_ int sv[2] = EBADF_PAIR;
    if (socketpair(AF_UNIX, DEFUSED_SOCKET_TYPE, 0, sv) == -1) {
        perror("socketpair");
        return -errno;
    }

    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid == 0) {
        /* Mimic systemd's Accept=yes handoff (sd_listen_fds(3)) rather than
         * the old inetd-style stdin convention. */
        close(sv[0]);
        if (sv[1] != 3) {
            dup2(sv[1], 3);
            close(sv[1]);
        }
        char pidbuf[16];
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int)getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "1", 1);
        const char *argv[8] = {"defused"};
        size_t argc = 1;
        for (size_t i = 0; extra_args != NULL && extra_args[i] != NULL &&
                           argc < ARRAY_SIZE(argv) - 1;
             i++)
            argv[argc++] = extra_args[i];
        argv[argc] = NULL;
        execv(defused_path, (char *const *)argv);
        perror("exec");
        _exit(127);
    }

    *client_sock = TAKE_FD(sv[0]);
    *out_pid = pid;
    return 0;
}

/* Takes ownership of sock_fd; the outcome lands in *err. */
static int send_mount_req(int sock_fd, const struct defused_request *req,
                          int dev_fd, int mnt_fd, struct defused_error *err) {
    _cleanup_close_ int sock = sock_fd;
    return defused_call(sock, req, (const int[]){dev_fd, mnt_fd}, err);
}

/* Just what a test varies; the rest is the same every time. */
static struct defused_request mount_req(uint32_t flags, const char *fsname) {
    struct defused_request req = {
        .magic = DEFUSED_MAGIC, .op = DEFUSED_OP_MOUNT, .mount_flags = flags};
    if (fsname != NULL)
        strcpy(req.fsname, fsname);
    return req;
}

/* Always refused for its shape, so it never reaches a mount(2) that
 * would need root. */
static struct defused_request bad_opt_req(void) {
    return mount_req(1u << 31, NULL);
}

/* Against a fresh defused instance; the caller decides what passes. */
static int run_mount_req(const char *defused_path,
                         const char *const *extra_args,
                         const struct defused_request *req, const char *path,
                         const char *dev_path, struct defused_error *err) {
    _cleanup_close_ int sock = -EBADF;
    pid_t pid;
    int ret = spawn_defused(defused_path, extra_args, &sock, &pid);
    if (ret < 0)
        return ret;

    _cleanup_close_ int mnt_fd =
        open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd < 0) {
        ret = -errno;
        perror(path);
        return ret;
    }
    _cleanup_close_ int dev_fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        ret = -errno;
        perror(dev_path);
        return ret;
    }

    ret = send_mount_req(TAKE_FD(sock), req, dev_fd, mnt_fd, err);

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (ret < 0) {
        if (WIFEXITED(wstatus))
            fprintf(stderr, "FAIL: service exited with status %d\n",
                    WEXITSTATUS(wstatus));
        else if (WIFSIGNALED(wstatus))
            fprintf(stderr, "FAIL: service killed by signal %d\n",
                    WTERMSIG(wstatus));
        return ret;
    }
    if (!WIFEXITED(wstatus)) {
        fprintf(stderr, "FAIL: service did not exit normally\n");
        return -ECHILD;
    }
    return 0;
}

/* dev_path is sent as the FUSE device: /dev/null reaches the option
 * checks, the policy gate needs a real /dev/fuse. */
static int expect_mount_reply(const char *defused_path,
                              const char *const *extra_args,
                              const struct defused_request *req,
                              const char *path, const char *dev_path,
                              uint32_t expect_code, const char *why) {
    struct defused_error err;
    int ret =
        run_mount_req(defused_path, extra_args, req, path, dev_path, &err);
    if (ret < 0)
        return ret;
    return check_err(&err, expect_code, why);
}

/* "/" is not foreign-owned everywhere: inside an unprivileged user
 * namespace it belongs to the caller. */
static const char *find_unowned_dir(void) {
    static const char *const candidates[] = {"/", "/proc", "/sys", "/usr",
                                             "/etc"};
    uid_t self = getuid();
    for (size_t i = 0; i < ARRAY_SIZE(candidates); i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && S_ISDIR(st.st_mode) &&
            st.st_uid != self)
            return candidates[i];
    }
    return NULL;
}

/* The policy tests need a real /dev/fuse fd and skip without one. */
static bool fuse_device_usable(void) {
    _cleanup_close_ int probe = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    return probe >= 0;
}

static gid_t foreign_gid(void) {
    gid_t groups[NGROUPS_MAX];
    int n = getgroups(NGROUPS_MAX, groups);
    if (n < 0)
        n = 0;
    for (gid_t gid = 60000;; gid++) {
        bool held = gid == getgid() || gid == getegid();
        for (int i = 0; i < n && !held; i++)
            held = groups[i] == gid;
        if (!held)
            return gid;
    }
}

/* MountFailed: past the gate, the unprivileged mount syscall failed. */
static int test_policy(const char *defused_path) {
    if (!fuse_device_usable()) {
        fprintf(stderr,
                "SKIP: /dev/fuse not usable here (%s), skipping the policy "
                "test\n",
                strerror(errno));
        return 0;
    }

    char dir_template[] = "/tmp/defused-policy-test-XXXXXX";
    _cleanup_(rmdirp) const char *dir = mkdtemp(dir_template);
    if (dir == NULL) {
        perror("mkdtemp");
        return -errno;
    }

    char groups_arg[64];
    snprintf(groups_arg, sizeof(groups_arg), "--allow-groups=%u",
             (unsigned)foreign_gid());
    const char *const wrong_group[] = {groups_arg, NULL};
    const struct defused_request plain = mount_req(0, NULL);
    int ret = expect_mount_reply(defused_path, wrong_group, &plain, dir,
                                 "/dev/fuse", DEFUSED_ERR_NOT_ALLOWED,
                                 "caller outside --allow-groups");
    if (ret < 0)
        return ret;

    const struct defused_request allow_other =
        mount_req(DEFUSED_FUSE_ALLOW_OTHER, NULL);
    ret = expect_mount_reply(defused_path, NULL, &allow_other, dir, "/dev/fuse",
                             DEFUSED_ERR_NOT_ALLOWED,
                             "allow_other without --allow-other");
    if (ret < 0)
        return ret;

    const char *const with_allow_other[] = {"--allow-other", NULL};
    return expect_mount_reply(defused_path, with_allow_other, &allow_other, dir,
                              "/dev/fuse", DEFUSED_ERR_MOUNT_FAILED,
                              "allow_other with --allow-other");
}

/* Rejected args: EXIT_FAILURE before touching the connection, so EOF. */
static int expect_rejected_args(const char *defused_path,
                                const char *const *args) {
    _cleanup_close_ int sock = -EBADF;
    pid_t pid;
    int ret = spawn_defused(defused_path, args, &sock, &pid);
    if (ret < 0)
        return ret;

    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    char byte;
    ssize_t n = -1;
    if (poll(&pfd, 1, 10000) > 0)
        n = read(sock, &byte, 1);
    if (n != 0) {
        fprintf(stderr, "FAIL: defused accepted \"%s\" (%s)\n", args[0],
                n < 0 ? "no EOF within 10s" : "it replied");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -EINVAL;
    }

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != EXIT_FAILURE) {
        fprintf(stderr, "FAIL: defused with \"%s\" did not exit with %d\n",
                args[0], EXIT_FAILURE);
        return -EINVAL;
    }
    return 0;
}

static int test_bad_args(const char *defused_path) {
    static const char *const cases[][3] = {
        {"--policy=builtin", NULL},
        {"--max-mounts=0", NULL},
        {"--max-mounts=ten", NULL},
        {"--allow-groups=defused-no-such-group", NULL},
        {"--allow-other=yes", NULL},
        {"--child", NULL}, /* removed: privileged callers mount in-process */
        {"stray-argument", NULL},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        int ret = expect_rejected_args(defused_path, cases[i]);
        if (ret < 0)
            return ret;
    }
    return 0;
}

/* Pointed at sock_path via $DEFUSED_SOCKET, as daemon.nix does. */
static int spawn_defused_daemon(const char *defused_path, const char *sock_path,
                                pid_t *out_pid) {
    pid_t pid = fork();
    if (pid == 0) {
        setenv("DEFUSED_SOCKET", sock_path, 1);
        execl(defused_path, "defused", "--daemon", NULL);
        perror("exec");
        _exit(127);
    }
    if (pid < 0)
        return -errno;

    *out_pid = pid;
    return 0;
}

/* Retries while the daemon has not bound (ENOENT) or listened yet
 * (ECONNREFUSED). */
static int connect_daemon_socket(const char *sock_path) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(sock_path) >= sizeof(sa.sun_path))
        return -ENAMETOOLONG;
    (void)strlcpy(sa.sun_path, sock_path, sizeof(sa.sun_path));

    for (int i = 0; i < 100; i++) {
        _cleanup_close_ int sock =
            socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
        if (sock == -1)
            return -errno;
        if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == 0)
            return TAKE_FD(sock);
        if (errno != ENOENT && errno != ECONNREFUSED)
            return -errno;
        usleep(10000);
    }
    return -ETIMEDOUT;
}

/* Runs one mount request through an already-running --daemon instance,
 * failing unless the reply is exactly expect_code. */
static int run_daemon_mount_req(const char *sock_path,
                                const struct defused_request *req,
                                const char *path, uint32_t expect_code) {
    _cleanup_close_ int sock = connect_daemon_socket(sock_path);
    if (sock < 0) {
        fprintf(stderr, "FAIL: could not connect to daemon socket: %s\n",
                strerror(-sock));
        return sock;
    }

    _cleanup_close_ int mnt_fd =
        open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    _cleanup_close_ int dev_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (mnt_fd < 0 || dev_fd < 0) {
        int ret = -errno;
        perror("open");
        return ret;
    }

    struct defused_error err;
    int ret = send_mount_req(TAKE_FD(sock), req, dev_fd, mnt_fd, &err);
    if (ret < 0)
        return ret;
    return check_err(&err, expect_code, "daemon mount request");
}

/* Two requests back-to-back against a --daemon instance: one alone would
 * not show that it keeps accepting after handling a connection, and not
 * pausing between them exercises the live_children cap without
 * tripping it. */
static int test_daemon_mode(const char *defused_path) {
    _cleanup_(daemon_scratch_done) struct daemon_scratch scratch = {};
    int ret = daemon_scratch_create(&scratch);
    if (ret < 0)
        return ret;

    _cleanup_(sigterm_waitp) pid_t pid = 0;
    ret = spawn_defused_daemon(defused_path, scratch.sock_path, &pid);
    if (ret < 0)
        return ret;

    const struct defused_request bad_opt = bad_opt_req();
    ret = run_daemon_mount_req(scratch.sock_path, &bad_opt, ".",
                               DEFUSED_ERR_BAD_OPTION);
    if (ret < 0)
        return ret;
    return run_daemon_mount_req(scratch.sock_path, &bad_opt, ".",
                                DEFUSED_ERR_BAD_OPTION);
}

/* --daemon binds inside a directory that must already exist (systemd's
 * RuntimeDirectory=); it must fail fast rather than create it or hang. */
static int test_daemon_missing_socket_dir(const char *defused_path) {
    _cleanup_(daemon_scratch_done) struct daemon_scratch scratch = {};
    int ret = daemon_scratch_create(&scratch);
    if (ret < 0)
        return ret;

    char missing_dir[sizeof(scratch.dir) + sizeof("/does-not-exist")];
    snprintf(missing_dir, sizeof(missing_dir), "%s/does-not-exist",
             scratch.dir);
    char sock_path[sizeof(missing_dir) + sizeof("/defused.sock")];
    snprintf(sock_path, sizeof(sock_path), "%s/defused.sock", missing_dir);

    pid_t pid;
    ret = spawn_defused_daemon(defused_path, sock_path, &pid);
    if (ret < 0)
        return ret;

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ret = -errno;
        perror("waitpid");
        return ret;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) == 0) {
        fprintf(stderr,
                "FAIL: expected --daemon to exit nonzero with a missing "
                "socket directory (status 0x%x)\n",
                status);
        return -EINVAL;
    }
    if (access(missing_dir, F_OK) == 0 || errno != ENOENT) {
        fprintf(stderr, "FAIL: --daemon should not have created the socket "
                        "directory\n");
        return -EINVAL;
    }
    return 0;
}

/* Must match DAEMON_MAX_CONNECTIONS in src/defused.c: the number of
 * concurrent connections test_daemon_connection_cap() needs to open to pin
 * run_daemon()'s live_children count at the cap. */
#define TEST_DAEMON_MAX_CONNECTIONS 64

/* The connections test_daemon_connection_cap() holds open, closed together
 * when the batch goes out of scope. */
struct connection_slots {
    int fds[TEST_DAEMON_MAX_CONNECTIONS];
};

static void connection_slots_init(struct connection_slots *slots) {
    for (int i = 0; i < TEST_DAEMON_MAX_CONNECTIONS; i++)
        slots->fds[i] = -EBADF;
}

static void connection_slots_done(struct connection_slots *slots) {
    for (int i = 0; i < TEST_DAEMON_MAX_CONNECTIONS; i++)
        safe_close(slots->fds[i]);
}

static void unix_addr(struct sockaddr_un *sa, const char *sock_path) {
    *sa = (struct sockaddr_un){.sun_family = AF_UNIX};
    (void)strlcpy(sa->sun_path, sock_path, sizeof(sa->sun_path));
}

/* The first connection rides out the daemon's startup race; by then it
 * is known to be up. On failure the caller cleans up what was opened. */
static int open_daemon_connections(const char *sock_path,
                                   struct connection_slots *slots) {
    slots->fds[0] = connect_daemon_socket(sock_path);
    if (slots->fds[0] < 0)
        return slots->fds[0];

    struct sockaddr_un sa;
    unix_addr(&sa, sock_path);
    for (int i = 1; i < TEST_DAEMON_MAX_CONNECTIONS; i++) {
        _cleanup_close_ int sock =
            socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
        if (sock == -1 ||
            connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
            int ret = -errno;
            perror("connect");
            return ret;
        }
        slots->fds[i] = TAKE_FD(sock);
    }
    return 0;
}

/* Holds the cap's worth of connections open without sending a request,
 * then adds one more. connect() still succeeds (that only needs listen
 * backlog room), but the daemon should close it rather than fork for it,
 * and the connections under the cap should be untouched. */
static int test_daemon_connection_cap(const char *defused_path) {
    _cleanup_(daemon_scratch_done) struct daemon_scratch scratch = {};
    int ret = daemon_scratch_create(&scratch);
    if (ret < 0)
        return ret;

    _cleanup_(sigterm_waitp) pid_t pid = 0;
    ret = spawn_defused_daemon(defused_path, scratch.sock_path, &pid);
    if (ret < 0)
        return ret;

    _cleanup_(connection_slots_done) struct connection_slots slots;
    connection_slots_init(&slots);
    ret = open_daemon_connections(scratch.sock_path, &slots);
    if (ret < 0)
        return ret;

    /* Give the single-threaded accept loop a moment to accept()/fork() all
     * of the above before adding the connection meant to overflow the cap
     * -- otherwise a slow accept loop could still have room left and
     * legitimately accept it. */
    usleep(200000);

    struct sockaddr_un sa;
    unix_addr(&sa, scratch.sock_path);
    _cleanup_close_ int overflow =
        socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
    if (overflow == -1 ||
        connect(overflow, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        ret = -errno;
        perror("overflow connection");
        return ret;
    }

    struct pollfd pfd = {.fd = overflow, .events = POLLIN};
    ret = poll(&pfd, 1, 2000);
    if (ret <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) {
        fprintf(stderr, "FAIL: overflow connection was not dropped\n");
        return -EINVAL;
    }
    char buf[1];
    ssize_t n = recv(overflow, buf, sizeof(buf), 0);
    if (n != 0) {
        fprintf(stderr, "FAIL: expected EOF on overflow connection, got %zd\n",
                n);
        return -EINVAL;
    }

    for (int i = 0; i < TEST_DAEMON_MAX_CONNECTIONS; i++) {
        struct pollfd p = {.fd = slots.fds[i], .events = POLLIN};
        if (poll(&p, 1, 0) > 0) {
            fprintf(stderr, "FAIL: connection %d under the cap was dropped\n",
                    i);
            return -EINVAL;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/defused\n", argv[0]);
        return 2;
    }
    const char *defused = argv[1];
    test_set_timeout();

    /* Refused for its shape; this only checks the options parse. */
    static const char *const all_policy_args[] = {
        "--max-mounts=5", "--allow-groups=", "--allow-other", NULL};
    const struct defused_request bad_opt = bad_opt_req();
    if (expect_mount_reply(defused, all_policy_args, &bad_opt, ".", "/dev/null",
                           DEFUSED_ERR_BAD_OPTION, "all policy options") != 0)
        return 1;

    /* Only a privileged fusermount3 honors these; the service never does. */
    const struct defused_request privileged_opts[] = {
        mount_req(DEFUSED_MOUNT_ALLOW_SUID, NULL),
        mount_req(DEFUSED_MOUNT_ALLOW_DEV, NULL),
        mount_req(DEFUSED_MOUNT_BLKDEV, "dev"),
    };
    for (size_t i = 0; i < ARRAY_SIZE(privileged_opts); i++)
        if (expect_mount_reply(defused, NULL, &privileged_opts[i], ".",
                               "/dev/null", DEFUSED_ERR_BAD_OPTION,
                               "privileged mount option") != 0)
            return 1;

    if (test_bad_args(defused) != 0)
        return 1;

    if (getuid() != 0) {
        const char *unowned = find_unowned_dir();
        if (unowned == NULL) {
            fprintf(stderr,
                    "SKIP: no directory owned by another user is visible "
                    "here, skipping the mountpoint ownership test\n");
        } else {
            const struct defused_request not_owned = mount_req(0, NULL);
            if (expect_mount_reply(defused, NULL, &not_owned, unowned,
                                   "/dev/null", DEFUSED_ERR_NOT_ALLOWED,
                                   "mountpoint owned by another user") != 0)
                return 1;
        }

        if (test_policy(defused) != 0)
            return 1;
    }

    if (test_daemon_mode(defused) != 0)
        return 1;

    if (test_daemon_missing_socket_dir(defused) != 0)
        return 1;

    if (test_daemon_connection_cap(defused) != 0)
        return 1;

    return 0;
}
