/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * defused handling a client in a different mount namespace, without host
 * root. Both cases send an unmount request for a non-FUSE bind mount, so
 * neither reaches a real FUSE unmount.
 *
 * test_can_join: defused runs in a mapped-root namespace A and the client
 * in a descendant B, so defused has CAP_SYS_ADMIN over B. The join is
 * proven by the answer being NotAFuseMount rather than UnmountFailed.
 *
 * test_cannot_join: defused runs unprivileged on the host and the client
 * in a user namespace of its own. defused cannot setns() there, and must
 * say so rather than fall back to its own namespace -- that would be a
 * namespace-confusion bug.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-proto.h"
#include "test_util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Maps the calling process to uid/gid 0 inside the user namespace it just
 * unshare(CLONE_NEWUSER)'d into -- the standard rootless-container dance.
 * @real_uid/@real_gid must be captured *before* unshare(), since getuid()
 * inside an unmapped new user namespace reads back as the overflow uid. */
static int write_file(const char *path, const char *buf, size_t len) {
    _cleanup_close_ int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    if (write(fd, buf, len) != (ssize_t)len)
        return -errno;
    return 0;
}

static int map_root(uid_t real_uid, gid_t real_gid) {
    /* best-effort on old kernels */
    (void)write_file("/proc/self/setgroups", "deny", 4);

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "0 %d 1\n", (int)real_uid);
    int ret = write_file("/proc/self/uid_map", buf, (size_t)len);
    if (ret < 0)
        return ret;

    len = snprintf(buf, sizeof(buf), "0 %d 1\n", (int)real_gid);
    return write_file("/proc/self/gid_map", buf, (size_t)len);
}

/* A temporary directory holding a private, intentionally non-FUSE bind
 * mount at <dir>/target, torn down when it goes out of scope. */
struct scratch_mount {
    char dir[sizeof("/tmp/defused-mountns-XXXXXX")];
    char target[sizeof("/tmp/defused-mountns-XXXXXX") + sizeof("/target")];
    bool have_dir;
    bool have_target;
    bool mounted;
};

static void scratch_mount_done(struct scratch_mount *m) {
    if (m->mounted)
        umount2(m->target, MNT_DETACH);
    if (m->have_target)
        rmdir(m->target);
    if (m->have_dir)
        rmdir(m->dir);
}

static int scratch_mount_create(struct scratch_mount *m) {
    strcpy(m->dir, "/tmp/defused-mountns-XXXXXX");
    if (mkdtemp(m->dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }
    m->have_dir = true;

    snprintf(m->target, sizeof(m->target), "%s/target", m->dir);
    if (mkdir(m->target, 0700) == -1) {
        perror("mkdir target");
        return -errno;
    }
    m->have_target = true;

    if (mount(m->target, m->target, NULL, MS_BIND, NULL) == -1) {
        perror("bind mount target");
        return -errno;
    }
    m->mounted = true;
    return 0;
}

/* Unmount of a non-FUSE bind mount. Takes ownership of sock_fd. */
static int send_non_fuse_umount_request(int sock_fd,
                                        struct defused_error *err) {
    _cleanup_close_ int sock = sock_fd;
    _cleanup_(scratch_mount_done) struct scratch_mount scratch = {};
    int ret = scratch_mount_create(&scratch);
    if (ret < 0)
        return ret;

    _cleanup_close_ int parent_fd =
        open(scratch.dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0) {
        ret = -errno;
        perror("open parent");
        return ret;
    }

    struct defused_request req = {
        .magic = DEFUSED_MAGIC, .op = DEFUSED_OP_UNMOUNT, .lazy = 1};
    strcpy(req.name, "target");
    return defused_call(sock, &req, (const int[]){parent_fd}, err);
}

static int abstract_addr(struct sockaddr_un *sa, socklen_t *len,
                         const char *tag) {
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    snprintf(sa->sun_path + 1, sizeof(sa->sun_path) - 1, "defused-test-%ld-%s",
             (long)getpid(), tag);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                       strlen(sa->sun_path + 1));
    return 0;
}

static int listen_addr(struct sockaddr_un *sa, socklen_t *len,
                       const char *tag) {
    int ret = abstract_addr(sa, len, tag);
    if (ret < 0)
        return ret;

    _cleanup_close_ int fd =
        socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
    if (fd == -1 || bind(fd, (struct sockaddr *)sa, *len) == -1 ||
        listen(fd, 1) == -1) {
        perror("listen");
        return -errno;
    }
    return TAKE_FD(fd);
}

static int connect_addr(const struct sockaddr_un *sa, socklen_t len) {
    _cleanup_close_ int fd =
        socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
    if (fd == -1 || connect(fd, (const struct sockaddr *)sa, len) == -1) {
        perror("connect");
        return -errno;
    }
    return TAKE_FD(fd);
}

/* The client side of both tests: connect, send the unmount request, and exit
 * 0 only if the service answered with one of the two errors that mean it
 * looked at the real mount in the client's namespace. Anything else -- a
 * success, or an error raised before the namespace was reached -- fails.
 * Never returns; it always runs in a forked client process. */
static void run_client_and_exit(const struct sockaddr_un *sa, socklen_t salen,
                                const char *who) {
    int client_sock = connect_addr(sa, salen);
    if (client_sock < 0)
        _exit(1);

    struct defused_error err;
    int ret = send_non_fuse_umount_request(client_sock, &err);
    bool ok = ret == 0 && (err.code == DEFUSED_ERR_NOT_A_FUSE_MOUNT ||
                           err.code == DEFUSED_ERR_UNMOUNT_FAILED);
    if (!ok)
        fprintf(stderr, "%s: got %s, expected %s or %s\n", who,
                defused_error_description(err.code),
                defused_error_description(DEFUSED_ERR_NOT_A_FUSE_MOUNT),
                defused_error_description(DEFUSED_ERR_UNMOUNT_FAILED));
    _exit(ok ? 0 : 1);
}

/* A client that dies before connecting would otherwise leave accept()
 * blocked for the rest of the test. */
static int accept_client(int listen_fd) {
    struct pollfd pfd = {.fd = listen_fd, .events = POLLIN};
    int n = poll(&pfd, 1, 30000);
    if (n < 0)
        return -errno;
    if (n == 0) {
        fprintf(stderr, "FAIL: client never connected\n");
        return -ETIMEDOUT;
    }
    int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    return conn == -1 ? -errno : conn;
}

/* Runs @defused_path against @conn_fd, handed over via the same
 * $LISTEN_PID/$LISTEN_FDS protocol systemd's Accept=yes uses. */
static int spawn_defused(const char *defused_path, int conn_fd,
                         pid_t *out_pid) {
    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid == 0) {
        /* conn_fd is duplicated to fd 3, matching SD_LISTEN_FDS_START. If it is
         * already fd 3, leave it there; otherwise close fd 3 first so the
         * dup2 below never clobbers it. */
        if (conn_fd != 3) {
            close(3);
            dup2(conn_fd, 3);
            close(conn_fd);
        }
        char pidbuf[16];
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int)getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "1", 1);
        execl(defused_path, "defused", NULL);
        perror("exec defused");
        _exit(127);
    }
    *out_pid = pid;
    return 0;
}

/*
 * defused is spawned inside namespace A (mapped root, via the calling
 * process's own unshare(CLONE_NEWUSER|CLONE_NEWNS)); the actual protocol
 * exchange happens in a grandchild that additionally unshare(CLONE_NEWNS)'d
 * into namespace B, a child of A. Everything runs in this one process tree
 * so CAP_SYS_ADMIN over A (and hence B) is available without host root.
 */
static int test_can_join(const char *defused_path) {
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    _cleanup_close_pair_ int result_pipe[2] = EBADF_PAIR;
    if (pipe(result_pipe) == -1) {
        perror("pipe");
        return -errno;
    }

    pid_t outer = fork();
    if (outer < 0)
        return -errno;
    if (outer == 0) {
        result_pipe[0] = safe_close(result_pipe[0]);

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == -1) {
            perror("unshare(NEWUSER|NEWNS)");
            _exit(1);
        }
        if (map_root(real_uid, real_gid) < 0) {
            perror("map root");
            _exit(1);
        }

        struct sockaddr_un sa;
        socklen_t salen;
        _cleanup_close_ int listen_fd = listen_addr(&sa, &salen, "can");
        if (listen_fd < 0)
            _exit(1);

        pid_t inner = fork();
        if (inner == 0) {
            result_pipe[1] = safe_close(result_pipe[1]);
            /* Namespace B: a plain CLONE_NEWNS, no new user namespace, so it
             * stays inside A and defused (also in A) has CAP_SYS_ADMIN over
             * it -- but it is still a genuinely distinct mount namespace. */
            if (unshare(CLONE_NEWNS) == -1) {
                perror("unshare(NEWNS)");
                _exit(1);
            }
            run_client_and_exit(&sa, salen, "test_can_join");
        }

        _cleanup_close_ int conn = accept_client(listen_fd);
        if (conn < 0)
            _exit(1);
        pid_t defused_pid;
        if (spawn_defused(defused_path, conn, &defused_pid) < 0)
            _exit(1);
        conn = safe_close(conn);
        listen_fd = safe_close(listen_fd);

        int inner_status;
        waitpid(inner, &inner_status, 0);
        int ok = WIFEXITED(inner_status) && WEXITSTATUS(inner_status) == 0;

        int defused_status;
        waitpid(defused_pid, &defused_status, 0);

        char byte = ok ? 1 : 0;
        (void)!write(result_pipe[1], &byte, 1);
        result_pipe[1] = safe_close(result_pipe[1]);
        _exit(0);
    }

    result_pipe[1] = safe_close(result_pipe[1]);
    char byte = 0;
    ssize_t n = read(result_pipe[0], &byte, 1);
    waitpid(outer, NULL, 0);

    CHECK(n == 1);
    CHECK(byte == 1);
    if (n != 1 || byte != 1)
        fprintf(stderr, "test_can_join: got an error other than "
                        "NotAFuseMount/UnmountFailed\n");
    return failures ? -EINVAL : 0;
}

/*
 * defused runs unprivileged in the plain host namespace (same as every
 * other test in this suite); the client unshare(CLONE_NEWUSER|
 * CLONE_NEWNS)'s into a namespace of its own. defused has no capability
 * over it and must reject the request rather than silently proceeding.
 */
static int test_cannot_join(const char *defused_path) {
    struct sockaddr_un sa;
    socklen_t salen;
    _cleanup_close_ int listen_fd = listen_addr(&sa, &salen, "cannot");
    if (listen_fd < 0)
        return listen_fd;

    pid_t client = fork();
    if (client < 0)
        return -errno;
    if (client == 0) {
        uid_t real_uid = getuid();
        gid_t real_gid = getgid();
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == -1) {
            perror("unshare(NEWUSER|NEWNS)");
            _exit(1);
        }
        if (map_root(real_uid, real_gid) < 0) {
            perror("map root");
            _exit(1);
        }
        run_client_and_exit(&sa, salen, "test_cannot_join");
    }

    _cleanup_close_ int conn = accept_client(listen_fd);
    if (conn < 0) {
        CHECK(conn >= 0);
        waitpid(client, NULL, 0);
        return conn;
    }
    pid_t defused_pid;
    if (spawn_defused(defused_path, conn, &defused_pid) < 0)
        return -errno;
    conn = safe_close(conn);
    listen_fd = safe_close(listen_fd);

    int client_status;
    waitpid(client, &client_status, 0);
    waitpid(defused_pid, NULL, 0);

    bool ok = WIFEXITED(client_status) && WEXITSTATUS(client_status) == 0;
    CHECK(ok);
    if (!ok)
        fprintf(stderr,
                "test_cannot_join: unprivileged defused did not cleanly reject "
                "a client from an unrelated mount namespace\n");
    return failures ? -EINVAL : 0;
}

/* Both tests below need a nested user namespace they can map themselves
 * root in; under AppArmor's unprivileged-userns restriction the unshare()
 * succeeds but the uid_map write does not. */
static int userns_available(void) {
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == -1)
            _exit(errno ? errno : EPERM);
        int ret = map_root(real_uid, real_gid);
        _exit(ret < 0 ? -ret : 0);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -ECHILD;
    return WEXITSTATUS(status) == 0 ? 0 : -WEXITSTATUS(status);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/defused\n", argv[0]);
        return 2;
    }
    test_set_timeout();

    int ret = userns_available();
    if (ret < 0) {
        fprintf(stderr,
                "SKIP: cannot create a mapped user namespace here (%s); "
                "this test needs one to place the client and the service in "
                "namespaces of its own\n",
                strerror(-ret));
        return MESON_EXIT_SKIP;
    }

    (void)test_can_join(argv[1]);
    (void)test_cannot_join(argv[1]);

    return failures ? 1 : 0;
}
