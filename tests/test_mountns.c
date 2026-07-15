/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Exercises defused's handling of a client in a different mount namespace
 * from the service, without requiring host root:
 *
 *  - test_can_join: defused runs inside a freshly unshare(CLONE_NEWUSER|
 *    CLONE_NEWNS)'d namespace A (mapped so the test is "root" and holds
 *    CAP_SYS_ADMIN over A and everything descended from it -- the same
 *    unprivileged-rootless-container trick real sandboxes use). The client
 *    is a *grandchild* that additionally unshare(CLONE_NEWNS)'d into its
 *    own namespace B, a descendant of A. defused should be able to setns()
 *    into B (it has CAP_SYS_ADMIN there) and proceed with the request; we
 *    prove the join happened by sending a request with a deliberately bad
 *    mount flag and checking the response is DEFUSED_ERR_BAD_OPTION (from
 *    the policy check *after* the namespace join in main()) rather than
 *    DEFUSED_ERR_SETNS_FAILED (which is what a failed or skipped join
 *    would produce instead).
 *
 *  - test_cannot_join: defused runs unprivileged in the plain host
 *    namespace, like every other test in this suite. The client
 *    unshare(CLONE_NEWUSER|CLONE_NEWNS)'s into a namespace of its own that
 *    defused has no ancestry over. defused cannot legitimately setns()
 *    into it (no CAP_SYS_ADMIN there), and the test checks that this
 *    surfaces cleanly as DEFUSED_ERR_SETNS_FAILED/EPERM -- never as a
 *    silent fallback to operating on defused's own namespace instead,
 *    which would be a namespace-confusion bug (e.g. counting mount_max or
 *    mounting against the wrong mount table while believing it's the
 *    client's).
 *
 * Neither test reaches the real mount(2) call, for the same reason as
 * test_protocol.c: that's the one part of request handling that needs
 * privilege to succeed, orthogonal to what's being tested here.
 */
#define _GNU_SOURCE
#include "defused.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Maps the calling process to uid/gid 0 inside the user namespace it just
 * unshare(CLONE_NEWUSER)'d into -- the standard rootless-container dance.
 * @real_uid/@real_gid must be captured *before* unshare(), since getuid()
 * inside an unmapped new user namespace reads back as the overflow uid. */
static int map_root(uid_t real_uid, gid_t real_gid) {
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "deny", 4) < 0) { /* best-effort on old kernels */
        }
        close(fd);
    }

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "0 %d 1\n", (int)real_uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0 || write(fd, buf, len) != len) {
        perror("write uid_map");
        _exit(1);
    }
    close(fd);

    len = snprintf(buf, sizeof(buf), "0 %d 1\n", (int)real_gid);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0 || write(fd, buf, len) != len) {
        perror("write gid_map");
        _exit(1);
    }
    close(fd);
    return 0;
}

/* Sends a mount request (deliberately bad mount_flags, matching
 * test_protocol.c's technique) carrying the required mount fds, and returns
 * the service's response status, or -1 on a transport-level failure. */
static int send_bad_mount_request(int sock) {
    struct defused_mount_req req = {
        .hdr = {DEFUSED_PROTO_MAGIC, DEFUSED_PROTO_VERSION, DEFUSED_OP_MOUNT},
        .mount_flags = 1u << 31, /* never in DEFUSED_MOUNT_FLAGS_MASK */
    };
    int mnt_fd = open(".", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd < 0) {
        perror("open");
        return -errno;
    }
    int dev_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        int ret = -errno;
        perror("open /dev/null");
        close(mnt_fd);
        return ret;
    }

    struct iovec iov = {.iov_base = &req, .iov_len = sizeof(req)};
    union {
        struct cmsghdr h;
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } cbuf;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf.buf,
        .msg_controllen = sizeof(cbuf.buf),
    };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int fds[] = {dev_fd, mnt_fd};
    memcpy(CMSG_DATA(c), fds, sizeof(fds));

    if (sendmsg(sock, &msg, 0) < 0) {
        int ret = -errno;
        perror("sendmsg");
        close(dev_fd);
        close(mnt_fd);
        return ret;
    }
    close(dev_fd);
    close(mnt_fd);

    struct defused_resp resp;
    struct iovec riov = {.iov_base = &resp, .iov_len = sizeof(resp)};
    struct msghdr rmsg = {.msg_iov = &riov, .msg_iovlen = 1};
    ssize_t n = recvmsg(sock, &rmsg, 0);
    if (n != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "short/failed response: %zd\n", n);
        return n < 0 ? -errno : -EBADMSG;
    }
    if (resp.hdr.magic != DEFUSED_PROTO_MAGIC ||
        resp.hdr.version != DEFUSED_PROTO_VERSION) {
        fprintf(stderr, "bad response header\n");
        return -EBADMSG;
    }
    if (resp.status == DEFUSED_ERR_SETNS_FAILED)
        fprintf(stderr, "(setns failed, sys_errno=%d: %s)\n", resp.sys_errno,
                strerror(resp.sys_errno));
    return (int)resp.status;
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

    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd == -1 || bind(fd, (struct sockaddr *)sa, *len) == -1 ||
        listen(fd, 1) == -1) {
        perror("listen");
        return -errno;
    }
    return fd;
}

static int connect_addr(const struct sockaddr_un *sa, socklen_t len) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd == -1 || connect(fd, (const struct sockaddr *)sa, len) == -1) {
        perror("connect");
        return -errno;
    }
    return fd;
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
        execl(defused_path, "defused", "--mount-max=5", NULL);
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

    int result_pipe[2];
    if (pipe(result_pipe) == -1) {
        perror("pipe");
        return -errno;
    }

    pid_t outer = fork();
    if (outer < 0)
        return -errno;
    if (outer == 0) {
        close(result_pipe[0]);

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == -1) {
            perror("unshare(NEWUSER|NEWNS)");
            _exit(1);
        }
        (void)map_root(real_uid, real_gid);

        struct sockaddr_un sa;
        socklen_t salen;
        int listen_fd = listen_addr(&sa, &salen, "can");
        if (listen_fd < 0)
            _exit(1);

        pid_t inner = fork();
        if (inner == 0) {
            close(result_pipe[1]);
            /* Namespace B: a plain CLONE_NEWNS, no new user namespace, so it
             * stays inside A and defused (also in A) has CAP_SYS_ADMIN over
             * it -- but it is still a genuinely distinct mount namespace. */
            if (unshare(CLONE_NEWNS) == -1) {
                perror("unshare(NEWNS)");
                _exit(1);
            }
            int client_sock = connect_addr(&sa, salen);
            if (client_sock < 0)
                _exit(1);
            int status = send_bad_mount_request(client_sock);
            close(client_sock);
            _exit(status == DEFUSED_ERR_BAD_OPTION ? 0 : 1);
        }

        int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (conn == -1) {
            perror("accept");
            _exit(1);
        }
        pid_t defused_pid;
        if (spawn_defused(defused_path, conn, &defused_pid) < 0)
            _exit(1);
        close(conn);
        close(listen_fd);

        int inner_status;
        waitpid(inner, &inner_status, 0);
        int ok = WIFEXITED(inner_status) && WEXITSTATUS(inner_status) == 0;

        int defused_status;
        waitpid(defused_pid, &defused_status, 0);

        char byte = ok ? 1 : 0;
        write(result_pipe[1], &byte, 1);
        close(result_pipe[1]);
        _exit(0);
    }

    close(result_pipe[1]);
    char byte = 0;
    ssize_t n = read(result_pipe[0], &byte, 1);
    close(result_pipe[0]);
    waitpid(outer, NULL, 0);

    CHECK(n == 1);
    CHECK(byte == 1);
    if (n != 1 || byte != 1)
        fprintf(stderr,
                "test_can_join: defused failed to join a mount namespace it "
                "has CAP_SYS_ADMIN over\n");
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
    int listen_fd = listen_addr(&sa, &salen, "cannot");
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
        (void)map_root(real_uid, real_gid);
        int client_sock = connect_addr(&sa, salen);
        if (client_sock < 0)
            _exit(1);
        int status = send_bad_mount_request(client_sock);
        close(client_sock);
        if (status != DEFUSED_ERR_SETNS_FAILED)
            fprintf(stderr, "test_cannot_join: got status %d, expected %d\n",
                    status, DEFUSED_ERR_SETNS_FAILED);
        _exit(status == DEFUSED_ERR_SETNS_FAILED ? 0 : 1);
    }

    int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn == -1) {
        perror("accept");
        _exit(1);
    }
    pid_t defused_pid;
    if (spawn_defused(defused_path, conn, &defused_pid) < 0)
        return -errno;
    close(conn);
    close(listen_fd);

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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/defused\n", argv[0]);
        return 2;
    }

    (void)test_can_join(argv[1]);
    (void)test_cannot_join(argv[1]);

    return failures ? 1 : 0;
}
