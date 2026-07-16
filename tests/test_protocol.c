/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Exercises the defused.h wire protocol against a real `defused` process
 * without requiring root or CAP_SYS_ADMIN. The requests intentionally stop
 * before the real mount(2) call, since that's the one part of request
 * handling that needs privilege to succeed.
 */
#define _GNU_SOURCE
#include "defused.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int spawn_defused(const char *defused_path, int *client_sock,
                         pid_t *out_pid) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1) {
        perror("socketpair");
        return -errno;
    }

    pid_t pid = fork();
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
        execl(defused_path, "defused", "--mount-max=5", NULL);
        perror("exec");
        _exit(127);
    }

    close(sv[1]);
    *client_sock = sv[0];
    *out_pid = pid;
    return 0;
}

static int spawn_defused_daemon(const char *defused_path, const char *sock_path,
                                pid_t *out_pid) {
    pid_t pid = fork();
    if (pid == 0) {
        setenv("DEFUSED_SOCKET", sock_path, 1);
        execl(defused_path, "defused", "--daemon", "--mount-max=5", NULL);
        perror("exec");
        _exit(127);
    }
    if (pid < 0)
        return -errno;

    *out_pid = pid;
    return 0;
}

static int connect_defused(const char *sock_path) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(sock_path) >= sizeof(sa.sun_path))
        return -ENAMETOOLONG;
    strcpy(sa.sun_path, sock_path);

    for (int i = 0; i < 100; i++) {
        int sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (sock == -1)
            return -errno;
        if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == 0)
            return sock;

        int saved_errno = errno;
        close(sock);
        if (saved_errno != ENOENT && saved_errno != ECONNREFUSED)
            return -saved_errno;
        usleep(10000);
    }
    return -ETIMEDOUT;
}

static int send_mount_req(int sock, const struct defused_mount_req *req,
                          int dev_fd, int mnt_fd, struct defused_resp *resp) {
    struct iovec iov = {.iov_base = (void *)req, .iov_len = sizeof(*req)};
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
        perror("sendmsg");
        return -errno;
    }

    struct iovec riov = {.iov_base = resp, .iov_len = sizeof(*resp)};
    struct msghdr rmsg = {.msg_iov = &riov, .msg_iovlen = 1};
    ssize_t n = recvmsg(sock, &rmsg, 0);
    if (n < 0) {
        perror("recvmsg");
        return -errno;
    }
    if (n != (ssize_t)sizeof(*resp)) {
        fprintf(stderr, "FAIL: short response (%zd bytes)\n", n);
        return -EBADMSG;
    }
    if (resp->hdr.magic != DEFUSED_PROTO_MAGIC ||
        resp->hdr.version != DEFUSED_PROTO_VERSION) {
        fprintf(stderr, "FAIL: bad response header (magic=%#x version=%u)\n",
                resp->hdr.magic, resp->hdr.version);
        return -EBADMSG;
    }
    return 0;
}

static int run_mount_req(const char *defused_path,
                         const struct defused_mount_req *req, const char *path,
                         uint32_t expect_status) {
    int sock;
    pid_t pid;
    int ret = spawn_defused(defused_path, &sock, &pid);
    if (ret < 0)
        return ret;

    int mnt_fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd < 0) {
        ret = -errno;
        perror(path);
        return ret;
    }
    int dev_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        ret = -errno;
        perror("/dev/null");
        close(mnt_fd);
        return ret;
    }

    struct defused_resp resp;
    ret = send_mount_req(sock, req, dev_fd, mnt_fd, &resp);
    close(dev_fd);
    close(mnt_fd);
    close(sock);

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
    if (resp.status != expect_status) {
        fprintf(stderr, "FAIL: expected status %u, got %u\n", expect_status,
                resp.status);
        return -EINVAL;
    }
    if (!WIFEXITED(wstatus)) {
        fprintf(stderr, "FAIL: service did not exit normally\n");
        return -ECHILD;
    }
    return 0;
}

static int run_daemon_mount_req(const char *sock_path,
                                const struct defused_mount_req *req,
                                const char *path, uint32_t expect_status) {
    int sock = connect_defused(sock_path);
    if (sock < 0)
        return sock;

    int mnt_fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd < 0) {
        int ret = -errno;
        perror(path);
        close(sock);
        return ret;
    }
    int dev_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        int ret = -errno;
        perror("/dev/null");
        close(mnt_fd);
        close(sock);
        return ret;
    }

    struct defused_resp resp;
    int ret = send_mount_req(sock, req, dev_fd, mnt_fd, &resp);
    close(dev_fd);
    close(mnt_fd);
    close(sock);
    if (ret < 0)
        return ret;
    if (resp.status != expect_status) {
        fprintf(stderr, "FAIL: expected status %u, got %u\n", expect_status,
                resp.status);
        return -EINVAL;
    }
    return 0;
}

static int test_daemon_mode(const char *defused_path,
                            const struct defused_mount_req *req) {
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || strlen(tmp) > 64)
        tmp = "/tmp";
    char dir[96];
    snprintf(dir, sizeof(dir), "%s/defused-protocol-XXXXXX", tmp);
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }

    char sock_path[108];
    snprintf(sock_path, sizeof(sock_path), "%s/sock", dir);

    pid_t daemon_pid;
    int ret = spawn_defused_daemon(defused_path, sock_path, &daemon_pid);
    if (ret < 0)
        goto out_dir;

    ret = run_daemon_mount_req(sock_path, req, ".", DEFUSED_ERR_BAD_OPTION);
    if (ret == 0)
        ret = run_daemon_mount_req(sock_path, req, ".", DEFUSED_ERR_BAD_OPTION);

    kill(daemon_pid, SIGTERM);
    waitpid(daemon_pid, NULL, 0);
    unlink(sock_path);

out_dir:
    rmdir(dir);
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/defused\n", argv[0]);
        return 2;
    }

    struct defused_mount_req bad_opt = {
        .hdr = {DEFUSED_PROTO_MAGIC, DEFUSED_PROTO_VERSION, DEFUSED_OP_MOUNT},
        .mount_flags = 1u << 31, /* never in DEFUSED_MOUNT_FLAGS_MASK */
    };
    if (run_mount_req(argv[1], &bad_opt, ".", DEFUSED_ERR_BAD_OPTION) != 0)
        return 1;

    if (test_daemon_mode(argv[1], &bad_opt) != 0)
        return 1;

    if (getuid() != 0) {
        struct defused_mount_req root_owned = {
            .hdr = {DEFUSED_PROTO_MAGIC, DEFUSED_PROTO_VERSION,
                    DEFUSED_OP_MOUNT},
        };
        if (run_mount_req(argv[1], &root_owned, "/", DEFUSED_ERR_NOT_ALLOWED) !=
            0)
            return 1;
    }

    return 0;
}
