/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * End-to-end test of the fusermount3 client against a fake defused
 * service, without root: it binds a SOCK_SEQPACKET listener at a temp
 * path (handed to the client via the DEFUSED_SOCKET env override), runs
 * the client, and checks both directions of the protocol:
 *
 *  - mount: a fusermount3-style -o string arrives as the right typed
 *    defused_mount_req (generic options parsed into mount_flags, names
 *    unescaped, numbers parsed), carrying an fd for the right directory;
 *    and the fd the fake service returns is forwarded to _FUSE_COMMFD
 *    framed the way libfuse's receive_fd() expects (1 zero byte +
 *    SCM_RIGHTS).
 *
 *  - unmount: -u -z becomes a defused_umount_req with lazy set, and a
 *    service error status surfaces as a nonzero exit.
 */
#define _GNU_SOURCE
#include "defused.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

static int recv_with_fds(int sock, void *buf, size_t len, ssize_t *out_len,
                         int *fds, size_t max_fds, size_t *out_fd_count) {
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } cbuf;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf.buf,
        .msg_controllen = sizeof(cbuf.buf),
    };

    for (size_t i = 0; i < max_fds; i++)
        fds[i] = -1;
    *out_fd_count = 0;
    ssize_t n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    if (n < 0)
        return -errno;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            if (c->cmsg_len < CMSG_LEN(0))
                return -EMSGSIZE;
            size_t payload_len = c->cmsg_len - CMSG_LEN(0);
            size_t fd_count = payload_len / sizeof(int);
            if (payload_len % sizeof(int) != 0 ||
                *out_fd_count + fd_count > max_fds)
                return -EMSGSIZE;
            memcpy(&fds[*out_fd_count], CMSG_DATA(c), fd_count * sizeof(int));
            *out_fd_count += fd_count;
        }
    }
    *out_len = n;
    return 0;
}

static int recv_with_fd(int sock, void *buf, size_t len, ssize_t *out_len,
                        int *out_fd) {
    size_t fd_count = 0;
    int ret = recv_with_fds(sock, buf, len, out_len, out_fd, 1, &fd_count);
    if (ret < 0)
        return ret;
    return fd_count <= 1 ? 0 : -EMSGSIZE;
}

static int send_resp(int sock, uint32_t status, int fd) {
    struct defused_resp resp = {
        .hdr = {DEFUSED_PROTO_MAGIC, DEFUSED_PROTO_VERSION, 0},
        .status = status,
    };
    struct iovec iov = {.iov_base = &resp, .iov_len = sizeof(resp)};
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cbuf;
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};

    if (fd >= 0) {
        msg.msg_control = cbuf.buf;
        msg.msg_controllen = sizeof(cbuf.buf);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(int));
    }
    if (sendmsg(sock, &msg, 0) != (ssize_t)sizeof(resp))
        return errno ? -errno : -EIO;
    return 0;
}

/* Runs the client with the given argv tail; comm_fd (if >= 0) is passed
 * through _FUSE_COMMFD. Returns the child's pid. */
static int spawn_client(const char *client, int comm_fd, char *const extra[],
                        int nextra, pid_t *out_pid) {
    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid != 0) {
        *out_pid = pid;
        return 0;
    }

    if (comm_fd >= 0) {
        char fdstr[16];
        snprintf(fdstr, sizeof(fdstr), "%d", comm_fd);
        setenv("_FUSE_COMMFD", fdstr, 1);
    }
    setenv("DEFUSED_FUSE_DEVICE", "/dev/null", 1);
    char *argv[16] = {(char *)"fusermount3"};
    int argc = 1;
    for (int i = 0; i < nextra; i++)
        argv[argc++] = extra[i];
    argv[argc] = NULL;
    execv(client, argv);
    perror("exec");
    _exit(127);
}

static int wait_exit_code(pid_t pid) {
    int wstatus;
    if (waitpid(pid, &wstatus, 0) != pid || !WIFEXITED(wstatus))
        return -ECHILD;
    return WEXITSTATUS(wstatus);
}

static int test_mount(const char *client, int listen_fd) {
    int comm[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, comm) == 0);

    char *args[] = {
        (char *)"-o",
        (char *)"ro,noexec,suid,dev,sync,dirsync,fsname=test\\,fs,subtype="
                "mem\\,fs,max_read=4096,"
                "default_permissions,nonempty,x-gvfs-hide",
        (char *)".",
    };
    pid_t pid;
    CHECK(spawn_client(client, comm[1], args, 3, &pid) == 0);
    close(comm[1]);

    int conn = accept(listen_fd, NULL, NULL);
    CHECK(conn >= 0);

    union defused_req req;
    memset(&req, 0, sizeof(req));
    int fds[2];
    size_t fd_count = 0;
    ssize_t n = -1;
    CHECK(recv_with_fds(conn, &req, sizeof(req), &n, fds, 2, &fd_count) == 0);
    CHECK(n == (ssize_t)sizeof(struct defused_mount_req));
    CHECK(fd_count == 2);
    CHECK(req.hdr.magic == DEFUSED_PROTO_MAGIC);
    CHECK(req.hdr.version == DEFUSED_PROTO_VERSION);
    CHECK(req.hdr.op == DEFUSED_OP_MOUNT);

    /* "suid" is unsafe on defused's unprivileged path and is ignored. */
    uint32_t expected_flags =
        DEFUSED_MOUNT_RDONLY | DEFUSED_MOUNT_NOEXEC | DEFUSED_MOUNT_ALLOW_DEV |
        DEFUSED_MOUNT_SYNCHRONOUS | DEFUSED_MOUNT_DIRSYNC |
        DEFUSED_FUSE_DEFAULT_PERMISSIONS;
    CHECK(req.mount.mount_flags == expected_flags);
    CHECK(req.mount.max_read == 4096);
    CHECK(req.mount.blksize == 0);
    CHECK(strcmp(req.mount.fsname, "test,fs") == 0); /* backslash unescaped */
    CHECK(strcmp(req.mount.subtype, "mem,fs") == 0);

    CHECK(fds[0] >= 0);
    struct stat fuse_in_st;
    CHECK(fstat(fds[0], &fuse_in_st) == 0 && S_ISCHR(fuse_in_st.st_mode));
    close(fds[0]);

    int mnt_fd = fds[1];
    CHECK(mnt_fd >= 0);
    struct stat fd_st, dot_st;
    CHECK(fstat(mnt_fd, &fd_st) == 0 && stat(".", &dot_st) == 0);
    CHECK(S_ISDIR(fd_st.st_mode));
    CHECK(fd_st.st_dev == dot_st.st_dev && fd_st.st_ino == dot_st.st_ino);
    close(mnt_fd);

    /* Play the service's success path. The client already opened the device
     * fd it sent to the service, so the response carries no fd. */
    CHECK(send_resp(conn, DEFUSED_OK, -1) == 0);
    close(conn);

    char byte = 0x7f;
    int fuse_fd;
    CHECK(recv_with_fd(comm[0], &byte, 1, &n, &fuse_fd) == 0);
    CHECK(n == 1);
    CHECK(byte == 0); /* libfuse's receive_fd() convention */
    CHECK(fuse_fd >= 0);
    struct stat fuse_st;
    CHECK(fstat(fuse_fd, &fuse_st) == 0 && S_ISCHR(fuse_st.st_mode));
    close(fuse_fd);
    close(comm[0]);

    CHECK(wait_exit_code(pid) == 0);
    return failures ? -EINVAL : 0;
}

static int test_unmount(const char *client, int listen_fd) {
    /* The client resolves "." via realpath() before splitting it into a
     * parent dir + basename, so compute the same split here to check
     * against -- since it forks without chdir'ing, the child's cwd (and
     * hence its realpath(".")) is this process's cwd. */
    char cwd[PATH_MAX];
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    char *dir_copy = strdup(cwd);
    char *base_copy = strdup(cwd);
    CHECK(dir_copy != NULL && base_copy != NULL);
    const char *expect_parent = dirname(dir_copy);
    const char *expect_name = basename(base_copy);

    char *args[] = {(char *)"-u", (char *)"-z", (char *)"."};
    pid_t pid;
    CHECK(spawn_client(client, -1, args, 3, &pid) == 0);

    int conn = accept(listen_fd, NULL, NULL);
    CHECK(conn >= 0);

    union defused_req req;
    memset(&req, 0, sizeof(req));
    int parent_fd;
    ssize_t n = -1;
    CHECK(recv_with_fd(conn, &req, sizeof(req), &n, &parent_fd) == 0);
    CHECK(n == (ssize_t)sizeof(struct defused_umount_req));
    CHECK(req.hdr.magic == DEFUSED_PROTO_MAGIC);
    CHECK(req.hdr.version == DEFUSED_PROTO_VERSION);
    CHECK(req.hdr.op == DEFUSED_OP_UNMOUNT);
    CHECK(req.umount.lazy != 0);
    CHECK(strcmp(req.umount.name, expect_name) == 0);

    /* The received fd must be the *parent* directory, never the mountpoint
     * itself -- holding an fd open on the mount would make a non-lazy
     * umount2() see it as busy (that was the actual bug this test guards
     * against). */
    CHECK(parent_fd >= 0);
    struct stat fd_st, parent_st;
    CHECK(fstat(parent_fd, &fd_st) == 0 &&
          stat(expect_parent, &parent_st) == 0);
    CHECK(fd_st.st_dev == parent_st.st_dev && fd_st.st_ino == parent_st.st_ino);
    close(parent_fd);
    free(dir_copy);
    free(base_copy);

    /* An error status must surface as a nonzero exit. */
    CHECK(send_resp(conn, DEFUSED_ERR_NOT_A_FUSE_MOUNT, -1) == 0);
    close(conn);

    CHECK(wait_exit_code(pid) == 1);
    return failures ? -EINVAL : 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/fusermount3\n", argv[0]);
        return 2;
    }

    if (getuid() == 0 || geteuid() == 0) {
        char *args[] = {(char *)"."};
        pid_t pid;
        CHECK(spawn_client(argv[1], -1, args, 1, &pid) == 0);
        CHECK(wait_exit_code(pid) != 0);
        return failures ? 1 : 0;
    }

    /* If the client never connects (e.g. it errored out during option
     * parsing), fail fast instead of hanging in accept(). */
    alarm(20);

    /* sun_path is only ~108 bytes, so fall back to /tmp if TMPDIR is deep. */
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || strlen(tmp) > 64)
        tmp = "/tmp";
    char dir[96];
    snprintf(dir, sizeof(dir), "%s/defused-client-XXXXXX", tmp);
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    char sock_path[108];
    snprintf(sock_path, sizeof(sock_path), "%s/sock", dir);

    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    strcpy(sa.sun_path, sock_path);
    int listen_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) ||
        listen(listen_fd, 2)) {
        perror("listen socket");
        return 1;
    }
    setenv("DEFUSED_SOCKET", sock_path, 1);

    (void)test_mount(argv[1], listen_fd);
    (void)test_unmount(argv[1], listen_fd);

    close(listen_fd);
    unlink(sock_path);
    rmdir(dir);
    return failures ? 1 : 0;
}
