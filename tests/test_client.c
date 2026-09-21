/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * End-to-end test of the fusermount3 client against a fake defused
 * service, without root: a seqpacket listener at a temp path (given to
 * the client via $DEFUSED_SOCKET), then both directions of the protocol.
 *
 * A mount's -o string must arrive as the right request and the device fd
 * must reach _FUSE_COMMFD framed as libfuse's receive_fd() expects; -u -z
 * must arrive as op UNMOUNT with lazy set, and an error must surface as a
 * nonzero exit. A privileged caller performs the request in its own
 * process and never touches the socket.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-proto.h"
#include "test_util.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
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

static int recv_with_fd(int sock, void *buf, size_t len, ssize_t *out_len,
                        int *out_fd) {
    (void)len;
    struct iovec iov = {.iov_base = buf, .iov_len = 1};
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cbuf;
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = cbuf.buf,
                         .msg_controllen = sizeof(cbuf.buf)};
    *out_fd = -1;
    ssize_t n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    if (n < 0)
        return -errno;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len == CMSG_LEN(sizeof(int)))
            memcpy(out_fd, CMSG_DATA(c), sizeof(int));
    *out_len = n;
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

/* The one binary is installed under both helper names, so the -V banner
 * follows argv[0]: libfuse2 callers must see "fusermount version:". */
static void check_version_banner(const char *client, const char *argv0,
                                 const char *name) {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        CHECK(false);
        return;
    }
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        char *argv[] = {(char *)argv0, (char *)"-V", NULL};
        execv(client, argv);
        _exit(127);
    }
    (void)close(pipefd[1]);
    char buf[256] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    (void)close(pipefd[0]);
    CHECK(wait_exit_code(pid) == 0);
    CHECK(n > 0);

    char expected[64];
    snprintf(expected, sizeof(expected), "%s version: ", name);
    bool ok = strncmp(buf, expected, strlen(expected)) == 0;
    CHECK(ok);
    if (!ok)
        fprintf(stderr, "  argv[0] %s printed: %s", argv0, buf);
}

/* The client forwards the device fd to _FUSE_COMMFD framed the way libfuse's
 * receive_fd() expects: one zero byte plus SCM_RIGHTS. */
static void check_forwarded_fd(int comm_fd) {
    char byte = 0x7f;
    _cleanup_close_ int fuse_fd = -EBADF;
    ssize_t n = -1;
    CHECK(recv_with_fd(comm_fd, &byte, 1, &n, &fuse_fd) == 0);
    CHECK(n == 1);
    CHECK(byte == 0);
    CHECK(fuse_fd >= 0);
    struct stat fuse_st;
    CHECK(fstat(fuse_fd, &fuse_st) == 0 && S_ISCHR(fuse_st.st_mode));
}

/* The -o string test_mount() sends, and what
 * check_mount_request() expects it to have been parsed into. noatime,atime and
 * large_read are here for libfuse2's fusermount, whose option set is a
 * subset of fusermount3's apart from those two. */
#define MOUNT_OPTS                                                             \
    "ro,noexec,suid,dev,sync,dirsync,noatime,atime,large_read,"                \
    "fsname=test\\,fs,subtype=mem\\,fs,"                                       \
    "max_read=4096,default_permissions,nonempty,x-gvfs-hide"
static const char mount_opts[] = MOUNT_OPTS;
static const char privileged_mount_opts[] = MOUNT_OPTS ",blkdev";

static void check_mount_request(const struct defused_request *req, int fuse_fd,
                                int mnt_fd) {
    uint32_t expected_flags = DEFUSED_MOUNT_RDONLY | DEFUSED_MOUNT_NOEXEC |
                              DEFUSED_MOUNT_SYNCHRONOUS |
                              DEFUSED_MOUNT_DIRSYNC |
                              DEFUSED_FUSE_DEFAULT_PERMISSIONS;
    /* No NOATIME: the later atime clears what noatime set. No suid or dev
     * either: only the unprivileged path reaches the service, and it
     * drops both with a warning. */
    CHECK(req->mount_flags == expected_flags);
    CHECK(req->max_read == 4096);
    CHECK(req->blksize == 0);
    CHECK(strcmp(req->fsname, "test,fs") == 0);
    CHECK(strcmp(req->subtype, "mem,fs") == 0);

    struct stat fuse_st;
    CHECK(fstat(fuse_fd, &fuse_st) == 0 && S_ISCHR(fuse_st.st_mode));

    struct stat fd_st, dot_st;
    CHECK(fstat(mnt_fd, &fd_st) == 0 && stat(".", &dot_st) == 0);
    CHECK(S_ISDIR(fd_st.st_mode));
    CHECK(fd_st.st_dev == dot_st.st_dev && fd_st.st_ino == dot_st.st_ino);
}

/* Expects an unmount of ".": the client resolves it via realpath() before
 * splitting it into a parent dir + basename, so compute the same split here
 * -- nothing chdir()s, so the client's cwd is this process's cwd. */
static void check_unmount_request(const struct defused_request *req,
                                  int parent_fd) {
    char cwd[PATH_MAX];
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    _cleanup_free_ char *dir_copy = strdup(cwd);
    _cleanup_free_ char *base_copy = strdup(cwd);
    CHECK(dir_copy != NULL && base_copy != NULL);
    const char *expect_parent = dirname(dir_copy);
    const char *expect_name = basename(base_copy);

    CHECK(req->lazy);
    CHECK(strcmp(req->name, expect_name) == 0);
    /* The parent directory, never the mountpoint itself: an fd held open on
     * the mount would make a non-lazy umount2() fail with EBUSY. */
    struct stat fd_st, parent_st;
    CHECK(fstat(parent_fd, &fd_st) == 0 &&
          stat(expect_parent, &parent_st) == 0);
    CHECK(fd_st.st_dev == parent_st.st_dev && fd_st.st_ino == parent_st.st_ino);
}

/* Takes ownership of conn_fd. */
static int serve_connection(int conn_fd) {
    _cleanup_close_ int conn = conn_fd;
    struct defused_request req;
    int fds[DEFUSED_MAX_FDS];
    size_t n_fds = 0;
    int ret = defused_recv_request(conn, &req, fds, &n_fds);
    if (ret < 0) {
        fprintf(stderr, "FAIL: reading the request failed: %s\n",
                strerror(-ret));
        failures++;
        return ret;
    }
    _cleanup_close_ int fd0 = fds[0];
    _cleanup_close_ int fd1 = n_fds > 1 ? fds[1] : -EBADF;

    struct defused_error err = {};
    if (req.op == DEFUSED_OP_MOUNT) {
        check_mount_request(&req, fd0, fd1);
    } else {
        check_unmount_request(&req, fd0);
        /* An error the client must turn into a nonzero exit. */
        defused_error_set(&err, DEFUSED_ERR_NOT_A_FUSE_MOUNT, 0, NULL);
    }
    return defused_send_reply(conn, &err);
}

/* Accepts one connection on listen_fd and plays the service to completion. */
static void serve_one(int listen_fd) {
    _cleanup_close_ int conn = accept(listen_fd, NULL, NULL);
    CHECK(conn >= 0);
    CHECK(serve_connection(TAKE_FD(conn)) == 0);
}

/* listen_fd < 0 means the client should send no request at all. */
static void test_mount(const char *client, int listen_fd, const char *opts) {
    _cleanup_close_pair_ int comm[2] = EBADF_PAIR;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, comm) == 0);

    char *args[] = {(char *)"-o", (char *)opts, (char *)"."};
    pid_t pid;
    CHECK(spawn_client(client, comm[1], args, 3, &pid) == 0);
    comm[1] = safe_close(comm[1]);

    /* The success path. The client already opened the device fd it sent to
     * the service, so the response carries no fd. */
    if (listen_fd >= 0)
        serve_one(listen_fd);

    check_forwarded_fd(comm[0]);
    CHECK(wait_exit_code(pid) == 0);
}

/* mnt is "." for the unprivileged path, which is what the fake service
 * expects; the privileged path really calls umount2(), so it gets a
 * scratch directory that is certainly not a mountpoint. */
static void test_unmount(const char *client, int listen_fd, const char *mnt) {
    char *args[] = {(char *)"-u", (char *)"-z", (char *)mnt};
    pid_t pid;
    CHECK(spawn_client(client, -1, args, 3, &pid) == 0);

    if (listen_fd >= 0)
        serve_one(listen_fd);

    /* An error status must surface as a nonzero exit. */
    CHECK(wait_exit_code(pid) == 1);
}

/*
 * A privileged caller mounts in its own process, so there is no request
 * to intercept. What is still observable: the socket is never contacted
 * (DEFUSED_SOCKET points at nothing), and the privileged options were
 * accepted -- the flag mask is checked first, so reaching any later
 * complaint proves suid/dev/blkdev were allowed. Here the run stops at
 * the FUSE device check, since the test hands it /dev/null.
 */
static void test_privileged_mount(const char *client, const char *opts) {
    int errpipe[2];
    CHECK(pipe(errpipe) == 0);
    _cleanup_close_pair_ int comm[2] = EBADF_PAIR;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, comm) == 0);

    char *args[] = {(char *)"-o", (char *)opts, (char *)"."};
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        (void)dup2(errpipe[1], STDERR_FILENO);
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        (void)close(comm[0]);
        char fdstr[16];
        snprintf(fdstr, sizeof(fdstr), "%d", comm[1]);
        setenv("_FUSE_COMMFD", fdstr, 1);
        setenv("DEFUSED_FUSE_DEVICE", "/dev/null", 1);
        char *argv[] = {(char *)"fusermount3", args[0], args[1], args[2], NULL};
        execv(client, argv);
        _exit(127);
    }
    (void)close(errpipe[1]);
    char buf[1024] = {0};
    ssize_t n = read(errpipe[0], buf, sizeof(buf) - 1);
    (void)close(errpipe[0]);

    CHECK(wait_exit_code(pid) == 1);
    CHECK(n > 0);
    bool ok = strstr(buf, "mount options rejected") == NULL &&
              strstr(buf, "cannot connect") == NULL;
    /* One message, from fusermount3 -- not a second from a helper logging
     * to the caller's stderr, as `defused --child` used to. */
    ok = ok && strncmp(buf, "defused: ", 9) != 0 &&
         strstr(buf, "\ndefused: ") == NULL;
    CHECK(ok);
    if (!ok)
        fprintf(stderr, "  privileged mount printed: %s", buf);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/fusermount3\n", argv[0]);
        return 2;
    }
    test_set_timeout();

    check_version_banner(argv[1], "fusermount3", "fusermount3");
    check_version_banner(argv[1], "fusermount", "fusermount");
    check_version_banner(argv[1], "/usr/bin/fusermount", "fusermount");

    /* spawn_client() hands the client /dev/null as the FUSE device. */
    int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull < 0) {
        fprintf(stderr,
                "SKIP: /dev/null is not usable as a stand-in FUSE device "
                "here (%s)\n",
                strerror(errno));
        return MESON_EXIT_SKIP;
    }
    (void)safe_close(devnull);

    /* A privileged caller must never touch the socket: point it somewhere
     * that fails immediately so a wrong turn is an error, not a hang. */
    setenv("DEFUSED_TEST_UID", "0", 1);
    setenv("DEFUSED_SOCKET", "/nonexistent/defused.sock", 1);
    test_privileged_mount(argv[1], privileged_mount_opts);
    char priv_dir[] = "/tmp/defused-client-priv-XXXXXX";
    if (mkdtemp(priv_dir) != NULL) {
        test_unmount(argv[1], -1, priv_dir);
        rmdir(priv_dir);
    } else {
        CHECK(false);
    }

    setenv("DEFUSED_TEST_UID", "1", 1);

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
    _cleanup_close_ int listen_fd =
        socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
    if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) ||
        listen(listen_fd, 2)) {
        perror("listen socket");
        return 1;
    }
    setenv("DEFUSED_SOCKET", sock_path, 1);

    test_mount(argv[1], listen_fd, mount_opts);
    test_unmount(argv[1], listen_fd, ".");

    unlink(sock_path);
    rmdir(dir);
    unsetenv("DEFUSED_TEST_UID");
    return failures ? 1 : 0;
}
