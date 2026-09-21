/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * End-to-end test of the fusermount3 client against a fake defused
 * service, without root: it binds a SOCK_STREAM listener at a temp
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
 *
 *  - privileged caller: the client spawns `defused --child` (this binary,
 *    via DEFUSED_PATH) instead of connecting to the socket; the fake child
 *    runs the same mount/unmount checks as above.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused_proto.h"
#include "test_timeout.h"

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
#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

static int failures;

/* Meson reads 77 as a skip. */
#define MESON_EXIT_SKIP 77

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

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

/* The -o string test_mount() and test_privileged_mount() send, and what
 * method_mount() expects it to have been parsed into. noatime,atime and
 * large_read are here for libfuse2's fusermount, whose option set is a
 * subset of fusermount3's apart from those two. */
#define MOUNT_OPTS                                                             \
    "ro,noexec,suid,dev,sync,dirsync,noatime,atime,large_read,"                \
    "fsname=test\\,fs,subtype=mem\\,fs,"                                       \
    "max_read=4096,default_permissions,nonempty,x-gvfs-hide"
static const char mount_opts[] = MOUNT_OPTS;
static const char privileged_mount_opts[] = MOUNT_OPTS ",blkdev";

static int method_mount(sd_varlink *link, sd_json_variant *parameters,
                        sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    (void)userdata;
    struct mount_parameters {
        uint32_t fuse_fd_index;
        uint32_t mnt_fd_index;
        uint32_t mount_flags;
        uint32_t max_read;
        uint32_t blksize;
        const char *fsname;
        const char *subtype;
    } p = {};
    static const sd_json_dispatch_field dispatch_table[] = {
        {"fuseFileDescriptor", SD_JSON_VARIANT_UNSIGNED,
         sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, fuse_fd_index), SD_JSON_MANDATORY},
        {"mountpointFileDescriptor", SD_JSON_VARIANT_UNSIGNED,
         sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, mnt_fd_index), SD_JSON_MANDATORY},
        {"mountFlags", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, mount_flags), SD_JSON_MANDATORY},
        {"maxRead", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, max_read), SD_JSON_MANDATORY},
        {"blockSize", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, blksize), SD_JSON_MANDATORY},
        {"fsName", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
         offsetof(struct mount_parameters, fsname), SD_JSON_MANDATORY},
        {"subtype", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
         offsetof(struct mount_parameters, subtype), SD_JSON_MANDATORY},
        {},
    };

    CHECK(sd_varlink_dispatch(link, parameters, dispatch_table, &p) == 0);
    CHECK(sd_varlink_get_n_fds(link) == 2);

    uint32_t expected_flags = DEFUSED_MOUNT_RDONLY | DEFUSED_MOUNT_NOEXEC |
                              DEFUSED_MOUNT_SYNCHRONOUS |
                              DEFUSED_MOUNT_DIRSYNC |
                              DEFUSED_FUSE_DEFAULT_PERMISSIONS;
    /* No NOATIME: the later atime in the -o string clears what noatime set.
     *
     * suid and dev are ignored for an unprivileged caller and honored for a
     * privileged one, which also sends blkdev (see privileged_mount_opts). */
    if (strcmp(getenv("DEFUSED_TEST_UID"), "0") == 0)
        expected_flags |= DEFUSED_MOUNT_ALLOW_SUID | DEFUSED_MOUNT_ALLOW_DEV |
                          DEFUSED_MOUNT_BLKDEV;
    CHECK(p.mount_flags == expected_flags);
    CHECK(p.max_read == 4096);
    CHECK(p.blksize == 0);
    CHECK(strcmp(p.fsname, "test,fs") == 0);
    CHECK(strcmp(p.subtype, "mem,fs") == 0);

    _cleanup_close_ int fuse_fd = sd_varlink_take_fd(link, p.fuse_fd_index);
    CHECK(fuse_fd >= 0);
    struct stat fuse_in_st;
    CHECK(fstat(fuse_fd, &fuse_in_st) == 0 && S_ISCHR(fuse_in_st.st_mode));

    _cleanup_close_ int mnt_fd = sd_varlink_take_fd(link, p.mnt_fd_index);
    CHECK(mnt_fd >= 0);
    struct stat fd_st, dot_st;
    CHECK(fstat(mnt_fd, &fd_st) == 0 && stat(".", &dot_st) == 0);
    CHECK(S_ISDIR(fd_st.st_mode));
    CHECK(fd_st.st_dev == dot_st.st_dev && fd_st.st_ino == dot_st.st_ino);

    return sd_varlink_reply(link, NULL);
}

/* Expects an unmount of ".": the client resolves it via realpath() before
 * splitting it into a parent dir + basename, so compute the same split here
 * -- nothing chdir()s, so the client's cwd is this process's cwd. */
static int method_unmount(sd_varlink *link, sd_json_variant *parameters,
                          sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    (void)userdata;
    char cwd[PATH_MAX];
    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    _cleanup_free_ char *dir_copy = strdup(cwd);
    _cleanup_free_ char *base_copy = strdup(cwd);
    CHECK(dir_copy != NULL && base_copy != NULL);
    const char *expect_parent = dirname(dir_copy);
    const char *expect_name = basename(base_copy);

    struct unmount_parameters {
        uint32_t parent_fd_index;
        const char *name;
        int lazy;
    } p = {};
    static const sd_json_dispatch_field dispatch_table[] = {
        {"parentFileDescriptor", SD_JSON_VARIANT_UNSIGNED,
         sd_json_dispatch_uint32,
         offsetof(struct unmount_parameters, parent_fd_index),
         SD_JSON_MANDATORY},
        {"name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
         offsetof(struct unmount_parameters, name), SD_JSON_MANDATORY},
        {"lazy", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_intbool,
         offsetof(struct unmount_parameters, lazy), SD_JSON_MANDATORY},
        {},
    };

    CHECK(sd_varlink_dispatch(link, parameters, dispatch_table, &p) == 0);
    CHECK(sd_varlink_get_n_fds(link) == 1);
    CHECK(p.lazy);
    CHECK(strcmp(p.name, expect_name) == 0);
    /* The parent directory, never the mountpoint itself: an fd held open on
     * the mount would make a non-lazy umount2() fail with EBUSY. */
    _cleanup_close_ int parent_fd = sd_varlink_take_fd(link, p.parent_fd_index);
    CHECK(parent_fd >= 0);
    struct stat fd_st, parent_st;
    CHECK(fstat(parent_fd, &fd_st) == 0 &&
          stat(expect_parent, &parent_st) == 0);
    CHECK(fd_st.st_dev == parent_st.st_dev && fd_st.st_ino == parent_st.st_ino);
    return sd_varlink_error(link, DEFUSED_VARLINK_ERROR_NOT_A_FUSE_MOUNT, NULL);
}

/* Serves one connection to completion. Takes ownership of conn_fd. */
static int serve_connection(int conn_fd) {
    _cleanup_close_ int conn = conn_fd;
    _cleanup_(sd_event_unrefp) sd_event *event = NULL;
    _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
    int ret = sd_event_new(&event);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_new(&server,
                                SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT |
                                    SD_VARLINK_SERVER_INHERIT_USERDATA);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_add_interface(server,
                                          &vl_interface_website_soss_defused);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_bind_method_many(
        server, DEFUSED_VARLINK_METHOD_MOUNT, method_mount,
        DEFUSED_VARLINK_METHOD_UNMOUNT, method_unmount);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_set_exit_on_idle(server, true);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_attach_event(server, event, 0);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_add_connection(server, conn, NULL);
    if (ret < 0)
        return ret;
    TAKE_FD(conn);
    return sd_event_loop(event);
}

static int test_mount(const char *client, int listen_fd) {
    _cleanup_close_pair_ int comm[2] = EBADF_PAIR;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, comm) == 0);

    char *args[] = {(char *)"-o", (char *)mount_opts, (char *)"."};
    pid_t pid;
    CHECK(spawn_client(client, comm[1], args, 3, &pid) == 0);
    comm[1] = safe_close(comm[1]);

    _cleanup_close_ int conn = accept(listen_fd, NULL, NULL);
    CHECK(conn >= 0);

    /* Play the service's success path. The client already opened the device
     * fd it sent to the service, so the response carries no fd. */
    CHECK(serve_connection(TAKE_FD(conn)) == 0);

    check_forwarded_fd(comm[0]);
    CHECK(wait_exit_code(pid) == 0);
    return failures ? -EINVAL : 0;
}

static int test_unmount(const char *client, int listen_fd) {
    char *args[] = {(char *)"-u", (char *)"-z", (char *)"."};
    pid_t pid;
    CHECK(spawn_client(client, -1, args, 3, &pid) == 0);

    _cleanup_close_ int conn = accept(listen_fd, NULL, NULL);
    CHECK(conn >= 0);
    CHECK(serve_connection(TAKE_FD(conn)) == 0);

    /* An error status must surface as a nonzero exit. */
    CHECK(wait_exit_code(pid) == 1);
    return failures ? -EINVAL : 0;
}

/* Same as test_mount()/test_unmount(), but the service side is played by
 * fake_defused_child() in a process the client spawns itself. */
static int test_privileged_mount(const char *client) {
    _cleanup_close_pair_ int comm[2] = EBADF_PAIR;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, comm) == 0);

    char *args[] = {(char *)"-o", (char *)privileged_mount_opts, (char *)"."};
    pid_t pid;
    CHECK(spawn_client(client, comm[1], args, 3, &pid) == 0);
    comm[1] = safe_close(comm[1]);

    check_forwarded_fd(comm[0]);
    CHECK(wait_exit_code(pid) == 0);
    return failures ? -EINVAL : 0;
}

static int test_privileged_unmount(const char *client) {
    char *args[] = {(char *)"-u", (char *)"-z", (char *)"."};
    pid_t pid;
    CHECK(spawn_client(client, -1, args, 3, &pid) == 0);
    CHECK(wait_exit_code(pid) == 1);
    return failures ? -EINVAL : 0;
}

/* Runs as the `defused --child` the client spawned. The socket arrives as
 * fd 3 via $LISTEN_FDS, as the real defused expects. A failed CHECK here is
 * only visible in stderr, since the client's exit code reflects the reply. */
static int fake_defused_child(int argc, char *argv[]) {
    CHECK(argc == 2 && strcmp(argv[0], "defused") == 0);
    const char *listen_fds = getenv("LISTEN_FDS");
    CHECK(listen_fds != NULL && strcmp(listen_fds, "1") == 0);
    CHECK(serve_connection(3) == 0);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--child") == 0)
        return fake_defused_child(argc, argv);

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
    (void)test_privileged_mount(argv[1]);
    (void)test_privileged_unmount(argv[1]);

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
        socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) ||
        listen(listen_fd, 2)) {
        perror("listen socket");
        return 1;
    }
    setenv("DEFUSED_SOCKET", sock_path, 1);

    (void)test_mount(argv[1], listen_fd);
    (void)test_unmount(argv[1], listen_fd);

    unlink(sock_path);
    rmdir(dir);
    unsetenv("DEFUSED_TEST_UID");
    return failures ? 1 : 0;
}
