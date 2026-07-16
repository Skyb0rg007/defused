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
 */
#define _GNU_SOURCE
#include "defused.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
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

static int reply_status(sd_varlink *link, uint32_t status) {
    return sd_varlink_replybo(link,
                              SD_JSON_BUILD_PAIR_UNSIGNED("status", status),
                              SD_JSON_BUILD_PAIR_INTEGER("sysErrno", 0));
}

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

    uint32_t expected_flags =
        DEFUSED_MOUNT_RDONLY | DEFUSED_MOUNT_NOEXEC | DEFUSED_MOUNT_ALLOW_DEV |
        DEFUSED_MOUNT_SYNCHRONOUS | DEFUSED_MOUNT_DIRSYNC |
        DEFUSED_FUSE_DEFAULT_PERMISSIONS;
    CHECK(p.mount_flags == expected_flags);
    CHECK(p.max_read == 4096);
    CHECK(p.blksize == 0);
    CHECK(strcmp(p.fsname, "test,fs") == 0);
    CHECK(strcmp(p.subtype, "mem,fs") == 0);

    int fuse_fd = sd_varlink_take_fd(link, p.fuse_fd_index);
    CHECK(fuse_fd >= 0);
    struct stat fuse_in_st;
    CHECK(fstat(fuse_fd, &fuse_in_st) == 0 && S_ISCHR(fuse_in_st.st_mode));
    close(fuse_fd);

    int mnt_fd = sd_varlink_take_fd(link, p.mnt_fd_index);
    CHECK(mnt_fd >= 0);
    struct stat fd_st, dot_st;
    CHECK(fstat(mnt_fd, &fd_st) == 0 && stat(".", &dot_st) == 0);
    CHECK(S_ISDIR(fd_st.st_mode));
    CHECK(fd_st.st_dev == dot_st.st_dev && fd_st.st_ino == dot_st.st_ino);
    close(mnt_fd);

    return reply_status(link, DEFUSED_OK);
}

static int method_unmount(sd_varlink *link, sd_json_variant *parameters,
                          sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    const struct {
        const char *parent;
        const char *name;
    } *expect = userdata;
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
    CHECK(strcmp(p.name, expect->name) == 0);
    int parent_fd = sd_varlink_take_fd(link, p.parent_fd_index);
    CHECK(parent_fd >= 0);
    struct stat fd_st, parent_st;
    CHECK(fstat(parent_fd, &fd_st) == 0 &&
          stat(expect->parent, &parent_st) == 0);
    CHECK(fd_st.st_dev == parent_st.st_dev && fd_st.st_ino == parent_st.st_ino);
    close(parent_fd);
    return reply_status(link, DEFUSED_ERR_NOT_A_FUSE_MOUNT);
}

static int serve_connection(int conn, sd_varlink_method_t method,
                            void *userdata) {
    sd_event *event = NULL;
    sd_varlink_server *server = NULL;
    int ret = sd_event_new(&event);
    if (ret < 0)
        return ret;
    ret = sd_varlink_server_new(&server,
                                SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT |
                                    SD_VARLINK_SERVER_INHERIT_USERDATA);
    if (ret < 0)
        goto out;
    ret = sd_varlink_server_add_interface(server,
                                          &vl_interface_website_soss_defused);
    if (ret < 0)
        goto out;
    ret = sd_varlink_server_bind_method_many(
        server, DEFUSED_VARLINK_METHOD_MOUNT, method,
        DEFUSED_VARLINK_METHOD_UNMOUNT, method);
    if (ret < 0)
        goto out;
    sd_varlink_server_set_userdata(server, userdata);
    ret = sd_varlink_server_set_exit_on_idle(server, true);
    if (ret < 0)
        goto out;
    ret = sd_varlink_server_attach_event(server, event, 0);
    if (ret < 0)
        goto out;
    ret = sd_varlink_server_add_connection(server, conn, NULL);
    if (ret < 0)
        goto out;
    conn = -1;
    ret = sd_event_loop(event);

out:
    if (conn >= 0)
        close(conn);
    sd_varlink_server_unref(server);
    sd_event_unref(event);
    return ret;
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

    /* Play the service's success path. The client already opened the device
     * fd it sent to the service, so the response carries no fd. */
    CHECK(serve_connection(conn, method_mount, NULL) == 0);

    char byte = 0x7f;
    int fuse_fd;
    ssize_t n = -1;
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

    /* The received fd must be the *parent* directory, never the mountpoint
     * itself -- holding an fd open on the mount would make a non-lazy
     * umount2() see it as busy (that was the actual bug this test guards
     * against). */
    /* An error status must surface as a nonzero exit. */
    struct {
        const char *parent;
        const char *name;
    } expect = {.parent = expect_parent, .name = expect_name};
    CHECK(serve_connection(conn, method_unmount, &expect) == 0);
    free(dir_copy);
    free(base_copy);

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
    int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
