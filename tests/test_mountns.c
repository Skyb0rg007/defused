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
 *    prove the join happened by sending an unmount request for a non-FUSE
 *    bind mount and checking the response is NotAFuseMount rather than
 *    UnmountFailed.
 *
 *  - test_cannot_join: defused runs unprivileged in the plain host
 *    namespace, like every other test in this suite. The client
 *    unshare(CLONE_NEWUSER|CLONE_NEWNS)'s into a namespace of its own that
 *    defused has no ancestry over. defused cannot legitimately setns()
 *    into it (no CAP_SYS_ADMIN there), and the test checks that this
 *    surfaces cleanly as UnmountFailed/EPERM -- never as a silent
 *    fallback to operating on defused's own namespace instead, which would
 *    be a namespace-confusion bug (e.g. counting FUSE mounts or mounting
 *    against the wrong mount table while believing it's the client's).
 *
 * Neither test reaches a real FUSE mount/unmount. The client creates only a
 * private bind mount inside its own mount namespace.
 *
 * Both scenarios send DEFUSED_OP_UNMOUNT, which now asks polkit before
 * join_peer_mnt_ns() (the same ordering constraint as mount -- see
 * check_polkit_authorized()'s doc comment in defused.c). polkit only lets
 * a *trusted* caller (uid 0, or an action's declared owner) check another
 * identity's authorization at all, and neither defused nor its simulated
 * client is real uid 0 in this unprivileged harness, so both scenarios
 * are expected to be turned away there with UnmountFailed, before ever
 * reaching the setns() logic these tests were written to distinguish -- so,
 * unprivileged, the two scenarios are no longer distinguishable from each
 * other via this harness, and neither actually exercises setns() at all.
 * Both CHECKs below accept UnmountFailed alongside each test's originally
 * expected error so they still pass unprivileged (and still verify the
 * polkit gate really runs before anything namespace-sensitive).
 * test_cannot_join still catches the bug it cares most about either way:
 * silently falling back to defused's own namespace instead of failing would
 * show up as neither of its two accepted errors. Real, trusted-caller (root)
 * coverage of both mount and unmount across mount namespaces lives in
 * packaging/nixos/tests/mount-namespace.nix instead.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused_proto.h"
#include "test_timeout.h"

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

/* Sends an unmount request for a bind mount that is intentionally not FUSE.
 * A service that can enter the client's namespace should therefore return
 * NotAFuseMount; one that cannot should fail earlier with UnmountFailed. In
 * this unprivileged harness both are instead turned away even earlier, by
 * polkit -- see the file-level comment above. Takes ownership of sock_fd. */
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

    _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
    /* Borrowed from the link, valid until its next call; not ours to unref. */
    sd_json_variant *reply = NULL;
    const char *error_id = NULL;
    ret = sd_varlink_connect_fd(&link, sock);
    if (ret < 0)
        return ret;
    TAKE_FD(sock);
    ret = sd_varlink_set_allow_fd_passing_input(link, true);
    if (ret < 0)
        return ret;
    ret = sd_varlink_set_allow_fd_passing_output(link, true);
    if (ret < 0)
        return ret;
    ret = sd_varlink_push_dup_fd(link, parent_fd);
    if (ret < 0)
        return ret;
    ret = sd_varlink_callbo(
        link, DEFUSED_VARLINK_METHOD_UNMOUNT, &reply, &error_id,
        SD_JSON_BUILD_PAIR_UNSIGNED("parentFileDescriptor", 0),
        SD_JSON_BUILD_PAIR_STRING("name", "target"),
        SD_JSON_BUILD_PAIR_BOOLEAN("lazy", true));
    if (ret < 0)
        return ret;
    ret = defused_error_from_reply(error_id, reply, err);
    if (ret < 0)
        return ret;
    return 0;
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

    _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1 || bind(fd, (struct sockaddr *)sa, *len) == -1 ||
        listen(fd, 1) == -1) {
        perror("listen");
        return -errno;
    }
    return TAKE_FD(fd);
}

static int connect_addr(const struct sockaddr_un *sa, socklen_t len) {
    _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1 || connect(fd, (const struct sockaddr *)sa, len) == -1) {
        perror("connect");
        return -errno;
    }
    return TAKE_FD(fd);
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
            int client_sock = connect_addr(&sa, salen);
            if (client_sock < 0)
                _exit(1);
            struct defused_error err;
            int ret = send_non_fuse_umount_request(client_sock, &err);
            _exit(
                ret == 0 &&
                        (!strcmp(err.id,
                                 DEFUSED_VARLINK_ERROR_NOT_A_FUSE_MOUNT) ||
                         !strcmp(err.id, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED))
                    ? 0
                    : 1);
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
        write(result_pipe[1], &byte, 1);
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
        int client_sock = connect_addr(&sa, salen);
        if (client_sock < 0)
            _exit(1);
        struct defused_error err;
        int ret = send_non_fuse_umount_request(client_sock, &err);
        bool accepted =
            ret == 0 && !strcmp(err.id, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED);
        if (!accepted)
            fprintf(stderr, "test_cannot_join: got %s, expected %s\n",
                    err.id[0] ? err.id : "a successful reply",
                    DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED);
        _exit(accepted ? 0 : 1);
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

/* Meson reads 77 as a skip. */
#define MESON_EXIT_SKIP 77

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
