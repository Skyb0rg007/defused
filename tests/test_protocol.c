/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Exercises the defused_proto.h Varlink protocol against a real `defused`
 * process without requiring root or CAP_SYS_ADMIN. The requests intentionally
 * stop before the real mount(2) call, since that's the one part of request
 * handling that needs privilege to succeed.
 */
#define _GNU_SOURCE
#include "defused_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

static int spawn_defused(const char *defused_path, int *client_sock,
                         pid_t *out_pid) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
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
        execl(defused_path, "defused", NULL);
        perror("exec");
        _exit(127);
    }

    close(sv[1]);
    *client_sock = sv[0];
    *out_pid = pid;
    return 0;
}

static int send_mount_req(int sock, const struct defused_mount_req *req,
                          int dev_fd, int mnt_fd, struct defused_resp *resp) {
    sd_varlink *link = NULL;
    sd_json_variant *reply = NULL;
    const char *error_id = NULL;
    int ret = sd_varlink_connect_fd(&link, sock);
    if (ret < 0)
        return ret;
    sock = -1;

    ret = sd_varlink_set_allow_fd_passing_input(link, true);
    if (ret < 0)
        goto out;
    ret = sd_varlink_set_allow_fd_passing_output(link, true);
    if (ret < 0)
        goto out;
    ret = sd_varlink_push_dup_fd(link, dev_fd);
    if (ret < 0)
        goto out;
    ret = sd_varlink_push_dup_fd(link, mnt_fd);
    if (ret < 0)
        goto out;

    ret = sd_varlink_callbo(
        link, DEFUSED_VARLINK_METHOD_MOUNT, &reply, &error_id,
        SD_JSON_BUILD_PAIR_UNSIGNED("mountFlags", req->mount_flags),
        SD_JSON_BUILD_PAIR_UNSIGNED("maxRead", req->max_read),
        SD_JSON_BUILD_PAIR_UNSIGNED("blockSize", req->blksize),
        SD_JSON_BUILD_PAIR_STRING("fsName", req->fsname),
        SD_JSON_BUILD_PAIR_STRING("subtype", req->subtype));
    if (ret < 0)
        goto out;
    if (error_id != NULL) {
        fprintf(stderr, "FAIL: Varlink error %s\n", error_id);
        ret = -EBADMSG;
        goto out;
    }

    static const sd_json_dispatch_field dispatch_table[] = {
        {"status", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct defused_resp, status), SD_JSON_MANDATORY},
        {"sysErrno", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int32,
         offsetof(struct defused_resp, sys_errno), SD_JSON_MANDATORY},
        {},
    };
    ret = sd_json_dispatch(reply, dispatch_table, 0, resp);
    if (ret < 0)
        goto out;

out:
    sd_json_variant_unref(reply);
    sd_varlink_flush_close_unref(link);
    if (sock >= 0)
        close(sock);
    return ret;
}

/* Runs one mount request against a fresh defused instance and reports the
 * response status via *out_status, without asserting what it should be --
 * callers decide what counts as a pass. */
static int run_mount_req(const char *defused_path,
                         const struct defused_mount_req *req, const char *path,
                         const char *dev_path, uint32_t *out_status) {
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
    int dev_fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        ret = -errno;
        perror(dev_path);
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
    if (!WIFEXITED(wstatus)) {
        fprintf(stderr, "FAIL: service did not exit normally\n");
        return -ECHILD;
    }
    *out_status = resp.status;
    return 0;
}

static int run_mount_req_expect(const char *defused_path,
                                const struct defused_mount_req *req,
                                const char *path, uint32_t expect_status) {
    uint32_t status;
    int ret = run_mount_req(defused_path, req, path, "/dev/null", &status);
    if (ret < 0)
        return ret;
    if (status != expect_status) {
        fprintf(stderr, "FAIL: expected status %u, got %u\n", expect_status,
                status);
        return -EINVAL;
    }
    return 0;
}

/* The mountpoint ownership check happens before the polkit check, so it
 * takes a real self-owned mountpoint (and a real /dev/fuse fd, since
 * check_fuse_device_fd() validates the device major/minor) to reach
 * check_polkit_authorized() at all. Skips gracefully if this sandbox has
 * no /dev/fuse, rather than asserting anything about polkit's specific
 * answer -- what matters here is that an unauthorized request never gets
 * past this gate to the privileged mount syscalls, not what a particular
 * polkit configuration decides. */
static int test_polkit_gate(const char *defused_path) {
    int probe = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (probe < 0) {
        fprintf(stderr,
                "SKIP: /dev/fuse not usable here (%s), skipping polkit gate "
                "test\n",
                strerror(errno));
        return 0;
    }
    close(probe);

    char dir[] = "/tmp/defused-polkit-test-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }

    struct defused_mount_req req = {};
    uint32_t status = DEFUSED_OK;
    int ret = run_mount_req(defused_path, &req, dir, "/dev/fuse", &status);
    rmdir(dir);
    if (ret < 0)
        return ret;

    /* Without an interactive polkit agent, an AUTH_ADMIN_KEEP action can
     * never succeed; either polkit is reachable and says no
     * (DEFUSED_ERR_NOT_ALLOWED), or it isn't reachable at all in this
     * sandbox and the check fails closed (DEFUSED_ERR_MOUNT_FAILED). Either
     * is a pass -- DEFUSED_OK (or any earlier, deterministic error) would
     * mean the gate was skipped or something regressed before it. */
    if (status != DEFUSED_ERR_NOT_ALLOWED &&
        status != DEFUSED_ERR_MOUNT_FAILED) {
        fprintf(stderr,
                "FAIL: expected the polkit gate to block the mount (got "
                "status %u)\n",
                status);
        return -EINVAL;
    }
    return 0;
}

/* Spawns `defused --daemon`, pointed at sock_path via $DEFUSED_SOCKET
 * instead of the real /run/defused/defused.sock, mirroring how
 * nixos/tests/daemon.nix exercises the same knob for non-systemd setups. */
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

/* Connects to a listening AF_UNIX SOCK_STREAM socket at sock_path, retrying
 * while the daemon hasn't created it yet (ENOENT) or hasn't called listen()
 * yet (ECONNREFUSED). */
static int connect_daemon_socket(const char *sock_path) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(sock_path) >= sizeof(sa.sun_path))
        return -ENAMETOOLONG;
    (void)strlcpy(sa.sun_path, sock_path, sizeof(sa.sun_path));

    for (int i = 0; i < 100; i++) {
        int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

/* Connects to an already-running --daemon instance's socket at sock_path
 * (retrying while it isn't up yet, see connect_daemon_socket()) and runs
 * one mount request through it, failing unless the response status is
 * exactly expect_status. */
static int run_daemon_mount_req(const char *sock_path,
                                const struct defused_mount_req *req,
                                const char *path, uint32_t expect_status) {
    int sock = connect_daemon_socket(sock_path);
    if (sock < 0) {
        fprintf(stderr, "FAIL: could not connect to daemon socket: %s\n",
                strerror(-sock));
        return sock;
    }

    int mnt_fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dev_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (mnt_fd < 0 || dev_fd < 0) {
        int ret = -errno;
        perror("open");
        if (mnt_fd >= 0)
            close(mnt_fd);
        if (dev_fd >= 0)
            close(dev_fd);
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

/* Exercises --daemon end to end: spawn the daemon against a scratch socket
 * path, connect to it like a real client would, and confirm a real Varlink
 * mount request round-trips through the forked-child connection handler.
 * Uses the same bad-mount-flags negative case as run_mount_req_expect()
 * above, since (as there) a real mount() needs root.
 *
 * Drives two requests back-to-back, without waiting for the first child to
 * be reaped before starting the second: a single request wouldn't tell us
 * the daemon keeps accepting new connections after handling one (i.e. that
 * it's really forking per connection, not a one-shot handler), and issuing
 * them without a pause also exercises run_fork_daemon()'s live_children
 * cap under light concurrency without tripping it. */
static int test_daemon_mode(const char *defused_path) {
    char dir[] = "/tmp/defused-daemon-test-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }
    char sock_path[sizeof(dir) + 16];
    snprintf(sock_path, sizeof(sock_path), "%s/defused.sock", dir);

    pid_t pid;
    int ret = spawn_defused_daemon(defused_path, sock_path, &pid);
    if (ret < 0) {
        rmdir(dir);
        return ret;
    }

    struct defused_mount_req bad_opt = {
        .mount_flags = 1u << 31, /* never in DEFUSED_MOUNT_FLAGS_MASK */
    };
    ret =
        run_daemon_mount_req(sock_path, &bad_opt, ".", DEFUSED_ERR_BAD_OPTION);
    if (ret < 0)
        goto out_kill;
    ret =
        run_daemon_mount_req(sock_path, &bad_opt, ".", DEFUSED_ERR_BAD_OPTION);

out_kill:
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    unlink(sock_path);
    rmdir(dir);
    return ret;
}

/* --daemon does not create the socket's parent directory -- it just binds
 * inside a directory that must already exist (e.g. via systemd's
 * RuntimeDirectory=, see packaging/nixos/tests/daemon.nix). Confirms it
 * fails fast with a nonzero exit rather than creating the directory or
 * hanging. */
static int test_daemon_missing_socket_dir(const char *defused_path) {
    char dir[] = "/tmp/defused-daemon-missing-dir-test-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }
    char missing_dir[sizeof(dir) + 16];
    snprintf(missing_dir, sizeof(missing_dir), "%s/does-not-exist", dir);
    char sock_path[sizeof(missing_dir) + 16];
    snprintf(sock_path, sizeof(sock_path), "%s/defused.sock", missing_dir);

    pid_t pid;
    int ret = spawn_defused_daemon(defused_path, sock_path, &pid);
    if (ret < 0) {
        rmdir(dir);
        return ret;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ret = -errno;
        perror("waitpid");
        goto out;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) == 0) {
        fprintf(stderr,
                "FAIL: expected --daemon to exit nonzero with a missing "
                "socket directory (status 0x%x)\n",
                status);
        ret = -EINVAL;
        goto out;
    }
    if (access(missing_dir, F_OK) == 0 || errno != ENOENT) {
        fprintf(stderr, "FAIL: --daemon should not have created the socket "
                        "directory\n");
        ret = -EINVAL;
        goto out;
    }
    ret = 0;

out:
    rmdir(dir);
    return ret;
}

/* Must match DEFUSED_DAEMON_MAX_CONNECTIONS in src/defused.c: the number of
 * concurrent connections test_daemon_connection_cap() needs to open to pin
 * run_fork_daemon()'s live_children count at the cap. */
#define TEST_DAEMON_MAX_CONNECTIONS 64

/* Opens n connections to sock_path into slots[0..n), leaving each one open
 * without sending a request, so every forked child stays alive blocked on
 * read and live_children holds at n. The first connection goes through
 * connect_daemon_socket() to ride out the daemon's startup race; the rest
 * connect directly since the daemon is known to be up by then. On failure,
 * closes whatever it already opened. */
static int open_daemon_connections(const char *sock_path, int *slots, int n) {
    slots[0] = connect_daemon_socket(sock_path);
    if (slots[0] < 0)
        return slots[0];

    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    (void)strlcpy(sa.sun_path, sock_path, sizeof(sa.sun_path));
    for (int i = 1; i < n; i++) {
        int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock == -1 ||
            connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
            int ret = -errno;
            perror("connect");
            if (sock >= 0)
                close(sock);
            for (int j = 0; j < i; j++)
                close(slots[j]);
            return ret;
        }
        slots[i] = sock;
    }
    return 0;
}

/* Exercises the DEFUSED_DAEMON_MAX_CONNECTIONS cap in run_fork_daemon():
 * opens exactly the cap's worth of connections and leaves them open without
 * sending a request, so live_children sits at the cap. A further connection
 * is then accepted by the kernel (connect() succeeds immediately, since
 * that only requires room in the listen backlog) but should be closed by
 * the daemon rather than handed to a forked child, so the client sees EOF
 * without ever getting a response. Also checks the connections under the
 * cap are untouched by the overflow. */
static int test_daemon_connection_cap(const char *defused_path) {
    char dir[] = "/tmp/defused-daemon-cap-test-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }
    char sock_path[sizeof(dir) + 16];
    snprintf(sock_path, sizeof(sock_path), "%s/defused.sock", dir);

    pid_t pid;
    int ret = spawn_defused_daemon(defused_path, sock_path, &pid);
    if (ret < 0) {
        rmdir(dir);
        return ret;
    }

    int slots[TEST_DAEMON_MAX_CONNECTIONS];
    ret =
        open_daemon_connections(sock_path, slots, TEST_DAEMON_MAX_CONNECTIONS);
    if (ret < 0)
        goto out_kill;

    /* Give the single-threaded accept loop a moment to accept()/fork() all
     * of the above before adding the connection meant to overflow the cap
     * -- otherwise a slow accept loop could still have room left and
     * legitimately accept it. */
    usleep(200000);

    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    (void)strlcpy(sa.sun_path, sock_path, sizeof(sa.sun_path));
    int overflow = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (overflow == -1) {
        ret = -errno;
        perror("socket");
        goto out_close;
    }
    if (connect(overflow, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        ret = -errno;
        perror("connect");
        close(overflow);
        goto out_close;
    }

    struct pollfd pfd = {.fd = overflow, .events = POLLIN};
    ret = poll(&pfd, 1, 2000);
    if (ret <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) {
        fprintf(stderr, "FAIL: overflow connection was not dropped\n");
        ret = -EINVAL;
        goto out_close_overflow;
    }
    char buf[1];
    ssize_t n = recv(overflow, buf, sizeof(buf), 0);
    if (n != 0) {
        fprintf(stderr, "FAIL: expected EOF on overflow connection, got %zd\n",
                n);
        ret = -EINVAL;
        goto out_close_overflow;
    }

    ret = 0;
    for (int i = 0; i < TEST_DAEMON_MAX_CONNECTIONS; i++) {
        struct pollfd p = {.fd = slots[i], .events = POLLIN};
        if (poll(&p, 1, 0) > 0) {
            fprintf(stderr, "FAIL: connection %d under the cap was dropped\n",
                    i);
            ret = -EINVAL;
            break;
        }
    }

out_close_overflow:
    close(overflow);
out_close:
    for (int i = 0; i < TEST_DAEMON_MAX_CONNECTIONS; i++)
        close(slots[i]);
out_kill:
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    unlink(sock_path);
    rmdir(dir);
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/defused\n", argv[0]);
        return 2;
    }

    struct defused_mount_req bad_opt = {
        .mount_flags = 1u << 31, /* never in DEFUSED_MOUNT_FLAGS_MASK */
    };
    if (run_mount_req_expect(argv[1], &bad_opt, ".", DEFUSED_ERR_BAD_OPTION) !=
        0)
        return 1;

    if (getuid() != 0) {
        struct defused_mount_req root_owned = {};
        if (run_mount_req_expect(argv[1], &root_owned, "/",
                                 DEFUSED_ERR_NOT_ALLOWED) != 0)
            return 1;

        if (test_polkit_gate(argv[1]) != 0)
            return 1;
    }

    if (test_daemon_mode(argv[1]) != 0)
        return 1;

    if (test_daemon_missing_socket_dir(argv[1]) != 0)
        return 1;

    if (test_daemon_connection_cap(argv[1]) != 0)
        return 1;

    return 0;
}
