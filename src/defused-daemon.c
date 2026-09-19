/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * --daemon: listening socket and accept loop, without systemd.
 */
#define _GNU_SOURCE
#include "defused-daemon.h"
#include "common.h"
#include "defused_proto.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static int create_listening_socket(void)
    __attribute__((__warn_unused_result__));
static void tag_varlink_entrypoint(const char *path)
    __attribute__((__nonnull__(1)));
static int bind_unix_socket(int fd, const struct sockaddr_un *sa,
                            socklen_t sa_len, const char *path)
    __attribute__((__nonnull__(2, 4), __warn_unused_result__));

/* A backstop like systemd's MaxConnections=. */
#define DEFUSED_DAEMON_MAX_CONNECTIONS 64

static volatile sig_atomic_t live_children = 0;

/* Async-signal-safe: only waitpid() and a sig_atomic_t. */
static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        live_children--;
    errno = saved_errno;
}

/* Past the cap: accept and close, so the client fails fast. */
int defused_run_fork_daemon(int (*handle_connection)(int sock_fd)) {
    _cleanup_close_ int listen_fd = create_listening_socket();
    if (listen_fd < 0)
        return listen_fd;

    /* SA_RESTART: accept4() only sees EINTR from other signals. */
    struct sigaction sa = {
        .sa_handler = sigchld_handler,
        .sa_flags = SA_RESTART,
    };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        int ret = -errno;
        fprintf(stderr, "defused: sigaction(SIGCHLD): %s\n", strerror(errno));
        return ret;
    }

    for (;;) {
        _cleanup_close_ int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (conn == -1) {
            /* Transient near the cap; keep listening. */
            if (errno == EINTR)
                continue;
            if (errno == EMFILE || errno == ENFILE || errno == ECONNABORTED) {
                fprintf(stderr, "defused: accept4: %s\n", strerror(errno));
                continue;
            }
            int ret = -errno;
            fprintf(stderr, "defused: accept4: %s\n", strerror(errno));
            return ret;
        }

        if (live_children >= DEFUSED_DAEMON_MAX_CONNECTIONS) {
            fprintf(stderr,
                    "defused: refusing connection: %d already being handled "
                    "(max %d)\n",
                    (int)live_children, DEFUSED_DAEMON_MAX_CONNECTIONS);
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            fprintf(stderr, "defused: fork: %s\n", strerror(errno));
            continue;
        }
        if (pid == 0) {
            listen_fd = safe_close(listen_fd);
            /* This child waits for a sandbox child of its own. */
            struct sigaction dfl = {.sa_handler = SIG_DFL};
            sigemptyset(&dfl.sa_mask);
            (void)sigaction(SIGCHLD, &dfl, NULL);
            _exit(handle_connection(TAKE_FD(conn)));
        }
        live_children++;
    }
}

/* Mode 0666, so non-root callers can reach it. */
static int create_listening_socket(void) {
    const char *path = getenv("DEFUSED_SOCKET");
    if (path == NULL || *path == '\0')
        path = DEFUSED_SOCKET_PATH;

    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "defused: socket path too long: %s\n", path);
        return -ENAMETOOLONG;
    }
    (void)strlcpy(sa.sun_path, path, sizeof(sa.sun_path));

    _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
        fprintf(stderr, "defused: socket: %s\n", strerror(errno));
        return -errno;
    }

    int ret = bind_unix_socket(fd, &sa, sizeof(sa), path);
    if (ret < 0)
        return ret;

    tag_varlink_entrypoint(path);

    if (chmod(path, 0666) == -1) {
        ret = -errno;
        fprintf(stderr, "defused: chmod(%s): %s\n", path, strerror(errno));
        goto fail_unlink;
    }

    if (listen(fd, SOMAXCONN) == -1) {
        ret = -errno;
        fprintf(stderr, "defused: listen(%s): %s\n", path, strerror(errno));
        goto fail_unlink;
    }

    fprintf(stderr, "defused: listening on %s\n", path);
    return TAKE_FD(fd);

fail_unlink:
    unlink(path);
    return ret;
}

/* Like systemd's XAttrEntryPoint=; kernels before 7.0 refuse with EPERM. */
static void tag_varlink_entrypoint(const char *path) {
    static const char value[] = "entrypoint";
    if (setxattr(path, "user.varlink", value, sizeof(value) - 1, 0) == 0)
        return;
    if (errno == EPERM || errno == ENOTSUP || errno == EOPNOTSUPP)
        return;
    fprintf(stderr, "defused: setxattr(%s, user.varlink): %s\n", path,
            strerror(errno));
}

/* A stale socket (ECONNREFUSED) is unlinked and rebound. */
static int bind_unix_socket(int fd, const struct sockaddr_un *sa,
                            socklen_t sa_len, const char *path) {
    if (bind(fd, (const struct sockaddr *)sa, sa_len) == 0)
        return 0;
    if (errno != EADDRINUSE) {
        int ret = -errno;
        fprintf(stderr, "defused: bind(%s): %s\n", path, strerror(errno));
        return ret;
    }

    _cleanup_close_ int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (probe == -1) {
        int ret = -errno;
        fprintf(stderr, "defused: socket probe: %s\n", strerror(errno));
        return ret;
    }

    if (connect(probe, (const struct sockaddr *)sa, sa_len) == 0) {
        fprintf(stderr, "defused: socket already in use: %s\n", path);
        return -EADDRINUSE;
    }
    if (errno != ECONNREFUSED) {
        int ret = -errno;
        fprintf(stderr, "defused: cannot connect to existing socket %s: %s\n",
                path, strerror(errno));
        return ret;
    }

    if (unlink(path) == -1) {
        int ret = -errno;
        fprintf(stderr, "defused: unlink stale socket %s: %s\n", path,
                strerror(errno));
        return ret;
    }
    if (bind(fd, (const struct sockaddr *)sa, sa_len) == -1) {
        int ret = -errno;
        fprintf(stderr, "defused: bind(%s): %s\n", path, strerror(errno));
        return ret;
    }

    return 0;
}
