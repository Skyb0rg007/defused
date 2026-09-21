/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Socket activation for defused without a service manager: binds the
 * Varlink socket, then forks and execs the given program once per
 * connection, handing the connection over exactly as systemd's Accept=yes
 * does.
 *
 * systemd-socket-activate(1) very nearly does this already, but it binds
 * AF_UNIX sockets 0644 with no way to ask for anything else, it does not
 * tag the socket for Varlink discovery, and on EADDRINUSE it unlinks and
 * rebinds even when another process is still serving that socket.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

/* The defaults the .socket unit relies on systemd for: MaxConnections= and
 * MaxConnectionsPerSource=, which for AF_UNIX counts per peer uid. */
#define MAX_CONNECTIONS 64
#define MAX_CONNECTIONS_PER_UID 16

/* Logs "defused-activate: <message>: <strerror(-ret)>" and returns ret. */
__attribute__((__format__(__printf__, 2, 3))) static int
log_error(int ret, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("defused-activate: ", stderr);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", strerror(-ret));
    va_end(ap);
    return ret;
}

/* Mode 0666, so non-root callers can reach it. A stale socket (nothing
 * accepting) is replaced. */
static int listen_socket(const char *path) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(sa.sun_path))
        return log_error(-ENAMETOOLONG, "socket path %s", path);
    strcpy(sa.sun_path, path);
    _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1)
        return log_error(-errno, "socket");
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        if (errno != EADDRINUSE)
            return log_error(-errno, "bind(%s)", path);
        _cleanup_close_ int probe =
            socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (probe == -1 ||
            connect(probe, (struct sockaddr *)&sa, sizeof(sa)) == 0 ||
            errno != ECONNREFUSED)
            return log_error(-EADDRINUSE, "socket %s", path);
        if (unlink(path) == -1 ||
            bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
            return log_error(-errno, "replacing the stale socket %s", path);
    }
    /* Like systemd's XAttrEntryPoint=; kernels before 7.0 refuse it. */
    (void)setxattr(path, "user.varlink", "entrypoint", 10, 0);
    if (chmod(path, 0666) == -1 || listen(fd, SOMAXCONN) == -1) {
        int ret = log_error(-errno, "chmod()/listen() on %s", path);
        unlink(path);
        return ret;
    }
    fprintf(stderr, "defused-activate: listening on %s\n", path);
    return TAKE_FD(fd);
}

/* The connections being served, so both caps can be counted. */
static struct child {
    pid_t pid;
    uid_t uid;
} children[MAX_CONNECTIONS];
static size_t n_children;

static void reap_children(void) {
    for (pid_t pid; (pid = waitpid(-1, NULL, WNOHANG)) > 0;)
        for (size_t i = 0; i < n_children; i++)
            if (children[i].pid == pid) {
                children[i] = children[--n_children];
                break;
            }
}

static size_t connections_of_uid(uid_t uid) {
    size_t n = 0;
    for (size_t i = 0; i < n_children; i++)
        n += children[i].uid == uid;
    return n;
}

/* systemd's Accept=yes handoff: the connection as the one $LISTEN_FDS fd,
 * named "varlink", which is what sd_varlink_invocation(3) looks for. */
static __attribute__((__noreturn__)) void exec_child(int conn, char *argv[]) {
    if (conn != STDERR_FILENO + 1) {
        /* dup2() clears CLOEXEC on the copy; the original stays ours. */
        if (dup2(conn, STDERR_FILENO + 1) == -1)
            _exit(EXIT_FAILURE);
        safe_close(conn);
    } else if (fcntl(conn, F_SETFD, 0) == -1)
        _exit(EXIT_FAILURE);

    char pid[16];
    snprintf(pid, sizeof(pid), "%d", (int)getpid());
    if (setenv("LISTEN_PID", pid, 1) == -1 ||
        setenv("LISTEN_FDS", "1", 1) == -1 ||
        setenv("LISTEN_FDNAMES", "varlink", 1) == -1)
        _exit(EXIT_FAILURE);

    execv(argv[0], argv);
    log_error(-errno, "exec %s", argv[0]);
    _exit(127);
}

/* Returns only on a fatal error. */
static int run(const char *path, char *argv[]) {
    _cleanup_close_ int listen_fd = listen_socket(path);
    if (listen_fd < 0)
        return listen_fd;

    for (;;) {
        _cleanup_close_ int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (conn == -1) {
            if (errno == EINTR)
                continue;
            log_error(-errno, "accept4");
            /* Transient near the cap; keep listening. */
            if (errno == EMFILE || errno == ENFILE || errno == ECONNABORTED)
                continue;
            return -errno;
        }
        /* Only here, so zombies pile up while idle -- never past the cap. */
        reap_children();

        struct ucred cred;
        socklen_t len = sizeof(cred);
        if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
            log_error(-errno, "SO_PEERCRED");
            continue;
        }
        /* Past a cap: closed, so the client fails fast. */
        if (n_children >= MAX_CONNECTIONS ||
            connections_of_uid(cred.uid) >= MAX_CONNECTIONS_PER_UID) {
            fprintf(stderr,
                    "defused-activate: refusing a connection from uid %u: "
                    "%zu being handled (max %d, %d per uid)\n",
                    (unsigned)cred.uid, n_children, MAX_CONNECTIONS,
                    MAX_CONNECTIONS_PER_UID);
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            log_error(-errno, "fork");
            continue;
        }
        if (pid == 0) {
            listen_fd = safe_close(listen_fd);
            exec_child(TAKE_FD(conn), argv);
        }
        children[n_children++] = (struct child){.pid = pid, .uid = cred.uid};
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [--socket=PATH] PROGRAM [ARGUMENT...]\n"
            "\n"
            "Binds the defused Varlink socket and runs PROGRAM once per\n"
            "connection with it on fd 3, the way systemd socket activation\n"
            "with Accept=yes and FileDescriptorName=varlink would. For\n"
            "setups without systemd as the service manager; under systemd,\n"
            "use defused.socket instead.\n"
            "\n"
            "  --socket=PATH  listen here instead of $DEFUSED_SOCKET (or\n"
            "                 %s)\n"
            "\n"
            "At most %d connections are served at a time, %d per peer uid.\n",
            prog, DEFUSED_SOCKET_PATH, MAX_CONNECTIONS,
            MAX_CONNECTIONS_PER_UID);
}

int main(int argc, char *argv[]) {
    const char *path = getenv("DEFUSED_SOCKET");
    if (path == NULL || *path == '\0')
        path = DEFUSED_SOCKET_PATH;

    enum { OPT_SOCKET = 256 };
    static const struct option opts[] = {
        {"socket", required_argument, NULL, OPT_SOCKET},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    /* "+": stop at PROGRAM, so its own options are left for it. */
    for (int c; (c = getopt_long(argc, argv, "+h", opts, NULL)) != -1;) {
        switch (c) {
        case OPT_SOCKET:
            path = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "defused-activate: no program given\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* reap_children() needs the kernel's autoreaping off, and a SIG_IGN
     * disposition survives the exec that started us. */
    signal(SIGCHLD, SIG_DFL);
    return run(path, argv + optind) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
