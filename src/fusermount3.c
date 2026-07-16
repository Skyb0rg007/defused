/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Drop-in replacement for libfuse's setuid-root fusermount3,
 * implemented as an unprivileged client of defused.service.
 *
 * The fusermount3 binary receives a communication file descriptor indicated
 * via the _FUSE_COMMFD environment variable or --comm-fd command-line option.
 * After the mount occurs, the the opened /dev/fuse file descriptor will be
 * sent to that file descriptor via SCM_RIGHTS (along with a single zero byte).
 *
 * All option parsing happens here, as the server uses a binary protocol.
 */
#define _GNU_SOURCE
#include "defused.h"
#include "util.h"

#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#define FUSE_COMMFD_ENV "_FUSE_COMMFD"

#ifndef DEFUSED_VERSION
#define DEFUSED_VERSION "unknown"
#endif

/* This table is copied from libfuse */
struct flag_opt {
    /* Option name */
    const char *opt;
    /* Corresponding defused protocol bitmask */
    uint32_t flag;
    /* Does this option set or clear the bit? */
    bool on;
    /* Is this option available to defused's unprivileged client path? */
    bool safe;
};

static const struct flag_opt flag_opts[] = {
    {"rw", DEFUSED_MOUNT_RDONLY, false, true},
    {"ro", DEFUSED_MOUNT_RDONLY, true, true},
    {"suid", 0, true, false},
    {"nosuid", 0, false, true},
    {"dev", DEFUSED_MOUNT_ALLOW_DEV, true, true},
    {"nodev", DEFUSED_MOUNT_ALLOW_DEV, false, true},
    {"exec", DEFUSED_MOUNT_NOEXEC, false, true},
    {"noexec", DEFUSED_MOUNT_NOEXEC, true, true},
    {"async", DEFUSED_MOUNT_SYNCHRONOUS, false, true},
    {"sync", DEFUSED_MOUNT_SYNCHRONOUS, true, true},
    {"noatime", DEFUSED_MOUNT_NOATIME, true, true},
    {"nodiratime", DEFUSED_MOUNT_NODIRATIME, true, true},
    {"norelatime", 0, false, true},
    {"nostrictatime", 0, false, true},
    {"symfollow", DEFUSED_MOUNT_NOSYMFOLLOW, false, true},
    {"nosymfollow", DEFUSED_MOUNT_NOSYMFOLLOW, true, true},
    {"dirsync", DEFUSED_MOUNT_DIRSYNC, true, true},
    {NULL, 0, false, false},
};

static const char *const short_opts = "hVo:uzq";

static const struct option long_opts[] = {
    {"unmount", no_argument, NULL, 'u'},
    {"lazy", no_argument, NULL, 'z'},
    {"quiet", no_argument, NULL, 'q'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {"options", required_argument, NULL, 'o'},
    {"auto-unmount", no_argument, NULL, 'U'},
    {"comm-fd", required_argument, NULL, 'c'},
    {"sync-init", no_argument, NULL, 'S'},
    {NULL, 0, NULL, 0},
};

static int do_mount(const char *mnt, const char *opts, int cfd)
    __attribute__((__nonnull__(1, 2), __warn_unused_result__));
static int do_unmount(const char *mnt, bool lazy)
    __attribute__((__nonnull__(1)));
static int wait_and_auto_unmount(int cfd, const char *mnt)
    __attribute__((__nonnull__(2), __warn_unused_result__));
static int connect_service(void) __attribute__((__warn_unused_result__));
static int transact(const union defused_req *req, size_t req_len,
                    const int *fds, size_t fd_count, struct defused_resp *resp)
    __attribute__((__nonnull__(1, 3, 5), __warn_unused_result__));
static void print_service_error(uint32_t op, const char *mnt,
                                const struct defused_resp *resp)
    __attribute__((__nonnull__(2, 3)));
static int parse_mount_opts(const char *opts, struct defused_mount_req *req)
    __attribute__((__nonnull__(1, 2), __warn_unused_result__));
static int copy_name(char *dst, size_t dstsz, const char *what, const char *s,
                     unsigned len)
    __attribute__((__nonnull__(1, 3, 4), __warn_unused_result__));
static int parse_u32(const char *s, unsigned len, const char *pfx,
                     uint32_t *out)
    __attribute__((__nonnull__(1, 3, 4), __warn_unused_result__));

static noreturn void usage(void) __attribute__((__noreturn__));
static noreturn void die(const char *fmt, ...)
    __attribute__((__noreturn__, __format__(__printf__, 1, 2)));

static const char *progname;
static bool quiet;
static bool auto_unmount;

int main(int argc, char *argv[]) {
    progname = argc > 0 ? argv[0] : "fusermount3";

    int exit_status = EXIT_FAILURE;
    bool unmount = false;
    bool lazy = false;
    bool setup_auto_unmount_only = false;
    const char *opts = "";
    const char *commfd_str = NULL;
    char *mnt = NULL;
    int ch;
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            usage();
            break;
        case 'V':
            printf("fusermount3 version: %s (defused)\n", DEFUSED_VERSION);
            return 0;
        case 'o':
            opts = optarg;
            break;
        case 'u':
            unmount = true;
            break;
        case 'z':
            lazy = true;
            break;
        case 'q':
            quiet = true;
            break;
        case 'U':
            unmount = true;
            auto_unmount = true;
            setup_auto_unmount_only = true;
            break;
        case 'c':
            commfd_str = optarg;
            break;
        case 'S':
            die("--sync-init is not supported");
        default:
            return EXIT_FAILURE;
        }
    }

    if (lazy && !unmount)
        die("-z can only be used with -u");

    if (optind >= argc)
        die("missing mountpoint argument");

    if (argc > optind + 1)
        die("extra arguments after the mountpoint");

    if (getuid() == 0 || geteuid() == 0)
        die("root callers are not handled by defused");

    mnt = fuse_mnt_resolve_path(progname, argv[optind]);
    if (mnt == NULL)
        goto out;

    if (unmount && !setup_auto_unmount_only) {
        exit_status = do_unmount(mnt, lazy) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        goto out;
    }

    if (commfd_str == NULL)
        commfd_str = getenv(FUSE_COMMFD_ENV);
    if (commfd_str == NULL) {
        fprintf(stderr, "%s: old style mounting not supported\n", progname);
        goto out;
    }

    long cfd_long;
    if (libfuse_strtol(commfd_str, &cfd_long) < 0 || cfd_long < 0 ||
        cfd_long > INT_MAX) {
        fprintf(stderr, "%s: invalid _FUSE_COMMFD: %s\n", progname, commfd_str);
        goto out;
    }
    int cfd = (int)cfd_long;

    struct stat st;
    if (fstat(cfd, &st) == -1) {
        fprintf(stderr, "%s: fstat of comm fd %d failed: %s\n", progname, cfd,
                strerror(errno));
        goto out;
    }

    if (!S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "%s: file descriptor %d is not a socket\n", progname,
                cfd);
        goto out;
    }

    if (!setup_auto_unmount_only) {
        if (do_mount(mnt, opts, cfd) < 0) {
            exit_status = EXIT_FAILURE;
            goto out;
        }
        if (!auto_unmount) {
            exit_status = EXIT_SUCCESS;
            goto out;
        }
    }
    exit_status =
        wait_and_auto_unmount(cfd, mnt) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

out:
    free(mnt);
    return exit_status;
}

static int do_mount(const char *mnt, const char *opts, int cfd) {
    union defused_req u = {0};
    u.mount.hdr.magic = DEFUSED_PROTO_MAGIC;
    u.mount.hdr.version = DEFUSED_PROTO_VERSION;
    u.mount.hdr.op = DEFUSED_OP_MOUNT;
    int ret = parse_mount_opts(opts, &u.mount);
    if (ret < 0)
        return ret;
    int mnt_fd = -1;
    int fuse_fd = -1;

    /* Resolve the mountpoint to a file descriptor.
     * This file descriptor is sent to the service to perform the mount. */
    mnt_fd = open(mnt, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1) {
        ret = -errno;
        fprintf(stderr, "%s: failed to access mountpoint %s: %s\n", progname,
                mnt, strerror(errno));
        goto out;
    }

    const char *dev_path = getenv("DEFUSED_FUSE_DEVICE");
    if (!dev_path || !*dev_path)
        dev_path = "/dev/fuse";
    fuse_fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (fuse_fd == -1) {
        ret = -errno;
        fprintf(stderr, "%s: failed to open %s: %s\n", progname, dev_path,
                strerror(errno));
        goto out;
    }

    struct defused_resp resp = {0};
    int fds[] = {fuse_fd, mnt_fd};
    int res = transact(&u, sizeof(u.mount), fds, 2, &resp);
    if (res < 0) {
        ret = res;
        goto out;
    }
    if (resp.status != DEFUSED_OK) {
        print_service_error(DEFUSED_OP_MOUNT, mnt, &resp);
        ret = -EPERM;
        goto out;
    }

    ret = send_fd(cfd, fuse_fd);
    if (ret < 0) {
        /* The library will never get the fd, so don't leave the filesystem
         * mounted -- same cleanup fusermount3 does, via the service. */
        quiet = true;
        (void)do_unmount(mnt, true);
        goto out;
    }

out:
    if (mnt_fd >= 0)
        close(mnt_fd);
    if (fuse_fd >= 0)
        close(fuse_fd);
    return ret;
}

static int do_unmount(const char *mnt, bool lazy) {
    if (!strcmp(mnt, "/")) {
        fprintf(stderr, "%s: refusing to unmount /\n", progname);
        return -EINVAL;
    }
    int ret = 0;
    char *dir_copy = NULL;
    char *base_copy = NULL;
    int parent_fd = -1;

    /* dirname()/basename() may modify their argument in place and may
     * return a pointer into it, so each gets its own copy to work on. */
    dir_copy = strdup(mnt);
    base_copy = strdup(mnt);
    if (!dir_copy || !base_copy) {
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
        ret = -ENOMEM;
        goto out;
    }
    const char *parent = dirname(dir_copy);
    const char *name = basename(base_copy);
    if (strlen(name) >= DEFUSED_MAX_FILENAME) {
        fprintf(stderr, "%s: mountpoint name too long: %s\n", progname, name);
        ret = -ENAMETOOLONG;
        goto out;
    }

    /* Open the parent directory, not the FUSE mount directory itself.
     * This is to make sure the umount2() call doesn't fail due to a held
     * file descriptor. */
    parent_fd = open(parent, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd == -1) {
        ret = -errno;
        if (!quiet)
            fprintf(stderr, "%s: failed to access %s: %s\n", progname, parent,
                    strerror(errno));
        goto out;
    }

    union defused_req u = {
        .umount = {.hdr = {DEFUSED_PROTO_MAGIC, DEFUSED_PROTO_VERSION,
                           DEFUSED_OP_UNMOUNT},
                   .lazy = lazy}};
    (void)strlcpy(u.umount.name, name, sizeof(u.umount.name));

    struct defused_resp resp = {0};
    int fds[] = {parent_fd};
    int res = transact(&u, sizeof(u.umount), fds, 1, &resp);
    if (res < 0) {
        ret = res;
        goto out;
    }
    if (resp.status != DEFUSED_OK) {
        print_service_error(DEFUSED_OP_UNMOUNT, mnt, &resp);
        ret = -EPERM;
        goto out;
    }

out:
    if (parent_fd >= 0)
        close(parent_fd);
    free(dir_copy);
    free(base_copy);
    return ret;
}

/*
 * Starts the auto_unmount daemon.
 * Creates a new process tree, closes all file descriptors,
 * blocks all signals, and waits for the fuse server to exit (seen via EOF
 * on the communication socket).
 * Then it lazily unmounts the filesystem.
 */
static int wait_and_auto_unmount(int cfd, const char *mnt) {
    int ret = close_inherited_fds(cfd);
    if (ret < 0)
        return ret;

    (void)setsid();
    if (chdir("/") == -1)
        return -errno;

    sigset_t sigs;
    sigfillset(&sigs);
    sigprocmask(SIG_BLOCK, &sigs, NULL);

    for (;;) {
        char buf[16];
        ssize_t n = recv(cfd, buf, sizeof(buf), 0);
        if (n == 0)
            break;
        if (n < 0 && errno != EINTR)
            break;
    }

    quiet = true;
    return do_unmount(mnt, true);
}

static int connect_service(void) {
    const char *path = getenv("DEFUSED_SOCKET");
    if (path == NULL || *path == '\0')
        path = DEFUSED_SOCKET_PATH;

    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "%s: socket path too long: %s\n", progname, path);
        return -ENAMETOOLONG;
    }
    (void)strlcpy(sa.sun_path, path, sizeof(sa.sun_path));

    int ret = 0;
    int sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (sock == -1) {
        ret = -errno;
        fprintf(stderr, "%s: socket: %s\n", progname, strerror(errno));
        return ret;
    }
    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        ret = -errno;
        fprintf(stderr, "%s: cannot connect to the defused service at %s: %s\n",
                progname, path, strerror(errno));
        goto out_close;
    }
    return sock;

out_close:
    close(sock);
    return ret;
}

/* One request/response with the service */
static int transact(const union defused_req *req, size_t req_len,
                    const int *fds, size_t fd_count,
                    struct defused_resp *resp) {
    if (fd_count > 2)
        return -EINVAL;

    int sock = connect_service();
    if (sock < 0)
        return sock;
    int ret = 0;

    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } cbuf;
    struct iovec iov = {.iov_base = (void *)req, .iov_len = req_len};
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    if (fd_count > 0) {
        msg.msg_control = cbuf.buf;
        msg.msg_controllen = CMSG_SPACE(fd_count * sizeof(int));
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
        memcpy(CMSG_DATA(c), fds, fd_count * sizeof(int));
    }

    if (sendmsg(sock, &msg, MSG_NOSIGNAL) == -1) {
        ret = -errno;
        fprintf(stderr,
                "%s: failed to send request to the defused service: %s\n",
                progname, strerror(errno));
        goto out_close;
    }

    ssize_t n = recv(sock, resp, sizeof(*resp), 0);
    ret = n < 0 ? -errno : 0;
    if (n != (ssize_t)sizeof(*resp) || resp->hdr.magic != DEFUSED_PROTO_MAGIC ||
        resp->hdr.version != DEFUSED_PROTO_VERSION) {
        fprintf(stderr, "%s: unexpected reply from the defused service\n",
                progname);
        ret = ret < 0 ? ret : -EBADMSG;
        goto out_close;
    }
    ret = 0;

out_close:
    close(sock);
    return ret;
}

static void print_service_error(uint32_t op, const char *mnt,
                                const struct defused_resp *resp) {
    if (quiet)
        return;
    const char *what = op == DEFUSED_OP_MOUNT ? "mount" : "unmount";
    switch (resp->status) {
    case DEFUSED_ERR_BAD_OPTION:
        fprintf(stderr, "%s: mount options rejected by the defused service\n",
                progname);
        break;
    case DEFUSED_ERR_NOT_ALLOWED:
        if (op == DEFUSED_OP_MOUNT)
            fprintf(stderr,
                    "%s: mount of %s not allowed by the defused service\n",
                    progname, mnt);
        else
            fprintf(stderr,
                    "%s: not allowed to unmount %s: not mounted by you\n",
                    progname, mnt);
        break;
    case DEFUSED_ERR_NOT_A_FUSE_MOUNT:
        fprintf(stderr, "%s: %s is not a FUSE mount\n", progname, mnt);
        break;
    case DEFUSED_ERR_MOUNT_FAILED:
    case DEFUSED_ERR_UNMOUNT_FAILED:
        fprintf(stderr, "%s: failed to %s %s: %s\n", progname, what, mnt,
                strerror(resp->sys_errno));
        break;
    case DEFUSED_ERR_SETNS_FAILED:
        fprintf(stderr,
                "%s: defused service could not join this mount namespace: %s\n",
                progname, strerror(resp->sys_errno));
        break;
    default:
        fprintf(stderr,
                "%s: %s request rejected by the defused service "
                "(status %u)\n",
                progname, what, resp->status);
        break;
    }
}

static void die(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(args);
    exit(1);
}

static void usage(void) {
    printf("%s: [options] mountpoint\n"
           "Options:\n"
           " -h		    print help\n"
           " -V		    print version\n"
           " -o opt[,opt...]    mount options\n"
           " -u		    unmount\n"
           " -q		    quiet\n"
           " -z		    lazy unmount\n",
           progname);
    exit(1);
}

/*
 * Parses a fusermount3 -o string.
 * See prepare_mount() in libfuse's util/fusermount.c
 *
 * - fsname=/subtype= honor backslash escapes
 * - auto_unmount sets the global configuration variable
 * - the legacy/internal options are dropped silently
 * - unsafe flag options (just suid) are warned about and ignored
 * - anything unrecognized is a hard error.
 */
static int parse_mount_opts(const char *opts, struct defused_mount_req *req) {
    uint32_t mount_flags = 0;

    for (const char *s = opts; *s;) {
        int escape_ok = begins_with(s, "fsname=") || begins_with(s, "subtype=");
        unsigned len;
        for (len = 0; s[len]; len++) {
            if (escape_ok && s[len] == '\\' && s[len + 1])
                len++;
            else if (s[len] == ',')
                break;
        }

        if (begins_with(s, "fsname=")) {
            int ret = copy_name(req->fsname, sizeof(req->fsname), "fsname",
                                s + 7, len - 7);
            if (ret < 0)
                return ret;
        } else if (begins_with(s, "subtype=")) {
            int ret = copy_name(req->subtype, sizeof(req->subtype), "subtype",
                                s + 8, len - 8);
            if (ret < 0)
                return ret;
        } else if (opt_eq(s, len, "blkdev")) {
            fprintf(stderr, "%s: option blkdev is privileged\n", progname);
            return -EPERM;
        } else if (opt_eq(s, len, "auto_unmount")) {
            auto_unmount = true;
        } else if (opt_eq(s, len, "default_permissions")) {
            mount_flags |= DEFUSED_FUSE_DEFAULT_PERMISSIONS;
        } else if (opt_eq(s, len, "allow_other")) {
            mount_flags |= DEFUSED_FUSE_ALLOW_OTHER;
        } else if (begins_with(s, "max_read=")) {
            int ret = parse_u32(s, len, "max_read=", &req->max_read);
            if (ret < 0)
                return ret;
        } else if (begins_with(s, "blksize=")) {
            int ret = parse_u32(s, len, "blksize=", &req->blksize);
            if (ret < 0)
                return ret;
        } else if (opt_eq(s, len, "nonempty") || begins_with(s, "fd=") ||
                   begins_with(s, "rootmode=") || begins_with(s, "user_id=") ||
                   begins_with(s, "group_id=") || begins_with(s, "x-")) {
            /* dropped silently */
        } else {
            const struct flag_opt *fo;
            for (fo = flag_opts; fo->opt; fo++)
                if (opt_eq(s, len, fo->opt))
                    break;
            if (!fo->opt) {
                fprintf(stderr, "%s: unknown option '%.*s'\n", progname,
                        (int)len, s);
                return -EINVAL;
            }
            if (!fo->safe)
                fprintf(stderr, "%s: unsafe option %s ignored\n", progname,
                        fo->opt);
            else if (fo->on)
                mount_flags |= fo->flag;
            else
                mount_flags &= ~fo->flag;
        }

        s += len;
        if (*s)
            s++;
    }

    req->mount_flags = mount_flags;
    return 0;
}

/* Copies an fsname=/subtype= value, resolving backslash escapes, and
 * checking character/length rules.
 * Escaped commas are valid here, matching libfuse's fuse_opt parser. */
static int copy_name(char *dst, size_t dstsz, const char *what, const char *s,
                     unsigned len) {
    size_t d = 0;
    for (unsigned i = 0; i < len; i++) {
        char ch = s[i];
        if (ch == '\\' && i + 1 < len)
            ch = s[++i];
        if (ch == '/') {
            fprintf(stderr, "%s: invalid character '%c' in %s\n", progname, ch,
                    what);
            return -EINVAL;
        }
        if (d + 1 >= dstsz) {
            fprintf(stderr, "%s: %s too long (max %zu characters)\n", progname,
                    what, dstsz - 1);
            return -ENAMETOOLONG;
        }
        dst[d++] = ch;
    }
    dst[d] = '\0';
    return 0;
}

static int parse_u32(const char *s, unsigned len, const char *pfx,
                     uint32_t *out) {
    unsigned plen = (unsigned)strlen(pfx);
    char buf[16];
    if (len <= plen || len - plen >= sizeof(buf))
        goto bad;
    memcpy(buf, s + plen, len - plen);
    buf[len - plen] = '\0';

    long v;
    if (libfuse_strtol(buf, &v) < 0 || v < 0 || v > UINT32_MAX)
        goto bad;
    *out = (uint32_t)v;
    return 0;

bad:
    fprintf(stderr, "%s: invalid value for '%s' option\n", progname, pfx);
    return -EINVAL;
}
