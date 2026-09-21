/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Drop-in replacement for libfuse's setuid-root fusermount3, implemented as
 * an unprivileged client of the defused service. The same binary is also
 * installed as libfuse2's `fusermount`, whose command line is a subset.
 *
 * libfuse hands over a socket via _FUSE_COMMFD (or --comm-fd); after the
 * mount, the opened /dev/fuse fd is sent back over it with SCM_RIGHTS.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-proto.h"
#include "defused-syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef DEFUSED_VERSION
#define DEFUSED_VERSION "unknown"
#endif
#ifndef DEFUSED_PATH
#define DEFUSED_PATH "/usr/lib/defused/defused"
#endif

static const char *progname = "fusermount3";
static bool quiet, auto_unmount, privileged;

__attribute__((__noreturn__, __format__(__printf__, 1, 2))) static void
die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(EXIT_FAILURE);
}

/* A non-root caller keeps CAP_SYS_ADMIN across exec only via the ambient
 * set. */
static bool caller_is_privileged(void) {
#ifdef DEFUSED_TEST
    const char *forced_uid = getenv("DEFUSED_TEST_UID");
    if (forced_uid != NULL)
        return strcmp(forced_uid, "0") == 0;
#endif
    return getuid() == 0 || geteuid() == 0 ||
           prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0) ==
               0;
}

/*** Mount options ***/

/* libfuse's table: option, its protocol bit, whether it sets or clears the
 * bit, and whether an unprivileged caller may use it. */
static const struct {
    const char *opt;
    uint32_t flag;
    bool on, safe;
} flag_opts[] = {
    {"rw", DEFUSED_MOUNT_RDONLY, false, true},
    {"ro", DEFUSED_MOUNT_RDONLY, true, true},
    {"suid", DEFUSED_MOUNT_ALLOW_SUID, true, false},
    {"nosuid", DEFUSED_MOUNT_ALLOW_SUID, false, true},
    {"dev", DEFUSED_MOUNT_ALLOW_DEV, true, false},
    {"nodev", DEFUSED_MOUNT_ALLOW_DEV, false, true},
    {"exec", DEFUSED_MOUNT_NOEXEC, false, true},
    {"noexec", DEFUSED_MOUNT_NOEXEC, true, true},
    {"async", DEFUSED_MOUNT_SYNCHRONOUS, false, true},
    {"sync", DEFUSED_MOUNT_SYNCHRONOUS, true, true},
    {"atime", DEFUSED_MOUNT_NOATIME, false, true},
    {"noatime", DEFUSED_MOUNT_NOATIME, true, true},
    {"nodiratime", DEFUSED_MOUNT_NODIRATIME, true, true},
    {"norelatime", 0, false, true},
    {"nostrictatime", 0, false, true},
    {"symfollow", DEFUSED_MOUNT_NOSYMFOLLOW, false, true},
    {"nosymfollow", DEFUSED_MOUNT_NOSYMFOLLOW, true, true},
    {"dirsync", DEFUSED_MOUNT_DIRSYNC, true, true},
};

static bool opt_is(const char *s, size_t len, const char *opt) {
    return strlen(opt) == len && strncmp(s, opt, len) == 0;
}

static bool opt_starts(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* An fsname=/subtype= value, with libfuse's backslash escapes resolved. */
static void copy_name(char *dst, size_t dstsz, const char *what, const char *s,
                      size_t len, bool allow_slash) {
    size_t d = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = s[i];
        if (ch == '\\' && i + 1 < len)
            ch = s[++i];
        if (ch == '/' && !allow_slash)
            die("invalid character '/' in %s", what);
        if (d + 1 >= dstsz)
            die("%s too long (max %zu characters)", what, dstsz - 1);
        dst[d++] = ch;
    }
    dst[d] = '\0';
}

static uint32_t parse_u32(const char *s, size_t len, const char *opt) {
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (len == 0 || *s < '0' || *s > '9' || errno != 0 || end != s + len ||
        v > UINT32_MAX)
        die("invalid value for '%s' option", opt);
    return (uint32_t)v;
}

/*
 * Parses a fusermount3 -o string like libfuse's util/fusermount.c does:
 * fsname=/subtype= honor backslash escapes, auto_unmount is remembered
 * here, libfuse's internal and legacy options are dropped silently, the
 * privileged options (suid, dev) are warned about and ignored for an
 * unprivileged caller while blkdev is an error, and anything unrecognized
 * is an error.
 */
static void parse_mount_opts(const char *opts, struct defused_request *req) {
    uint32_t flags = 0;
    size_t len;
    for (const char *s = opts; *s; s += len + (s[len] == ',')) {
        bool escape_ok = opt_starts(s, "fsname=") || opt_starts(s, "subtype=");
        for (len = 0; s[len]; len++) {
            if (escape_ok && s[len] == '\\' && s[len + 1])
                len++;
            else if (s[len] == ',')
                break;
        }

        if (opt_starts(s, "fsname="))
            copy_name(req->fsname, sizeof(req->fsname), "fsname", s + 7,
                      len - 7, privileged);
        else if (opt_starts(s, "subtype="))
            copy_name(req->subtype, sizeof(req->subtype), "subtype", s + 8,
                      len - 8, false);
        else if (opt_starts(s, "max_read="))
            req->max_read = parse_u32(s + 9, len - 9, "max_read");
        else if (opt_starts(s, "blksize="))
            req->blksize = parse_u32(s + 8, len - 8, "blksize");
        else if (opt_is(s, len, "auto_unmount"))
            auto_unmount = true;
        else if (opt_is(s, len, "default_permissions"))
            flags |= DEFUSED_FUSE_DEFAULT_PERMISSIONS;
        else if (opt_is(s, len, "allow_other"))
            flags |= DEFUSED_FUSE_ALLOW_OTHER;
        else if (opt_is(s, len, "blkdev")) {
            if (!privileged)
                die("option blkdev is privileged");
            flags |= DEFUSED_MOUNT_BLKDEV;
        } else if (opt_is(s, len, "nonempty") || opt_is(s, len, "large_read") ||
                   opt_starts(s, "fd=") || opt_starts(s, "rootmode=") ||
                   opt_starts(s, "user_id=") || opt_starts(s, "group_id=") ||
                   opt_starts(s, "x-")) {
            /* dropped silently */
        } else {
            size_t i = 0;
            while (i < ARRAY_SIZE(flag_opts) &&
                   !opt_is(s, len, flag_opts[i].opt))
                i++;
            if (i == ARRAY_SIZE(flag_opts))
                die("unknown option '%.*s'", (int)len, s);
            if (!flag_opts[i].safe && !privileged)
                fprintf(stderr, "%s: unsafe option %s ignored\n", progname,
                        flag_opts[i].opt);
            else if (flag_opts[i].on)
                flags |= flag_opts[i].flag;
            else
                flags &= ~flag_opts[i].flag;
        }
    }
    req->mount_flags = flags;
}

/*** The service ***/

/* Where a request goes: the service socket, or the `defused --child` a
 * privileged caller runs instead. */
struct service {
    int sock;
    pid_t child; /* 0 when this is the socket */
};
#define SERVICE_UNSET {.sock = -EBADF, .child = 0}

static void service_done(struct service *svc) {
    svc->sock = safe_close(svc->sock);
    if (svc->child > 0) {
        while (waitpid(svc->child, NULL, 0) == -1 && errno == EINTR)
            ;
        svc->child = 0;
    }
}
#define _cleanup_service_ _cleanup_(service_done)

static int connect_socket(const char *path) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(sa.sun_path))
        return -ENAMETOOLONG;
    strcpy(sa.sun_path, path);
    _cleanup_close_ int fd =
        socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
    if (fd == -1)
        return -errno;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
        return -errno;
    return TAKE_FD(fd);
}

/* A privileged caller needs no service: it runs `defused --child` on a
 * socket pair, handed over the way Accept=yes hands over a connection. */
static int spawn_child(struct service *svc) {
    int sv[2];
    if (socketpair(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0, sv) == -1)
        return -errno;
    pid_t pid = fork();
    if (pid < 0) {
        int ret = -errno;
        safe_close(sv[0]);
        safe_close(sv[1]);
        return ret;
    }
    if (pid == 0) {
        /* sv[0] first: it may be sitting on DEFUSED_LISTEN_FD itself. */
        (void)close(sv[0]);
        if (sv[1] == DEFUSED_LISTEN_FD ? fcntl(sv[1], F_SETFD, 0) == -1
                                       : dup2(sv[1], DEFUSED_LISTEN_FD) == -1)
            _exit(127);
        char pidbuf[16];
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int)getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "1", 1);
        char *argv[] = {(char *)"defused", (char *)"--child", NULL};
        execv(DEFUSED_PATH, argv);
        _exit(127);
    }
    (void)close(sv[1]);
    svc->sock = sv[0];
    svc->child = pid;
    return 0;
}

static int connect_service(struct service *svc) {
    const char *target = DEFUSED_PATH;
    int ret;
    if (privileged) {
        ret = spawn_child(svc);
    } else {
        target = getenv("DEFUSED_SOCKET");
        if (target == NULL || *target == '\0')
            target = DEFUSED_SOCKET_PATH;
        ret = connect_socket(target);
        if (ret >= 0) {
            svc->sock = ret;
            ret = 0;
        }
    }
    if (ret < 0 && !quiet)
        fprintf(stderr, "%s: cannot %s %s: %s\n", progname,
                privileged ? "spawn" : "connect to the defused service at",
                target, strerror(-ret));
    return ret;
}

/* ret if the exchange failed, -EPERM for an error from the service
 * (explained unless quiet), 0 for success. */
static int check_reply(int ret, const char *what, const char *mnt,
                       const struct defused_error *err) {
    if (ret < 0) {
        if (!quiet)
            fprintf(stderr, "%s: %s request to %s failed: %s\n", progname, what,
                    privileged ? DEFUSED_PATH : "the service", strerror(-ret));
        return ret;
    }
    if (err->code == DEFUSED_OK)
        return 0;
    if (quiet)
        return -EPERM;
    const char *reason = err->sys_errno ? strerror(err->sys_errno)
                                        : "no reason given by the service";
    switch (err->code) {
    case DEFUSED_ERR_MALFORMED:
        fprintf(stderr, "%s: %s request rejected by the defused service: %s\n",
                progname, what, reason);
        break;
    case DEFUSED_ERR_BAD_OPTION:
        fprintf(stderr, "%s: mount options rejected by the defused service\n",
                progname);
        break;
    case DEFUSED_ERR_NOT_ALLOWED:
        fprintf(stderr,
                !strcmp(what, "mount")
                    ? "%s: mount of %s not allowed by the defused service\n"
                    : "%s: not allowed to unmount %s: not mounted by you\n",
                progname, mnt);
        break;
    case DEFUSED_ERR_NOT_A_FUSE_MOUNT:
        fprintf(stderr, "%s: %s is not a FUSE mount\n", progname, mnt);
        break;
    default: /* MountFailed, UnmountFailed */
        fprintf(stderr, "%s: failed to %s %s: %s\n", progname, what, mnt,
                reason);
        break;
    }
    return -EPERM;
}

/* mnt is absolute and canonical, so its last component is the name. */
static int do_unmount(const char *mnt, bool lazy) {
    const char *name = strrchr(mnt, '/') + 1;
    if (*name == '\0') {
        if (!quiet)
            fprintf(stderr, "%s: refusing to unmount /\n", progname);
        return -EINVAL;
    }
    struct defused_request req = {
        .magic = DEFUSED_MAGIC, .op = DEFUSED_OP_UNMOUNT, .lazy = lazy};
    if (strlen(name) >= sizeof(req.name)) {
        if (!quiet)
            fprintf(stderr, "%s: mountpoint name too long: %s\n", progname,
                    name);
        return -ENAMETOOLONG;
    }
    strcpy(req.name, name);
    _cleanup_free_ char *parent =
        strndup(mnt, name - 1 == mnt ? 1 : (size_t)(name - 1 - mnt));
    if (parent == NULL)
        return -ENOMEM;
    /* The parent directory, not the mountpoint: an fd held open on the mount
     * would make a non-lazy umount2() fail with EBUSY. */
    _cleanup_close_ int parent_fd =
        open(parent, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd == -1) {
        int ret = -errno;
        if (!quiet)
            fprintf(stderr, "%s: failed to access %s: %s\n", progname, parent,
                    strerror(errno));
        return ret;
    }

    _cleanup_service_ struct service svc = SERVICE_UNSET;
    int ret = connect_service(&svc);
    if (ret < 0)
        return ret;
    struct defused_error err;
    return check_reply(
        defused_call(svc.sock, &req, (const int[]){parent_fd}, &err), "unmount",
        mnt, &err);
}

/* Hands fd to libfuse over the _FUSE_COMMFD socket, framed the way its
 * receive_fd() expects: one zero byte plus SCM_RIGHTS. */
static int send_fd(int sock, int fd) {
    char zero = 0;
    struct iovec iov = {.iov_base = &zero, .iov_len = 1};
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsg = {0};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = &cmsg,
                         .msg_controllen = sizeof(cmsg)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    ssize_t n;
    do
        n = sendmsg(sock, &msg, 0);
    while (n == -1 && errno == EINTR);
    if (n != 1) {
        fprintf(stderr, "%s: sending the FUSE fd to the caller failed: %s\n",
                progname, strerror(errno));
        return -EIO;
    }
    return 0;
}

static int do_mount(const char *mnt, const char *opts, int cfd) {
    struct defused_request req = {.magic = DEFUSED_MAGIC,
                                  .op = DEFUSED_OP_MOUNT};
    parse_mount_opts(opts, &req);

    _cleanup_close_ int mnt_fd = open(mnt, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1)
        die("failed to access mountpoint %s: %s", mnt, strerror(errno));
    const char *dev = getenv("DEFUSED_FUSE_DEVICE");
    if (dev == NULL || *dev == '\0')
        dev = "/dev/fuse";
    _cleanup_close_ int fuse_fd = open(dev, O_RDWR | O_CLOEXEC);
    if (fuse_fd == -1)
        die("failed to open %s: %s", dev, strerror(errno));

    _cleanup_service_ struct service svc = SERVICE_UNSET;
    int ret = connect_service(&svc);
    if (ret < 0)
        return ret;
    struct defused_error err;
    /* The order the protocol fixes: /dev/fuse, then the mountpoint. */
    ret = check_reply(
        defused_call(svc.sock, &req, (const int[]){fuse_fd, mnt_fd}, &err),
        "mount", mnt, &err);
    if (ret < 0)
        return ret;

    ret = send_fd(cfd, fuse_fd);
    if (ret < 0) {
        /* The library will never get the fd, so don't leave the filesystem
         * mounted -- the same cleanup libfuse's fusermount3 does. */
        quiet = true;
        (void)do_unmount(mnt, true);
    }
    return ret;
}

/*** auto_unmount ***/

/* Closes every inherited fd but cfd and points stdio at /dev/null: this
 * process lingers for the FUSE server's lifetime and must not hold anything
 * else open. */
static int close_inherited_fds(int cfd) {
    if (cfd <= STDERR_FILENO)
        return -EINVAL; /* We can't even report an error */
    if ((cfd > STDERR_FILENO + 1 &&
         sys_close_range((unsigned)STDERR_FILENO + 1, (unsigned)cfd - 1, 0) <
             0) ||
        sys_close_range((unsigned)cfd + 1, ~0U, 0) < 0)
        for (int fd = STDERR_FILENO + 1, max = (int)sysconf(_SC_OPEN_MAX);
             fd < max; fd++)
            if (fd != cfd)
                close(fd);

    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0)
        return -errno;
    dup2(nullfd, STDIN_FILENO);
    dup2(nullfd, STDOUT_FILENO);
    dup2(nullfd, STDERR_FILENO);
    if (nullfd > STDERR_FILENO)
        close(nullfd);
    return 0;
}

/* Detaches from the caller's session in place (no fork: the caller already
 * has the FUSE fd and isn't waiting on this process), then blocks until the
 * FUSE server exits -- seen as EOF on the communication socket -- and lazily
 * unmounts the filesystem. */
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

    char buf[16];
    ssize_t n;
    do
        n = recv(cfd, buf, sizeof(buf), 0);
    while (n > 0 || (n < 0 && errno == EINTR));

    quiet = true;
    return do_unmount(mnt, true);
}

/*** Command line ***/

/* realpath() of the mountpoint's parent plus its basename, like libfuse's
 * fuse_mnt_resolve_path(): resolving the mountpoint itself would traverse
 * into a FUSE mount whose server may be dead. */
static char *resolve_mountpoint(const char *orig) {
    _cleanup_free_ char *dir_copy = strdup(orig), *base_copy = strdup(orig);
    if (dir_copy == NULL || base_copy == NULL)
        die("failed to allocate memory");
    const char *base = basename(base_copy);
    char resolved[PATH_MAX];
    char *dst = NULL;
    if (!strcmp(base, ".") || !strcmp(base, "..") || !strcmp(base, "/")) {
        if (realpath(orig, resolved) != NULL)
            dst = strdup(resolved);
    } else if (realpath(dirname(dir_copy), resolved) != NULL &&
               asprintf(&dst, "%s/%s", strcmp(resolved, "/") ? resolved : "",
                        base) < 0) {
        dst = NULL;
    }
    if (dst == NULL)
        die("bad mount point %s: %s", orig, strerror(errno));
    return dst;
}

static __attribute__((__noreturn__)) void usage(void) {
    printf("%s: [options] mountpoint\n"
           "Options:\n"
           " -h		    print help\n"
           " -V		    print version\n"
           " -o opt[,opt...]    mount options\n"
           " -u		    unmount\n"
           " -q		    quiet\n"
           " -z		    lazy unmount\n",
           progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
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
    if (argc > 0 && argv[0] != NULL && argv[0][0] != '\0')
        progname = argv[0];
    privileged = caller_is_privileged();

    bool unmount = false, lazy = false, auto_unmount_only = false;
    const char *opts = "", *commfd_str = NULL;
    for (int c;
         (c = getopt_long(argc, argv, "hVo:uzq", long_opts, NULL)) != -1;) {
        switch (c) {
        case 'h':
            usage();
        case 'V': {
            /* Only the banner follows argv[0]: "fusermount3", or libfuse2's
             * "fusermount". */
            const char *slash = strrchr(progname, '/');
            printf("%s version: %s (defused)\n",
                   slash != NULL && slash[1] != '\0' ? slash + 1 : progname,
                   DEFUSED_VERSION);
            return EXIT_SUCCESS;
        }
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
            unmount = auto_unmount = auto_unmount_only = true;
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

    _cleanup_free_ char *mnt = resolve_mountpoint(argv[optind]);
    if (unmount && !auto_unmount_only)
        return do_unmount(mnt, lazy) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    if (commfd_str == NULL)
        commfd_str = getenv("_FUSE_COMMFD");
    if (commfd_str == NULL)
        die("old style mounting not supported");
    char *end;
    long cfd = strtol(commfd_str, &end, 10);
    if (*commfd_str == '\0' || *end != '\0' || cfd < 0 || cfd > INT_MAX)
        die("invalid _FUSE_COMMFD: %s", commfd_str);
    struct stat st;
    if (fstat((int)cfd, &st) == -1)
        die("fstat of comm fd %ld failed: %s", cfd, strerror(errno));
    if (!S_ISSOCK(st.st_mode))
        die("file descriptor %ld is not a socket", cfd);

    if (!auto_unmount_only) {
        if (do_mount(mnt, opts, (int)cfd) < 0)
            return EXIT_FAILURE;
        if (!auto_unmount)
            return EXIT_SUCCESS;
    }
    return wait_and_auto_unmount((int)cfd, mnt) < 0 ? EXIT_FAILURE
                                                    : EXIT_SUCCESS;
}
