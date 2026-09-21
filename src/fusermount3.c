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
 * FUSE option parsing happens here; the service wire protocol is Varlink.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused_proto.h"
#include "util.h"

#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#define FUSE_COMMFD_ENV "_FUSE_COMMFD"

#ifndef DEFUSED_VERSION
#define DEFUSED_VERSION "unknown"
#endif

#ifndef DEFUSED_PATH
#define DEFUSED_PATH "/usr/lib/defused/defused"
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
    {"suid", DEFUSED_MOUNT_ALLOW_SUID, true, false},
    {"nosuid", DEFUSED_MOUNT_ALLOW_SUID, false, true},
    {"dev", DEFUSED_MOUNT_ALLOW_DEV, true, false},
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
static int connect_service(sd_varlink **ret)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int transact(uint32_t op, const union defused_req *req, const int *fds,
                    size_t fd_count, const char *mnt)
    __attribute__((__nonnull__(2, 3, 5), __warn_unused_result__));
static void print_service_error(uint32_t op, const char *mnt,
                                const struct defused_error *err)
    __attribute__((__nonnull__(2, 3)));
static int parse_mount_opts(const char *opts, struct defused_mount_req *req)
    __attribute__((__nonnull__(1, 2), __warn_unused_result__));
static int copy_name(char *dst, size_t dstsz, const char *what, const char *s,
                     unsigned len, bool allow_slash)
    __attribute__((__nonnull__(1, 3, 4), __warn_unused_result__));
static int parse_u32(const char *s, unsigned len, const char *pfx,
                     uint32_t *out)
    __attribute__((__nonnull__(1, 3, 4), __warn_unused_result__));

static noreturn void usage(void) __attribute__((__noreturn__));
static noreturn void die(const char *fmt, ...)
    __attribute__((__noreturn__, __format__(__printf__, 1, 2)));
static bool caller_is_privileged(void);

static const char *progname;
static bool quiet;
static bool auto_unmount;
static bool privileged;

int main(int argc, char *argv[]) {
    progname = argc > 0 ? argv[0] : "fusermount3";

    privileged = caller_is_privileged();

    bool unmount = false;
    bool lazy = false;
    bool setup_auto_unmount_only = false;
    const char *opts = "";
    const char *commfd_str = NULL;
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

    _cleanup_free_ char *mnt = fuse_mnt_resolve_path(progname, argv[optind]);
    if (mnt == NULL)
        return EXIT_FAILURE;

    if (unmount && !setup_auto_unmount_only)
        return do_unmount(mnt, lazy) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    if (commfd_str == NULL)
        commfd_str = getenv(FUSE_COMMFD_ENV);
    if (commfd_str == NULL) {
        fprintf(stderr, "%s: old style mounting not supported\n", progname);
        return EXIT_FAILURE;
    }

    long cfd_long;
    if (libfuse_strtol(commfd_str, &cfd_long) < 0 || cfd_long < 0 ||
        cfd_long > INT_MAX) {
        fprintf(stderr, "%s: invalid _FUSE_COMMFD: %s\n", progname, commfd_str);
        return EXIT_FAILURE;
    }
    int cfd = (int)cfd_long;

    struct stat st;
    if (fstat(cfd, &st) == -1) {
        fprintf(stderr, "%s: fstat of comm fd %d failed: %s\n", progname, cfd,
                strerror(errno));
        return EXIT_FAILURE;
    }

    if (!S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "%s: file descriptor %d is not a socket\n", progname,
                cfd);
        return EXIT_FAILURE;
    }
    if (!setup_auto_unmount_only) {
        if (do_mount(mnt, opts, cfd) < 0)
            return EXIT_FAILURE;
        if (!auto_unmount)
            return EXIT_SUCCESS;
    }
    return wait_and_auto_unmount(cfd, mnt) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* A non-root caller keeps CAP_SYS_ADMIN across exec only via the ambient set.
 */
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

static int do_mount(const char *mnt, const char *opts, int cfd) {
    union defused_req u = {0};
    int ret = parse_mount_opts(opts, &u.mount);
    if (ret < 0)
        return ret;

    /* Resolve the mountpoint to a file descriptor.
     * This file descriptor is sent to the service to perform the mount. */
    _cleanup_close_ int mnt_fd = open(mnt, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1) {
        ret = -errno;
        fprintf(stderr, "%s: failed to access mountpoint %s: %s\n", progname,
                mnt, strerror(errno));
        return ret;
    }

    const char *dev_path = getenv("DEFUSED_FUSE_DEVICE");
    if (!dev_path || !*dev_path)
        dev_path = "/dev/fuse";
    _cleanup_close_ int fuse_fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (fuse_fd == -1) {
        ret = -errno;
        fprintf(stderr, "%s: failed to open %s: %s\n", progname, dev_path,
                strerror(errno));
        return ret;
    }

    int fds[] = {fuse_fd, mnt_fd};
    ret = transact(DEFUSED_OP_MOUNT, &u, fds, 2, mnt);
    if (ret < 0)
        return ret;

    ret = send_fd(cfd, fuse_fd);
    if (ret < 0) {
        /* The library will never get the fd, so don't leave the filesystem
         * mounted -- same cleanup fusermount3 does, via the service. */
        quiet = true;
        (void)do_unmount(mnt, true);
        return ret;
    }

    return 0;
}

static int do_unmount(const char *mnt, bool lazy) {
    if (!strcmp(mnt, "/")) {
        fprintf(stderr, "%s: refusing to unmount /\n", progname);
        return -EINVAL;
    }

    /* dirname()/basename() may modify their argument in place and may
     * return a pointer into it, so each gets its own copy to work on. */
    _cleanup_free_ char *dir_copy = strdup(mnt);
    _cleanup_free_ char *base_copy = strdup(mnt);
    if (!dir_copy || !base_copy) {
        fprintf(stderr, "%s: failed to allocate memory\n", progname);
        return -ENOMEM;
    }
    const char *parent = dirname(dir_copy);
    const char *name = basename(base_copy);
    if (strlen(name) >= DEFUSED_MAX_FILENAME) {
        fprintf(stderr, "%s: mountpoint name too long: %s\n", progname, name);
        return -ENAMETOOLONG;
    }

    /* Open the parent directory, not the FUSE mount directory itself.
     * This is to make sure the umount2() call doesn't fail due to a held
     * file descriptor. */
    _cleanup_close_ int parent_fd =
        open(parent, O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd == -1) {
        int ret = -errno;
        if (!quiet)
            fprintf(stderr, "%s: failed to access %s: %s\n", progname, parent,
                    strerror(errno));
        return ret;
    }

    union defused_req u = {.umount = {.lazy = lazy}};
    (void)strlcpy(u.umount.name, name, sizeof(u.umount.name));

    int fds[] = {parent_fd};
    return transact(DEFUSED_OP_UNMOUNT, &u, fds, 1, mnt);
}

/*
 * Detaches from the caller's session in place (no fork: the caller already
 * has the FUSE fd from do_mount()'s send_fd() and isn't waiting on this
 * process to exit), then blocks until the fuse server exits -- seen via EOF
 * on the communication socket -- and lazily unmounts the filesystem.
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

static int connect_service(sd_varlink **ret) {
    _cleanup_(sd_varlink_close_unrefp) sd_varlink *link = NULL;
    int r;

    if (privileged) {
        char *argv[] = {(char *)"defused", (char *)"--child", NULL};
        r = sd_varlink_connect_exec(&link, DEFUSED_PATH, argv);
        if (r < 0) {
            fprintf(stderr, "%s: cannot spawn %s: %s\n", progname, DEFUSED_PATH,
                    strerror(-r));
            return r;
        }
    } else {
        const char *path = getenv("DEFUSED_SOCKET");
        if (path == NULL || *path == '\0')
            path = DEFUSED_SOCKET_PATH;

        r = sd_varlink_connect_address(&link, path);
        if (r < 0) {
            fprintf(stderr,
                    "%s: cannot connect to the defused service at %s: %s\n",
                    progname, path, strerror(-r));
            return r;
        }
    }
    r = sd_varlink_set_allow_fd_passing_input(link, true);
    if (r < 0)
        return r;
    r = sd_varlink_set_allow_fd_passing_output(link, true);
    if (r < 0)
        return r;
    *ret = TAKE_PTR(link);
    return 0;
}

/* One request/response with the service. Returns 0, -EPERM if the call came
 * back as a Varlink error (also printed via print_service_error(), unless
 * quiet), or whatever negative errno the RPC itself failed with. */
static int transact(uint32_t op, const union defused_req *req, const int *fds,
                    size_t fd_count, const char *mnt) {
    if (fd_count > 2)
        return -EINVAL;

    _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
    int ret = connect_service(&link);
    if (ret < 0)
        return ret;

    for (size_t i = 0; i < fd_count; i++) {
        ret = sd_varlink_push_dup_fd(link, fds[i]);
        if (ret < 0)
            return ret;
    }

    /* Borrowed from the link, valid until its next call; not ours to unref. */
    sd_json_variant *reply = NULL;
    const char *error_id = NULL;
    if (op == DEFUSED_OP_MOUNT)
        ret = sd_varlink_callbo(
            link, DEFUSED_VARLINK_METHOD_MOUNT, &reply, &error_id,
            SD_JSON_BUILD_PAIR_UNSIGNED("fuseFileDescriptor", 0),
            SD_JSON_BUILD_PAIR_UNSIGNED("mountpointFileDescriptor", 1),
            SD_JSON_BUILD_PAIR_UNSIGNED("mountFlags", req->mount.mount_flags),
            SD_JSON_BUILD_PAIR_UNSIGNED("maxRead", req->mount.max_read),
            SD_JSON_BUILD_PAIR_UNSIGNED("blockSize", req->mount.blksize),
            SD_JSON_BUILD_PAIR_STRING("fsName", req->mount.fsname),
            SD_JSON_BUILD_PAIR_STRING("subtype", req->mount.subtype));
    else if (op == DEFUSED_OP_UNMOUNT)
        ret = sd_varlink_callbo(
            link, DEFUSED_VARLINK_METHOD_UNMOUNT, &reply, &error_id,
            SD_JSON_BUILD_PAIR_UNSIGNED("parentFileDescriptor", 0),
            SD_JSON_BUILD_PAIR_STRING("name", req->umount.name),
            SD_JSON_BUILD_PAIR_BOOLEAN("lazy", req->umount.lazy != 0));
    else
        ret = -EINVAL;
    if (ret < 0) {
        if (!quiet)
            fprintf(stderr, "%s: %s request to %s failed: %s\n", progname,
                    op == DEFUSED_OP_MOUNT ? "mount" : "unmount",
                    privileged ? DEFUSED_PATH : "the service", strerror(-ret));
        return ret;
    }

    if (error_id != NULL) {
        struct defused_error err;
        ret = defused_error_from_reply(error_id, reply, &err);
        if (ret < 0)
            return ret;
        print_service_error(op, mnt, &err);
        return -EPERM;
    }

    return 0;
}

static void print_service_error(uint32_t op, const char *mnt,
                                const struct defused_error *err) {
    if (quiet)
        return;
    const char *what = op == DEFUSED_OP_MOUNT ? "mount" : "unmount";
    const char *reason = err->sys_errno ? strerror(err->sys_errno)
                                        : "no reason given by the service";

    if (!strcmp(err->id, DEFUSED_VARLINK_ERROR_MALFORMED))
        fprintf(stderr, "%s: %s request rejected by the defused service: %s\n",
                progname, what, reason);
    else if (!strcmp(err->id, DEFUSED_VARLINK_ERROR_BAD_OPTION))
        fprintf(stderr, "%s: mount options rejected by the defused service\n",
                progname);
    else if (!strcmp(err->id, DEFUSED_VARLINK_ERROR_NOT_ALLOWED))
        fprintf(stderr,
                op == DEFUSED_OP_MOUNT
                    ? "%s: mount of %s not allowed by the defused service\n"
                    : "%s: not allowed to unmount %s: not mounted by you\n",
                progname, mnt);
    else if (!strcmp(err->id, DEFUSED_VARLINK_ERROR_NOT_A_FUSE_MOUNT))
        fprintf(stderr, "%s: %s is not a FUSE mount\n", progname, mnt);
    else if (!strcmp(err->id, DEFUSED_VARLINK_ERROR_MOUNT_FAILED) ||
             !strcmp(err->id, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED))
        fprintf(stderr, "%s: failed to %s %s: %s\n", progname, what, mnt,
                reason);
    else
        /* A Varlink-level error, e.g. one of libsystemd's own. */
        fprintf(stderr, "%s: %s request failed: %s\n", progname, what, err->id);
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
 * - unsafe flag options (suid, dev) and blkdev are privileged: otherwise
 *   they are warned about and ignored, blkdev is an error
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
                                s + 7, len - 7, privileged);
            if (ret < 0)
                return ret;
        } else if (begins_with(s, "subtype=")) {
            int ret = copy_name(req->subtype, sizeof(req->subtype), "subtype",
                                s + 8, len - 8, false);
            if (ret < 0)
                return ret;
        } else if (opt_eq(s, len, "blkdev")) {
            if (!privileged) {
                fprintf(stderr, "%s: option blkdev is privileged\n", progname);
                return -EPERM;
            }
            mount_flags |= DEFUSED_MOUNT_BLKDEV;
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
            if (!fo->safe && !privileged)
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
                     unsigned len, bool allow_slash) {
    size_t d = 0;
    for (unsigned i = 0; i < len; i++) {
        char ch = s[i];
        if (ch == '\\' && i + 1 < len)
            ch = s[++i];
        if (ch == '/' && !allow_slash) {
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
