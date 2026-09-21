/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The defused system service that mounts/unmounts FUSE filesystems on
 * behalf of unprivileged users.
 *
 * By default it handles the one connection systemd's Accept=yes socket
 * activation hands it, then exits. With --daemon it listens itself and
 * forks a child per connection; with --child (spawned by fusermount3 for a
 * privileged caller) policy is skipped and the mount/unmount is done
 * in-process.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-sandbox.h"
#include "defused_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <mntent.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>

/* The kernel's own constants: SO_PEERGROUPS, and the new mount API's
 * FSOPEN_*, FSCONFIG_*, MOUNT_ATTR_* and MOVE_MOUNT_*. musl declares none
 * of them, and both libcs tolerate these alongside their own headers. The
 * mount API is used by syscall number: glibc only grew wrappers in 2.36 and
 * musl has none. */
#include <asm/socket.h>
#include <linux/mount.h>

#define DEFAULT_MAX_MOUNTS 100
/* A backstop for --daemon, like systemd's MaxConnections=. */
#define DAEMON_MAX_CONNECTIONS 64

static bool cfg_daemon, cfg_child, cfg_allow_other;
static long cfg_max_mounts = DEFAULT_MAX_MOUNTS;
static gid_t cfg_allow_groups[32];
static size_t cfg_n_allow_groups;

struct peer {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

/* Logs "defused: <message>: <strerror(-ret)>" and returns ret. */
__attribute__((__format__(__printf__, 2, 3))) static int
log_error(int ret, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("defused: ", stderr);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", strerror(-ret));
    va_end(ap);
    return ret;
}

static int parse_long(const char *s, long *out) {
    char *end;
    errno = 0;
    *out = strtol(s, &end, 10);
    return errno != 0 ? -errno : end == s || *end != '\0' ? -EINVAL : 0;
}

/*** Policy: whether the caller may use defused at all ***/

/* Like libfuse's mount_max: FUSE mounts in the service's own namespace. */
static int count_fuse_mounts(void) {
    FILE *fp = setmntent(_PATH_MOUNTED, "r");
    if (fp == NULL)
        return -errno;
    int count = 0;
    for (struct mntent *e; (e = getmntent(fp)) != NULL;)
        count += strcmp(e->mnt_type, "fuse") == 0 ||
                 strncmp(e->mnt_type, "fuse.", 5) == 0;
    endmntent(fp);
    return count;
}

/* Returns 1, 0, or a negative errno. SO_PEERGROUPS needs Linux 4.13. */
static int peer_in_allowed_groups(sd_varlink *link, gid_t gid) {
    int sock = sd_varlink_get_fd(link);
    socklen_t len = 0;
    if (getsockopt(sock, SOL_SOCKET, SO_PEERGROUPS, NULL, &len) == -1 &&
        errno != ERANGE)
        return -errno;
    _cleanup_free_ gid_t *groups = malloc(len + sizeof(gid_t));
    if (groups == NULL)
        return -ENOMEM;
    if (getsockopt(sock, SOL_SOCKET, SO_PEERGROUPS, groups, &len) == -1)
        return -errno;
    size_t n = len / sizeof(gid_t);
    groups[n++] = gid; /* the primary group, after the supplementary ones */
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < cfg_n_allow_groups; j++)
            if (groups[i] == cfg_allow_groups[j])
                return 1;
    return 0;
}

/* -EACCES, with *err filled in, for a refusal. Unmount only gets the group
 * check: --max-mounts and --allow-other describe no teardown, and whether
 * the mount is the caller's is checked separately. */
static int policy_check(sd_varlink *link, const struct peer *peer,
                        enum defused_op op, uint32_t mount_flags,
                        struct defused_error *err) {
    const char *what = op == DEFUSED_OP_MOUNT ? "mount" : "unmount";
    const char *fail_id = op == DEFUSED_OP_MOUNT ? DEFUSED_ERROR_MOUNT_FAILED
                                                 : DEFUSED_ERROR_UNMOUNT_FAILED;
    if (cfg_n_allow_groups > 0) {
        int ret = peer_in_allowed_groups(link, peer->gid);
        if (ret < 0)
            return defused_error_setf(err, fail_id, -ret,
                                      "SO_PEERGROUPS on the client socket "
                                      "failed");
        if (ret == 0) {
            defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                               "policy refused a %s: uid %u (gid %u) is in "
                               "none of the --allow-groups groups",
                               what, (unsigned)peer->uid, (unsigned)peer->gid);
            return -EACCES;
        }
    }
    if (op != DEFUSED_OP_MOUNT)
        return 0;
    if ((mount_flags & DEFUSED_FUSE_ALLOW_OTHER) && !cfg_allow_other) {
        defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                           "policy refused a mount: allow_other is not "
                           "granted by --allow-other");
        return -EACCES;
    }
    int mounts = count_fuse_mounts();
    if (mounts < 0)
        return defused_error_setf(err, fail_id, -mounts,
                                  "could not count the existing FUSE mounts");
    if (mounts >= cfg_max_mounts) {
        defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                           "policy refused a mount: %d FUSE filesystems "
                           "already mounted (--max-mounts=%ld)",
                           mounts, cfg_max_mounts);
        return -EACCES;
    }
    return 0;
}

/* SPDX-SnippetBegin
 * SPDX-SnippetCopyrightText: 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * libfuse's allowlist of filesystems an unprivileged user may mount over
 * (util/fusermount.c). Notably absent: procfs, which has a couple of places
 * a user can write to without being meant to put just anything there. */
static bool fstype_allows_user_mounts(const struct statfs *fs) {
    static const unsigned long allowed[] = {
        0x61756673 /* aufs */,         0x00000187 /* autofs */,
        0xCA451A4E /* bcachefs */,     0x9123683E /* btrfs */,
        0x00C36400 /* ceph */,         0xFF534D42 /* cifs */,
        0x0000F15F /* ecryptfs */,     0X2011BAB0 /* exfat */,
        0x0000EF53 /* ext[234] */,     0xF2F52010 /* f2fs */,
        0x65735546 /* fuse */,         0x01161970 /* gfs2 */,
        0x47504653 /* gpfs */,         0x0000482b /* hfsplus */,
        0x000072B6 /* jffs2 */,        0x3153464A /* jfs */,
        0x0BD00BD0 /* lustre */,       0X00004D44 /* msdos */,
        0x0000564C /* ncp */,          0x00006969 /* nfs */,
        0x00003434 /* nilfs */,        0x5346544E /* ntfs */,
        0x7366746E /* ntfs3 */,        0x5346414f /* openafs */,
        0x794C7630 /* overlayfs */,    0xAAD7AAEA /* panfs */,
        0x52654973 /* reiserfs */,     0xFE534D42 /* smb2 */,
        0x73717368 /* squashfs */,     0x01021994 /* tmpfs */,
        0x24051905 /* ubifs */,        0x18031977 /* wekafs */,
#if __SIZEOF_LONG__ > 4
        0x736675005346544e /* ufsd */,
#endif
        0x58465342 /* xfs */,          0x2FC12FC1 /* zfs */,
        0x858458f6 /* ramfs */,
    };
    for (size_t i = 0; i < ARRAY_SIZE(allowed); i++)
        if (allowed[i] == (unsigned long)fs->f_type)
            return true;
    return false;
}
/* SPDX-SnippetEnd */

/*** Mount ***/

/* Best-effort path of an fd for log messages, as seen from this process's
 * mount namespace; never used for a decision. */
static const char *fd_path(int fd, char *buf, size_t size) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, buf, size - 1);
    if (n < 0)
        return "?";
    buf[n] = '\0';
    return buf;
}

/* "ro,allow_other" for log messages; unknown bits are appended in hex. */
static const char *mount_flags_str(uint32_t flags, char *buf, size_t size) {
    static const char *const names[] = {
        "ro",          "dev",
        "noexec",      "noatime",
        "nodiratime",  "nosymfollow",
        "sync",        "dirsync",
        "allow_other", "default_permissions",
        "suid",        "blkdev",
    };
    size_t off = 0;
    for (unsigned bit = 0; bit < 32 && off < size; bit++) {
        if (!(flags & (1u << bit)))
            continue;
        if (bit < ARRAY_SIZE(names))
            off += (size_t)snprintf(buf + off, size - off, "%s%s",
                                    off ? "," : "", names[bit]);
        else
            off += (size_t)snprintf(buf + off, size - off, "%s%#x",
                                    off ? "," : "", 1u << bit);
    }
    if (off == 0)
        snprintf(buf, size, "none");
    return buf;
}

/* "fuse.sshfs on \"/home/u/mnt\" (fsname=..., flags=ro,nosuid)" */
static const char *describe_mount_req(const struct defused_mount_req *req,
                                      int mnt_fd, char *buf, size_t size) {
    char path[256], flags[160];
    snprintf(buf, size, "%s%s%s on \"%s\" (fsname=\"%s\", flags=%s)",
             req->mount_flags & DEFUSED_MOUNT_BLKDEV ? "fuseblk" : "fuse",
             req->subtype[0] ? "." : "", req->subtype,
             fd_path(mnt_fd, path, sizeof(path)), req->fsname,
             mount_flags_str(req->mount_flags, flags, sizeof(flags)));
    return buf;
}

/* Logs the outcome and replies. errno goes on the wire only for the errors
 * declared to carry it. sd_varlink_error() hands the error it just sent
 * back as a negative errno, so a negative return here is the normal case. */
static int finish_request(sd_varlink *link, const char *what,
                          const char *target, const struct peer *peer, int ret,
                          const struct defused_error *err) {
    if (ret >= 0) {
        fprintf(stderr, "defused: %sed %s for uid %u\n", what, target,
                (unsigned)peer->uid);
        return sd_varlink_reply(link, NULL);
    }
    fprintf(stderr,
            "defused: %s request from pid %d (uid %u) for %s failed with %s "
            "(%s)%s%s\n",
            what, (int)peer->pid, (unsigned)peer->uid, target, err->id,
            strerror(err->sys_errno ? err->sys_errno : -ret),
            err->detail[0] ? " -- " : "", err->detail);
    return sd_varlink_errorbo(
        link, err->id,
        SD_JSON_BUILD_PAIR_CONDITION(err->sys_errno != 0, "errno",
                                     SD_JSON_BUILD_INTEGER(err->sys_errno)));
}

static int get_peer(sd_varlink *link, struct peer *peer) {
    int ret;
    if ((ret = sd_varlink_get_peer_pid(link, &peer->pid)) < 0 ||
        (ret = sd_varlink_get_peer_uid(link, &peer->uid)) < 0 ||
        (ret = sd_varlink_get_peer_gid(link, &peer->gid)) < 0)
        return log_error(ret, "SO_PEERCRED on the client socket failed");
    return 0;
}

static int check_fuse_device(int dev_fd, struct defused_error *err) {
    struct stat st;
    int flags;
    if (fstat(dev_fd, &st) == -1 || (flags = fcntl(dev_fd, F_GETFL)) == -1)
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, errno,
                                  "fstat()/fcntl() on the /dev/fuse fd failed");
    if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 10 ||
        minor(st.st_rdev) != 229)
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, EINVAL,
                                  "the /dev/fuse fd is not character device "
                                  "10:229 (st_mode %#o, %u:%u)",
                                  (unsigned)st.st_mode, major(st.st_rdev),
                                  minor(st.st_rdev));
    if ((flags & O_ACCMODE) != O_RDWR)
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, EINVAL,
                                  "the /dev/fuse fd is not open O_RDWR "
                                  "(flags %#o)",
                                  (unsigned)flags);
    return 0;
}

/* Reads the kernel's explanation of an fs_context failure ("<severity>
 * <message>", the only place that names the rejected mount option) as a
 * ": ..." suffix for a log message, or "" if there is none. */
static const char *fs_context_message(int fsfd, char *buf, size_t size) {
    int saved_errno = errno;
    ssize_t n = read(fsfd, buf + 2, size - 3);
    errno = saved_errno;
    if (n <= 0)
        return "";
    memcpy(buf, ": ", 2);
    n += 2;
    while (n > 2 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
        n--;
    buf[n] = '\0';
    return buf;
}

/* fsconfig(FSCONFIG_SET_STRING), or FSCONFIG_SET_FLAG for a NULL value. */
static int fsconfig_set(int fsfd, const char *key, const char *value,
                        struct defused_error *err) {
    if (syscall(SYS_fsconfig, fsfd,
                value ? FSCONFIG_SET_STRING : FSCONFIG_SET_FLAG, key, value,
                0) == 0)
        return 0;
    char msg[128];
    return defused_error_setf(err, DEFUSED_ERROR_MOUNT_FAILED, errno,
                              "fsconfig(\"%s\"%s%s) failed%s", key,
                              value ? "=" : "", value ? value : "",
                              fs_context_message(fsfd, msg, sizeof(msg)));
}

/* Creates the FUSE superblock and a detached mount of it, still to be
 * attached with move_mount(); returns the mount fd. */
static int create_detached_mount(const struct defused_mount_req *req,
                                 int dev_fd, mode_t rootmode,
                                 const struct peer *peer,
                                 struct defused_error *err) {
    uint32_t flags = req->mount_flags;
    char type[DEFUSED_MAX_NAME + 16], msg[128];
    snprintf(type, sizeof(type), "%s%s%s",
             flags & DEFUSED_MOUNT_BLKDEV ? "fuseblk" : "fuse",
             req->subtype[0] ? "." : "", req->subtype);
    _cleanup_close_ int fsfd = (int)syscall(SYS_fsopen, type, FSOPEN_CLOEXEC);
    if (fsfd == -1)
        return defused_error_setf(
            err, DEFUSED_ERROR_MOUNT_FAILED, errno, "fsopen(\"%s\") failed%s",
            type, errno == ENODEV ? " -- is the fuse module loaded?" : "");

    char fd[16], mode[16], uid[16], gid[16], max_read[16], blksize[16];
    snprintf(fd, sizeof(fd), "%d", dev_fd);
    snprintf(mode, sizeof(mode), "%o", (unsigned)rootmode);
    snprintf(uid, sizeof(uid), "%u", (unsigned)peer->uid);
    snprintf(gid, sizeof(gid), "%u", (unsigned)peer->gid);
    snprintf(max_read, sizeof(max_read), "%u", req->max_read);
    snprintf(blksize, sizeof(blksize), "%u", req->blksize);
    const struct {
        const char *key, *value;
        bool set;
    } options[] = {
        {"subtype", req->subtype, req->subtype[0] != '\0'},
        {"source", req->fsname[0] ? req->fsname : "fuse", true},
        {"fd", fd, true},
        {"rootmode", mode, true},
        {"user_id", uid, true},
        {"group_id", gid, true},
        {"max_read", max_read, req->max_read != 0},
        {"blksize", blksize, req->blksize != 0},
        {"allow_other", NULL, flags & DEFUSED_FUSE_ALLOW_OTHER},
        {"default_permissions", NULL, flags & DEFUSED_FUSE_DEFAULT_PERMISSIONS},
        {"ro", NULL, flags & DEFUSED_MOUNT_RDONLY},
        {"sync", NULL, flags & DEFUSED_MOUNT_SYNCHRONOUS},
        {"dirsync", NULL, flags & DEFUSED_MOUNT_DIRSYNC},
    };
    for (size_t i = 0; i < ARRAY_SIZE(options); i++) {
        int ret = options[i].set ? fsconfig_set(fsfd, options[i].key,
                                                options[i].value, err)
                                 : 0;
        if (ret < 0)
            return ret;
    }
    if (syscall(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1)
        return defused_error_setf(err, DEFUSED_ERROR_MOUNT_FAILED, errno,
                                  "fsconfig(CMD_CREATE) for %s failed%s", type,
                                  fs_context_message(fsfd, msg, sizeof(msg)));

    /* nosuid and nodev unless a privileged caller asked otherwise. */
    unsigned attrs =
        (flags & DEFUSED_MOUNT_ALLOW_SUID ? 0 : MOUNT_ATTR_NOSUID) |
        (flags & DEFUSED_MOUNT_ALLOW_DEV ? 0 : MOUNT_ATTR_NODEV) |
        (flags & DEFUSED_MOUNT_RDONLY ? MOUNT_ATTR_RDONLY : 0) |
        (flags & DEFUSED_MOUNT_NOEXEC ? MOUNT_ATTR_NOEXEC : 0) |
        (flags & DEFUSED_MOUNT_NOATIME ? MOUNT_ATTR_NOATIME : 0) |
        (flags & DEFUSED_MOUNT_NODIRATIME ? MOUNT_ATTR_NODIRATIME : 0) |
        (flags & DEFUSED_MOUNT_NOSYMFOLLOW ? MOUNT_ATTR_NOSYMFOLLOW : 0);
    int mountfd = (int)syscall(SYS_fsmount, fsfd, FSMOUNT_CLOEXEC, attrs);
    if (mountfd == -1)
        return defused_error_setf(err, DEFUSED_ERROR_MOUNT_FAILED, errno,
                                  "fsmount(attrs %#x) failed%s", attrs,
                                  fs_context_message(fsfd, msg, sizeof(msg)));
    return mountfd;
}

/* Validates and performs a mount request. On failure, *err says why. */
static int mount_request(sd_varlink *link, const struct defused_mount_req *req,
                         int mnt_fd, int dev_fd, const struct peer *peer,
                         struct defused_error *err) {
    if (!cfg_child && strchr(req->fsname, '/'))
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, EINVAL,
                                  "fsname \"%s\" contains '/' and the caller "
                                  "is not privileged",
                                  req->fsname);
    if (strchr(req->subtype, '/'))
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, EINVAL,
                                  "subtype \"%s\" contains '/'", req->subtype);
    if ((req->mount_flags & DEFUSED_MOUNT_BLKDEV) && !req->fsname[0])
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, EINVAL,
                                  "a fuseblk mount needs an fsname naming the "
                                  "block device");
    uint32_t allowed = DEFUSED_MOUNT_FLAGS_MASK;
    if (!cfg_child)
        allowed &= ~(uint32_t)DEFUSED_MOUNT_PRIVILEGED_FLAGS;
    if (req->mount_flags & ~allowed) {
        char flags[160];
        defused_error_setf(
            err, DEFUSED_ERROR_BAD_OPTION, 0,
            "mount flags %s are not available here (%s)",
            mount_flags_str(req->mount_flags & ~allowed, flags, sizeof(flags)),
            req->mount_flags & DEFUSED_MOUNT_PRIVILEGED_FLAGS
                ? "privileged flags need a privileged caller"
                : "unknown flag bits");
        return -EINVAL;
    }

    struct stat st;
    if (fstat(mnt_fd, &st) == -1)
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, errno,
                                  "fstat() on the mountpoint fd failed");
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED,
                                  S_ISLNK(st.st_mode) ? ELOOP : ENOTDIR,
                                  "the mountpoint is neither a directory nor "
                                  "a regular file (st_mode %#o)",
                                  (unsigned)st.st_mode);
    int ret, pidfd = -EBADF;
    if (!cfg_child) {
        /* Ownership: stricter than libfuse's setuid fusermount3, see
         * doc/protocol.md. */
        if (st.st_uid != peer->uid) {
            defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                               "the mountpoint is owned by uid %u, not the "
                               "caller's uid %u",
                               (unsigned)st.st_uid, (unsigned)peer->uid);
            return -EPERM;
        }
        if (!(st.st_mode & S_IWUSR) ||
            (S_ISDIR(st.st_mode) && !(st.st_mode & S_IXUSR))) {
            defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                               "the mountpoint is not writable%s by its owner "
                               "(st_mode %#o)",
                               S_ISDIR(st.st_mode) ? " and searchable" : "",
                               (unsigned)st.st_mode);
            return -EPERM;
        }
        struct statfs fs;
        if (fstatfs(mnt_fd, &fs) == -1)
            return defused_error_setf(err, DEFUSED_ERROR_MOUNT_FAILED, errno,
                                      "fstatfs() on the mountpoint fd failed");
        if (!fstype_allows_user_mounts(&fs)) {
            defused_error_setf(err, DEFUSED_ERROR_NOT_ALLOWED, 0,
                               "unprivileged mounts are not allowed on the "
                               "mountpoint's filesystem (statfs f_type %#lx)",
                               (unsigned long)fs.f_type);
            return -EPERM;
        }
    }
    ret = check_fuse_device(dev_fd, err);
    if (ret < 0)
        return ret;
    if (!cfg_child) {
        pidfd = sd_varlink_get_peer_pidfd(link);
        if (pidfd < 0)
            return defused_error_setf(err, DEFUSED_ERROR_MOUNT_FAILED, -pidfd,
                                      "SO_PEERPIDFD on the client socket "
                                      "failed");
        ret = policy_check(link, peer, DEFUSED_OP_MOUNT, req->mount_flags, err);
        if (ret < 0)
            return ret;
    }

    _cleanup_close_ int mountfd =
        create_detached_mount(req, dev_fd, st.st_mode & S_IFMT, peer, err);
    if (mountfd < 0)
        return mountfd;
    if (!cfg_child)
        return defused_sandbox_mount(pidfd, mountfd, mnt_fd, err);
    if (syscall(SYS_move_mount, mountfd, "", mnt_fd, "",
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == -1)
        return defused_error_setf(err, DEFUSED_ERROR_MOUNT_FAILED, errno,
                                  "move_mount() onto the mountpoint failed");
    return 0;
}

static int varlink_mount(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    (void)userdata;
    struct defused_mount_req req = {};
    int ret = sd_varlink_dispatch(link, parameters, defused_mount_fields, &req);
    if (ret != 0)
        return ret;
    if (strlen(req.fsname) >= DEFUSED_MAX_FSNAME)
        return sd_varlink_error_invalid_parameter_name(link, "fsName");
    if (strlen(req.subtype) >= DEFUSED_MAX_NAME)
        return sd_varlink_error_invalid_parameter_name(link, "subtype");
    if (sd_varlink_get_n_fds(link) != 2)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "fuseFileDescriptor");
    _cleanup_close_ int dev_fd = sd_varlink_take_fd(link, req.fuse_fd);
    _cleanup_close_ int mnt_fd = sd_varlink_take_fd(link, req.mnt_fd);
    if (dev_fd < 0 || mnt_fd < 0)
        return sd_varlink_error_invalid_parameter_name(
            link,
            dev_fd < 0 ? "fuseFileDescriptor" : "mountpointFileDescriptor");

    struct peer peer;
    ret = get_peer(link, &peer);
    if (ret < 0)
        return ret;
    struct defused_error err = {};
    char target[512];
    ret = mount_request(link, &req, mnt_fd, dev_fd, &peer, &err);
    return finish_request(
        link, "mount", describe_mount_req(&req, mnt_fd, target, sizeof(target)),
        &peer, ret, &err);
}

/*** Unmount ***/

/* Validates and performs an unmount request. On failure, *err says why. */
static int umount_request(sd_varlink *link,
                          const struct defused_umount_req *req, int parent_fd,
                          const struct peer *peer, struct defused_error *err) {
    if (req->name[0] == '\0' || strchr(req->name, '/') ||
        !strcmp(req->name, ".") || !strcmp(req->name, ".."))
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, EINVAL,
                                  "the mountpoint name must be a plain "
                                  "basename, not \"%s\"",
                                  req->name);

    /* The service's own procfs, kept for use after entering the client's
     * mount namespace. */
    _cleanup_close_ int proc_fd =
        open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd == -1)
        return defused_error_setf(err, DEFUSED_ERROR_UNMOUNT_FAILED, errno,
                                  "opening /proc failed");
    _cleanup_close_ int mnt_fd =
        openat(parent_fd, req->name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1)
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, errno,
                                  "opening \"%s\" under the parent directory "
                                  "failed",
                                  req->name);
    long parent_mnt_id = -1, mnt_id = -1;
    int ret = defused_fd_mnt_id(proc_fd, parent_fd, &parent_mnt_id);
    if (ret == 0)
        ret = defused_fd_mnt_id(proc_fd, mnt_fd, &mnt_id);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERROR_MALFORMED, -ret,
                                  "could not read the mnt_id of \"%s\" or its "
                                  "parent directory from procfs",
                                  req->name);
    if (mnt_id == parent_mnt_id) {
        defused_error_setf(err, DEFUSED_ERROR_NOT_A_FUSE_MOUNT, 0,
                           "nothing is mounted on \"%s\" (it shares mnt_id "
                           "%ld with its parent directory); already "
                           "unmounted?",
                           req->name, mnt_id);
        return -EINVAL;
    }
    /* From here on mnt_id identifies the target. An open reference to the
     * mount, here or inherited by the sandboxed child, makes a non-lazy
     * umount2() fail with EBUSY. */
    mnt_fd = safe_close(mnt_fd);
    int umount_flags = UMOUNT_NOFOLLOW | (req->lazy ? MNT_DETACH : 0);

    if (cfg_child) {
        if (fchdir(parent_fd) == -1)
            return defused_error_setf(err, DEFUSED_ERROR_UNMOUNT_FAILED, errno,
                                      "fchdir() to the parent directory "
                                      "failed");
        if (umount2(req->name, umount_flags) == -1)
            return defused_error_setf(err, DEFUSED_ERROR_UNMOUNT_FAILED, errno,
                                      "umount2(\"%s\"%s) failed", req->name,
                                      req->lazy ? ", MNT_DETACH" : "");
        return 0;
    }

    int pidfd = sd_varlink_get_peer_pidfd(link);
    if (pidfd < 0)
        return defused_error_setf(err, DEFUSED_ERROR_UNMOUNT_FAILED, -pidfd,
                                  "SO_PEERPIDFD on the client socket failed");
    ret = policy_check(link, peer, DEFUSED_OP_UNMOUNT, 0, err);
    if (ret < 0)
        return ret;
    return defused_sandbox_unmount(pidfd, proc_fd, parent_fd, req->name,
                                   req->lazy, mnt_id, peer->uid, err);
}

static int varlink_unmount(sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    (void)userdata;
    struct defused_umount_req req = {};
    int ret =
        sd_varlink_dispatch(link, parameters, defused_umount_fields, &req);
    if (ret != 0)
        return ret;
    if (strlen(req.name) >= DEFUSED_MAX_FILENAME)
        return sd_varlink_error_invalid_parameter_name(link, "name");
    if (sd_varlink_get_n_fds(link) != 1)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "parentFileDescriptor");
    _cleanup_close_ int parent_fd = sd_varlink_take_fd(link, req.parent_fd);
    if (parent_fd < 0)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "parentFileDescriptor");

    struct peer peer;
    ret = get_peer(link, &peer);
    if (ret < 0)
        return ret;
    struct defused_error err = {};
    char path[256], target[512];
    ret = umount_request(link, &req, parent_fd, &peer, &err);
    snprintf(target, sizeof(target), "\"%s/%s\"%s",
             fd_path(parent_fd, path, sizeof(path)), req.name,
             req.lazy ? " (lazy)" : "");
    return finish_request(link, "unmount", target, &peer, ret, &err);
}

/*** Connections ***/

/* Serves one already-connected Varlink socket to completion (one
 * mount/unmount request). Takes ownership of sock_fd; returns an exit
 * status. */
static int handle_connection(int sock_fd) {
    _cleanup_close_ int sock = sock_fd;
    _cleanup_(sd_event_unrefp) sd_event *event = NULL;
    _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
    int ret;
    if ((ret = sd_event_new(&event)) < 0 ||
        (ret = sd_varlink_server_new(
             &server, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT |
                          SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT)) < 0 ||
        (ret = sd_varlink_server_add_interface(
             server, &vl_interface_website_soss_defused)) < 0 ||
        (ret = sd_varlink_server_bind_method_many(
             server, DEFUSED_METHOD_MOUNT, varlink_mount,
             DEFUSED_METHOD_UNMOUNT, varlink_unmount)) < 0 ||
        (ret = sd_varlink_server_set_exit_on_idle(server, true)) < 0 ||
        (ret = sd_varlink_server_attach_event(server, event, 0)) < 0 ||
        /* The server owns the fd once added; on failure it is still ours. */
        (ret = sd_varlink_server_add_connection(server, sock, NULL)) < 0) {
        log_error(ret, "Varlink server setup failed");
        return EXIT_FAILURE;
    }
    TAKE_FD(sock);
    ret = sd_event_loop(event);
    if (ret < 0) {
        log_error(ret, "Varlink server failed");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static volatile sig_atomic_t live_children;

static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        live_children--;
    errno = saved_errno;
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
    fprintf(stderr, "defused: listening on %s\n", path);
    return TAKE_FD(fd);
}

/* --daemon: returns only on a fatal error. */
static int run_daemon(void) {
    const char *path = getenv("DEFUSED_SOCKET");
    if (path == NULL || *path == '\0')
        path = DEFUSED_SOCKET_PATH;
    _cleanup_close_ int listen_fd = listen_socket(path);
    if (listen_fd < 0)
        return listen_fd;

    /* SA_RESTART: accept4() only sees EINTR from other signals. */
    struct sigaction sa = {.sa_handler = sigchld_handler,
                           .sa_flags = SA_RESTART};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
        return log_error(-errno, "sigaction(SIGCHLD)");

    for (;;) {
        _cleanup_close_ int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (conn == -1) {
            if (errno == EINTR)
                continue;
            log_error(-errno, "accept4");
            if (errno == EMFILE || errno == ENFILE || errno == ECONNABORTED)
                continue; /* transient */
            return -errno;
        }
        /* Past the cap: closed, so the client fails fast. */
        if (live_children >= DAEMON_MAX_CONNECTIONS) {
            fprintf(stderr,
                    "defused: refusing connection: %d already being handled "
                    "(max %d)\n",
                    (int)live_children, DAEMON_MAX_CONNECTIONS);
            continue;
        }
        pid_t pid = fork();
        if (pid == -1) {
            log_error(-errno, "fork");
            continue;
        }
        if (pid == 0) {
            listen_fd = safe_close(listen_fd);
            /* This child waits for a sandbox child of its own. */
            signal(SIGCHLD, SIG_DFL);
            _exit(handle_connection(TAKE_FD(conn)));
        }
        live_children++;
    }
}

/*** Command line ***/

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [--daemon | --child] [POLICY OPTION...]\n"
            "\n"
            "Handles one mount/unmount request on the socket-activation fd;\n"
            "meant to be spawned by systemd, one process per connection.\n"
            "\n"
            "  --daemon  listen on $DEFUSED_SOCKET (default %s)\n"
            "            and fork a child per connection, for non-systemd\n"
            "            setups\n"
            "  --child   handle the request with this process's own\n"
            "            privileges and no policy; spawned by fusermount3\n"
            "            for root and CAP_SYS_ADMIN callers\n"
            "\n"
            "Policy options, for unprivileged callers (see doc/protocol.md):\n"
            "  --max-mounts=N            refuse a mount once N FUSE\n"
            "                            filesystems are mounted (default %d)\n"
            "  --allow-groups=GROUP,...  only members of these groups (names\n"
            "                            or gids) may mount and unmount\n"
            "  --allow-other             let callers set allow_other\n",
            prog, DEFUSED_SOCKET_PATH, DEFAULT_MAX_MOUNTS);
}

/* Empty is allowed, so a unit file can pass an unset variable. */
static int parse_allow_groups(const char *arg) {
    _cleanup_free_ char *list = strdup(arg);
    if (list == NULL)
        return -ENOMEM;
    cfg_n_allow_groups = 0;
    char *saveptr = NULL;
    for (char *name = strtok_r(list, ",", &saveptr); name != NULL;
         name = strtok_r(NULL, ",", &saveptr)) {
        if (cfg_n_allow_groups == ARRAY_SIZE(cfg_allow_groups)) {
            fprintf(stderr, "defused: --allow-groups: more than %zu groups\n",
                    ARRAY_SIZE(cfg_allow_groups));
            return -EINVAL;
        }
        long gid;
        if (parse_long(name, &gid) == 0) {
            if (gid < 0 || gid > (long)(gid_t)-1) {
                fprintf(stderr,
                        "defused: --allow-groups: gid out of range: "
                        "%s\n",
                        name);
                return -EINVAL;
            }
        } else {
            struct group *gr = getgrnam(name);
            if (gr == NULL) {
                fprintf(stderr, "defused: --allow-groups: no such group: %s\n",
                        name);
                return -EINVAL;
            }
            gid = gr->gr_gid;
        }
        cfg_allow_groups[cfg_n_allow_groups++] = (gid_t)gid;
    }
    return 0;
}

static int parse_args(int argc, char *argv[]) {
    enum {
        OPT_DAEMON = 256,
        OPT_CHILD,
        OPT_MAX_MOUNTS,
        OPT_ALLOW_GROUPS,
        OPT_ALLOW_OTHER
    };
    static const struct option opts[] = {
        {"daemon", no_argument, NULL, OPT_DAEMON},
        {"child", no_argument, NULL, OPT_CHILD},
        {"max-mounts", required_argument, NULL, OPT_MAX_MOUNTS},
        {"allow-groups", required_argument, NULL, OPT_ALLOW_GROUPS},
        {"allow-other", no_argument, NULL, OPT_ALLOW_OTHER},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    for (int c; (c = getopt_long(argc, argv, "h", opts, NULL)) != -1;) {
        switch (c) {
        case OPT_DAEMON:
            cfg_daemon = true;
            break;
        case OPT_CHILD:
            cfg_child = true;
            break;
        case OPT_MAX_MOUNTS:
            if (parse_long(optarg, &cfg_max_mounts) < 0 ||
                cfg_max_mounts <= 0) {
                fprintf(stderr,
                        "defused: --max-mounts: expected a positive "
                        "number, got '%s'\n",
                        optarg);
                return -EINVAL;
            }
            break;
        case OPT_ALLOW_GROUPS:
            if (parse_allow_groups(optarg) < 0)
                return -EINVAL;
            break;
        case OPT_ALLOW_OTHER:
            cfg_allow_other = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            usage(argv[0]);
            return -EINVAL;
        }
    }
    if (optind < argc || (cfg_daemon && cfg_child)) {
        fprintf(stderr,
                optind < argc ? "defused: unexpected argument: %s\n"
                              : "defused: --daemon and --child are exclusive\n",
                argv[optind]);
        usage(argv[0]);
        return -EINVAL;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (parse_args(argc, argv) < 0)
        return EXIT_FAILURE;
    if (cfg_daemon)
        return run_daemon() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    /* systemd's Accept=yes (and sd_varlink_connect_exec()) hand over the
     * connection as fd 3. */
    if (sd_listen_fds(1) != 1 ||
        sd_is_socket_unix(SD_LISTEN_FDS_START, SOCK_STREAM, 0, NULL, 0) <= 0) {
        fprintf(stderr, "defused: expected exactly one connected AF_UNIX "
                        "stream socket via $LISTEN_FDS\n");
        return EXIT_FAILURE;
    }
    return handle_connection(SD_LISTEN_FDS_START);
}
