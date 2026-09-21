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
#include "defused-proto.h"
#include "defused-sandbox.h"
#include "defused-syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
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
#include <unistd.h>

/* The kernel's own constants: SO_PEERGROUPS and SO_PEERPIDFD, and the new
 * mount API's FSOPEN_*, FSCONFIG_*, MOUNT_ATTR_* and MOVE_MOUNT_*. musl
 * declares none of them, and both libcs tolerate these alongside their own
 * headers. The mount API is used by syscall number: glibc only grew
 * wrappers in 2.36 and musl has none. */
#include <asm/socket.h>
#include <linux/mount.h>

#define DEFAULT_MAX_MOUNTS 100
/* A backstop for --daemon, like systemd's MaxConnections=. */
#define DAEMON_MAX_CONNECTIONS 64

static bool cfg_daemon, cfg_child, cfg_allow_other;
static long cfg_max_mounts = DEFAULT_MAX_MOUNTS;
static gid_t cfg_allow_groups[32];
static size_t cfg_n_allow_groups;

/* The client at the other end of the connection. */
struct peer {
    int sock;  /* the connection itself, for SO_PEERGROUPS */
    int pidfd; /* SO_PEERPIDFD; unset for --child, which skips policy */
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

/* Like libfuse's mount_max: the FUSE mounts in the client's mount
 * namespace, the one the new mount lands in. */
static int count_fuse_mounts(int pidfd) {
    uint64_t ns_id;
    int ret = defused_peer_mnt_ns_id(pidfd, &ns_id);
    if (ret < 0)
        return ret;
    struct mnt_id_req req = {
        .size = MNT_ID_REQ_SIZE_VER1,
        .mnt_id = LSMT_ROOT,
        .mnt_ns_id = ns_id,
    };
    uint64_t ids[256];
    int count = 0;
    for (;;) {
        ssize_t n = sys_listmount(&req, ids, ARRAY_SIZE(ids), 0);
        if (n < 0)
            return -errno;
        for (ssize_t i = 0; i < n; i++) {
            /* libfuse's mount_max counts "fuse" and not "fuseblk". */
            bool blkdev = false;
            ret = defused_is_fuse_mount(ns_id, ids[i], &blkdev, NULL);
            /* A mount that went away is one fewer mount, not an error. */
            if (ret == 1 && !blkdev)
                count++;
            else if (ret < 0 && ret != -ENOENT)
                return ret;
        }
        if (n < (ssize_t)ARRAY_SIZE(ids))
            return count;
        /* Continue after the last id returned. */
        req.param = ids[n - 1];
    }
}

/* Returns 1, 0, or a negative errno. SO_PEERGROUPS needs Linux 4.13. */
static int peer_in_allowed_groups(int sock, gid_t gid) {
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
static int policy_check(const struct peer *peer, uint32_t op,
                        uint32_t mount_flags, struct defused_error *err) {
    const char *what = op == DEFUSED_OP_MOUNT ? "mount" : "unmount";
    uint32_t fail_code = op == DEFUSED_OP_MOUNT ? DEFUSED_ERR_MOUNT_FAILED
                                                : DEFUSED_ERR_UNMOUNT_FAILED;
    if (cfg_n_allow_groups > 0) {
        int ret = peer_in_allowed_groups(peer->sock, peer->gid);
        if (ret < 0)
            return defused_error_setf(err, fail_code, -ret,
                                      "SO_PEERGROUPS on the client socket "
                                      "failed");
        if (ret == 0) {
            defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
                               "policy refused a %s: uid %u (gid %u) is in "
                               "none of the --allow-groups groups",
                               what, (unsigned)peer->uid, (unsigned)peer->gid);
            return -EACCES;
        }
    }
    if (op != DEFUSED_OP_MOUNT)
        return 0;
    if ((mount_flags & DEFUSED_FUSE_ALLOW_OTHER) && !cfg_allow_other) {
        defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
                           "policy refused a mount: allow_other is not "
                           "granted by --allow-other");
        return -EACCES;
    }
    int mounts = count_fuse_mounts(peer->pidfd);
    if (mounts < 0)
        return defused_error_setf(err, fail_code, -mounts,
                                  "could not count the existing FUSE mounts");
    if (mounts >= cfg_max_mounts) {
        defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
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
static const char *describe_mount_req(const struct defused_request *req,
                                      int mnt_fd, char *buf, size_t size) {
    char path[256], flags[160];
    snprintf(buf, size, "%s%s%s on \"%s\" (fsname=\"%s\", flags=%s)",
             req->mount_flags & DEFUSED_MOUNT_BLKDEV ? "fuseblk" : "fuse",
             req->subtype[0] ? "." : "", req->subtype,
             fd_path(mnt_fd, path, sizeof(path)), req->fsname,
             mount_flags_str(req->mount_flags, flags, sizeof(flags)));
    return buf;
}

/* Logs the outcome and answers. Only the code and errno go on the wire;
 * err->detail stays in the log. */
static int finish_request(const char *what, const char *target,
                          const struct peer *peer, int ret,
                          const struct defused_error *err) {
    if (ret >= 0)
        fprintf(stderr, "defused: %sed %s for uid %u\n", what, target,
                (unsigned)peer->uid);
    else
        fprintf(stderr,
                "defused: %s request from pid %d (uid %u) for %s: "
                "%s (%s)%s%s\n",
                what, (int)peer->pid, (unsigned)peer->uid, target,
                defused_error_description(err->code),
                strerror(err->sys_errno ? err->sys_errno : -ret),
                err->detail[0] ? " -- " : "", err->detail);
    int sent = defused_send_reply(peer->sock, err);
    return sent < 0 ? log_error(sent, "sending the reply failed") : ret;
}

static int get_peer(int sock, struct peer *peer) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1)
        return log_error(-errno, "SO_PEERCRED on the client socket failed");
    *peer = (struct peer){.sock = sock,
                          .pidfd = -EBADF,
                          .pid = cred.pid,
                          .uid = cred.uid,
                          .gid = cred.gid};
    return 0;
}

/* The connecting process, naming the namespace to act in. Linux 6.5+. */
static int get_peer_pidfd(struct peer *peer) {
    int fd = -1;
    socklen_t len = sizeof(fd);
    if (getsockopt(peer->sock, SOL_SOCKET, SO_PEERPIDFD, &fd, &len) == -1)
        return -errno;
    peer->pidfd = fd;
    return 0;
}

static int check_fuse_device(int dev_fd, struct defused_error *err) {
    struct stat st;
    int flags;
    if (fstat(dev_fd, &st) == -1 || (flags = fcntl(dev_fd, F_GETFL)) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, errno,
                                  "fstat()/fcntl() on the /dev/fuse fd failed");
    if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 10 ||
        minor(st.st_rdev) != 229)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
                                  "the /dev/fuse fd is not character device "
                                  "10:229 (st_mode %#o, %u:%u)",
                                  (unsigned)st.st_mode, major(st.st_rdev),
                                  minor(st.st_rdev));
    if ((flags & O_ACCMODE) != O_RDWR)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
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
    if (sys_fsconfig(fsfd, value ? FSCONFIG_SET_STRING : FSCONFIG_SET_FLAG, key,
                     value, 0) == 0)
        return 0;
    char msg[128];
    return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
                              "fsconfig(\"%s\"%s%s) failed%s", key,
                              value ? "=" : "", value ? value : "",
                              fs_context_message(fsfd, msg, sizeof(msg)));
}

/* Creates the FUSE superblock and a detached mount of it, still to be
 * attached with move_mount(); returns the mount fd. */
static int create_detached_mount(const struct defused_request *req, int dev_fd,
                                 mode_t rootmode, const struct peer *peer,
                                 struct defused_error *err) {
    uint32_t flags = req->mount_flags;
    char type[DEFUSED_MAX_SUBTYPE + 16], msg[128];
    snprintf(type, sizeof(type), "%s%s%s",
             flags & DEFUSED_MOUNT_BLKDEV ? "fuseblk" : "fuse",
             req->subtype[0] ? "." : "", req->subtype);
    _cleanup_close_ int fsfd = sys_fsopen(type, FSOPEN_CLOEXEC);
    if (fsfd == -1)
        return defused_error_setf(
            err, DEFUSED_ERR_MOUNT_FAILED, errno, "fsopen(\"%s\") failed%s",
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
    if (sys_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
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
    int mountfd = sys_fsmount(fsfd, FSMOUNT_CLOEXEC, attrs);
    if (mountfd == -1)
        return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
                                  "fsmount(attrs %#x) failed%s", attrs,
                                  fs_context_message(fsfd, msg, sizeof(msg)));
    return mountfd;
}

/* Validates and performs a mount request. On failure, *err says why. */
static int mount_request(const struct defused_request *req, int mnt_fd,
                         int dev_fd, const struct peer *peer,
                         struct defused_error *err) {
    if (!cfg_child && strchr(req->fsname, '/'))
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
                                  "fsname \"%s\" contains '/' and the caller "
                                  "is not privileged",
                                  req->fsname);
    if (strchr(req->subtype, '/'))
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
                                  "subtype \"%s\" contains '/'", req->subtype);
    if ((req->mount_flags & DEFUSED_MOUNT_BLKDEV) && !req->fsname[0])
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
                                  "a fuseblk mount needs an fsname naming the "
                                  "block device");
    uint32_t allowed = DEFUSED_MOUNT_FLAGS_MASK;
    if (!cfg_child)
        allowed &= ~(uint32_t)DEFUSED_MOUNT_PRIVILEGED_FLAGS;
    if (req->mount_flags & ~allowed) {
        char flags[160];
        defused_error_setf(
            err, DEFUSED_ERR_BAD_OPTION, 0,
            "mount flags %s are not available here (%s)",
            mount_flags_str(req->mount_flags & ~allowed, flags, sizeof(flags)),
            req->mount_flags & DEFUSED_MOUNT_PRIVILEGED_FLAGS
                ? "privileged flags need a privileged caller"
                : "unknown flag bits");
        return -EINVAL;
    }

    struct stat st;
    if (fstat(mnt_fd, &st) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, errno,
                                  "fstat() on the mountpoint fd failed");
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED,
                                  S_ISLNK(st.st_mode) ? ELOOP : ENOTDIR,
                                  "the mountpoint is neither a directory nor "
                                  "a regular file (st_mode %#o)",
                                  (unsigned)st.st_mode);
    int ret;
    if (!cfg_child) {
        /* Ownership: stricter than libfuse's setuid fusermount3, see
         * doc/protocol.md. */
        if (st.st_uid != peer->uid) {
            defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
                               "the mountpoint is owned by uid %u, not the "
                               "caller's uid %u",
                               (unsigned)st.st_uid, (unsigned)peer->uid);
            return -EPERM;
        }
        if (!(st.st_mode & S_IWUSR) ||
            (S_ISDIR(st.st_mode) && !(st.st_mode & S_IXUSR))) {
            defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
                               "the mountpoint is not writable%s by its owner "
                               "(st_mode %#o)",
                               S_ISDIR(st.st_mode) ? " and searchable" : "",
                               (unsigned)st.st_mode);
            return -EPERM;
        }
        struct statfs fs;
        if (fstatfs(mnt_fd, &fs) == -1)
            return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
                                      "fstatfs() on the mountpoint fd failed");
        if (!fstype_allows_user_mounts(&fs)) {
            defused_error_setf(err, DEFUSED_ERR_NOT_ALLOWED, 0,
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
        ret = policy_check(peer, DEFUSED_OP_MOUNT, req->mount_flags, err);
        if (ret < 0)
            return ret;
    }

    _cleanup_close_ int mountfd =
        create_detached_mount(req, dev_fd, st.st_mode & S_IFMT, peer, err);
    if (mountfd < 0)
        return mountfd;
    if (!cfg_child)
        return defused_sandbox_mount(peer->pidfd, mountfd, mnt_fd, err);
    if (sys_move_mount(mountfd, "", mnt_fd, "",
                       MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
                                  "move_mount() onto the mountpoint failed");
    return 0;
}

static int handle_mount(const struct defused_request *req, int dev_fd,
                        int mnt_fd, struct peer *peer,
                        struct defused_error *err) {
    int ret = cfg_child ? 0 : get_peer_pidfd(peer);
    if (ret < 0)
        defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, -ret,
                           "SO_PEERPIDFD on the client socket failed");
    else
        ret = mount_request(req, mnt_fd, dev_fd, peer, err);
    char target[512];
    return finish_request(
        "mount", describe_mount_req(req, mnt_fd, target, sizeof(target)), peer,
        ret, err);
}

/*** Unmount ***/

/* Validates and performs an unmount request. On failure, *err says why. */
static int umount_request(const struct defused_request *req, int parent_fd,
                          const struct peer *peer, struct defused_error *err) {
    if (req->name[0] == '\0' || strchr(req->name, '/') ||
        !strcmp(req->name, ".") || !strcmp(req->name, ".."))
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
                                  "the mountpoint name must be a plain "
                                  "basename, not \"%s\"",
                                  req->name);

    /* No open fd: a reference to the mount, here or inherited by the
     * sandboxed child, makes a non-lazy umount2() fail with EBUSY. */
    uint64_t parent_mnt_id = 0, mnt_id = 0;
    int ret = defused_mnt_id(parent_fd, "", &parent_mnt_id);
    if (ret == 0)
        ret = defused_mnt_id(parent_fd, req->name, &mnt_id);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, -ret,
                                  "could not read the mnt_id of \"%s\" or its "
                                  "parent directory",
                                  req->name);
    if (mnt_id == parent_mnt_id) {
        defused_error_setf(err, DEFUSED_ERR_NOT_A_FUSE_MOUNT, 0,
                           "nothing is mounted on \"%s\" (it shares mnt_id "
                           "%llu with its parent directory); already "
                           "unmounted?",
                           req->name, (unsigned long long)mnt_id);
        return -EINVAL;
    }
    /* From here on mnt_id identifies the target. */
    int umount_flags = UMOUNT_NOFOLLOW | (req->lazy ? MNT_DETACH : 0);

    if (cfg_child) {
        if (fchdir(parent_fd) == -1)
            return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, errno,
                                      "fchdir() to the parent directory "
                                      "failed");
        if (umount2(req->name, umount_flags) == -1)
            return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, errno,
                                      "umount2(\"%s\"%s) failed", req->name,
                                      req->lazy ? ", MNT_DETACH" : "");
        return 0;
    }

    ret = policy_check(peer, DEFUSED_OP_UNMOUNT, 0, err);
    if (ret < 0)
        return ret;
    return defused_sandbox_unmount(peer->pidfd, parent_fd, req->name, req->lazy,
                                   mnt_id, peer->uid, err);
}

static int handle_unmount(const struct defused_request *req, int parent_fd,
                          struct peer *peer, struct defused_error *err) {
    int ret = cfg_child ? 0 : get_peer_pidfd(peer);
    if (ret < 0)
        defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, -ret,
                           "SO_PEERPIDFD on the client socket failed");
    else
        ret = umount_request(req, parent_fd, peer, err);
    char path[256], target[512];
    snprintf(target, sizeof(target), "\"%s/%s\"%s",
             fd_path(parent_fd, path, sizeof(path)), req->name,
             req->lazy ? " (lazy)" : "");
    return finish_request("unmount", target, peer, ret, err);
}

/*** Connections ***/

/* One request in, one reply out. Takes ownership of sock_fd; the exit
 * status says whether the client was answered, not what the answer was. */
static int handle_connection(int sock_fd) {
    _cleanup_close_ int sock = sock_fd;
    struct defused_error err = {};
    struct defused_request req;
    int fds[DEFUSED_MAX_FDS];
    size_t n_fds = 0;

    int ret = defused_recv_request(sock, &req, fds, &n_fds);
    if (ret < 0) {
        log_error(ret, "could not read a request from the client");
        defused_error_set(&err, DEFUSED_ERR_MALFORMED, -ret, NULL);
        (void)defused_send_reply(sock, &err);
        return EXIT_FAILURE;
    }
    _cleanup_close_ int fd0 = fds[0];
    _cleanup_close_ int fd1 = n_fds > 1 ? fds[1] : -EBADF;

    struct peer peer;
    if (get_peer(sock, &peer) < 0)
        return EXIT_FAILURE;

    /* /dev/fuse then the mountpoint; for an unmount, its parent. */
    if (req.op == DEFUSED_OP_MOUNT)
        (void)handle_mount(&req, fd0, fd1, &peer, &err);
    else
        (void)handle_unmount(&req, fd0, &peer, &err);
    safe_close(peer.pidfd);
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
    _cleanup_close_ int fd =
        socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
    if (fd == -1)
        return log_error(-errno, "socket");
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        if (errno != EADDRINUSE)
            return log_error(-errno, "bind(%s)", path);
        _cleanup_close_ int probe =
            socket(AF_UNIX, DEFUSED_SOCKET_TYPE | SOCK_CLOEXEC, 0);
        if (probe == -1 ||
            connect(probe, (struct sockaddr *)&sa, sizeof(sa)) == 0 ||
            errno != ECONNREFUSED)
            return log_error(-EADDRINUSE, "socket %s", path);
        if (unlink(path) == -1 ||
            bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
            return log_error(-errno, "replacing the stale socket %s", path);
    }
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

/* The $LISTEN_PID/$LISTEN_FDS handover, all this ever needed of
 * sd_listen_fds(3): one connected socket of our type, or a negative
 * errno. */
static int inherited_connection(void) {
    const char *pid = getenv("LISTEN_PID"), *count = getenv("LISTEN_FDS");
    long value;
    if (pid == NULL || parse_long(pid, &value) < 0 || value != (long)getpid() ||
        count == NULL || parse_long(count, &value) < 0 || value != 1)
        return -EINVAL;
    unsetenv("LISTEN_PID");
    unsetenv("LISTEN_FDS");
    unsetenv("LISTEN_FDNAMES");
    if (fcntl(DEFUSED_LISTEN_FD, F_SETFD, FD_CLOEXEC) == -1)
        return -errno;

    int domain = 0, type = 0, listening = 0;
    socklen_t domain_len = sizeof(domain), type_len = sizeof(type),
              listening_len = sizeof(listening);
    if (getsockopt(DEFUSED_LISTEN_FD, SOL_SOCKET, SO_DOMAIN, &domain,
                   &domain_len) == -1 ||
        getsockopt(DEFUSED_LISTEN_FD, SOL_SOCKET, SO_TYPE, &type, &type_len) ==
            -1 ||
        getsockopt(DEFUSED_LISTEN_FD, SOL_SOCKET, SO_ACCEPTCONN, &listening,
                   &listening_len) == -1)
        return -errno;
    if (domain != AF_UNIX || type != DEFUSED_SOCKET_TYPE || listening)
        return -EINVAL;
    return DEFUSED_LISTEN_FD;
}

int main(int argc, char *argv[]) {
    if (parse_args(argc, argv) < 0)
        return EXIT_FAILURE;
    if (cfg_daemon)
        return run_daemon() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    int sock = inherited_connection();
    if (sock < 0) {
        fprintf(stderr,
                "defused: expected exactly one connected AF_UNIX "
                "SOCK_SEQPACKET socket on fd %d via $LISTEN_FDS: %s\n",
                DEFUSED_LISTEN_FD, strerror(-sock));
        return EXIT_FAILURE;
    }
    return handle_connection(sock);
}
