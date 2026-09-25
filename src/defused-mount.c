/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The checks that describe a well-formed request, the FUSE superblock
 * construction, and -- for a privileged fusermount3 -- carrying it out.
 * Nothing here decides whether a caller is *allowed* to ask: that is the
 * service's policy, in defused.c.
 */
#define _GNU_SOURCE
#include "defused-mount.h"
#include "common.h"
#include "defused-syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

/* FSOPEN_*, FSCONFIG_*, MOUNT_ATTR_* and MOVE_MOUNT_*: musl declares
 * none of them. */
#include <linux/mount.h>

/* AT_HANDLE_FID and AT_HANDLE_MNT_ID_UNIQUE. The define skips
 * <asm-generic/fcntl.h>, which would clash with <fcntl.h> above. */
#define _ASM_GENERIC_FCNTL_H
#include <linux/fcntl.h>

#define DEFUSED_MOVE_MOUNT_FLAGS                                               \
    (MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)

/* Linux 6.13's subtype: a request bit, and a string offset in the __u32
 * after mnt_ns_id, which older UAPI headers leave as padding. Read by
 * position so this builds against those headers too. */
#define STATMOUNT_FS_SUBTYPE_OFFSET                                            \
    (offsetof(struct statmount, mnt_ns_id) + sizeof(__u64))
#ifdef STATMOUNT_FS_SUBTYPE
_Static_assert(offsetof(struct statmount, fs_subtype) ==
                   STATMOUNT_FS_SUBTYPE_OFFSET,
               "fs_subtype must follow mnt_ns_id");
#else
#define STATMOUNT_FS_SUBTYPE 0x00000100U
#endif

static uint32_t statmount_fs_subtype(const struct statmount *sm) {
    uint32_t off;
    memcpy(&off, (const char *)sm + STATMOUNT_FS_SUBTYPE_OFFSET, sizeof(off));
    return off;
}

const char *defused_mount_flags_str(uint32_t flags, char *buf, size_t size) {
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

/* FUSE's user_id= among the comma-separated options. Matched only at an
 * option start, so a value ending in "user_id=" cannot pass for one. */
static int mount_opts_owner(const char *opts, uid_t *out_uid) {
    for (const char *p = opts;; p++) {
        if (strncmp(p, "user_id=", 8) == 0 && p[8] >= '0' && p[8] <= '9') {
            char *end;
            errno = 0;
            unsigned long uid = strtoul(p + 8, &end, 10);
            if (errno != 0 || uid > (uid_t)-1 || (*end != ',' && *end != '\0'))
                return -EINVAL;
            *out_uid = (uid_t)uid;
            return 0;
        }
        p += strcspn(p, ",");
        if (*p != ',')
            return -EINVAL;
    }
}

int defused_is_fuse_mount(uint64_t mnt_ns_id, uint64_t mnt_id, bool *out_blkdev,
                          const char *subtype, uid_t *out_uid) {
    struct mnt_id_req req = {
        .size = MNT_ID_REQ_SIZE_VER1,
        .mnt_id = mnt_id,
        .param = STATMOUNT_FS_TYPE | (subtype ? STATMOUNT_FS_SUBTYPE : 0) |
                 (out_uid ? STATMOUNT_MNT_OPTS : 0),
        .mnt_ns_id = mnt_ns_id,
    };
    /* An over-long string fails with EOVERFLOW rather than truncating. */
    union {
        struct statmount sm;
        char raw[4096];
    } buf;
    if (sys_statmount(&req, &buf.sm, sizeof(buf), 0) == -1)
        return -errno;
    if (!(buf.sm.mask & STATMOUNT_FS_TYPE))
        return -EINVAL;
    /* A "fuse.sshfs" mount reports its subtype separately, so these are
     * the only two spellings. */
    const char *fstype = buf.sm.str + buf.sm.fs_type;
    bool blkdev = strcmp(fstype, "fuseblk") == 0;
    if (!blkdev && strcmp(fstype, "fuse") != 0)
        return 0;
    /* Linux 6.12 reports no subtype at all, and later kernels report none
     * for a mount without one, so only a reported subtype is compared. */
    if (subtype && (buf.sm.mask & STATMOUNT_FS_SUBTYPE) &&
        strcmp(buf.sm.str + statmount_fs_subtype(&buf.sm), subtype) != 0)
        return 0;
    if (out_blkdev)
        *out_blkdev = blkdev;
    if (!out_uid)
        return 1;
    if (!(buf.sm.mask & STATMOUNT_MNT_OPTS))
        return -EINVAL;
    int ret = mount_opts_owner(buf.sm.str + buf.sm.mnt_opts, out_uid);
    return ret < 0 ? ret : 1;
}

/* struct file_handle ends in a flexible array member, so it cannot be
 * embedded. The same layout, at the largest size. */
struct mount_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[MAX_HANDLE_SZ];
};

int defused_mnt_id(int dir_fd, const char *name, uint64_t *out_id) {
    /* Unlike statx(), never calls getattr() -- see doc/protocol.md. */
    struct mount_handle handle = {.handle_bytes = MAX_HANDLE_SZ};
    if (sys_name_to_handle_at(dir_fd, name, &handle, out_id,
                              AT_EMPTY_PATH | AT_HANDLE_FID |
                                  AT_HANDLE_MNT_ID_UNIQUE) == -1)
        return -errno;
    return 0;
}

int defused_check_mount_request(const struct defused_request *req,
                                bool allow_privileged,
                                struct defused_error *err) {
    /* Flags first, so an unprivileged blkdev request hears that blkdev is
     * privileged rather than something about its fsname. */
    uint32_t allowed = DEFUSED_MOUNT_FLAGS_MASK;
    if (!allow_privileged)
        allowed &= ~(uint32_t)DEFUSED_MOUNT_PRIVILEGED_FLAGS;
    if (req->mount_flags & ~allowed) {
        char flags[160];
        defused_error_setf(err, DEFUSED_ERR_BAD_OPTION, 0,
                           "mount flags %s are not available here (%s)",
                           defused_mount_flags_str(req->mount_flags & ~allowed,
                                                   flags, sizeof(flags)),
                           req->mount_flags & DEFUSED_MOUNT_PRIVILEGED_FLAGS
                               ? "privileged flags need a privileged caller"
                               : "unknown flag bits");
        return -EINVAL;
    }
    /* Only blkdev's fsname names a device path, so only it may have a
     * slash. */
    if (!allow_privileged && strchr(req->fsname, '/'))
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
    return 0;
}

int defused_check_mountpoint(int mnt_fd, struct stat *out_st,
                             struct defused_error *err) {
    if (fstat(mnt_fd, out_st) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, errno,
                                  "fstat() on the mountpoint fd failed");
    if (!S_ISDIR(out_st->st_mode) && !S_ISREG(out_st->st_mode))
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED,
                                  S_ISLNK(out_st->st_mode) ? ELOOP : ENOTDIR,
                                  "the mountpoint is neither a directory nor "
                                  "a regular file (st_mode %#o)",
                                  (unsigned)out_st->st_mode);
    return 0;
}

int defused_check_fuse_device(int dev_fd, struct defused_error *err) {
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

/* The kernel's explanation of an fs_context failure -- the only place
 * that names the rejected option -- as a ": ..." suffix, or "". */
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

int defused_create_mount(const struct defused_request *req, int dev_fd,
                         mode_t rootmode, uid_t uid, gid_t gid,
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

    char fd[16], mode[16], uid_s[16], gid_s[16], max_read[16], blksize[16];
    snprintf(fd, sizeof(fd), "%d", dev_fd);
    snprintf(mode, sizeof(mode), "%o", (unsigned)rootmode);
    snprintf(uid_s, sizeof(uid_s), "%u", (unsigned)uid);
    snprintf(gid_s, sizeof(gid_s), "%u", (unsigned)gid);
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
        {"user_id", uid_s, true},
        {"group_id", gid_s, true},
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

int defused_check_umount_request(const struct defused_request *req,
                                 int parent_fd, uint64_t *out_mnt_id,
                                 struct defused_error *err) {
    if (req->name[0] == '\0' || strchr(req->name, '/') ||
        !strcmp(req->name, ".") || !strcmp(req->name, ".."))
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, EINVAL,
                                  "the mountpoint name must be a plain "
                                  "basename, not \"%s\"",
                                  req->name);

    uint64_t parent_mnt_id = 0, mnt_id = 0;
    int ret = defused_mnt_id(parent_fd, "", &parent_mnt_id);
    if (ret == 0)
        ret = defused_mnt_id(parent_fd, req->name, &mnt_id);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERR_MALFORMED, -ret,
                                  "could not read the mnt_id of \"%s\" or its "
                                  "parent directory",
                                  req->name);
    /* A mountpoint, not just a directory inside the same mount. */
    if (mnt_id == parent_mnt_id) {
        defused_error_setf(err, DEFUSED_ERR_NOT_A_FUSE_MOUNT, 0,
                           "nothing is mounted on \"%s\" (it shares mnt_id "
                           "%llu with its parent directory); already "
                           "unmounted?",
                           req->name, (unsigned long long)mnt_id);
        return -EINVAL;
    }
    *out_mnt_id = mnt_id;
    return 0;
}

/*** Performing it here, for a privileged caller ***/

static int perform_mount(const struct defused_request *req, int dev_fd,
                         int mnt_fd, struct defused_error *err) {
    struct stat st;
    int ret = defused_check_mount_request(req, true, err);
    if (ret == 0)
        ret = defused_check_mountpoint(mnt_fd, &st, err);
    if (ret == 0)
        ret = defused_check_fuse_device(dev_fd, err);
    if (ret < 0)
        return ret;

    /* The effective ids: what SO_PEERCRED gave the service when this was
     * a separate process. */
    _cleanup_close_ int mountfd = defused_create_mount(
        req, dev_fd, st.st_mode & S_IFMT, geteuid(), getegid(), err);
    if (mountfd < 0)
        return mountfd;
    if (sys_move_mount(mountfd, "", mnt_fd, "", DEFUSED_MOVE_MOUNT_FLAGS) == -1)
        return defused_error_setf(err, DEFUSED_ERR_MOUNT_FAILED, errno,
                                  "move_mount() onto the mountpoint failed");
    return 0;
}

/*
 * For fuseblk the kernel tears the superblock down on the way out of
 * umount2(), which sends FUSE_DESTROY and waits uninterruptibly for the
 * server. A caller that is the server, or waiting on one, would deadlock
 * with no way out -- the task cannot even be killed. A short-lived child
 * keeps this process killable, which breaks the cycle, and keeps the
 * chdir umount2() needs out of this process.
 */
static int umount_in_child(int parent_fd, const char *name, int flags) {
    _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
    if (pipe2(pipefd, O_CLOEXEC) == -1)
        return -errno;
    pid_t pid = fork();
    if (pid < 0)
        return -errno;
    if (pid == 0) {
        int child_errno = 0;
        if (fchdir(parent_fd) == -1 || umount2(name, flags) == -1)
            child_errno = errno;
        (void)!write(pipefd[1], &child_errno, sizeof(child_errno));
        _exit(child_errno == 0 ? 0 : 1);
    }
    pipefd[1] = safe_close(pipefd[1]);

    int child_errno = 0;
    ssize_t n;
    do
        n = read(pipefd[0], &child_errno, sizeof(child_errno));
    while (n < 0 && errno == EINTR);
    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
        ;
    return n == (ssize_t)sizeof(child_errno) ? -child_errno : -EIO;
}

static int perform_unmount(const struct defused_request *req, int parent_fd,
                           struct defused_error *err) {
    uint64_t mnt_id = 0;
    int ret = defused_check_umount_request(req, parent_fd, &mnt_id, err);
    if (ret < 0)
        return ret;

    int flags = UMOUNT_NOFOLLOW | (req->lazy ? MNT_DETACH : 0);
    ret = umount_in_child(parent_fd, req->name, flags);
    if (ret < 0)
        return defused_error_setf(err, DEFUSED_ERR_UNMOUNT_FAILED, -ret,
                                  "umount2(\"%s\"%s) failed", req->name,
                                  req->lazy ? ", MNT_DETACH" : "");
    return 0;
}

int defused_perform(const struct defused_request *req, const int *fds,
                    struct defused_error *err) {
    *err = (struct defused_error){0};
    int ret = req->op == DEFUSED_OP_MOUNT
                  ? perform_mount(req, fds[0], fds[1], err)
                  : perform_unmount(req, fds[0], err);
    /* Every failure above names itself; this only stops a silent one from
     * reading as success. */
    if (ret < 0 && err->code == DEFUSED_OK)
        defused_error_set(err,
                          req->op == DEFUSED_OP_MOUNT
                              ? DEFUSED_ERR_MOUNT_FAILED
                              : DEFUSED_ERR_UNMOUNT_FAILED,
                          -ret, NULL);
    return 0;
}

#ifdef DEFUSED_TEST
int defused_test_mount_opts_owner(const char *opts, uid_t *out_uid) {
    return mount_opts_owner(opts, out_uid);
}
#endif
