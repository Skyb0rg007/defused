/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The defused system service that mounts/unmounts FUSE filesystems on
 * behalf of unprivileged users.
 *
 * This program is designed to be called via systemd Accept=yes
 * socket activation, on a AF_UNIX SOCK_SEQPACKET socket.
 * The process exits after processing the operation.
 */
#define _GNU_SOURCE
#include "defused.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

static int recv_request(int sock, union defused_req *req, ssize_t *out_len,
                        int fds[2], int *out_fd_count, struct ucred *cred)
    __attribute__((__nonnull__(2, 3, 5, 6), __warn_unused_result__));
static int send_response(int sock, uint32_t status, int sys_errno, int fd);
static const char *status_name(uint32_t status)
    __attribute__((__const__, __warn_unused_result__));
static int join_peer_mnt_ns(int sock, enum defused_op op)
    __attribute__((__warn_unused_result__));
static int install_seccomp(enum defused_op op)
    __attribute__((__warn_unused_result__));
static int check_mount_policy(const struct defused_mount_req *req)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int check_mountpoint_fstype(int mnt_fd)
    __attribute__((__warn_unused_result__));
static int check_fuse_device_fd(int dev_fd)
    __attribute__((__warn_unused_result__));
static int mount_fuse_new_api(const struct defused_mount_req *req, int mnt_fd,
                              int dev_fd, const struct stat *st,
                              const struct ucred *cred)
    __attribute__((__nonnull__(1, 4, 5), __warn_unused_result__));
static int handle_mount(int sock, const struct defused_mount_req *req,
                        int mnt_fd, int dev_fd, const struct ucred *cred)
    __attribute__((__nonnull__(2, 5), __warn_unused_result__));
static int handle_umount(int sock, const struct defused_umount_req *req,
                         int parent_fd, int proc_fd, const struct ucred *cred)
    __attribute__((__nonnull__(2, 5), __warn_unused_result__));
static void usage(const char *prog) __attribute__((__nonnull__(1)));
static int parse_args(int argc, char *argv[])
    __attribute__((__nonnull__(2), __warn_unused_result__));
static int socket_activation_fd(int *out_fd)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int fuse_mount_entry(const char *line, const char **out_sep)
    __attribute__((__nonnull__(1, 2), __warn_unused_result__));
static int fd_mnt_id(int proc_fd, int fd, long *out_id)
    __attribute__((__nonnull__(3), __warn_unused_result__));
static int fuse_mount_owner(int proc_fd, long mnt_id, uid_t *out_uid)
    __attribute__((__nonnull__(3), __warn_unused_result__));

static long cfg_mount_max = 1000;
static bool cfg_user_allow_other = false;

int main(int argc, char *argv[]) {
    int exit_status = EXIT_FAILURE;

    int ret = parse_args(argc, argv);
    if (ret < 0)
        return EXIT_FAILURE;

    int sock = -1;
    ret = socket_activation_fd(&sock);
    if (ret < 0)
        return EXIT_FAILURE;

    int client_fd_count = 0;

    /* Keep a handle to the service's procfs before entering the client's
     * mount namespace. */
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd == -1) {
        fprintf(stderr, "defused: failed to open /proc: %s\n", strerror(errno));
        goto out;
    }
    union defused_req req;
    struct ucred cred;
    int client_fds[2] = {-1, -1};
    ssize_t n = -1;
    ret = recv_request(sock, &req, &n, client_fds, &client_fd_count, &cred);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to receive request: %s\n",
                strerror(-ret));
        goto out;
    }

    if ((size_t)n < sizeof(req.hdr) || req.hdr.magic != DEFUSED_PROTO_MAGIC ||
        req.hdr.version != DEFUSED_PROTO_VERSION) {
        fprintf(stderr,
                "defused: malformed request header (len=%zd, magic=%#x, "
                "version=%u)\n",
                n, (size_t)n >= sizeof(req.hdr) ? req.hdr.magic : 0,
                (size_t)n >= sizeof(req.hdr) ? req.hdr.version : 0);
        goto malformed;
    }

    switch (req.hdr.op) {
    case DEFUSED_OP_MOUNT:
        if ((size_t)n != sizeof(req.mount) || client_fd_count != 2) {
            fprintf(stderr,
                    "defused: malformed mount request (len=%zd, fds=%d)\n", n,
                    client_fd_count);
            goto malformed;
        }
        ret =
            handle_mount(sock, &req.mount, client_fds[1], client_fds[0], &cred);
        break;
    case DEFUSED_OP_UNMOUNT:
        if ((size_t)n != sizeof(req.umount) || client_fd_count != 1) {
            fprintf(stderr,
                    "defused: malformed unmount request (len=%zd, fds=%d)\n", n,
                    client_fd_count);
            goto malformed;
        }
        ret = handle_umount(sock, &req.umount, client_fds[0], proc_fd, &cred);
        break;
    default:
        fprintf(stderr, "defused: unknown request operation %u\n", req.hdr.op);
        goto malformed;
    }

    exit_status = EXIT_SUCCESS;
    goto out;

malformed:
    send_response(sock, DEFUSED_ERR_MALFORMED, 0, -1);
out:
    for (int i = 0; i < client_fd_count; i++)
        close(client_fds[i]);
    if (proc_fd >= 0)
        close(proc_fd);
    if (sock >= 0)
        close(sock);
    return exit_status;
}

/* Reads the one request message, up to two fds, and peer credentials */
static int recv_request(int sock, union defused_req *req, ssize_t *out_len,
                        int fds[2], int *out_fd_count, struct ucred *cred) {
    struct iovec iov = {.iov_base = req, .iov_len = sizeof(*req)};
    union {
        struct cmsghdr hdr;
        char
            buf[CMSG_SPACE(2 * sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
    } cmsg_buf;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf.buf,
        .msg_controllen = sizeof(cmsg_buf.buf),
    };

    fds[0] = -1;
    fds[1] = -1;
    *out_fd_count = 0;

    socklen_t cred_len = sizeof(*cred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, cred, &cred_len) == -1) {
        fprintf(stderr, "defused: SO_PEERCRED failed: %s\n", strerror(errno));
        return -errno;
    }

    ssize_t n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    if (n < 0) {
        fprintf(stderr, "defused: recvmsg failed: %s\n", strerror(errno));
        return -errno;
    }
    /* Ensure neither the message nor ancillary data were truncated */
    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        fprintf(stderr, "defused: request or ancillary data was truncated\n");
        return -EMSGSIZE;
    }

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            if (c->cmsg_len < CMSG_LEN(0)) {
                fprintf(stderr, "defused: malformed SCM_RIGHTS header\n");
                return -EMSGSIZE;
            }
            size_t payload_len = c->cmsg_len - CMSG_LEN(0);
            if (payload_len == 0 || payload_len % sizeof(int) != 0) {
                fprintf(stderr, "defused: malformed SCM_RIGHTS payload\n");
                return -EMSGSIZE;
            }
            size_t fd_count = payload_len / sizeof(int);
            if (*out_fd_count + (int)fd_count > 2) {
                int *extra = (int *)CMSG_DATA(c);
                for (size_t i = 0; i < fd_count; i++)
                    close(extra[i]);
                fprintf(stderr, "defused: too many request file descriptors\n");
                return -EMSGSIZE;
            }
            memcpy(&fds[*out_fd_count], CMSG_DATA(c), fd_count * sizeof(int));
            *out_fd_count += (int)fd_count;
        }
    }

    *out_len = n;
    return 0;
}

static int send_response(int sock, uint32_t status, int sys_errno, int fd) {
    struct defused_resp resp = {
        .hdr = {DEFUSED_PROTO_MAGIC, DEFUSED_PROTO_VERSION, 0},
        .status = status,
        .sys_errno = sys_errno,
    };
    struct iovec iov = {.iov_base = &resp, .iov_len = sizeof(resp)};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};

    if (fd >= 0) {
        union {
            struct cmsghdr hdr;
            char buf[CMSG_SPACE(sizeof(int))];
        } cmsg_buf;

        msg.msg_control = cmsg_buf.buf;
        msg.msg_controllen = sizeof(cmsg_buf.buf);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof(int));
    }

    /* Don't send a signal if the peer is gone, just return an error */
    if (sendmsg(sock, &msg, MSG_NOSIGNAL) == -1) {
        fprintf(stderr, "defused: failed to send response %s: %s\n",
                status_name(status), strerror(errno));
        return -errno;
    }
    return 0;
}

static const char *status_name(uint32_t status) {
    switch (status) {
    case DEFUSED_OK:
        return "DEFUSED_OK";
    case DEFUSED_ERR_MALFORMED:
        return "DEFUSED_ERR_MALFORMED";
    case DEFUSED_ERR_BAD_OPTION:
        return "DEFUSED_ERR_BAD_OPTION";
    case DEFUSED_ERR_NOT_ALLOWED:
        return "DEFUSED_ERR_NOT_ALLOWED";
    case DEFUSED_ERR_TOO_MANY_MOUNTS:
        return "DEFUSED_ERR_TOO_MANY_MOUNTS";
    case DEFUSED_ERR_NOT_A_FUSE_MOUNT:
        return "DEFUSED_ERR_NOT_A_FUSE_MOUNT";
    case DEFUSED_ERR_MOUNT_FAILED:
        return "DEFUSED_ERR_MOUNT_FAILED";
    case DEFUSED_ERR_UNMOUNT_FAILED:
        return "DEFUSED_ERR_UNMOUNT_FAILED";
    case DEFUSED_ERR_SETNS_FAILED:
        return "DEFUSED_ERR_SETNS_FAILED";
    default:
        return "unknown status";
    }
}

/* Joins the peer's mount namespace using the socket peer's pidfd */
static int join_peer_mnt_ns(int sock, enum defused_op op) {
    int pidfd = -1;
    int ret = 0;
    socklen_t len = sizeof(pidfd);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) == -1) {
        fprintf(stderr, "defused: SO_PEERPIDFD failed: %s\n", strerror(errno));
        return -errno;
    }

    ret = install_seccomp(op);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to install seccomp filter: %s\n",
                strerror(-ret));
        goto out;
    }

    fprintf(stderr, "defused: seccomp installed\n");

    if (setns(pidfd, CLONE_NEWNS) == -1) {
        fprintf(stderr, "defused: failed to join peer mount namespace: %s\n",
                strerror(errno));
        ret = -errno;
    }

out:
    if (pidfd >= 0)
        close(pidfd);
    return ret;
}

/* After setns(), the filesystem will be controlled by the client.
 * Restrict ourselves before that to make sure nothing bad happens. */
static int install_seccomp(enum defused_op op) {
    static const int allowed_syscalls[] = {
        SCMP_SYS(read),         SCMP_SYS(write),      SCMP_SYS(close),
        SCMP_SYS(fstat),        SCMP_SYS(sendmsg),    SCMP_SYS(exit),
        SCMP_SYS(fcntl),        SCMP_SYS(exit_group), SCMP_SYS(setns),
        SCMP_SYS(rt_sigreturn),
    };
    static const int mount_syscalls[] = {
        SCMP_SYS(move_mount),
        SCMP_SYS(fsopen),
        SCMP_SYS(fsconfig),
        SCMP_SYS(fsmount),
    };
    static const int unmount_syscalls[] = {
        SCMP_SYS(fchdir),
        SCMP_SYS(umount2),
        SCMP_SYS(openat),
    };

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_LOG);
    if (!ctx)
        return -ENOMEM;

    int ret = 0;
    for (size_t i = 0;
         i < sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]); i++) {
        ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed_syscalls[i], 0);
        if (ret < 0)
            goto out;
    }

    switch (op) {
    case DEFUSED_OP_MOUNT:
        for (size_t i = 0;
             i < sizeof(mount_syscalls) / sizeof(mount_syscalls[0]); i++) {
            ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, mount_syscalls[i], 0);
            if (ret < 0)
                goto out;
        }
        break;
    case DEFUSED_OP_UNMOUNT:
        for (size_t i = 0;
             i < sizeof(unmount_syscalls) / sizeof(unmount_syscalls[0]); i++) {
            ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, unmount_syscalls[i], 0);
            if (ret < 0)
                goto out;
        }
        break;
    default:
        return -EINVAL;
    }

    ret = seccomp_load(ctx);
out:
    seccomp_release(ctx);
    return ret < 0 ? ret : 0;
}

/* Check the client's mount request against the configured policy */
static int check_mount_policy(const struct defused_mount_req *req) {
    if ((req->mount_flags & ~(uint32_t)DEFUSED_MOUNT_FLAGS_MASK) != 0)
        return -EINVAL;

    if ((req->mount_flags & DEFUSED_FUSE_ALLOW_OTHER) && !cfg_user_allow_other)
        return -EPERM;

    return 0;
}

static int check_mountpoint_fstype(int mnt_fd) {
    struct statfs fs;
    if (fstatfs(mnt_fd, &fs) == -1)
        return -errno;

    return check_nonroot_fstype("defused", &fs) == 0 ? 0 : -EPERM;
}

static int check_fuse_device_fd(int dev_fd) {
    struct stat st;
    if (fstat(dev_fd, &st) == -1)
        return -errno;
    if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 10 ||
        minor(st.st_rdev) != 229)
        return -EINVAL;

    int flags = fcntl(dev_fd, F_GETFL);
    if (flags == -1)
        return -errno;
    if ((flags & O_ACCMODE) != O_RDWR)
        return -EINVAL;
    return 0;
}

static int fsconfig_string(int fsfd, const char *key, const char *value) {
    if (fsconfig(fsfd, FSCONFIG_SET_STRING, key, value, 0) == -1)
        return -errno;
    return 0;
}

static int fsconfig_flag(int fsfd, const char *key) {
    if (fsconfig(fsfd, FSCONFIG_SET_FLAG, key, NULL, 0) == -1)
        return -errno;
    return 0;
}

static int mount_fuse_new_api(const struct defused_mount_req *req, int mnt_fd,
                              int dev_fd, const struct stat *st,
                              const struct ucred *cred) {
    char type[2 * DEFUSED_MAX_NAME + 16];
    snprintf(type, sizeof(type), "fuse%s%s", req->subtype[0] ? "." : "",
             req->subtype);

    int fsfd = fsopen(type, FSOPEN_CLOEXEC);
    if (fsfd == -1)
        return -errno;

    int mountfd = -1;
    int ret = 0;
    uint32_t flags = req->mount_flags & DEFUSED_MOUNT_FLAGS_MASK;
    unsigned int mount_attrs = 0;

    if (req->subtype[0]) {
        ret = fsconfig_string(fsfd, "subtype", req->subtype);
        if (ret < 0)
            goto out;
    }

    ret =
        fsconfig_string(fsfd, "source", req->fsname[0] ? req->fsname : "fuse");
    if (ret < 0)
        goto out;

    char value[32];
    snprintf(value, sizeof(value), "%d", dev_fd);
    ret = fsconfig_string(fsfd, "fd", value);
    if (ret < 0)
        goto out;

    snprintf(value, sizeof(value), "%o", st->st_mode & S_IFMT);
    ret = fsconfig_string(fsfd, "rootmode", value);
    if (ret < 0)
        goto out;

    snprintf(value, sizeof(value), "%u", cred->uid);
    ret = fsconfig_string(fsfd, "user_id", value);
    if (ret < 0)
        goto out;

    snprintf(value, sizeof(value), "%u", cred->gid);
    ret = fsconfig_string(fsfd, "group_id", value);
    if (ret < 0)
        goto out;

    if (flags & DEFUSED_FUSE_ALLOW_OTHER) {
        ret = fsconfig_flag(fsfd, "allow_other");
        if (ret < 0)
            goto out;
    }
    if (flags & DEFUSED_FUSE_DEFAULT_PERMISSIONS) {
        ret = fsconfig_flag(fsfd, "default_permissions");
        if (ret < 0)
            goto out;
    }
    if (req->max_read) {
        snprintf(value, sizeof(value), "%u", req->max_read);
        ret = fsconfig_string(fsfd, "max_read", value);
        if (ret < 0)
            goto out;
    }
    if (req->blksize) {
        snprintf(value, sizeof(value), "%u", req->blksize);
        ret = fsconfig_string(fsfd, "blksize", value);
        if (ret < 0)
            goto out;
    }

    if (flags & DEFUSED_MOUNT_RDONLY) {
        ret = fsconfig_flag(fsfd, "ro");
        if (ret < 0)
            goto out;
        mount_attrs |= MOUNT_ATTR_RDONLY;
    }
    if (flags & DEFUSED_MOUNT_SYNCHRONOUS) {
        ret = fsconfig_flag(fsfd, "sync");
        if (ret < 0)
            goto out;
    }
    if (flags & DEFUSED_MOUNT_DIRSYNC) {
        ret = fsconfig_flag(fsfd, "dirsync");
        if (ret < 0)
            goto out;
    }
    mount_attrs |= MOUNT_ATTR_NOSUID;
    if (!(flags & DEFUSED_MOUNT_ALLOW_DEV))
        mount_attrs |= MOUNT_ATTR_NODEV;
    if (flags & DEFUSED_MOUNT_NOEXEC)
        mount_attrs |= MOUNT_ATTR_NOEXEC;
    if (flags & DEFUSED_MOUNT_NOATIME)
        mount_attrs |= MOUNT_ATTR_NOATIME;
    if (flags & DEFUSED_MOUNT_NODIRATIME)
        mount_attrs |= MOUNT_ATTR_NODIRATIME;
    if (flags & DEFUSED_MOUNT_NOSYMFOLLOW)
        mount_attrs |= MOUNT_ATTR_NOSYMFOLLOW;

    if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1) {
        ret = -errno;
        goto out;
    }

    mountfd = fsmount(fsfd, FSMOUNT_CLOEXEC, mount_attrs);
    if (mountfd == -1) {
        ret = -errno;
        goto out;
    }

    close(fsfd);
    fsfd = -1;

    if (move_mount(mountfd, "", mnt_fd, "",
                   MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == -1) {
        ret = -errno;
        goto out;
    }

    ret = 0;

out:
    if (mountfd >= 0)
        close(mountfd);
    if (fsfd >= 0)
        close(fsfd);
    return ret;
}

static int handle_mount(int sock, const struct defused_mount_req *req,
                        int mnt_fd, int dev_fd, const struct ucred *cred) {
    uint32_t status;
    int sys_errno = 0;
    int ret = 0;

    if (strnlen(req->fsname, DEFUSED_MAX_NAME) == DEFUSED_MAX_NAME ||
        strnlen(req->subtype, DEFUSED_MAX_NAME) == DEFUSED_MAX_NAME ||
        strchr(req->fsname, '/') || strchr(req->subtype, '/')) {
        status = DEFUSED_ERR_MALFORMED;
        ret = -EINVAL;
        goto fail;
    }

    ret = check_mount_policy(req);
    if (ret < 0) {
        status =
            ret == -EINVAL ? DEFUSED_ERR_BAD_OPTION : DEFUSED_ERR_NOT_ALLOWED;
        goto fail;
    }

    struct stat st;
    if (fstat(mnt_fd, &st) == -1) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = errno;
        ret = -errno;
        goto fail;
    }
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = S_ISLNK(st.st_mode) ? ELOOP : ENOTDIR;
        ret = -sys_errno;
        goto fail;
    }
    /* Callers may only mount on writable mountpoints they own,
     * and only over filesystems libfuse permits for unprivileged mounts. */
    if (st.st_uid != cred->uid || !(st.st_mode & S_IWUSR) ||
        (S_ISDIR(st.st_mode) && !(st.st_mode & S_IXUSR))) {
        status = DEFUSED_ERR_NOT_ALLOWED;
        ret = -EPERM;
        goto fail;
    }
    ret = check_mountpoint_fstype(mnt_fd);
    if (ret < 0) {
        status = DEFUSED_ERR_NOT_ALLOWED;
        goto fail;
    }

    ret = check_fuse_device_fd(dev_fd);
    if (ret < 0) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = -ret;
        goto fail;
    }

    if (cfg_mount_max != -1) {
        errno = 0;
        int n = count_fuse_fs("defused");

        if (n < 0) {
            int saved_errno = errno ? errno : EIO;
            status = DEFUSED_ERR_MOUNT_FAILED;
            sys_errno = saved_errno;
            ret = -saved_errno;
            goto fail;
        }
        if (n >= cfg_mount_max) {
            status = DEFUSED_ERR_TOO_MANY_MOUNTS;
            ret = -EUSERS;
            goto fail;
        }
    }

    ret = join_peer_mnt_ns(sock, DEFUSED_OP_MOUNT);
    if (ret < 0) {
        status = DEFUSED_ERR_SETNS_FAILED;
        sys_errno = -ret;
        goto fail;
    }

    ret = mount_fuse_new_api(req, mnt_fd, dev_fd, &st, cred);
    if (ret < 0) {
        status = DEFUSED_ERR_MOUNT_FAILED;
        sys_errno = -ret;
        goto fail;
    }

    return send_response(sock, DEFUSED_OK, 0, -1);

fail:
    fprintf(stderr,
            "defused: mount request failed with %s (ret=%d, errno=%d: %s)\n",
            status_name(status), ret, sys_errno,
            sys_errno ? strerror(sys_errno) : "none");
    (void)send_response(sock, status, sys_errno, -1);
    return ret;
}

static int handle_umount(int sock, const struct defused_umount_req *req,
                         int parent_fd, int proc_fd, const struct ucred *cred) {
    uint32_t status = DEFUSED_OK;
    int sys_errno = 0;
    int ret = 0;
    int mnt_fd = -1;

    if (strnlen(req->name, DEFUSED_MAX_FILENAME) == DEFUSED_MAX_FILENAME ||
        req->name[0] == '\0' || strchr(req->name, '/') ||
        !strcmp(req->name, ".") || !strcmp(req->name, "..")) {
        status = DEFUSED_ERR_MALFORMED;
        ret = -EINVAL;
        goto out;
    }

    mnt_fd = openat(parent_fd, req->name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = errno;
        ret = -errno;
        goto out;
    }

    long parent_mnt_id = -1;
    ret = fd_mnt_id(proc_fd, parent_fd, &parent_mnt_id);
    if (ret < 0) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = -ret;
        goto out;
    }

    /* Identify the mount that the fd refers to *without* calling into the
     * filesystem.
     * fdinfo's mnt_id comes straight from the VFS and therefore works even
     * if the FUSE server is not responding */
    long mnt_id = -1;
    ret = fd_mnt_id(proc_fd, mnt_fd, &mnt_id);
    if (ret < 0) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = -ret;
        goto out;
    }
    close(mnt_fd);
    mnt_fd = -1;

    if (mnt_id == parent_mnt_id) {
        status = DEFUSED_ERR_NOT_A_FUSE_MOUNT;
        ret = -EINVAL;
        goto out;
    }

    ret = join_peer_mnt_ns(sock, DEFUSED_OP_UNMOUNT);
    if (ret < 0) {
        status = DEFUSED_ERR_SETNS_FAILED;
        sys_errno = -ret;
        goto out;
    }

    /* The fd's mount must actually be FUSE, and be recorded as mounted
     * by this caller. Both facts come from the same mountinfo line. */
    uid_t owner;
    ret = fuse_mount_owner(proc_fd, mnt_id, &owner);
    if (ret < 0) {
        status = DEFUSED_ERR_NOT_A_FUSE_MOUNT;
        goto out;
    }
    if (owner != cred->uid) {
        status = DEFUSED_ERR_NOT_ALLOWED;
        ret = -EPERM;
        goto out;
    }

    /* Unmount via procfs fd, parent file descriptor, and filename. */
    if (fchdir(proc_fd) == -1) {
        status = DEFUSED_ERR_UNMOUNT_FAILED;
        sys_errno = errno;
        ret = -errno;
        goto out;
    }

    char proc_path[32 + DEFUSED_MAX_FILENAME];
    snprintf(proc_path, sizeof(proc_path), "self/fd/%d/%s", parent_fd,
             req->name);
    if (umount2(proc_path, (req->lazy ? MNT_DETACH : 0) | UMOUNT_NOFOLLOW) ==
        -1) {
        status = DEFUSED_ERR_UNMOUNT_FAILED;
        sys_errno = errno;
        ret = -errno;
        goto out;
    }

out:
    if (mnt_fd >= 0)
        close(mnt_fd);
    if (ret < 0)
        fprintf(
            stderr,
            "defused: unmount request failed with %s (ret=%d, errno=%d: %s)\n",
            status_name(status), ret, sys_errno,
            sys_errno ? strerror(sys_errno) : "none");
    int send_ret = send_response(sock, status, sys_errno, -1);
    if (ret == 0)
        ret = send_ret;
    return ret;
}

static void usage(const char *prog) {
    fprintf(
        stderr,
        "usage: %s [--mount-max=N] [--user-allow-other]\n"
        "\n"
        "Handles one mount/unmount request on the socket-activation fd (see\n"
        "defused.h); meant to be spawned by systemd socket activation, one\n"
        "process per connection. There is no config file -- these two\n"
        "options are the command-line equivalents of fuse.conf's mount_max\n"
        "and user_allow_other.\n"
        "\n"
        "  --mount-max=N       cap on simultaneous FUSE mounts; -1 disables\n"
        "                      the limit (default: 1000)\n"
        "  --user-allow-other  let callers pass -o allow_other (default: "
        "off)\n",
        prog);
}

static int parse_args(int argc, char *argv[]) {
    enum { OPT_MOUNT_MAX = 256, OPT_USER_ALLOW_OTHER };

    static const struct option opts[] = {
        {"mount-max", required_argument, NULL, OPT_MOUNT_MAX},
        {"user-allow-other", no_argument, NULL, OPT_USER_ALLOW_OTHER},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    for (;;) {
        int c = getopt_long(argc, argv, "h", opts, NULL);

        if (c == -1)
            break;
        switch (c) {
        case OPT_MOUNT_MAX: {
            long v;

            if (libfuse_strtol(optarg, &v) < 0 || (v < 0 && v != -1)) {
                fprintf(stderr, "%s: invalid --mount-max value: %s\n", argv[0],
                        optarg);
                return -EINVAL;
            }
            cfg_mount_max = v;
            break;
        }
        case OPT_USER_ALLOW_OTHER:
            cfg_user_allow_other = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -EINVAL;
        }
    }
    return 0;
}

/* Implements systemd socket activation */
static int socket_activation_fd(int *out_fd) {
    int n = sd_listen_fds(1 /* unset_environment */);
    if (n < 0) {
        fprintf(stderr, "defused: sd_listen_fds failed: %s\n", strerror(-n));
        return n;
    }
    if (n != 1) {
        fprintf(stderr,
                "defused: not socket-activated with exactly one fd (got "
                "%d) -- $LISTEN_PID/$LISTEN_FDS not set or wrong?\n",
                n);
        return -EINVAL;
    }

    *out_fd = SD_LISTEN_FDS_START;
    return 0;
}

/* Convert a FUSE mount's self/mountinfo line into
 * " - <fstype> <source> <superopts>".
 * Writes NULL into out_sep if the mount isn't FUSE.
 */
static int fuse_mount_entry(const char *line, const char **out_sep) {
    char *sep = strstr(line, " - ");
    char fstype[64];

    if (!sep || sscanf(sep + 3, "%63s", fstype) != 1)
        return -ENOENT;
    if (strcmp(fstype, "fuse") && strncmp(fstype, "fuse.", 5) &&
        strcmp(fstype, "fuseblk") && strncmp(fstype, "fuseblk.", 8))
        return -ENOENT;
    *out_sep = sep;
    return 0;
}

/* Determine the mount ID given a mount file descriptor via trusted procfs */
static int fd_mnt_id(int proc_fd, int fd, long *out_id) {
    char path[48];
    snprintf(path, sizeof(path), "self/fdinfo/%d", fd);
    int info_fd = openat(proc_fd, path, O_RDONLY | O_CLOEXEC);

    if (info_fd == -1)
        return -errno;

    FILE *f = fdopen(info_fd, "r");
    if (!f) {
        int saved_errno = errno;
        close(info_fd);
        errno = saved_errno;
        return -errno;
    }

    char line[256];
    long id = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "mnt_id:%ld", &id) == 1)
            break;
    fclose(f);
    if (id < 0)
        return -ENODATA;
    *out_id = id;
    return 0;
}

/* Extract the `user_id=` option from a FUSE mount.
 * This determines who originally mounted it. */
static int fuse_mount_owner(int proc_fd, long mnt_id, uid_t *out_uid) {
    int mountinfo_fd = openat(proc_fd, "self/mountinfo", O_RDONLY | O_CLOEXEC);

    if (mountinfo_fd == -1)
        return -errno;

    FILE *f = fdopen(mountinfo_fd, "r");
    if (!f) {
        int saved_errno = errno;
        close(mountinfo_fd);
        errno = saved_errno;
        return -errno;
    }

    char line[1024];
    int ret = -ENOENT;
    while (ret < 0 && fgets(line, sizeof(line), f)) {
        long id;

        if (sscanf(line, "%ld", &id) != 1 || id != mnt_id)
            continue;

        const char *sep;
        if (fuse_mount_entry(line, &sep) < 0)
            break; /* Not a FUSE mount */

        char *uidp = strstr(sep, "user_id=");
        unsigned uid;
        if (!uidp || sscanf(uidp + 8, "%u", &uid) != 1)
            break;

        *out_uid = (uid_t)uid;
        ret = 0;
    }
    fclose(f);
    return ret;
}
