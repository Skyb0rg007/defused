/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Varlink protocol for setting up FUSE mounts.
 *
 * The protocol consists of a single request/response over a local Unix stream
 * socket. Framing, JSON parsing, and fd association are delegated to
 * libsystemd's sd-varlink implementation.
 * The default socket path is /run/defused/defused.sock, but can be overridden
 * with the DEFUSED_SOCKET environment variable.
 *
 * The server component (defused.service) will perform the validation, then
 * join the connecting process's mount namespace before performing the
 * mount or umount operations.
 */

#ifndef DEFUSED_PROTO_H
#define DEFUSED_PROTO_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink-idl.h>

#define DEFUSED_SOCKET_PATH "/run/defused/defused.sock"

#define DEFUSED_VARLINK_INTERFACE "website.soss.defused"
#define DEFUSED_VARLINK_METHOD_MOUNT "website.soss.defused.Mount"
#define DEFUSED_VARLINK_METHOD_UNMOUNT "website.soss.defused.Unmount"

/* The operation to perform */
enum defused_op {
    DEFUSED_OP_MOUNT = 1,
    DEFUSED_OP_UNMOUNT = 2,
};

/* The Varlink errors a failed request is reported as; a successful one gets
 * an empty reply. Defined in defused-varlink.c. */
#define DEFUSED_VARLINK_ERROR_MALFORMED                                        \
    DEFUSED_VARLINK_INTERFACE ".MalformedRequest"
#define DEFUSED_VARLINK_ERROR_BAD_OPTION                                       \
    DEFUSED_VARLINK_INTERFACE ".BadMountOption"
#define DEFUSED_VARLINK_ERROR_NOT_ALLOWED                                      \
    DEFUSED_VARLINK_INTERFACE ".NotAllowed"
#define DEFUSED_VARLINK_ERROR_NOT_A_FUSE_MOUNT                                 \
    DEFUSED_VARLINK_INTERFACE ".NotAFuseMount"
#define DEFUSED_VARLINK_ERROR_MOUNT_FAILED                                     \
    DEFUSED_VARLINK_INTERFACE ".MountFailed"
#define DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED                                   \
    DEFUSED_VARLINK_INTERFACE ".UnmountFailed"

/* Max length of an error id in struct defused_error */
#define DEFUSED_MAX_ERROR_ID 64

/* Max length of the log-only diagnostic in struct defused_error */
#define DEFUSED_MAX_ERROR_DETAIL 160

/* Max length of subtype */
#define DEFUSED_MAX_NAME 32

/* Max length of fsname (a device path for blkdev) */
#define DEFUSED_MAX_FSNAME 4096

/* Mountpoint basename */
#define DEFUSED_MAX_FILENAME 255

/* Options that can be specified when creating a FUSE mount */
enum defused_mount_flag {
    /* Create a read-only mount */
    DEFUSED_MOUNT_RDONLY = 1u << 0,
    /* Allow device files */
    DEFUSED_MOUNT_ALLOW_DEV = 1u << 1,
    /* Strip the execute bit from files */
    DEFUSED_MOUNT_NOEXEC = 1u << 2,
    /* Don't track file access time */
    DEFUSED_MOUNT_NOATIME = 1u << 3,
    /* Don't track directory access time */
    DEFUSED_MOUNT_NODIRATIME = 1u << 4,
    /* Block access of files through symlinks on the filesystem  */
    DEFUSED_MOUNT_NOSYMFOLLOW = 1u << 5,
    /* Force synchronous I/O */
    DEFUSED_MOUNT_SYNCHRONOUS = 1u << 6,
    /* Force synchronous I/O for directory modifications */
    DEFUSED_MOUNT_DIRSYNC = 1u << 7,
    /* Allow any user on the system to access the filesystem */
    DEFUSED_FUSE_ALLOW_OTHER = 1u << 8,
    /* Have Linux VFS perform Unix permission checks */
    DEFUSED_FUSE_DEFAULT_PERMISSIONS = 1u << 9,
    /* Honor set-user-ID bits (privileged) */
    DEFUSED_MOUNT_ALLOW_SUID = 1u << 10,
    /* Mount fuseblk on the block device named by fsname (privileged) */
    DEFUSED_MOUNT_BLKDEV = 1u << 11,
};
#define DEFUSED_MOUNT_PRIVILEGED_FLAGS                                         \
    (DEFUSED_MOUNT_ALLOW_SUID | DEFUSED_MOUNT_BLKDEV)
#define DEFUSED_MOUNT_FLAGS_MASK                                               \
    (DEFUSED_MOUNT_RDONLY | DEFUSED_MOUNT_ALLOW_DEV | DEFUSED_MOUNT_NOEXEC |   \
     DEFUSED_MOUNT_NOATIME | DEFUSED_MOUNT_NODIRATIME |                        \
     DEFUSED_MOUNT_NOSYMFOLLOW | DEFUSED_MOUNT_SYNCHRONOUS |                   \
     DEFUSED_MOUNT_DIRSYNC | DEFUSED_FUSE_ALLOW_OTHER |                        \
     DEFUSED_FUSE_DEFAULT_PERMISSIONS | DEFUSED_MOUNT_PRIVILEGED_FLAGS)

/*
 * Request a FUSE mount. The Varlink call carries two file descriptors,
 * referenced from the JSON payload by fd index:
 *
 *  1. A file descriptor opened from /dev/fuse
 *  2. A file descriptor opened to the destination mountpoint directory or
 *     regular file
 *
 * The service will then attempt to create the mountpoint with the given
 * options at the location specified by the second file descriptor.
 */
struct defused_mount_req {
    /* enum defused_mount_flag bits */
    uint32_t mount_flags;
    /* maximum read size, 0 for unset */
    uint32_t max_read;
    /* maximum block size, 0 for unset */
    uint32_t blksize;
    char fsname[DEFUSED_MAX_FSNAME];
    char subtype[DEFUSED_MAX_NAME];
};

/*
 * Request a FUSE unmount. The Varlink call carries one file descriptor for the
 * *parent* directory of the mount to tear down, referenced from the JSON
 * payload by fd index.
 *
 * The service will unmount the FUSE filesystem mounted with the given name
 * in the directory passed via file descriptor.
 */
struct defused_umount_req {
    /* set nonzero to perform a lazy unmount (MNT_DETACH) */
    uint32_t lazy;
    /* basename of the mountpoint */
    char name[DEFUSED_MAX_FILENAME];
};

union defused_req {
    struct defused_mount_req mount;
    struct defused_umount_req umount;
};

/* Why an operation failed; an empty id means it did not. sys_errno is the
 * error's "errno" field, 0 for the errors that don't carry one.
 *
 * detail names the exact check or syscall that failed. It only ever reaches
 * the service's log, never the wire, so it may say things the client is
 * deliberately not told: several causes share one error id, and some errors
 * carry no errno. */
struct defused_error {
    char id[DEFUSED_MAX_ERROR_ID];
    char detail[DEFUSED_MAX_ERROR_DETAIL];
    int32_t sys_errno;
};

/* The setters return -sys_errno so a caller can `return
 * defused_error_setf(...)`. */
static inline int defused_error_set_detail(struct defused_error *err,
                                           const char *id, int sys_errno,
                                           const char *detail) {
    strncpy(err->id, id ? id : "", sizeof(err->id) - 1);
    err->id[sizeof(err->id) - 1] = '\0';
    strncpy(err->detail, detail ? detail : "", sizeof(err->detail) - 1);
    err->detail[sizeof(err->detail) - 1] = '\0';
    err->sys_errno = sys_errno;
    return -sys_errno;
}

static inline int defused_error_set(struct defused_error *err, const char *id,
                                    int sys_errno) {
    return defused_error_set_detail(err, id, sys_errno, NULL);
}

/* vsnprintf() is more than the sandboxed child's seccomp filter allows, and
 * it may clobber errno: capture errno before calling. */
__attribute__((__format__(__printf__, 4, 5))) static inline int
defused_error_setf(struct defused_error *err, const char *id, int sys_errno,
                   const char *fmt, ...) {
    defused_error_set(err, id, sys_errno);

    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err->detail, sizeof(err->detail), fmt, ap);
    va_end(ap);
    return -sys_errno;
}

/* Fills in *err from an sd_varlink_call() result; a NULL error_id is
 * success. */
int defused_error_from_reply(const char *error_id, sd_json_variant *parameters,
                             struct defused_error *err);

extern const sd_varlink_interface vl_interface_website_soss_defused;

#endif /* DEFUSED_PROTO_H */
