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

#ifndef DEFUSED_H
#define DEFUSED_H

#include <stdint.h>
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

/* Result codes for each operation */
enum defused_status {
    DEFUSED_OK = 0,
    DEFUSED_ERR_MALFORMED = 1,
    DEFUSED_ERR_BAD_OPTION = 2,
    DEFUSED_ERR_NOT_ALLOWED = 3,
    DEFUSED_ERR_NOT_A_FUSE_MOUNT = 4,
    DEFUSED_ERR_MOUNT_FAILED = 5,
    DEFUSED_ERR_UNMOUNT_FAILED = 6,
    DEFUSED_ERR_SETNS_FAILED = 7,
};

/* Max length of fsname and subtype */
#define DEFUSED_MAX_NAME 32

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
};
#define DEFUSED_MOUNT_FLAGS_MASK                                               \
    (DEFUSED_MOUNT_RDONLY | DEFUSED_MOUNT_ALLOW_DEV | DEFUSED_MOUNT_NOEXEC |   \
     DEFUSED_MOUNT_NOATIME | DEFUSED_MOUNT_NODIRATIME |                        \
     DEFUSED_MOUNT_NOSYMFOLLOW | DEFUSED_MOUNT_SYNCHRONOUS |                   \
     DEFUSED_MOUNT_DIRSYNC | DEFUSED_FUSE_ALLOW_OTHER |                        \
     DEFUSED_FUSE_DEFAULT_PERMISSIONS)

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
 * The
 */
struct defused_mount_req {
    /* enum defused_mount_flag bits */
    uint32_t mount_flags;
    /* maximum read size, 0 for unset */
    uint32_t max_read;
    /* maximum block size, 0 for unset */
    uint32_t blksize;
    char fsname[DEFUSED_MAX_NAME];
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

/* Responses to mount or unmount requests */
struct defused_resp {
    /* enum defused_status */
    uint32_t status;
    /* errno from mount setup/umount2(), when relevant */
    int32_t sys_errno;
};

extern const sd_varlink_interface vl_interface_website_soss_defused;

#endif /* DEFUSED_H */
