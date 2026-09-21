/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The Varlink protocol between fusermount3 and the defused service: one
 * request/response over an AF_UNIX stream socket, framed and parsed by
 * libsystemd's sd-varlink. See doc/protocol.md.
 */

#ifndef DEFUSED_PROTO_H
#define DEFUSED_PROTO_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#define DEFUSED_SOCKET_PATH "/run/defused/defused.sock"

#define DEFUSED_INTERFACE "website.soss.defused"
#define DEFUSED_METHOD_MOUNT DEFUSED_INTERFACE ".Mount"
#define DEFUSED_METHOD_UNMOUNT DEFUSED_INTERFACE ".Unmount"

/* A failed request is answered with one of these; a successful one gets an
 * empty reply. MalformedRequest, MountFailed and UnmountFailed carry an
 * "errno" field. */
#define DEFUSED_ERROR_MALFORMED DEFUSED_INTERFACE ".MalformedRequest"
#define DEFUSED_ERROR_BAD_OPTION DEFUSED_INTERFACE ".BadMountOption"
#define DEFUSED_ERROR_NOT_ALLOWED DEFUSED_INTERFACE ".NotAllowed"
#define DEFUSED_ERROR_NOT_A_FUSE_MOUNT DEFUSED_INTERFACE ".NotAFuseMount"
#define DEFUSED_ERROR_MOUNT_FAILED DEFUSED_INTERFACE ".MountFailed"
#define DEFUSED_ERROR_UNMOUNT_FAILED DEFUSED_INTERFACE ".UnmountFailed"

#define DEFUSED_MAX_NAME 32      /* subtype */
#define DEFUSED_MAX_FSNAME 4096  /* fsname (a device path for blkdev) */
#define DEFUSED_MAX_FILENAME 255 /* mountpoint basename */

enum defused_op {
    DEFUSED_OP_MOUNT = 1,
    DEFUSED_OP_UNMOUNT = 2,
};

/* Mount.mountFlags bits. */
enum defused_mount_flag {
    DEFUSED_MOUNT_RDONLY = 1u << 0,
    DEFUSED_MOUNT_ALLOW_DEV = 1u << 1, /* privileged */
    DEFUSED_MOUNT_NOEXEC = 1u << 2,
    DEFUSED_MOUNT_NOATIME = 1u << 3,
    DEFUSED_MOUNT_NODIRATIME = 1u << 4,
    DEFUSED_MOUNT_NOSYMFOLLOW = 1u << 5,
    DEFUSED_MOUNT_SYNCHRONOUS = 1u << 6,
    DEFUSED_MOUNT_DIRSYNC = 1u << 7,
    DEFUSED_FUSE_ALLOW_OTHER = 1u << 8,
    DEFUSED_FUSE_DEFAULT_PERMISSIONS = 1u << 9,
    DEFUSED_MOUNT_ALLOW_SUID = 1u << 10, /* privileged */
    DEFUSED_MOUNT_BLKDEV = 1u << 11,     /* privileged: fuseblk on fsname */
};
#define DEFUSED_MOUNT_PRIVILEGED_FLAGS                                         \
    (DEFUSED_MOUNT_ALLOW_SUID | DEFUSED_MOUNT_ALLOW_DEV | DEFUSED_MOUNT_BLKDEV)
#define DEFUSED_MOUNT_FLAGS_MASK ((1u << 12) - 1)

/* The Mount call. It carries two fds: /dev/fuse, and the mountpoint (a
 * directory or regular file); fuse_fd and mnt_fd are their indices. */
struct defused_mount_req {
    uint32_t fuse_fd, mnt_fd;
    uint32_t mount_flags;
    uint32_t max_read, blksize; /* 0 for unset */
    const char *fsname, *subtype;
};

/* The Unmount call. It carries one fd, the mountpoint's *parent* directory;
 * name is the mountpoint's basename within it. */
struct defused_umount_req {
    uint32_t parent_fd;
    const char *name;
    bool lazy;
};

/* Why a request failed; an empty id means it did not. detail is for the
 * service's log only and never goes on the wire. */
struct defused_error {
    char id[64];
    char detail[160];
    int32_t sys_errno; /* the error's "errno" field, 0 if it has none */
};

/* Both return -sys_errno so a caller can `return defused_error_set(...)`.
 * Only the plain one is usable in the sandboxed child, which may not call
 * vsnprintf(); a NULL id or detail means "". */
static inline int defused_error_set(struct defused_error *err, const char *id,
                                    int sys_errno, const char *detail) {
    strncpy(err->id, id ? id : "", sizeof(err->id) - 1);
    err->id[sizeof(err->id) - 1] = '\0';
    strncpy(err->detail, detail ? detail : "", sizeof(err->detail) - 1);
    err->detail[sizeof(err->detail) - 1] = '\0';
    err->sys_errno = sys_errno;
    return -sys_errno;
}

__attribute__((__format__(__printf__, 4, 5))) static inline int
defused_error_setf(struct defused_error *err, const char *id, int sys_errno,
                   const char *fmt, ...) {
    defused_error_set(err, id, sys_errno, NULL);
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err->detail, sizeof(err->detail), fmt, ap);
    va_end(ap);
    return -sys_errno;
}

/* Defined in defused-varlink.c. */
extern const sd_varlink_interface vl_interface_website_soss_defused;
extern const sd_json_dispatch_field defused_mount_fields[];
extern const sd_json_dispatch_field defused_umount_fields[];

/* Client side: one call, with its outcome in *err. Returns a negative errno
 * only if the RPC itself failed. A NULL fsname or subtype is sent as "". */
int defused_call_mount(sd_varlink *link, const struct defused_mount_req *req,
                       struct defused_error *err);
int defused_call_umount(sd_varlink *link, const struct defused_umount_req *req,
                        struct defused_error *err);

#endif /* DEFUSED_PROTO_H */
