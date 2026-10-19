/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Performing a request, with no policy of its own. The service calls the
 * pieces one at a time so it can interleave its authorization and hand
 * the finished mount to its seccomp sandbox; a privileged fusermount3 calls
 * defused_perform() and is done.
 */

#ifndef DEFUSED_MOUNT_H
#define DEFUSED_MOUNT_H

#include "defused-proto.h"

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEFUSED_HANDLE_FLAGS                                                   \
    (AT_EMPTY_PATH | AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE)
#define DEFUSED_MOVE_MOUNT_FLAGS                                               \
    (MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)

/* struct file_handle ends in a flexible array member, so it cannot be a
 * member of anything else. The same layout, at the largest size. */
struct defused_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[MAX_HANDLE_SZ];
};
static_assert(offsetof(struct defused_handle, f_handle) ==
                  sizeof(struct file_handle),
              "struct defused_handle must match struct file_handle");

/* "ro,allow_other"; unknown bits are appended in hex. */
const char *defused_mount_flags_str(uint32_t flags, char *buf, size_t size);

/* Returns 1 if mnt_id names a FUSE mount in namespace mnt_ns_id (pass 0 for
 * the caller's own mount namespace).
 * Returns 0 for any other mount, or a negative errno.
 * The optional out_blkdev distinguishes "fuseblk" from "fuse". */
int defused_is_fuse_mount(uint64_t mnt_ns_id, uint64_t mnt_id, bool *out_blkdev,
                          const char *subtype, uid_t *out_uid);

/* Computes the unique mount id for the file named name in directory dir_fd.
 * If name is "", computes the unique mount id for dir_fd. */
int defused_mnt_id(int dir_fd, const char *name, uint64_t *out_id);
/* The same, into the caller's buffers. */
int defused_mnt_id_into(int dir_fd, const char *name,
                        struct defused_handle *handle, uint64_t *out_id);

/* Validates a mount request.
 * allow_privileged lets suid/dev/blkdev through. */
int defused_check_mount_request(const struct defused_request *req,
                                bool allow_privileged,
                                struct defused_error *err);

/* Determine if mnt_fd is a directory or regular file.
 * Also computes the file status struct. */
int defused_check_mountpoint(int mnt_fd, struct stat *out_st,
                             struct defused_error *err);

/* Determine if dev_fd was created from open("/dev/fuse", O_RDWR) */
int defused_check_fuse_device(int dev_fd, struct defused_error *err);

/* Returns a detached mount file descriptor */
int defused_create_mount(const struct defused_request *req, int dev_fd,
                         mode_t rootmode, uid_t uid, gid_t gid,
                         struct defused_error *err);

/* Resolve the request target's unique mount id, making sure it differs from
 * the parent. Returns the target's mount_id in *out_mnt_id. */
int defused_check_umount_request(const struct defused_request *req,
                                 int parent_fd, uint64_t *out_mnt_id,
                                 struct defused_error *err);

/* Performs the request without any checks.
 * Called by fusermount3 when already privileged. */
int defused_perform(const struct defused_request *req, const int *fds,
                    struct defused_error *err);

#ifdef DEFUSED_TEST
int defused_test_mount_opts_owner(const char *opts, uid_t *out_uid);
#endif

#endif /* DEFUSED_MOUNT_H */
