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

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* "ro,allow_other"; unknown bits are appended in hex. */
const char *defused_mount_flags_str(uint32_t flags, char *buf, size_t size);

/* The 64-bit mount id, which the kernel never reuses. From the VFS, so it
 * works even when the FUSE server is dead. */
int defused_mnt_id(int dir_fd, const char *name, uint64_t *out_id);

/* allow_privileged lets suid/dev/blkdev through, and with them an fsname
 * that may name a block device path. */
int defused_check_mount_request(const struct defused_request *req,
                                bool allow_privileged,
                                struct defused_error *err);

/* A directory or a regular file. *out_st is for the caller's root mode
 * and, service-side, its ownership rule. */
int defused_check_mountpoint(int mnt_fd, struct stat *out_st,
                             struct defused_error *err);

int defused_check_fuse_device(int dev_fd, struct defused_error *err);

/* The superblock and a detached mount of it, still to be attached with
 * move_mount(); returns the mount fd. */
int defused_create_mount(const struct defused_request *req, int dev_fd,
                         mode_t rootmode, uid_t uid, gid_t gid,
                         struct defused_error *err);

/* *out_mnt_id identifies the target from here on. Takes no fd on it: an
 * open reference would make a non-lazy umount2() fail with EBUSY. */
int defused_check_umount_request(const struct defused_request *req,
                                 int parent_fd, uint64_t *out_mnt_id,
                                 struct defused_error *err);

/* The whole request, in this process and with no policy: what fusermount3
 * does for a root or CAP_SYS_ADMIN caller. Mirrors defused_call(), down to
 * reporting in *err, so the two are interchangeable at the call site. */
int defused_perform(const struct defused_request *req, const int *fds,
                    struct defused_error *err);

#endif /* DEFUSED_MOUNT_H */
