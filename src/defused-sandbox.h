/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_SANDBOX_H
#define DEFUSED_SANDBOX_H

#include "defused_proto.h"

#include <stdint.h>
#include <sys/types.h>

/* The client's mount namespace is entered only by a forked child under a
 * seccomp allowlist; these run that child and return its result. */
int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd,
                          struct defused_error *err);
int defused_sandbox_unmount(int pidfd, int parent_fd, const char *name,
                            bool lazy, uint64_t mnt_id, uid_t uid,
                            struct defused_error *err);

/* The mount id of name under dir_fd: the 64-bit one the kernel never
 * reuses. From the VFS, so it works even when the FUSE server is dead. */
int defused_mnt_id(int dir_fd, const char *name, uint64_t *out_id);

/* 1 if mnt_id names a FUSE mount in namespace mnt_ns_id (0 for the
 * caller's own), 0 for any other mount, or a negative errno. The optional
 * out_blkdev distinguishes "fuseblk"; the optional out_uid gets user_id=,
 * and asking for it makes a FUSE mount without one an error. */
int defused_is_fuse_mount(uint64_t mnt_ns_id, uint64_t mnt_id, bool *out_blkdev,
                          uid_t *out_uid);

#ifdef DEFUSED_TEST
int defused_test_install_seccomp(enum defused_op op);
int defused_test_mount_opts_owner(const char *opts, uid_t *out_uid);
pid_t defused_test_fdinfo_pid(const char *text);
#endif

#endif /* DEFUSED_SANDBOX_H */
