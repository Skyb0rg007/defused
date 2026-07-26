/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_SANDBOX_H
#define DEFUSED_SANDBOX_H

#include "defused_proto.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd, uint32_t *status,
                          int *sys_errno)
    __attribute__((__nonnull__(4, 5), __warn_unused_result__));

int defused_sandbox_unmount(int pidfd, int proc_fd, int mnt_fd, bool lazy,
                            long mnt_id, uid_t uid, uint32_t *status,
                            int *sys_errno)
    __attribute__((__nonnull__(7, 8), __warn_unused_result__));

#ifdef DEFUSED_TEST
int defused_test_install_seccomp(enum defused_op op)
    __attribute__((__warn_unused_result__));
int defused_test_mountinfo_owner(const char *line, long mnt_id, uid_t *out_uid)
    __attribute__((__nonnull__(1, 3), __warn_unused_result__));
#endif

#endif /* DEFUSED_SANDBOX_H */
