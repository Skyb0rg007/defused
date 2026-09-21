/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_POLICY_H
#define DEFUSED_POLICY_H

#include "defused_proto.h"

#include <stdint.h>
#include <sys/socket.h>

#define DEFUSED_DEFAULT_MAX_MOUNTS 100

/* Each logs and returns -EINVAL on a bad argument. */
int defused_policy_parse_max_mounts(const char *arg)
    __attribute__((__nonnull__(1), __warn_unused_result__));
int defused_policy_parse_allow_groups(const char *arg)
    __attribute__((__nonnull__(1), __warn_unused_result__));

/* Lets callers set the allow_other mount option; off until called. */
void defused_policy_set_allow_other(void);

/* Unmount passes mount_flags 0 and current_mounts -1; -EACCES is a denial. */
int defused_policy_check(int sock, const struct ucred *cred, enum defused_op op,
                         uint32_t mount_flags, long current_mounts)
    __attribute__((__nonnull__(2), __warn_unused_result__));

#endif /* DEFUSED_POLICY_H */
