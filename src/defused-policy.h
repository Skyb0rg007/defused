/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_POLICY_H
#define DEFUSED_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* polkit action ids checked before creating/tearing down a FUSE mount; see
 * packaging/polkit/website.soss.defused.policy for their declared defaults. */
#define DEFUSED_POLKIT_ACTION_MOUNT "website.soss.defused.mount"
#define DEFUSED_POLKIT_ACTION_UNMOUNT "website.soss.defused.unmount"

void defused_format_privileged_flags(uint32_t mount_flags, char *buf,
                                     size_t bufsz)
    __attribute__((__nonnull__(2)));

int defused_polkit_check_authorized(int pidfd, const struct ucred *cred,
                                    const char *action_id, long current_mounts,
                                    const char *privileged_flags)
    __attribute__((__nonnull__(2, 3), __warn_unused_result__));

#endif /* DEFUSED_POLICY_H */
