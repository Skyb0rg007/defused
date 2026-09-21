/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Policy: whether the connecting process may use defused at all.
 */
#define _GNU_SOURCE
#include "defused-policy.h"
#include "common.h"
#include "defused_proto.h"
#include "util.h"

#include <errno.h>
#include <grp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static long cfg_max_mounts = DEFUSED_DEFAULT_MAX_MOUNTS;
#define DEFUSED_MAX_ALLOW_GROUPS 32
static gid_t cfg_allow_groups[DEFUSED_MAX_ALLOW_GROUPS];
static size_t cfg_n_allow_groups = 0;
static bool cfg_allow_other = false;

/* Returns 1, 0, or a negative errno. SO_PEERGROUPS needs Linux 4.13. */
static __attribute__((__nonnull__(2), __warn_unused_result__)) int
peer_in_allowed_groups(int sock, const struct ucred *cred) {
    for (size_t i = 0; i < cfg_n_allow_groups; i++)
        if (cred->gid == cfg_allow_groups[i])
            return 1;

    gid_t stack_groups[32];
    _cleanup_free_ gid_t *heap_groups = NULL;
    gid_t *groups = stack_groups;
    socklen_t len = sizeof(stack_groups);
    int ret = getsockopt(sock, SOL_SOCKET, SO_PEERGROUPS, groups, &len);
    if (ret == -1 && errno == ERANGE) {
        heap_groups = malloc(len);
        if (heap_groups == NULL)
            return -ENOMEM;
        groups = heap_groups;
        ret = getsockopt(sock, SOL_SOCKET, SO_PEERGROUPS, groups, &len);
    }
    if (ret == -1) {
        fprintf(stderr, "defused: SO_PEERGROUPS failed: %s\n", strerror(errno));
        return -errno;
    }

    for (size_t i = 0; i < len / sizeof(gid_t); i++)
        for (size_t j = 0; j < cfg_n_allow_groups; j++)
            if (groups[i] == cfg_allow_groups[j])
                return 1;
    return 0;
}

/* Returns -EACCES on a denial. */
int defused_policy_check(int sock, const struct ucred *cred, enum defused_op op,
                         uint32_t mount_flags, long current_mounts) {
    const char *what = op == DEFUSED_OP_MOUNT ? "mount" : "unmount";

    if (cfg_n_allow_groups > 0) {
        int ret = peer_in_allowed_groups(sock, cred);
        if (ret < 0)
            return ret;
        if (ret == 0) {
            fprintf(stderr,
                    "defused: %s refused: uid %u (gid %u) is in none of the "
                    "--allow-groups groups\n",
                    what, (unsigned)cred->uid, (unsigned)cred->gid);
            return -EACCES;
        }
    }

    if ((mount_flags & DEFUSED_FUSE_ALLOW_OTHER) && !cfg_allow_other) {
        fprintf(stderr,
                "defused: %s refused: uid %u asked for allow_other, not "
                "granted by --allow-other\n",
                what, (unsigned)cred->uid);
        return -EACCES;
    }

    if (current_mounts >= 0 && current_mounts >= cfg_max_mounts) {
        fprintf(stderr,
                "defused: %s refused: %ld FUSE filesystems already mounted "
                "(--max-mounts=%ld)\n",
                what, current_mounts, cfg_max_mounts);
        return -EACCES;
    }
    return 0;
}

int defused_policy_parse_max_mounts(const char *arg) {
    long n;
    if (libfuse_strtol(arg, &n) < 0 || n <= 0) {
        fprintf(stderr,
                "defused: --max-mounts: expected a positive number, got '%s'\n",
                arg);
        return -EINVAL;
    }
    cfg_max_mounts = n;
    return 0;
}

static __attribute__((__nonnull__(1, 2), __warn_unused_result__)) int
parse_group(const char *name, gid_t *out_gid) {
    long n;
    if (libfuse_strtol(name, &n) == 0) {
        if (n < 0 || n > (long)(gid_t)-1) {
            fprintf(stderr, "defused: --allow-groups: gid out of range: %s\n",
                    name);
            return -EINVAL;
        }
        *out_gid = (gid_t)n;
        return 0;
    }

    errno = 0;
    struct group *gr = getgrnam(name);
    if (gr == NULL) {
        fprintf(stderr, "defused: --allow-groups: no such group: %s%s%s\n",
                name, errno ? ": " : "", errno ? strerror(errno) : "");
        return -EINVAL;
    }
    *out_gid = gr->gr_gid;
    return 0;
}

/* Empty is allowed, so a unit file can pass an unset variable. */
int defused_policy_parse_allow_groups(const char *arg) {
    _cleanup_free_ char *list = strdup(arg);
    if (list == NULL)
        return -ENOMEM;

    cfg_n_allow_groups = 0;
    char *saveptr = NULL;
    for (char *name = strtok_r(list, ",", &saveptr); name != NULL;
         name = strtok_r(NULL, ",", &saveptr)) {
        if (cfg_n_allow_groups == DEFUSED_MAX_ALLOW_GROUPS) {
            fprintf(stderr, "defused: --allow-groups: more than %d groups\n",
                    DEFUSED_MAX_ALLOW_GROUPS);
            return -EINVAL;
        }
        int ret = parse_group(name, &cfg_allow_groups[cfg_n_allow_groups]);
        if (ret < 0)
            return ret;
        cfg_n_allow_groups++;
    }
    return 0;
}

void defused_policy_set_allow_other(void) { cfg_allow_other = true; }
