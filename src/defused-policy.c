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

#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#ifdef HAVE_POLKIT
#include <systemd/sd-bus.h>
#endif

#ifdef HAVE_POLKIT
/* See packaging/polkit/website.soss.defused.policy. */
#define DEFUSED_POLKIT_ACTION_MOUNT "website.soss.defused.mount"
#define DEFUSED_POLKIT_ACTION_UNMOUNT "website.soss.defused.unmount"
#endif

/* Granted by name, so an old policy denies new options by default. */
static const struct {
    uint32_t flag;
    const char *name;
} privileged_mount_flags[] = {
    {DEFUSED_FUSE_ALLOW_OTHER, "allow_other"},
};

enum policy {
    POLICY_BUILTIN,
    POLICY_POLKIT,
};
#ifdef HAVE_POLKIT
#define DEFUSED_DEFAULT_POLICY POLICY_POLKIT
#else
#define DEFUSED_DEFAULT_POLICY POLICY_BUILTIN
#endif
static enum policy cfg_policy = DEFUSED_DEFAULT_POLICY;

static long cfg_max_mounts = DEFUSED_DEFAULT_MAX_MOUNTS;
#define DEFUSED_MAX_ALLOW_GROUPS 32
static gid_t cfg_allow_groups[DEFUSED_MAX_ALLOW_GROUPS];
static size_t cfg_n_allow_groups = 0;
static uint32_t cfg_allow_privileged_flags = 0;

/* Names that don't fit are dropped. */
static __attribute__((__nonnull__(2))) void
format_privileged_flags(uint32_t mount_flags, char *buf, size_t bufsz) {
    size_t len = 0;
    buf[0] = '\0';

    for (size_t i = 0;
         i < sizeof(privileged_mount_flags) / sizeof(privileged_mount_flags[0]);
         i++) {
        if (!(mount_flags & privileged_mount_flags[i].flag))
            continue;

        const char *name = privileged_mount_flags[i].name;
        size_t name_len = strlen(name);
        size_t sep_len = len > 0 ? 1 : 0;
        if (len + sep_len + name_len >= bufsz)
            break;

        if (sep_len)
            buf[len++] = ',';
        memcpy(buf + len, name, name_len);
        len += name_len;
        buf[len] = '\0';
    }
}

#ifdef HAVE_POLKIT
/* Fails closed if polkit is unreachable. */
static __attribute__((__nonnull__(2, 3), __warn_unused_result__)) int
check_polkit_authorized(int pidfd, const struct ucred *cred,
                        const char *action_id, long current_mounts,
                        const char *privileged_flags) {
    bool have_privileged_flags = privileged_flags && privileged_flags[0];

    _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
    _cleanup_(sd_bus_message_unrefp) sd_bus_message *call = NULL;
    _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
    _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret;

    ret = sd_bus_open_system(&bus);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to connect to the system bus: %s\n",
                strerror(-ret));
        return ret;
    }

    ret = sd_bus_message_new_method_call(
        bus, &call, "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization");
    if (ret < 0)
        return ret;

    /* "uid" + "pidfd": polkit resolves the subject from the pidfd. */
    ret = sd_bus_message_append(call, "(sa{sv})s", "unix-process", 2u, "uid",
                                "i", (int32_t)cred->uid, "pidfd", "h", pidfd,
                                action_id);
    if (ret < 0)
        return ret;

    /* No uid/gid/pid details: a rule gets those from the subject. */
    ret = sd_bus_message_open_container(call, 'a', "{ss}");
    if (ret < 0)
        return ret;
    char mounts_buf[32];
    if (current_mounts >= 0) {
        snprintf(mounts_buf, sizeof(mounts_buf), "%ld", current_mounts);
        ret = sd_bus_message_append(call, "{ss}", "current-mounts", mounts_buf);
        if (ret < 0)
            return ret;
    }
    if (have_privileged_flags) {
        ret = sd_bus_message_append(call, "{ss}", "privileged-flags",
                                    privileged_flags);
        if (ret < 0)
            return ret;
    }
    ret = sd_bus_message_close_container(call);
    if (ret < 0)
        return ret;

    /* ALLOW_USER_INTERACTION; no cancellation_id. */
    ret = sd_bus_message_append(call, "us", (uint32_t)1, "");
    if (ret < 0)
        return ret;

    ret = sd_bus_call(bus, call, 0, &error, &reply);
    if (ret < 0) {
        fprintf(stderr, "defused: polkit CheckAuthorization failed: %s\n",
                error.message ? error.message : strerror(-ret));
        return ret;
    }

    int is_authorized = 0;
    int is_challenge = 0;
    ret = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
    if (ret < 0)
        return ret;
    ret = sd_bus_message_read(reply, "bb", &is_authorized, &is_challenge);
    if (ret < 0)
        return ret;
    ret = sd_bus_message_skip(reply, "a{ss}");
    if (ret < 0)
        return ret;
    ret = sd_bus_message_exit_container(reply);
    if (ret < 0)
        return ret;

    if (!is_authorized) {
        fprintf(stderr, "defused: polkit denied %s to uid %u (challenge=%d)\n",
                action_id, (unsigned)cred->uid, is_challenge);
        return -EACCES;
    }
    return 0;
}
#endif /* HAVE_POLKIT */

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
static __attribute__((__nonnull__(2), __warn_unused_result__)) int
builtin_check_authorized(int sock, const struct ucred *cred, enum defused_op op,
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

    uint32_t denied_flags = mount_flags & ~cfg_allow_privileged_flags;
    char denied_names[128];
    format_privileged_flags(denied_flags, denied_names, sizeof(denied_names));
    if (denied_names[0]) {
        fprintf(stderr,
                "defused: %s refused: uid %u asked for %s, not granted by "
                "--allow-privileged-flags\n",
                what, (unsigned)cred->uid, denied_names);
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

int defused_policy_check(int sock, int pidfd, const struct ucred *cred,
                         enum defused_op op, uint32_t mount_flags,
                         long current_mounts) {
#ifdef HAVE_POLKIT
    if (cfg_policy == POLICY_POLKIT) {
        if (op == DEFUSED_OP_UNMOUNT)
            return check_polkit_authorized(
                pidfd, cred, DEFUSED_POLKIT_ACTION_UNMOUNT, -1, NULL);

        char privileged_flags[128];
        format_privileged_flags(mount_flags, privileged_flags,
                                sizeof(privileged_flags));
        return check_polkit_authorized(pidfd, cred, DEFUSED_POLKIT_ACTION_MOUNT,
                                       current_mounts, privileged_flags);
    }
#else
    (void)pidfd;
#endif
    assert(cfg_policy == POLICY_BUILTIN);
    return builtin_check_authorized(sock, cred, op, mount_flags,
                                    current_mounts);
}

int defused_policy_parse_policy(const char *arg) {
    if (strcmp(arg, "builtin") == 0) {
        cfg_policy = POLICY_BUILTIN;
        return 0;
    }
    if (strcmp(arg, "polkit") == 0) {
#ifdef HAVE_POLKIT
        cfg_policy = POLICY_POLKIT;
        return 0;
#else
        fprintf(stderr,
                "defused: --policy=polkit: this build has no polkit support\n");
        return -EINVAL;
#endif
    }
    fprintf(stderr,
            "defused: unknown policy '%s' (expected polkit or builtin)\n", arg);
    return -EINVAL;
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

int defused_policy_parse_allow_privileged_flags(const char *arg) {
    _cleanup_free_ char *list = strdup(arg);
    if (list == NULL)
        return -ENOMEM;

    cfg_allow_privileged_flags = 0;
    char *saveptr = NULL;
    for (char *name = strtok_r(list, ",", &saveptr); name != NULL;
         name = strtok_r(NULL, ",", &saveptr)) {
        bool found = false;
        for (size_t i = 0; i < sizeof(privileged_mount_flags) /
                                   sizeof(privileged_mount_flags[0]);
             i++) {
            if (strcmp(name, privileged_mount_flags[i].name) == 0) {
                cfg_allow_privileged_flags |= privileged_mount_flags[i].flag;
                found = true;
            }
        }
        if (!found) {
            fprintf(stderr,
                    "defused: --allow-privileged-flags: unknown privileged "
                    "mount option: %s\n",
                    name);
            return -EINVAL;
        }
    }
    return 0;
}
