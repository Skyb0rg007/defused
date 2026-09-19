/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The mount/unmount policy check: asks polkit whether the connecting
 * process may use defused for an operation at all.
 */
#define _GNU_SOURCE
#include "defused-policy.h"
#include "common.h"
#include "defused_proto.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <systemd/sd-bus.h>

/* Mount flags reported to polkit by name in the "privileged-flags" detail
 * (see defused_polkit_check_authorized()), so a rule can tell which capabilities a
 * mount request actually needs instead of only "is any capability used at
 * all". A rule should treat any name it doesn't specifically recognize as
 * requiring AUTH_ADMIN_KEEP --
 * packaging/polkit/examples/50-defused-mount-policy.rules does this by checking
 * requested names against its own allowlist and falling back otherwise, so a
 * rule written before a new privileged option existed denies it by default
 * instead of silently granting it. Add future privileged options here as
 * they're implemented. */
static const struct {
    uint32_t flag;
    const char *name;
} privileged_mount_flags[] = {
    {DEFUSED_FUSE_ALLOW_OTHER, "allow_other"},
};

/* Writes a comma-separated list of privileged_mount_flags[] names for the
 * bits set in mount_flags into buf (empty string if none are set), for the
 * "privileged-flags" polkit detail -- see privileged_mount_flags[]'s doc
 * comment. buf is always NUL-terminated; names that wouldn't fit are
 * silently dropped, which only matters if this table grows to carry far
 * more (and far longer) names than it does today. */
void defused_format_privileged_flags(uint32_t mount_flags, char *buf,
                                     size_t bufsz) {
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

/* Asks polkit whether the connecting process is allowed to perform
 * action_id (one of the DEFUSED_POLKIT_ACTION_* ids). This is independent
 * of (and in addition to) the ownership checks in handle_mount()/
 * handle_umount(): ownership says the caller has the right to act on
 * *this particular file or mount*, polkit says the caller is allowed to
 * use defused for this operation, with these specific options, at all --
 * and lets an administrator's policy (or a custom polkit rules.d script)
 * decide that per uid/gid, interactively, or based on the details passed
 * below.
 *
 * current_mounts and privileged_flags are mount-specific details (see
 * below); pass current_mounts < 0 and/or privileged_flags NULL or "" to
 * omit either, for actions/requests that have no use for them (unmount
 * has no use for either; an ordinary mount request with no privileged
 * options set has no use for privileged_flags).
 *
 * The subject's pid is conveyed to polkit as pidfd, obtained by the caller
 * from this connection's SO_PEERPIDFD, not a bare pid, for the same TOCTOU
 * reason the sandboxed mount/unmount child joins the peer namespace through a
 * pidfd: a pid alone can be recycled between the credential check and whenever
 * polkit gets around to looking at it, and a pidfd names one specific process
 * no matter what.
 *
 * Fails closed: if polkit cannot be reached at all (e.g. not installed or
 * not running), the operation is refused rather than silently falling back
 * to the ownership check alone. */
int defused_polkit_check_authorized(int pidfd, const struct ucred *cred,
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

    /* subject: (sa{sv}) = ("unix-process", {"uid": <i>, "pidfd": <h>}).
     * Passing both "uid" and "pidfd" (rather than "pid"/"start-time") makes
     * polkit resolve the subject from the pidfd directly -- see
     * polkit_subject_new_for_gvariant_invocation() in polkit's
     * src/polkit/polkitsubject.c. */
    ret = sd_bus_message_append(call, "(sa{sv})s", "unix-process", 2u, "uid",
                                "i", (int32_t)cred->uid, "pidfd", "h", pidfd,
                                action_id);
    if (ret < 0)
        return ret;

    /* details: a{ss}. uid, gid, and pid are deliberately not included: a
     * rule already gets those from the subject polkit itself constructs
     * (subject.uid, subject.groups, subject.pid), no need to duplicate them
     * here. current-mounts and privileged-flags (mount only, see above) are
     * the only things a rule can't get any other way, and are each omitted
     * entirely when the caller has nothing to say -- see
     * packaging/polkit/examples/50-defused-mount-policy.rules for a rule that
     * uses both. */
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

    /* flags: CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION (1), so that
     * an agent in the caller's session can answer an AUTH_ADMIN_KEEP-style
     * challenge instead of it failing outright. cancellation_id: unused, we
     * never call CancelCheckAuthorization. */
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
