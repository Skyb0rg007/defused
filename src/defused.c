/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The defused system service that mounts/unmounts FUSE filesystems on
 * behalf of unprivileged users.
 *
 * This program is designed to be called via systemd Accept=yes
 * socket activation, on an AF_UNIX SOCK_STREAM Varlink socket.
 * The process exits after processing the operation.
 */
#define _GNU_SOURCE
#include "defused-sandbox.h"
#include "defused_proto.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

/* polkit action ids checked before creating/tearing down a FUSE mount; see
 * data/website.soss.defused.policy for their declared defaults. */
#define DEFUSED_POLKIT_ACTION_MOUNT "website.soss.defused.mount"
#define DEFUSED_POLKIT_ACTION_UNMOUNT "website.soss.defused.unmount"

/* Mount flags reported to polkit by name in the "privileged-flags" detail
 * (see check_polkit_authorized()), so a rule can tell which capabilities a
 * mount request actually needs instead of only "is any capability used at
 * all". A rule should treat any name it doesn't specifically recognize as
 * requiring AUTH_ADMIN_KEEP -- examples/50-defused-mount-policy.rules does
 * this by checking requested names against its own allowlist and falling
 * back otherwise, so a rule written before a new privileged option existed
 * denies it by default instead of silently granting it. Add future
 * privileged options (suid, cuse, blkdev, ...) here as they're
 * implemented. */
static const struct {
    uint32_t flag;
    const char *name;
} privileged_mount_flags[] = {
    {DEFUSED_FUSE_ALLOW_OTHER, "allow_other"},
};

struct request_context {
    int sock;
    int proc_fd;
};

struct prepared_mount {
    char type[2 * DEFUSED_MAX_NAME + 16];
    char source[DEFUSED_MAX_NAME];
    char fd[32];
    char rootmode[32];
    char user_id[32];
    char group_id[32];
    char max_read[32];
    char blksize[32];
    int have_subtype;
    int have_max_read;
    int have_blksize;
    uint32_t flags;
    unsigned int mount_attrs;
};

static int reply_response(sd_varlink *link, uint32_t status, int sys_errno);
static int varlink_mount(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata)
    __attribute__((__nonnull__(1, 4), __warn_unused_result__));
static int varlink_unmount(sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_flags_t flags, void *userdata)
    __attribute__((__nonnull__(1, 4), __warn_unused_result__));
static const char *status_name(uint32_t status)
    __attribute__((__const__, __warn_unused_result__));
static int peer_pidfd(int sock) __attribute__((__warn_unused_result__));
static int check_mount_policy(const struct defused_mount_req *req)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int check_polkit_authorized(int sock, const struct ucred *cred,
                                   const char *action_id, long current_mounts,
                                   const char *privileged_flags)
    __attribute__((__nonnull__(2, 3), __warn_unused_result__));
static void format_privileged_flags(uint32_t mount_flags, char *buf,
                                    size_t bufsz)
    __attribute__((__nonnull__(2)));
static int check_mountpoint_fstype(int mnt_fd)
    __attribute__((__warn_unused_result__));
static int check_fuse_device_fd(int dev_fd)
    __attribute__((__warn_unused_result__));
static int prepare_mount(const struct defused_mount_req *req, int dev_fd,
                         const struct stat *st, const struct ucred *cred,
                         struct prepared_mount *out)
    __attribute__((__nonnull__(1, 3, 4, 5), __warn_unused_result__));
static int create_detached_mount(const struct prepared_mount *mnt)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int handle_mount(sd_varlink *link, int sock,
                        const struct defused_mount_req *req, int mnt_fd,
                        int dev_fd, const struct ucred *cred)
    __attribute__((__nonnull__(1, 3, 6), __warn_unused_result__));
static int handle_umount(sd_varlink *link, int sock,
                         const struct defused_umount_req *req, int parent_fd,
                         int proc_fd, const struct ucred *cred)
    __attribute__((__nonnull__(1, 3, 6), __warn_unused_result__));
static void usage(const char *prog) __attribute__((__nonnull__(1)));
static int parse_args(int argc, char *argv[])
    __attribute__((__nonnull__(2), __warn_unused_result__));
static int socket_activation_fd(int *out_fd)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int fd_mnt_id(int proc_fd, int fd, long *out_id)
    __attribute__((__nonnull__(3), __warn_unused_result__));

int main(int argc, char *argv[]) {
    int exit_status = EXIT_FAILURE;

    int ret = parse_args(argc, argv);
    if (ret < 0)
        return EXIT_FAILURE;

    int sock = -1;
    ret = socket_activation_fd(&sock);
    if (ret < 0)
        return EXIT_FAILURE;

    /* Keep a handle to the service's procfs before entering the client's
     * mount namespace. */
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd == -1) {
        fprintf(stderr, "defused: failed to open /proc: %s\n", strerror(errno));
        goto out;
    }

    sd_event *event = NULL;
    sd_varlink_server *server = NULL;
    ret = sd_event_new(&event);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to create event loop: %s\n",
                strerror(-ret));
        goto out;
    }
    ret = sd_varlink_server_new(&server,
                                SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT |
                                    SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT |
                                    SD_VARLINK_SERVER_INHERIT_USERDATA);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to create Varlink server: %s\n",
                strerror(-ret));
        goto out;
    }
    ret = sd_varlink_server_add_interface(server,
                                          &vl_interface_website_soss_defused);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to add Varlink interface: %s\n",
                strerror(-ret));
        goto out_unref_server;
    }
    ret = sd_varlink_server_bind_method_many(
        server, DEFUSED_VARLINK_METHOD_MOUNT, varlink_mount,
        DEFUSED_VARLINK_METHOD_UNMOUNT, varlink_unmount);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to bind Varlink methods: %s\n",
                strerror(-ret));
        goto out_unref_server;
    }

    struct request_context ctx = {.sock = sock, .proc_fd = proc_fd};
    sd_varlink_server_set_userdata(server, &ctx);
    ret = sd_varlink_server_set_exit_on_idle(server, true);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to configure Varlink server: %s\n",
                strerror(-ret));
        goto out_unref_server;
    }
    ret = sd_varlink_server_attach_event(server, event, 0);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to attach Varlink server: %s\n",
                strerror(-ret));
        goto out_unref_server;
    }
    ret = sd_varlink_server_add_connection(server, sock, NULL);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to add Varlink connection: %s\n",
                strerror(-ret));
        goto out_unref_server;
    }
    sock = -1;
    ret = sd_event_loop(event);
    if (ret < 0) {
        fprintf(stderr, "defused: Varlink server failed: %s\n", strerror(-ret));
        goto out_unref_server;
    }

    exit_status = EXIT_SUCCESS;
out_unref_server:
    sd_varlink_server_unref(server);
    sd_event_unref(event);
out:
    if (proc_fd >= 0)
        close(proc_fd);
    if (sock >= 0)
        close(sock);
    return exit_status;
}

static int reply_response(sd_varlink *link, uint32_t status, int sys_errno) {
    int ret =
        sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_UNSIGNED("status", status),
                           SD_JSON_BUILD_PAIR_INTEGER("sysErrno", sys_errno));
    if (ret < 0)
        fprintf(stderr, "defused: failed to send response %s: %s\n",
                status_name(status), strerror(-ret));
    return ret;
}

static int varlink_mount(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    struct request_context *ctx = userdata;
    struct defused_mount_req req = {0};
    int ret = 0;
    int dev_fd = -1, mnt_fd = -1;

    struct mount_parameters {
        uint32_t fuse_fd_index;
        uint32_t mnt_fd_index;
        uint32_t mount_flags;
        uint32_t max_read;
        uint32_t blksize;
        const char *fsname;
        const char *subtype;
    } parsed = {};
    static const sd_json_dispatch_field dispatch_table[] = {
        {"fuseFileDescriptor", SD_JSON_VARIANT_UNSIGNED,
         sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, fuse_fd_index), SD_JSON_MANDATORY},
        {"mountpointFileDescriptor", SD_JSON_VARIANT_UNSIGNED,
         sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, mnt_fd_index), SD_JSON_MANDATORY},
        {"mountFlags", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, mount_flags), SD_JSON_MANDATORY},
        {"maxRead", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, max_read), SD_JSON_MANDATORY},
        {"blockSize", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct mount_parameters, blksize), SD_JSON_MANDATORY},
        {"fsName", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
         offsetof(struct mount_parameters, fsname),
         SD_JSON_MANDATORY | SD_JSON_STRICT},
        {"subtype", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
         offsetof(struct mount_parameters, subtype),
         SD_JSON_MANDATORY | SD_JSON_STRICT},
        {},
    };

    ret = sd_varlink_dispatch(link, parameters, dispatch_table, &parsed);
    if (ret != 0)
        return ret;
    req.mount_flags = parsed.mount_flags;
    req.max_read = parsed.max_read;
    req.blksize = parsed.blksize;
    if (strlen(parsed.fsname) >= sizeof(req.fsname))
        return sd_varlink_error_invalid_parameter_name(link, "fsName");
    if (strlen(parsed.subtype) >= sizeof(req.subtype))
        return sd_varlink_error_invalid_parameter_name(link, "subtype");
    (void)strlcpy(req.fsname, parsed.fsname, sizeof(req.fsname));
    (void)strlcpy(req.subtype, parsed.subtype, sizeof(req.subtype));

    if (sd_varlink_get_n_fds(link) != 2)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "fuseFileDescriptor");
    dev_fd = sd_varlink_take_fd(link, parsed.fuse_fd_index);
    mnt_fd = sd_varlink_take_fd(link, parsed.mnt_fd_index);
    if (dev_fd < 0 || mnt_fd < 0) {
        if (dev_fd >= 0)
            close(dev_fd);
        if (mnt_fd >= 0)
            close(mnt_fd);
        return sd_varlink_error_invalid_parameter_name(
            link,
            dev_fd < 0 ? "fuseFileDescriptor" : "mountpointFileDescriptor");
    }

    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    if (getsockopt(ctx->sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) ==
        -1) {
        ret = -errno;
        fprintf(stderr, "defused: SO_PEERCRED failed: %s\n", strerror(errno));
    } else
        ret = handle_mount(link, ctx->sock, &req, mnt_fd, dev_fd, &cred);

    close(dev_fd);
    close(mnt_fd);
    return ret;
}

static int varlink_unmount(sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    struct request_context *ctx = userdata;
    struct defused_umount_req req = {0};
    int parent_fd = -1;
    int ret = 0;

    struct unmount_parameters {
        uint32_t parent_fd_index;
        const char *name;
        int lazy;
    } parsed = {};
    static const sd_json_dispatch_field dispatch_table[] = {
        {"parentFileDescriptor", SD_JSON_VARIANT_UNSIGNED,
         sd_json_dispatch_uint32,
         offsetof(struct unmount_parameters, parent_fd_index),
         SD_JSON_MANDATORY},
        {"name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
         offsetof(struct unmount_parameters, name),
         SD_JSON_MANDATORY | SD_JSON_STRICT},
        {"lazy", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_intbool,
         offsetof(struct unmount_parameters, lazy), SD_JSON_MANDATORY},
        {},
    };

    ret = sd_varlink_dispatch(link, parameters, dispatch_table, &parsed);
    if (ret != 0)
        return ret;
    if (strlen(parsed.name) >= sizeof(req.name))
        return sd_varlink_error_invalid_parameter_name(link, "name");
    (void)strlcpy(req.name, parsed.name, sizeof(req.name));
    req.lazy = parsed.lazy;

    if (sd_varlink_get_n_fds(link) != 1)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "parentFileDescriptor");
    parent_fd = sd_varlink_take_fd(link, parsed.parent_fd_index);
    if (parent_fd < 0)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "parentFileDescriptor");

    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    if (getsockopt(ctx->sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) ==
        -1) {
        ret = -errno;
        fprintf(stderr, "defused: SO_PEERCRED failed: %s\n", strerror(errno));
    } else
        ret = handle_umount(link, ctx->sock, &req, parent_fd, ctx->proc_fd,
                            &cred);

    close(parent_fd);
    return ret;
}

static const char *status_name(uint32_t status) {
    switch (status) {
    case DEFUSED_OK:
        return "DEFUSED_OK";
    case DEFUSED_ERR_MALFORMED:
        return "DEFUSED_ERR_MALFORMED";
    case DEFUSED_ERR_BAD_OPTION:
        return "DEFUSED_ERR_BAD_OPTION";
    case DEFUSED_ERR_NOT_ALLOWED:
        return "DEFUSED_ERR_NOT_ALLOWED";
    case DEFUSED_ERR_NOT_A_FUSE_MOUNT:
        return "DEFUSED_ERR_NOT_A_FUSE_MOUNT";
    case DEFUSED_ERR_MOUNT_FAILED:
        return "DEFUSED_ERR_MOUNT_FAILED";
    case DEFUSED_ERR_UNMOUNT_FAILED:
        return "DEFUSED_ERR_UNMOUNT_FAILED";
    case DEFUSED_ERR_SETNS_FAILED:
        return "DEFUSED_ERR_SETNS_FAILED";
    default:
        return "unknown status";
    }
}

static int peer_pidfd(int sock) {
    int pidfd = -1;
    socklen_t len = sizeof(pidfd);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) == -1) {
        fprintf(stderr, "defused: SO_PEERPIDFD failed: %s\n", strerror(errno));
        return -errno;
    }
    return pidfd;
}

static int neg_errno(void) { return -errno; }

static int mount_fsconfig_string(int fsfd, const char *key, const char *value) {
    if (fsconfig(fsfd, FSCONFIG_SET_STRING, key, value, 0) == -1)
        return neg_errno();
    return 0;
}

static int mount_fsconfig_flag(int fsfd, const char *key) {
    if (fsconfig(fsfd, FSCONFIG_SET_FLAG, key, NULL, 0) == -1)
        return neg_errno();
    return 0;
}

/* Check the client's mount request is well-formed. Policy questions like
 * whether this caller may use allow_other are answered entirely by polkit
 * (see check_polkit_authorized()); this only validates protocol shape. */
static int check_mount_policy(const struct defused_mount_req *req) {
    if ((req->mount_flags & ~(uint32_t)DEFUSED_MOUNT_FLAGS_MASK) != 0)
        return -EINVAL;

    return 0;
}

/* Writes a comma-separated list of privileged_mount_flags[] names for the
 * bits set in mount_flags into buf (empty string if none are set), for the
 * "privileged-flags" polkit detail -- see privileged_mount_flags[]'s doc
 * comment. buf is always NUL-terminated; names that wouldn't fit are
 * silently dropped, which only matters if this table grows to carry far
 * more (and far longer) names than it does today. */
static void format_privileged_flags(uint32_t mount_flags, char *buf,
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
 * The subject's pid is conveyed to polkit as a pidfd obtained from this
 * connection's SO_PEERPIDFD, not a bare pid, for the same TOCTOU reason the
 * sandboxed mount/unmount child joins the peer namespace through a pidfd: a
 * pid alone can be recycled between the credential check and whenever polkit
 * gets around to looking at it, and a pidfd names one specific process no
 * matter what.
 *
 * Fails closed: if polkit cannot be reached at all (e.g. not installed or
 * not running), the operation is refused rather than silently falling back
 * to the ownership check alone. */
static int check_polkit_authorized(int sock, const struct ucred *cred,
                                   const char *action_id, long current_mounts,
                                   const char *privileged_flags) {
    bool have_privileged_flags = privileged_flags && privileged_flags[0];
    int pidfd = -1;
    socklen_t pidfd_len = sizeof(pidfd);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfd_len) == -1) {
        fprintf(stderr, "defused: SO_PEERPIDFD failed: %s\n", strerror(errno));
        return -errno;
    }

    sd_bus *bus = NULL;
    sd_bus_message *call = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int ret;

    ret = sd_bus_open_system(&bus);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to connect to the system bus: %s\n",
                strerror(-ret));
        goto out;
    }

    ret = sd_bus_message_new_method_call(
        bus, &call, "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization");
    if (ret < 0)
        goto out;

    /* subject: (sa{sv}) = ("unix-process", {"uid": <i>, "pidfd": <h>}).
     * Passing both "uid" and "pidfd" (rather than "pid"/"start-time") makes
     * polkit resolve the subject from the pidfd directly -- see
     * polkit_subject_new_for_gvariant_invocation() in polkit's
     * src/polkit/polkitsubject.c. */
    ret = sd_bus_message_append(call, "(sa{sv})s", "unix-process", 2u, "uid",
                                "i", (int32_t)cred->uid, "pidfd", "h", pidfd,
                                action_id);
    if (ret < 0)
        goto out;

    /* details: a{ss}. uid, gid, and pid are deliberately not included: a
     * rule already gets those from the subject polkit itself constructs
     * (subject.uid, subject.groups, subject.pid), no need to duplicate them
     * here. current-mounts and privileged-flags (mount only, see above) are
     * the only things a rule can't get any other way, and are each omitted
     * entirely when the caller has nothing to say -- see
     * examples/50-defused-mount-policy.rules for a rule that uses both. */
    ret = sd_bus_message_open_container(call, 'a', "{ss}");
    if (ret < 0)
        goto out;
    char mounts_buf[32];
    if (current_mounts >= 0) {
        snprintf(mounts_buf, sizeof(mounts_buf), "%ld", current_mounts);
        ret = sd_bus_message_append(call, "{ss}", "current-mounts", mounts_buf);
        if (ret < 0)
            goto out;
    }
    if (have_privileged_flags) {
        ret = sd_bus_message_append(call, "{ss}", "privileged-flags",
                                    privileged_flags);
        if (ret < 0)
            goto out;
    }
    ret = sd_bus_message_close_container(call);
    if (ret < 0)
        goto out;

    /* flags: CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION (1), so that
     * an agent in the caller's session can answer an AUTH_ADMIN_KEEP-style
     * challenge instead of it failing outright. cancellation_id: unused, we
     * never call CancelCheckAuthorization. */
    ret = sd_bus_message_append(call, "us", (uint32_t)1, "");
    if (ret < 0)
        goto out;

    ret = sd_bus_call(bus, call, 0, &error, &reply);
    if (ret < 0) {
        fprintf(stderr, "defused: polkit CheckAuthorization failed: %s\n",
                error.message ? error.message : strerror(-ret));
        goto out;
    }

    int is_authorized = 0;
    int is_challenge = 0;
    ret = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
    if (ret < 0)
        goto out;
    ret = sd_bus_message_read(reply, "bb", &is_authorized, &is_challenge);
    if (ret < 0)
        goto out;
    ret = sd_bus_message_skip(reply, "a{ss}");
    if (ret < 0)
        goto out;
    ret = sd_bus_message_exit_container(reply);
    if (ret < 0)
        goto out;

    if (!is_authorized) {
        fprintf(stderr, "defused: polkit denied %s to uid %u (challenge=%d)\n",
                action_id, (unsigned)cred->uid, is_challenge);
        ret = -EACCES;
        goto out;
    }
    ret = 0;

out:
    sd_bus_error_free(&error);
    sd_bus_message_unref(call);
    sd_bus_message_unref(reply);
    sd_bus_flush_close_unref(bus);
    if (pidfd >= 0)
        close(pidfd);
    return ret;
}

static int check_mountpoint_fstype(int mnt_fd) {
    struct statfs fs;
    if (fstatfs(mnt_fd, &fs) == -1)
        return -errno;

    return check_nonroot_fstype("defused", &fs) == 0 ? 0 : -EPERM;
}

static int check_fuse_device_fd(int dev_fd) {
    struct stat st;
    if (fstat(dev_fd, &st) == -1)
        return -errno;
    if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 10 ||
        minor(st.st_rdev) != 229)
        return -EINVAL;

    int flags = fcntl(dev_fd, F_GETFL);
    if (flags == -1)
        return -errno;
    if ((flags & O_ACCMODE) != O_RDWR)
        return -EINVAL;
    return 0;
}

static int prepare_mount(const struct defused_mount_req *req, int dev_fd,
                         const struct stat *st, const struct ucred *cred,
                         struct prepared_mount *out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->type, sizeof(out->type), "fuse%s%s",
             req->subtype[0] ? "." : "", req->subtype);
    snprintf(out->source, sizeof(out->source), "%s",
             req->fsname[0] ? req->fsname : "fuse");
    snprintf(out->fd, sizeof(out->fd), "%d", dev_fd);
    snprintf(out->rootmode, sizeof(out->rootmode), "%o", st->st_mode & S_IFMT);
    snprintf(out->user_id, sizeof(out->user_id), "%u", cred->uid);
    snprintf(out->group_id, sizeof(out->group_id), "%u", cred->gid);
    if (req->max_read) {
        snprintf(out->max_read, sizeof(out->max_read), "%u", req->max_read);
        out->have_max_read = 1;
    }
    if (req->blksize) {
        snprintf(out->blksize, sizeof(out->blksize), "%u", req->blksize);
        out->have_blksize = 1;
    }
    out->have_subtype = req->subtype[0] != '\0';

    uint32_t flags = req->mount_flags & DEFUSED_MOUNT_FLAGS_MASK;
    out->flags = flags;
    out->mount_attrs = MOUNT_ATTR_NOSUID;
    if (flags & DEFUSED_MOUNT_RDONLY)
        out->mount_attrs |= MOUNT_ATTR_RDONLY;
    if (!(flags & DEFUSED_MOUNT_ALLOW_DEV))
        out->mount_attrs |= MOUNT_ATTR_NODEV;
    if (flags & DEFUSED_MOUNT_NOEXEC)
        out->mount_attrs |= MOUNT_ATTR_NOEXEC;
    if (flags & DEFUSED_MOUNT_NOATIME)
        out->mount_attrs |= MOUNT_ATTR_NOATIME;
    if (flags & DEFUSED_MOUNT_NODIRATIME)
        out->mount_attrs |= MOUNT_ATTR_NODIRATIME;
    if (flags & DEFUSED_MOUNT_NOSYMFOLLOW)
        out->mount_attrs |= MOUNT_ATTR_NOSYMFOLLOW;

    return 0;
}

static int create_detached_mount(const struct prepared_mount *mnt) {
    int fsfd = fsopen(mnt->type, FSOPEN_CLOEXEC);
    if (fsfd == -1)
        return neg_errno();

    int mountfd = -1;
    int ret = 0;

    if (mnt->have_subtype) {
        ret = mount_fsconfig_string(fsfd, "subtype", mnt->type + 5);
        if (ret < 0)
            goto out;
    }

    ret = mount_fsconfig_string(fsfd, "source", mnt->source);
    if (ret < 0)
        goto out;
    ret = mount_fsconfig_string(fsfd, "fd", mnt->fd);
    if (ret < 0)
        goto out;
    ret = mount_fsconfig_string(fsfd, "rootmode", mnt->rootmode);
    if (ret < 0)
        goto out;
    ret = mount_fsconfig_string(fsfd, "user_id", mnt->user_id);
    if (ret < 0)
        goto out;
    ret = mount_fsconfig_string(fsfd, "group_id", mnt->group_id);
    if (ret < 0)
        goto out;

    if (mnt->flags & DEFUSED_FUSE_ALLOW_OTHER) {
        ret = mount_fsconfig_flag(fsfd, "allow_other");
        if (ret < 0)
            goto out;
    }
    if (mnt->flags & DEFUSED_FUSE_DEFAULT_PERMISSIONS) {
        ret = mount_fsconfig_flag(fsfd, "default_permissions");
        if (ret < 0)
            goto out;
    }
    if (mnt->have_max_read) {
        ret = mount_fsconfig_string(fsfd, "max_read", mnt->max_read);
        if (ret < 0)
            goto out;
    }
    if (mnt->have_blksize) {
        ret = mount_fsconfig_string(fsfd, "blksize", mnt->blksize);
        if (ret < 0)
            goto out;
    }
    if (mnt->flags & DEFUSED_MOUNT_RDONLY) {
        ret = mount_fsconfig_flag(fsfd, "ro");
        if (ret < 0)
            goto out;
    }
    if (mnt->flags & DEFUSED_MOUNT_SYNCHRONOUS) {
        ret = mount_fsconfig_flag(fsfd, "sync");
        if (ret < 0)
            goto out;
    }
    if (mnt->flags & DEFUSED_MOUNT_DIRSYNC) {
        ret = mount_fsconfig_flag(fsfd, "dirsync");
        if (ret < 0)
            goto out;
    }

    if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1) {
        ret = neg_errno();
        goto out;
    }

    mountfd = fsmount(fsfd, FSMOUNT_CLOEXEC, mnt->mount_attrs);
    if (mountfd == -1) {
        ret = neg_errno();
        goto out;
    }

    ret = mountfd;
    mountfd = -1;

out:
    if (mountfd >= 0)
        close(mountfd);
    if (fsfd >= 0)
        close(fsfd);
    return ret;
}

static int handle_mount(sd_varlink *link, int sock,
                        const struct defused_mount_req *req, int mnt_fd,
                        int dev_fd, const struct ucred *cred) {
    uint32_t status;
    int sys_errno = 0;
    int ret = 0;
    int mountfd = -1;

    if (strnlen(req->fsname, DEFUSED_MAX_NAME) == DEFUSED_MAX_NAME ||
        strnlen(req->subtype, DEFUSED_MAX_NAME) == DEFUSED_MAX_NAME ||
        strchr(req->fsname, '/') || strchr(req->subtype, '/')) {
        status = DEFUSED_ERR_MALFORMED;
        ret = -EINVAL;
        goto fail;
    }

    ret = check_mount_policy(req);
    if (ret < 0) {
        status =
            ret == -EINVAL ? DEFUSED_ERR_BAD_OPTION : DEFUSED_ERR_NOT_ALLOWED;
        goto fail;
    }

    struct stat st;
    if (fstat(mnt_fd, &st) == -1) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = errno;
        ret = -errno;
        goto fail;
    }
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = S_ISLNK(st.st_mode) ? ELOOP : ENOTDIR;
        ret = -sys_errno;
        goto fail;
    }
    /* Ownership policy diverges from libfuse's setuid fusermount3 here --
     * see doc/protocol.md. */
    if (st.st_uid != cred->uid || !(st.st_mode & S_IWUSR) ||
        (S_ISDIR(st.st_mode) && !(st.st_mode & S_IXUSR))) {
        status = DEFUSED_ERR_NOT_ALLOWED;
        ret = -EPERM;
        goto fail;
    }
    ret = check_mountpoint_fstype(mnt_fd);
    if (ret < 0) {
        status = DEFUSED_ERR_NOT_ALLOWED;
        goto fail;
    }

    ret = check_fuse_device_fd(dev_fd);
    if (ret < 0) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = -ret;
        goto fail;
    }

    /* Handed to polkit below so a rule can implement its own mount-count
     * policy. */
    errno = 0;
    int current_mounts = count_fuse_fs("defused");
    if (current_mounts < 0) {
        int saved_errno = errno ? errno : EIO;
        status = DEFUSED_ERR_MOUNT_FAILED;
        sys_errno = saved_errno;
        ret = -saved_errno;
        goto fail;
    }

    char privileged_flags[128];
    format_privileged_flags(req->mount_flags, privileged_flags,
                            sizeof(privileged_flags));

    ret = check_polkit_authorized(sock, cred, DEFUSED_POLKIT_ACTION_MOUNT,
                                  current_mounts, privileged_flags);
    if (ret < 0) {
        status =
            ret == -EACCES ? DEFUSED_ERR_NOT_ALLOWED : DEFUSED_ERR_MOUNT_FAILED;
        sys_errno = -ret;
        goto fail;
    }

    int pidfd = peer_pidfd(sock);
    if (pidfd < 0) {
        status = DEFUSED_ERR_MOUNT_FAILED;
        sys_errno = -pidfd;
        ret = pidfd;
        goto fail;
    }

    struct prepared_mount prepared;
    ret = prepare_mount(req, dev_fd, &st, cred, &prepared);
    if (ret < 0) {
        status = DEFUSED_ERR_MOUNT_FAILED;
        sys_errno = -ret;
        close(pidfd);
        goto fail;
    }

    mountfd = create_detached_mount(&prepared);
    if (mountfd < 0) {
        status = DEFUSED_ERR_MOUNT_FAILED;
        sys_errno = -mountfd;
        ret = mountfd;
        close(pidfd);
        goto fail;
    }

    ret = defused_sandbox_mount(pidfd, mountfd, mnt_fd, &status, &sys_errno);
    close(pidfd);
    close(mountfd);
    mountfd = -1;
    if (ret < 0)
        goto fail;

    return reply_response(link, DEFUSED_OK, 0);

fail:
    if (mountfd >= 0)
        close(mountfd);
    fprintf(stderr,
            "defused: mount request failed with %s (ret=%d, errno=%d: %s)\n",
            status_name(status), ret, sys_errno,
            sys_errno ? strerror(sys_errno) : "none");
    (void)reply_response(link, status, sys_errno);
    return ret;
}

static int handle_umount(sd_varlink *link, int sock,
                         const struct defused_umount_req *req, int parent_fd,
                         int proc_fd, const struct ucred *cred) {
    uint32_t status = DEFUSED_OK;
    int sys_errno = 0;
    int ret = 0;
    int mnt_fd = -1;

    if (strnlen(req->name, DEFUSED_MAX_FILENAME) == DEFUSED_MAX_FILENAME ||
        req->name[0] == '\0' || strchr(req->name, '/') ||
        !strcmp(req->name, ".") || !strcmp(req->name, "..")) {
        status = DEFUSED_ERR_MALFORMED;
        ret = -EINVAL;
        goto out;
    }

    mnt_fd = openat(parent_fd, req->name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = errno;
        ret = -errno;
        goto out;
    }

    long parent_mnt_id = -1;
    ret = fd_mnt_id(proc_fd, parent_fd, &parent_mnt_id);
    if (ret < 0) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = -ret;
        goto out;
    }

    /* Identify the mount that the fd refers to *without* calling into the
     * filesystem.
     * fdinfo's mnt_id comes straight from the VFS and therefore works even
     * if the FUSE server is not responding */
    long mnt_id = -1;
    ret = fd_mnt_id(proc_fd, mnt_fd, &mnt_id);
    if (ret < 0) {
        status = DEFUSED_ERR_MALFORMED;
        sys_errno = -ret;
        goto out;
    }
    close(mnt_fd);
    mnt_fd = -1;

    if (mnt_id == parent_mnt_id) {
        status = DEFUSED_ERR_NOT_A_FUSE_MOUNT;
        ret = -EINVAL;
        goto out;
    }

    /* Before the sandboxed child installs seccomp: the filter has no room for
     * the syscalls talking to polkit over D-Bus needs. This asks only whether
     * the caller may use unmount at all -- whether this specific mount is
     * theirs to tear down is the ownership check below, which needs the
     * caller's mount namespace and so can't move here. */
    ret = check_polkit_authorized(sock, cred, DEFUSED_POLKIT_ACTION_UNMOUNT, -1,
                                  NULL);
    if (ret < 0) {
        status = ret == -EACCES ? DEFUSED_ERR_NOT_ALLOWED
                                : DEFUSED_ERR_UNMOUNT_FAILED;
        sys_errno = -ret;
        goto out;
    }

    int pidfd = peer_pidfd(sock);
    if (pidfd < 0) {
        status = DEFUSED_ERR_UNMOUNT_FAILED;
        sys_errno = -pidfd;
        ret = pidfd;
        goto out;
    }

    ret = defused_sandbox_unmount(pidfd, proc_fd, parent_fd, req, mnt_id,
                                  cred->uid, &status, &sys_errno);
    close(pidfd);
    if (ret < 0)
        goto out;

out:
    if (mnt_fd >= 0)
        close(mnt_fd);
    if (ret < 0)
        fprintf(
            stderr,
            "defused: unmount request failed with %s (ret=%d, errno=%d: %s)\n",
            status_name(status), ret, sys_errno,
            sys_errno ? strerror(sys_errno) : "none");
    int send_ret = reply_response(link, status, sys_errno);
    if (ret == 0)
        ret = send_ret;
    return ret;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s\n"
            "\n"
            "Handles one mount/unmount request on the socket-activation fd\n"
            "(see defused_proto.h); meant to be spawned by systemd socket\n"
            "activation, one process per connection. There are no options --\n"
            "policy decisions are made per request by polkit; see\n"
            "doc/protocol.md.\n",
            prog);
}

static int parse_args(int argc, char *argv[]) {
    static const struct option opts[] = {
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    for (;;) {
        int c = getopt_long(argc, argv, "h", opts, NULL);

        if (c == -1)
            break;
        switch (c) {
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -EINVAL;
        }
    }
    return 0;
}

/* Implements systemd socket activation */
static int socket_activation_fd(int *out_fd) {
    int n = sd_listen_fds(1 /* unset_environment */);
    if (n < 0) {
        fprintf(stderr, "defused: sd_listen_fds failed: %s\n", strerror(-n));
        return n;
    }
    if (n != 1) {
        fprintf(stderr,
                "defused: not socket-activated with exactly one fd (got "
                "%d) -- $LISTEN_PID/$LISTEN_FDS not set or wrong?\n",
                n);
        return -EINVAL;
    }

    int fd = SD_LISTEN_FDS_START;

    int r = sd_is_socket_unix(fd, SOCK_STREAM, 0 /* not listening */, NULL, 0);
    if (r < 0) {
        fprintf(stderr, "defused: sd_is_socket_unix failed: %s\n",
                strerror(-r));
        return r;
    }
    if (r == 0) {
        fprintf(stderr,
                "defused: socket-activation fd is not a connected AF_UNIX "
                "SOCK_STREAM socket (check ListenStream= in "
                "the .socket unit)\n");
        return -EINVAL;
    }

    *out_fd = fd;
    return 0;
}

/* Determine the mount ID given a mount file descriptor via trusted procfs */
static int fd_mnt_id(int proc_fd, int fd, long *out_id) {
    char path[48];
    snprintf(path, sizeof(path), "self/fdinfo/%d", fd);
    int info_fd = openat(proc_fd, path, O_RDONLY | O_CLOEXEC);

    if (info_fd == -1)
        return -errno;

    FILE *f = fdopen(info_fd, "r");
    if (!f) {
        int saved_errno = errno;
        close(info_fd);
        errno = saved_errno;
        return -errno;
    }

    char line[256];
    long id = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "mnt_id:%ld", &id) == 1)
            break;
    fclose(f);
    if (id < 0)
        return -ENODATA;
    *out_id = id;
    return 0;
}
