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
 *
 * With --child (spawned by fusermount3 for a privileged caller), policy is
 * skipped and the mount/unmount is done in-process.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-daemon.h"
#include "defused-policy.h"
#include "defused-sandbox.h"
#include "defused_proto.h"
#include "util.h"

#include <assert.h>
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
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

struct request_context {
    int sock;
    bool privileged;
};

struct prepared_mount {
    char type[DEFUSED_MAX_NAME + 16];
    char source[DEFUSED_MAX_FSNAME];
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

/* Forward declarations, only for functions used before their definition;
 * everything else carries its attributes on the definition itself. */
static int varlink_mount(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata)
    __attribute__((__nonnull__(1, 4), __warn_unused_result__));
static int varlink_unmount(sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_flags_t flags, void *userdata)
    __attribute__((__nonnull__(1, 4), __warn_unused_result__));
static int get_peer_cred(int sock, struct ucred *cred)
    __attribute__((__nonnull__(2), __warn_unused_result__));
static int handle_mount(sd_varlink *link, const struct request_context *ctx,
                        const struct defused_mount_req *req, int mnt_fd,
                        int dev_fd, const struct ucred *cred)
    __attribute__((__nonnull__(1, 2, 3, 6), __warn_unused_result__));
static int handle_umount(sd_varlink *link, const struct request_context *ctx,
                         const struct defused_umount_req *req, int parent_fd,
                         const struct ucred *cred)
    __attribute__((__nonnull__(1, 2, 3, 5), __warn_unused_result__));
static int parse_args(int argc, char *argv[])
    __attribute__((__nonnull__(2), __warn_unused_result__));
static int socket_activation_fd(int *out_fd)
    __attribute__((__nonnull__(1), __warn_unused_result__));
static int handle_connection(int sock_fd, bool privileged)
    __attribute__((__warn_unused_result__));
static int handle_unprivileged_connection(int sock_fd)
    __attribute__((__warn_unused_result__));
static int fd_mnt_id(int proc_fd, int fd, long *out_id)
    __attribute__((__nonnull__(3), __warn_unused_result__));

static bool cfg_daemon = false;
static bool cfg_child = false;

int main(int argc, char *argv[]) {
    int ret = parse_args(argc, argv);
    if (ret < 0)
        return EXIT_FAILURE;

    if (cfg_daemon)
        return defused_run_fork_daemon(handle_unprivileged_connection) == 0
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;

    int sock = -EBADF;
    ret = socket_activation_fd(&sock);
    if (ret < 0)
        return EXIT_FAILURE;

    return handle_connection(sock, cfg_child);
}

/* Handles a single already-connected Varlink socket to completion (one
 * mount/unmount request), then closes it. Takes ownership of sock_fd. Used
 * both for the systemd-Accept=yes case in main() (the handed-off connection)
 * and for each forked child in defused_run_fork_daemon() (the accepted
 * connection).
 */
static int handle_connection(int sock_fd, bool privileged) {
    _cleanup_close_ int sock = sock_fd;
    _cleanup_(sd_event_unrefp) sd_event *event = NULL;
    _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
    int ret;

    ret = sd_event_new(&event);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to create event loop: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }
    ret = sd_varlink_server_new(&server,
                                SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT |
                                    SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT |
                                    SD_VARLINK_SERVER_INHERIT_USERDATA);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to create Varlink server: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }
    ret = sd_varlink_server_add_interface(server,
                                          &vl_interface_website_soss_defused);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to add Varlink interface: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }
    ret = sd_varlink_server_bind_method_many(
        server, DEFUSED_VARLINK_METHOD_MOUNT, varlink_mount,
        DEFUSED_VARLINK_METHOD_UNMOUNT, varlink_unmount);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to bind Varlink methods: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }

    struct request_context ctx = {.sock = sock, .privileged = privileged};
    sd_varlink_server_set_userdata(server, &ctx);
    ret = sd_varlink_server_set_exit_on_idle(server, true);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to configure Varlink server: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }
    ret = sd_varlink_server_attach_event(server, event, 0);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to attach Varlink server: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }
    /* The server owns the fd once added; on failure it is still ours. */
    ret = sd_varlink_server_add_connection(server, sock, NULL);
    if (ret < 0) {
        fprintf(stderr, "defused: failed to add Varlink connection: %s\n",
                strerror(-ret));
        return EXIT_FAILURE;
    }
    TAKE_FD(sock);
    ret = sd_event_loop(event);
    if (ret < 0) {
        fprintf(stderr, "defused: Varlink server failed: %s\n", strerror(-ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/* For defused_run_fork_daemon(). */
static int handle_unprivileged_connection(int sock_fd) {
    return handle_connection(sock_fd, false);
}

/* errno goes on the wire only for the errors declared to carry it. Also,
 * sd_varlink_error() hands the error it just sent back as a negative errno
 * (-EBADR for an id it has no mapping for), so a negative return here is the
 * normal case, not a failure to reply. */
static int reply_error(sd_varlink *link, const struct defused_error *err) {
    return sd_varlink_errorbo(
        link, err->id,
        SD_JSON_BUILD_PAIR_CONDITION(err->sys_errno != 0, "errno",
                                     SD_JSON_BUILD_INTEGER(err->sys_errno)));
}

static int varlink_mount(sd_varlink *link, sd_json_variant *parameters,
                         sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    struct request_context *ctx = userdata;
    struct defused_mount_req req = {0};
    int ret = 0;

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
    _cleanup_close_ int dev_fd = sd_varlink_take_fd(link, parsed.fuse_fd_index);
    _cleanup_close_ int mnt_fd = sd_varlink_take_fd(link, parsed.mnt_fd_index);
    if (dev_fd < 0 || mnt_fd < 0)
        return sd_varlink_error_invalid_parameter_name(
            link,
            dev_fd < 0 ? "fuseFileDescriptor" : "mountpointFileDescriptor");

    struct ucred cred;
    ret = get_peer_cred(ctx->sock, &cred);
    if (ret < 0)
        return ret;
    return handle_mount(link, ctx, &req, mnt_fd, dev_fd, &cred);
}

static int varlink_unmount(sd_varlink *link, sd_json_variant *parameters,
                           sd_varlink_method_flags_t flags, void *userdata) {
    (void)flags;
    struct request_context *ctx = userdata;
    struct defused_umount_req req = {0};
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
    _cleanup_close_ int parent_fd =
        sd_varlink_take_fd(link, parsed.parent_fd_index);
    if (parent_fd < 0)
        return sd_varlink_error_invalid_parameter_name(link,
                                                       "parentFileDescriptor");

    struct ucred cred;
    ret = get_peer_cred(ctx->sock, &cred);
    if (ret < 0)
        return ret;
    return handle_umount(link, ctx, &req, parent_fd, &cred);
}

static __attribute__((__warn_unused_result__)) int peer_pidfd(int sock) {
    int pidfd = -1;
    socklen_t len = sizeof(pidfd);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) == -1) {
        fprintf(stderr, "defused: SO_PEERPIDFD failed: %s\n", strerror(errno));
        return -errno;
    }
    return pidfd;
}

static int get_peer_cred(int sock, struct ucred *cred) {
    socklen_t len = sizeof(*cred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, cred, &len) == -1) {
        fprintf(stderr, "defused: SO_PEERCRED failed: %s\n", strerror(errno));
        return -errno;
    }
    return 0;
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

static __attribute__((__warn_unused_result__)) int
check_mountpoint_fstype(int mnt_fd) {
    struct statfs fs;
    if (fstatfs(mnt_fd, &fs) == -1)
        return -errno;

    return check_nonroot_fstype("defused", &fs) == 0 ? 0 : -EPERM;
}

static __attribute__((__warn_unused_result__)) int
check_fuse_device_fd(int dev_fd) {
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

static __attribute__((__nonnull__(1, 3, 4, 5))) void
prepare_mount(const struct defused_mount_req *req, int dev_fd,
              const struct stat *st, const struct ucred *cred,
              struct prepared_mount *out) {
    memset(out, 0, sizeof(*out));
    uint32_t flags = req->mount_flags & DEFUSED_MOUNT_FLAGS_MASK;
    snprintf(out->type, sizeof(out->type), "%s%s%s",
             flags & DEFUSED_MOUNT_BLKDEV ? "fuseblk" : "fuse",
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

    out->flags = flags;
    out->mount_attrs = 0;
    if (!(flags & DEFUSED_MOUNT_ALLOW_SUID))
        out->mount_attrs |= MOUNT_ATTR_NOSUID;
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
}

static __attribute__((__nonnull__(1), __warn_unused_result__)) int
create_detached_mount(const struct prepared_mount *mnt) {
    _cleanup_close_ int fsfd = fsopen(mnt->type, FSOPEN_CLOEXEC);
    if (fsfd == -1)
        return neg_errno();

    const struct {
        const char *key;
        const char *value;
        bool present;
    } strings[] = {
        {"subtype", strchr(mnt->type, '.') + 1, mnt->have_subtype},
        {"source", mnt->source, true},
        {"fd", mnt->fd, true},
        {"rootmode", mnt->rootmode, true},
        {"user_id", mnt->user_id, true},
        {"group_id", mnt->group_id, true},
        {"max_read", mnt->max_read, mnt->have_max_read},
        {"blksize", mnt->blksize, mnt->have_blksize},
    };
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        if (!strings[i].present)
            continue;
        int ret = mount_fsconfig_string(fsfd, strings[i].key, strings[i].value);
        if (ret < 0)
            return ret;
    }

    const struct {
        const char *key;
        bool present;
    } flags[] = {
        {"allow_other", mnt->flags & DEFUSED_FUSE_ALLOW_OTHER},
        {"default_permissions", mnt->flags & DEFUSED_FUSE_DEFAULT_PERMISSIONS},
        {"ro", mnt->flags & DEFUSED_MOUNT_RDONLY},
        {"sync", mnt->flags & DEFUSED_MOUNT_SYNCHRONOUS},
        {"dirsync", mnt->flags & DEFUSED_MOUNT_DIRSYNC},
    };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (!flags[i].present)
            continue;
        int ret = mount_fsconfig_flag(fsfd, flags[i].key);
        if (ret < 0)
            return ret;
    }

    if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1)
        return neg_errno();

    int mountfd = fsmount(fsfd, FSMOUNT_CLOEXEC, mnt->mount_attrs);
    if (mountfd == -1)
        return neg_errno();
    return mountfd;
}

static __attribute__((__nonnull__(3, 4), __warn_unused_result__)) int
authorize_mount(int pidfd, uint32_t mount_flags, const struct ucred *cred,
                struct defused_error *err) {
    /* Handed to polkit so a rule can implement its own mount-count policy. */
    errno = 0;
    int current_mounts = count_fuse_fs("defused");
    if (current_mounts < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MOUNT_FAILED,
                          errno ? errno : EIO);
        return -err->sys_errno;
    }

    char privileged_flags[128];
    defused_format_privileged_flags(mount_flags, privileged_flags,
                                    sizeof(privileged_flags));

    int ret = defused_polkit_check_authorized(pidfd, cred,
                                              DEFUSED_POLKIT_ACTION_MOUNT,
                                              current_mounts, privileged_flags);
    if (ret < 0) {
        /* -EACCES is polkit's answer, not a failure to ask it. */
        if (ret == -EACCES)
            defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_ALLOWED, 0);
        else
            defused_error_set(err, DEFUSED_VARLINK_ERROR_MOUNT_FAILED, -ret);
    }
    return ret;
}

/* Validates and performs a mount request. On failure, *err describes what to
 * report to the client; the caller logs and replies. */
static __attribute__((__nonnull__(1, 2, 5, 6), __warn_unused_result__)) int
mount_request(const struct request_context *ctx,
              const struct defused_mount_req *req, int mnt_fd, int dev_fd,
              const struct ucred *cred, struct defused_error *err) {
    /* varlink_mount() already bounds-checked these before copying them out
     * of the JSON payload. */
    assert(strnlen(req->fsname, DEFUSED_MAX_FSNAME) < DEFUSED_MAX_FSNAME);
    assert(strnlen(req->subtype, DEFUSED_MAX_NAME) < DEFUSED_MAX_NAME);
    if ((!ctx->privileged && strchr(req->fsname, '/')) ||
        strchr(req->subtype, '/') ||
        ((req->mount_flags & DEFUSED_MOUNT_BLKDEV) && !req->fsname[0])) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, EINVAL);
        return -EINVAL;
    }

    /* Policy questions like whether this caller may use allow_other are
     * answered entirely by polkit (see defused_polkit_check_authorized());
     * this
     * only validates protocol shape. */
    uint32_t allowed = DEFUSED_MOUNT_FLAGS_MASK;
    if (!ctx->privileged)
        allowed &= ~(uint32_t)DEFUSED_MOUNT_PRIVILEGED_FLAGS;
    if ((req->mount_flags & ~allowed) != 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_BAD_OPTION, 0);
        return -EINVAL;
    }

    struct stat st;
    if (fstat(mnt_fd, &st) == -1) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, errno);
        return -errno;
    }
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
        int sys_errno = S_ISLNK(st.st_mode) ? ELOOP : ENOTDIR;
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, sys_errno);
        return -sys_errno;
    }
    int ret;
    if (!ctx->privileged) {
        /* Ownership policy diverges from libfuse's setuid fusermount3 here
         * -- see doc/protocol.md. */
        if (st.st_uid != cred->uid || !(st.st_mode & S_IWUSR) ||
            (S_ISDIR(st.st_mode) && !(st.st_mode & S_IXUSR))) {
            defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_ALLOWED, 0);
            return -EPERM;
        }
        ret = check_mountpoint_fstype(mnt_fd);
        if (ret < 0) {
            defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_ALLOWED, 0);
            return ret;
        }
    }

    ret = check_fuse_device_fd(dev_fd);
    if (ret < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, -ret);
        return ret;
    }

    _cleanup_close_ int pidfd = -EBADF;
    if (!ctx->privileged) {
        pidfd = peer_pidfd(ctx->sock);
        if (pidfd < 0) {
            defused_error_set(err, DEFUSED_VARLINK_ERROR_MOUNT_FAILED, -pidfd);
            return pidfd;
        }
        ret = authorize_mount(pidfd, req->mount_flags, cred, err);
        if (ret < 0)
            return ret;
    }

    struct prepared_mount prepared;
    prepare_mount(req, dev_fd, &st, cred, &prepared);

    _cleanup_close_ int mountfd = create_detached_mount(&prepared);
    if (mountfd < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MOUNT_FAILED, -mountfd);
        return mountfd;
    }

    if (ctx->privileged) {
        if (move_mount(mountfd, "", mnt_fd, "",
                       MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == 0)
            return 0;
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MOUNT_FAILED, errno);
        return -errno;
    }

    return defused_sandbox_mount(pidfd, mountfd, mnt_fd, err);
}

static __attribute__((__nonnull__(1, 2))) void
log_request_error(const char *what, const struct defused_error *err, int ret) {
    fprintf(stderr,
            "defused: %s request failed with %s (ret=%d, errno=%d: %s)\n", what,
            err->id, ret, err->sys_errno,
            err->sys_errno ? strerror(err->sys_errno) : "none");
}

static int handle_mount(sd_varlink *link, const struct request_context *ctx,
                        const struct defused_mount_req *req, int mnt_fd,
                        int dev_fd, const struct ucred *cred) {
    struct defused_error err = {};

    int ret = mount_request(ctx, req, mnt_fd, dev_fd, cred, &err);
    if (ret < 0) {
        log_request_error("mount", &err, ret);
        (void)reply_error(link, &err);
        return ret;
    }

    return sd_varlink_reply(link, NULL);
}

/* Validates and performs an unmount request. On failure, *err describes what
 * to report to the client; the caller logs and replies. */
static __attribute__((__nonnull__(1, 2, 4, 5), __warn_unused_result__)) int
umount_request(const struct request_context *ctx,
               const struct defused_umount_req *req, int parent_fd,
               const struct ucred *cred, struct defused_error *err) {
    /* varlink_unmount() already bounds-checked this before copying it out
     * of the JSON payload. */
    assert(strnlen(req->name, DEFUSED_MAX_FILENAME) < DEFUSED_MAX_FILENAME);
    if (req->name[0] == '\0' || strchr(req->name, '/') ||
        !strcmp(req->name, ".") || !strcmp(req->name, "..")) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, EINVAL);
        return -EINVAL;
    }

    /* Keep a handle to the service's procfs before entering the client's
     * mount namespace. */
    _cleanup_close_ int proc_fd =
        open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (proc_fd == -1) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED, errno);
        return -errno;
    }

    _cleanup_close_ int mnt_fd =
        openat(parent_fd, req->name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd == -1) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, errno);
        return -errno;
    }

    long parent_mnt_id = -1;
    int ret = fd_mnt_id(proc_fd, parent_fd, &parent_mnt_id);
    if (ret < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, -ret);
        return ret;
    }

    /* Identify the mount that the fd refers to *without* calling into the
     * filesystem.
     * fdinfo's mnt_id comes straight from the VFS and therefore works even
     * if the FUSE server is not responding */
    long mnt_id = -1;
    ret = fd_mnt_id(proc_fd, mnt_fd, &mnt_id);
    if (ret < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_MALFORMED, -ret);
        return ret;
    }
    if (mnt_id == parent_mnt_id) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_A_FUSE_MOUNT, 0);
        return -EINVAL;
    }

    /* From here on the target is identified by mnt_id. Close the fd now: an
     * open reference to the mount, here or inherited by the sandboxed child,
     * makes a non-lazy umount2() fail with EBUSY. */
    mnt_fd = safe_close(mnt_fd);

    if (ctx->privileged) {
        if (fchdir(parent_fd) == 0 &&
            umount2(req->name,
                    UMOUNT_NOFOLLOW | (req->lazy ? MNT_DETACH : 0)) == 0)
            return 0;
        defused_error_set(err, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED, errno);
        return -errno;
    }

    _cleanup_close_ int pidfd = peer_pidfd(ctx->sock);
    if (pidfd < 0) {
        defused_error_set(err, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED, -pidfd);
        return pidfd;
    }

    /* Before the sandboxed child installs seccomp: the filter has no room for
     * the syscalls talking to polkit over D-Bus needs. This asks only whether
     * the caller may use unmount at all -- whether this specific mount is
     * theirs to tear down is checked separately, inside
     * defused_sandbox_unmount(). */
    ret = defused_polkit_check_authorized(
        pidfd, cred, DEFUSED_POLKIT_ACTION_UNMOUNT, -1, NULL);
    if (ret < 0) {
        if (ret == -EACCES)
            defused_error_set(err, DEFUSED_VARLINK_ERROR_NOT_ALLOWED, 0);
        else
            defused_error_set(err, DEFUSED_VARLINK_ERROR_UNMOUNT_FAILED, -ret);
        return ret;
    }

    return defused_sandbox_unmount(pidfd, proc_fd, parent_fd, req->name,
                                   req->lazy, mnt_id, cred->uid, err);
}

static int handle_umount(sd_varlink *link, const struct request_context *ctx,
                         const struct defused_umount_req *req, int parent_fd,
                         const struct ucred *cred) {
    struct defused_error err = {};

    int ret = umount_request(ctx, req, parent_fd, cred, &err);
    if (ret < 0) {
        log_request_error("unmount", &err, ret);
        (void)reply_error(link, &err);
        return ret;
    }

    return sd_varlink_reply(link, NULL);
}

static __attribute__((__nonnull__(1))) void usage(const char *prog) {
    fprintf(
        stderr,
        "usage: %s [--daemon | --child]\n"
        "\n"
        "By default, handles one mount/unmount request on the\n"
        "socket-activation fd (see defused_proto.h); meant to be spawned by\n"
        "systemd socket activation, one process per connection. With\n"
        "--daemon, creates the defused Varlink socket itself and forks a\n"
        "child to handle each accepted connection, for non-systemd\n"
        "setups. There are no policy options -- policy decisions are\n"
        "made per request by polkit; see doc/protocol.md.\n"
        "\n"
        "  --daemon  listen on $DEFUSED_SOCKET (or the default socket\n"
        "            path) and fork a child for each connection\n"
        "  --child   same, but with this process's own privileges and no\n"
        "            policy at all; spawned by fusermount3 for root and\n"
        "            CAP_SYS_ADMIN callers, never for a service unit\n",
        prog);
}

static int parse_args(int argc, char *argv[]) {
    enum { OPT_DAEMON = 256, OPT_CHILD };

    static const struct option opts[] = {
        {"daemon", no_argument, NULL, OPT_DAEMON},
        {"child", no_argument, NULL, OPT_CHILD},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    for (;;) {
        int c = getopt_long(argc, argv, "h", opts, NULL);

        if (c == -1)
            break;
        switch (c) {
        case OPT_DAEMON:
            cfg_daemon = true;
            break;
        case OPT_CHILD:
            cfg_child = true;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -EINVAL;
        }
    }
    if (cfg_daemon && cfg_child) {
        fprintf(stderr, "defused: --daemon and --child are exclusive\n");
        return -EINVAL;
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
    _cleanup_close_ int info_fd = openat(proc_fd, path, O_RDONLY | O_CLOEXEC);
    if (info_fd == -1)
        return -errno;

    _cleanup_fclose_ FILE *f = fdopen(info_fd, "r");
    if (!f)
        return -errno;
    TAKE_FD(info_fd); /* now owned by the stream */

    char line[256];
    long id = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "mnt_id:%ld", &id) == 1)
            break;
    if (id < 0)
        return -ENODATA;
    *out_id = id;
    return 0;
}
