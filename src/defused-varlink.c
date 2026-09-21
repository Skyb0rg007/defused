/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The Varlink interface, shared by the service, the client and the tests.
 */

#include "defused_proto.h"

#include <stddef.h>
#include <systemd/sd-varlink-idl.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#define DEFUSED_ERRNO_FIELD SD_VARLINK_DEFINE_FIELD(errno, SD_VARLINK_INT, 0)

static SD_VARLINK_DEFINE_METHOD(
    Mount, SD_VARLINK_DEFINE_INPUT(fuseFileDescriptor, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(mountpointFileDescriptor, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(mountFlags, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(maxRead, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(blockSize, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(fsName, SD_VARLINK_STRING, 0),
    SD_VARLINK_DEFINE_INPUT(subtype, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
    Unmount, SD_VARLINK_DEFINE_INPUT(parentFileDescriptor, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
    SD_VARLINK_DEFINE_INPUT(lazy, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_ERROR(MalformedRequest, DEFUSED_ERRNO_FIELD);
static SD_VARLINK_DEFINE_ERROR(BadMountOption);
static SD_VARLINK_DEFINE_ERROR(NotAllowed);
static SD_VARLINK_DEFINE_ERROR(NotAFuseMount);
static SD_VARLINK_DEFINE_ERROR(MountFailed, DEFUSED_ERRNO_FIELD);
static SD_VARLINK_DEFINE_ERROR(UnmountFailed, DEFUSED_ERRNO_FIELD);

SD_VARLINK_DEFINE_INTERFACE(website_soss_defused, DEFUSED_INTERFACE,
                            &vl_method_Mount, &vl_method_Unmount,
                            &vl_error_MalformedRequest,
                            &vl_error_BadMountOption, &vl_error_NotAllowed,
                            &vl_error_NotAFuseMount, &vl_error_MountFailed,
                            &vl_error_UnmountFailed);

#pragma GCC diagnostic pop

#define U32(name, type, field)                                                 \
    {name, SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,                  \
     offsetof(struct type, field), SD_JSON_MANDATORY}
#define STR(name, type, field)                                                 \
    {name, SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,              \
     offsetof(struct type, field), SD_JSON_MANDATORY | SD_JSON_STRICT}

const sd_json_dispatch_field defused_mount_fields[] = {
    U32("fuseFileDescriptor", defused_mount_req, fuse_fd),
    U32("mountpointFileDescriptor", defused_mount_req, mnt_fd),
    U32("mountFlags", defused_mount_req, mount_flags),
    U32("maxRead", defused_mount_req, max_read),
    U32("blockSize", defused_mount_req, blksize),
    STR("fsName", defused_mount_req, fsname),
    STR("subtype", defused_mount_req, subtype),
    {},
};

const sd_json_dispatch_field defused_umount_fields[] = {
    U32("parentFileDescriptor", defused_umount_req, parent_fd),
    STR("name", defused_umount_req, name),
    {"lazy", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,
     offsetof(struct defused_umount_req, lazy), SD_JSON_MANDATORY},
    {},
};

/* Fills in *err from an sd_varlink_call() result; a NULL error_id is
 * success. */
static int error_from_reply(const char *error_id, sd_json_variant *reply,
                            struct defused_error *err) {
    int32_t sys_errno = 0;
    static const sd_json_dispatch_field fields[] = {
        {"errno", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int32, 0, 0},
        {},
    };
    if (error_id != NULL) {
        int ret = sd_json_dispatch(reply, fields, SD_JSON_ALLOW_EXTENSIONS,
                                   &sys_errno);
        if (ret < 0)
            return ret;
    }
    defused_error_set(err, error_id, sys_errno, NULL);
    return 0;
}

int defused_call_mount(sd_varlink *link, const struct defused_mount_req *req,
                       struct defused_error *err) {
    /* reply is borrowed from the link, valid until its next call. */
    sd_json_variant *reply = NULL;
    const char *error_id = NULL;
    int ret = sd_varlink_callbo(
        link, DEFUSED_METHOD_MOUNT, &reply, &error_id,
        SD_JSON_BUILD_PAIR_UNSIGNED("fuseFileDescriptor", req->fuse_fd),
        SD_JSON_BUILD_PAIR_UNSIGNED("mountpointFileDescriptor", req->mnt_fd),
        SD_JSON_BUILD_PAIR_UNSIGNED("mountFlags", req->mount_flags),
        SD_JSON_BUILD_PAIR_UNSIGNED("maxRead", req->max_read),
        SD_JSON_BUILD_PAIR_UNSIGNED("blockSize", req->blksize),
        SD_JSON_BUILD_PAIR_STRING("fsName", req->fsname ? req->fsname : ""),
        SD_JSON_BUILD_PAIR_STRING("subtype", req->subtype ? req->subtype : ""));
    return ret < 0 ? ret : error_from_reply(error_id, reply, err);
}

int defused_call_umount(sd_varlink *link, const struct defused_umount_req *req,
                        struct defused_error *err) {
    sd_json_variant *reply = NULL;
    const char *error_id = NULL;
    int ret = sd_varlink_callbo(
        link, DEFUSED_METHOD_UNMOUNT, &reply, &error_id,
        SD_JSON_BUILD_PAIR_UNSIGNED("parentFileDescriptor", req->parent_fd),
        SD_JSON_BUILD_PAIR_STRING("name", req->name),
        SD_JSON_BUILD_PAIR_BOOLEAN("lazy", req->lazy));
    return ret < 0 ? ret : error_from_reply(error_id, reply, err);
}
