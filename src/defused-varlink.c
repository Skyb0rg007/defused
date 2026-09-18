/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "defused_proto.h"

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

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

SD_VARLINK_DEFINE_INTERFACE(website_soss_defused, DEFUSED_VARLINK_INTERFACE,
                            &vl_method_Mount, &vl_method_Unmount,
                            &vl_error_MalformedRequest,
                            &vl_error_BadMountOption, &vl_error_NotAllowed,
                            &vl_error_NotAFuseMount, &vl_error_MountFailed,
                            &vl_error_UnmountFailed);

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

int defused_error_from_reply(const char *error_id, sd_json_variant *parameters,
                             struct defused_error *err) {
    int32_t sys_errno = 0;
    static const sd_json_dispatch_field dispatch_table[] = {
        {"errno", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int32, 0, 0},
        {},
    };

    if (error_id != NULL) {
        int ret = sd_json_dispatch(parameters, dispatch_table,
                                   SD_JSON_ALLOW_EXTENSIONS, &sys_errno);
        if (ret < 0)
            return ret;
    }
    defused_error_set(err, error_id, sys_errno);
    return 0;
}
