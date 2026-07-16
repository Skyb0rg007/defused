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

static SD_VARLINK_DEFINE_METHOD(
    Mount, SD_VARLINK_DEFINE_INPUT(fuseFileDescriptor, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(mountpointFileDescriptor, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(mountFlags, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(maxRead, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(blockSize, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(fsName, SD_VARLINK_STRING, 0),
    SD_VARLINK_DEFINE_INPUT(subtype, SD_VARLINK_STRING, 0),
    SD_VARLINK_DEFINE_OUTPUT(status, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_OUTPUT(sysErrno, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
    Unmount, SD_VARLINK_DEFINE_INPUT(parentFileDescriptor, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
    SD_VARLINK_DEFINE_INPUT(lazy, SD_VARLINK_BOOL, 0),
    SD_VARLINK_DEFINE_OUTPUT(status, SD_VARLINK_INT, 0),
    SD_VARLINK_DEFINE_OUTPUT(sysErrno, SD_VARLINK_INT, 0));

SD_VARLINK_DEFINE_INTERFACE(website_soss_defused, DEFUSED_VARLINK_INTERFACE,
                            &vl_method_Mount, &vl_method_Unmount);

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
