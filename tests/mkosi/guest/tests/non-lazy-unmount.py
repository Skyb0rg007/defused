# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""libfuse's fuse_kern_unmount() always runs fusermount3 with -z, so a plain
`fusermount3 -u` is the only path that reaches a non-lazy umount2()."""

from harness import boot, fail, mkmnt, mount_unmount


def run():
    boot()
    mkmnt("/home/alice/unmount-mnt")

    mount_unmount("/home/alice/unmount-mnt", "fsname=umntfs,subtype=umnt")
    fail("grep -F ' /home/alice/unmount-mnt ' /proc/self/mountinfo")
