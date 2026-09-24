# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""A regular file is a valid mountpoint, not just a directory."""

from harness import boot, mount, succeed


def run():
    boot()
    succeed("install -o alice -g alice -m 0600 /dev/null /home/alice/file-mnt")

    mount(
        "/home/alice/file-mnt",
        "fsname=filefs,subtype=file",
        " /home/alice/file-mnt ",
        " - fuse.file filefs ",
    )
