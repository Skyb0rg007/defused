# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""A mountpoint the caller does not own is refused, world-writable or not."""

from harness import boot, refuse, succeed


def run():
    boot()

    succeed("install -d -m 0777 -o root -g root /srv/root-owned-mnt")
    # DEFUSED_FUSE_DEVICE=/dev/null: the request never gets far enough for
    # the /dev/fuse fd to matter, and this proves the service refuses on the
    # mountpoint alone.
    refuse(
        "/srv/root-owned-mnt",
        "fsname=denied",
        run="runuser -u alice -- env DEFUSED_FUSE_DEVICE=/dev/null",
    )

    succeed("journalctl -u 'defused@*' --no-pager | grep -F ': not allowed ('")
