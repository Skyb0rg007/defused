# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""The mount lands in the caller's mount namespace, not the service's."""

from harness import boot, fail, hold, mkmnt, release


def run():
    boot()
    mkmnt("/home/alice/ns-mnt")

    line = hold(
        "/home/alice/ns-mnt",
        "fsname=nsfs,subtype=ns",
        " - fuse.ns nsfs ",
        run="unshare --mount --propagation private --fork runuser -u alice --",
    )

    # The mount is real inside the namespace, and invisible outside it.
    assert " - fuse.ns nsfs " in line, line
    fail("grep -F ' /home/alice/ns-mnt ' /proc/self/mountinfo")

    release()
    fail("grep -F ' /home/alice/ns-mnt ' /proc/self/mountinfo")
