# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""--allow-groups, --max-mounts and --allow-other.

The NixOS suite declares two machines for this; Accept=yes starts an
instance per connection, so here the drop-in is rewritten between subtests
and the next connection picks the new policy up.
"""

from harness import (
    boot,
    configure,
    hold,
    mkmnt,
    mount,
    mount_unmount,
    refuse,
    release,
    subtest,
    succeed,
)


def run():
    # Issue #59's policy; the limit is 1 so the test can reach it.
    configure(max_mounts=1, allow_groups=["fusers"])
    boot()

    with subtest("the drop-in carries the policy options"):
        succeed("systemctl cat defused@.service | grep -Fx 'Environment=DEFUSED_MAX_MOUNTS=1'")
        succeed(
            "systemctl cat defused@.service | grep -Fx 'Environment=DEFUSED_ALLOW_GROUPS=fusers'"
        )

    with subtest("a member of --allow-groups mounts and unmounts"):
        mkmnt("/home/alice/mnt-a", "/home/alice/mnt-b")
        mount_unmount("/home/alice/mnt-a")

    with subtest("a user outside --allow-groups is refused"):
        mkmnt("/home/bob/mnt", user="bob")
        refuse("/home/bob/mnt", "ro", run="runuser -u bob --")

    with subtest("allow_other is refused unless --allow-other grants it"):
        refuse("/home/alice/mnt-a", "allow_other")

    with subtest("--max-mounts refuses a mount past the limit"):
        hold("/home/alice/mnt-a", "__empty__", " - fuse fuse ")
        refuse("/home/alice/mnt-b", "ro")

    with subtest("the limit counts live mounts: released, the next one goes through"):
        release("/home/alice/mnt-a")
        mount("/home/alice/mnt-b", "__empty__", " - fuse fuse ")

    with subtest("--allow-other grants allow_other, to every user"):
        configure(allow_other=True)
        succeed(
            "systemctl cat defused@.service | grep -Fx "
            "'Environment=DEFUSED_EXTRA_ARGS=--allow-other'"
        )
        mkmnt("/home/alice/mnt-other")
        mount("/home/alice/mnt-other", "allow_other", " - fuse fuse ", "allow_other")
        mkmnt("/home/bob/mnt-other", user="bob")
        mount(
            "/home/bob/mnt-other",
            "allow_other",
            " - fuse fuse ",
            "allow_other",
            run="runuser -u bob --",
        )
