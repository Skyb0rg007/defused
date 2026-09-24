# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Which mount options reach the kernel, and which are dropped."""

from harness import boot, configure, mkmnt, mount, subtest


def run():
    # The one option the service refuses by default, and this test mounts
    # with it: grant it the way the README documents.
    configure(allow_other=True)
    boot()
    mkmnt(
        "/home/alice/default-mnt",
        "/home/alice/readonly-mnt",
        "/home/alice/options-mnt",
        "/home/alice/unsafe-mnt",
    )

    with subtest("a mount with no options is rw, nosuid, nodev"):
        mount(
            "/home/alice/default-mnt",
            "__empty__",
            " - fuse fuse ",
            "rw",
            "nosuid",
            "nodev",
            "user_id=",
            "group_id=",
        )

    with subtest("ro, fsname and subtype"):
        mount("/home/alice/readonly-mnt", "ro,fsname=rofs,subtype=ro", " - fuse.ro rofs ", "ro")

    with subtest("every other option defused forwards"):
        mount(
            "/home/alice/options-mnt",
            "noexec,noatime,nodiratime,nosymfollow,allow_other,default_permissions,"
            "fsname=optsfs,subtype=opts,max_read=4096",
            " - fuse.opts optsfs ",
            "noexec",
            "noatime",
            "nodiratime",
            "nosymfollow",
            "allow_other",
            "default_permissions",
        )

    with subtest("suid and dev are dropped for an unprivileged caller"):
        # libfuse marks the two unsafe: the caller gets a warning and the
        # flag is dropped, so the mount still has nosuid and nodev.
        mount("/home/alice/unsafe-mnt", "suid,dev", " - fuse fuse ", "nosuid", "nodev")
