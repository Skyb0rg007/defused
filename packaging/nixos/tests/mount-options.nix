# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

common.mkTest {
  name = "mount-options";

  script = ''
    boot(machine)
    machine.succeed("test -e /dev/fuse")
    mkmnt(
        machine,
        "/home/alice/default-mnt",
        "/home/alice/readonly-mnt",
        "/home/alice/options-mnt",
        "/home/alice/unsafe-mnt",
    )

    mount(
        machine,
        "/home/alice/default-mnt",
        "__empty__",
        " - fuse fuse ",
        "rw",
        "nosuid",
        "nodev",
        "user_id=",
        "group_id=",
    )
    mount(
        machine,
        "/home/alice/readonly-mnt",
        "ro,fsname=rofs,subtype=ro",
        " - fuse.ro rofs ",
        "ro",
    )
    mount(
        machine,
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
    # suid and dev are the two options libfuse marks unsafe: an unprivileged
    # caller gets a warning and the flag is dropped, so the mount still has
    # nosuid and nodev.
    mount(machine, "/home/alice/unsafe-mnt", "suid,dev", " - fuse fuse ", "nosuid", "nodev")
  '';
}
