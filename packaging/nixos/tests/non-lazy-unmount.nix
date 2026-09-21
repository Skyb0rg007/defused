# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

# libfuse's fuse_kern_unmount() always runs fusermount3 with -z, so a plain
# `fusermount3 -u` is the only path that reaches a non-lazy umount2().
common.mkTest {
  name = "non-lazy-unmount";

  script = ''
    boot(machine)
    machine.succeed("test -e /dev/fuse")
    mkmnt(machine, "/home/alice/unmount-mnt")

    mount_unmount(machine, "/home/alice/unmount-mnt", "fsname=umntfs,subtype=umnt")
    machine.fail("grep -F ' /home/alice/unmount-mnt ' /proc/self/mountinfo")
  '';
}
