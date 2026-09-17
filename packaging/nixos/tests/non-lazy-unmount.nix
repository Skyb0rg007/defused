# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
}:

let
  common = import ./common.nix { inherit self pkgs system; };
in
pkgs.testers.nixosTest {
  name = "defused-non-lazy-unmount";

  nodes.machine = common.baseNode;

  # libfuse's fuse_kern_unmount() always runs fusermount3 with -z, so a plain
  # `fusermount3 -u` is the only path that reaches a non-lazy umount2().
  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.socket")
    machine.succeed("test -e /dev/fuse")
    machine.succeed("install -d -o alice -g users /home/alice/unmount-mnt")

    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-unmount /home/alice/unmount-mnt fsname=umntfs,subtype=umnt"
    )
    machine.fail("grep -F ' /home/alice/unmount-mnt ' /proc/self/mountinfo")
  '';
}
