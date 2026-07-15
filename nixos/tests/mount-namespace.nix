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
  name = "defused-mount-namespace";

  nodes.machine = common.baseNode;

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.socket")
    machine.succeed("test -e /dev/fuse")
    machine.succeed("install -d -o alice -g users /home/alice/ns-mnt")
    machine.succeed("rm -f /tmp/defused-ready /tmp/defused-release")

    machine.succeed(
        "timeout 60s unshare --mount --propagation private --fork "
        "runuser -u alice -- ${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "hold-mount /home/alice/ns-mnt fsname=nsfs,subtype=ns "
        "/tmp/defused-ready /tmp/defused-release ' - fuse.ns nsfs ' &"
    )
    machine.wait_until_succeeds("test -s /tmp/defused-ready")

    machine.succeed("grep -F ' - fuse.ns nsfs ' /tmp/defused-ready")
    machine.fail("grep -F ' /home/alice/ns-mnt ' /proc/self/mountinfo")

    machine.succeed("touch /tmp/defused-release")
    machine.wait_until_succeeds("! grep -F ' /home/alice/ns-mnt ' /proc/self/mountinfo")
  '';
}
