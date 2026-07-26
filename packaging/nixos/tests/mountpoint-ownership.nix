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
  name = "defused-mountpoint-ownership";

  nodes.machine = common.baseNode;

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.socket")

    machine.succeed("install -d -m 0777 -o root -g root /srv/root-owned-mnt")
    machine.succeed(
        "timeout 45s runuser -u alice -- env DEFUSED_FUSE_DEVICE=/dev/null "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "expect-failure /srv/root-owned-mnt fsname=denied "
        "'not allowed by the defused service'"
    )

    machine.succeed(
        "journalctl -u 'defused@*' --no-pager | "
        "grep -F 'DEFUSED_ERR_NOT_ALLOWED'"
    )
  '';
}
