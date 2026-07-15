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
  name = "defused-file-mountpoint";

  nodes.machine = common.baseNode;

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.socket")
    machine.succeed("test -e /dev/fuse")
    machine.succeed("install -o alice -g users -m 0600 /dev/null /home/alice/file-mnt")

    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-mount /home/alice/file-mnt "
        "'fsname=filefs,subtype=file' "
        "' /home/alice/file-mnt ' ' - fuse.file filefs '"
    )
  '';
}
