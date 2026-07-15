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
  name = "defused-mount-options";

  nodes.machine =
    { ... }:
    {
      imports = [ common.baseNode ];

      services.defused.extraArgs = [ "--user-allow-other" ];
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.socket")
    machine.succeed("test -e /dev/fuse")
    machine.succeed("install -d -o alice -g users /home/alice/default-mnt")
    machine.succeed("install -d -o alice -g users /home/alice/readonly-mnt")
    machine.succeed("install -d -o alice -g users /home/alice/options-mnt")

    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-mount /home/alice/default-mnt __empty__ "
        "' - fuse fuse ' rw nosuid nodev user_id= group_id="
    )
    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-mount /home/alice/readonly-mnt "
        "'ro,fsname=rofs,subtype=ro' "
        "' - fuse.ro rofs ' ro"
    )
    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-mount /home/alice/options-mnt "
        "'noexec,dev,noatime,nodiratime,nosymfollow,"
        "allow_other,default_permissions,fsname=optsfs,subtype=opts,"
        "max_read=4096' "
        "' - fuse.opts optsfs ' noexec noatime nodiratime "
        "nosymfollow allow_other default_permissions"
    )
  '';
}
