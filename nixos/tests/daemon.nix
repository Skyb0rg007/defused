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
  package = common.package;
in
pkgs.testers.nixosTest {
  name = "defused-daemon";

  nodes.machine =
    { ... }:
    {
      boot.kernelModules = [ "fuse" ];

      environment.systemPackages = [ package ];

      systemd.services.defused = {
        description = "defused FUSE mount service";
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          ExecStart = "${package}/lib/defused/defused --daemon --mount-max=77";
          RuntimeDirectory = "defused";
        };
      };

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.service")
    machine.succeed("test -S /run/defused/defused.sock")
    machine.fail("systemctl status defused.socket")
    machine.succeed("test -e /dev/fuse")

    machine.succeed(
        "grep '^ExecStart=' /etc/systemd/system/defused.service | "
        "grep -F '${package}/lib/defused/defused --daemon --mount-max=77'"
    )

    machine.succeed("install -d -o alice -g users /home/alice/daemon-mnt-a")
    machine.succeed("install -d -o alice -g users /home/alice/daemon-mnt-b")

    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-mount /home/alice/daemon-mnt-a __empty__ "
        "' - fuse fuse ' rw nosuid nodev user_id= group_id="
    )
    machine.succeed(
        "timeout 45s runuser -u alice -- "
        "${pkgs.python3}/bin/python3 ${common.mountHelper} "
        "assert-mount /home/alice/daemon-mnt-b "
        "'fsname=daemonfs,subtype=daemon' "
        "' - fuse.daemon daemonfs ' rw nosuid nodev user_id= group_id="
    )

    machine.succeed("systemctl is-active defused.service")
    machine.succeed("journalctl -u defused.service --no-pager | grep -F defused")
  '';
}
