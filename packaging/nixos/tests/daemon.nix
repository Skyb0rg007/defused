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

  # This test deliberately does not use services.defused.enable (see
  # common.nix's baseNode) -- the whole point of --daemon is running without
  # systemd Accept=yes socket activation, so the unit here is a plain,
  # always-running service that execs `defused --daemon` directly. It's also
  # deliberately given no RuntimeDirectory=, to exercise --daemon's own
  # mkdir_parent() logic for creating /run/defused itself.
  nodes.machine =
    { ... }:
    {
      boot.kernelModules = [ "fuse" ];

      environment.systemPackages = [ package ];

      # defused asks polkit whether a client may create a FUSE mount at all
      # -- polkitd has to actually be running for that check to ever
      # succeed rather than fail closed (see nixos/module.nix, which this
      # standalone unit otherwise deliberately bypasses).
      security.polkit.enable = true;

      systemd.services.defused = {
        description = "defused FUSE mount service (fork-daemon mode)";
        wantedBy = [ "multi-user.target" ];
        wants = [ "polkit.service" ];
        after = [ "polkit.service" ];

        serviceConfig = {
          ExecStart = "${package}/lib/defused/defused --daemon";
        };
      };

      # Headless VM tests can't answer an interactive polkit prompt, so
      # unconditionally allow every defused action -- see common.nix's
      # baseNode for the same rule and its rationale.
      security.polkit.extraConfig = ''
        polkit.addRule(function(action, subject) {
          if (action.id.indexOf("website.soss.defused.") == 0) {
            return polkit.Result.YES;
          }
        });
      '';

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.service")
    machine.wait_for_file("/run/defused/defused.sock")

    # No socket unit is involved in --daemon mode.
    machine.fail("systemctl status defused.socket")

    machine.succeed(
        "grep '^ExecStart=' /etc/systemd/system/defused.service | "
        "grep -F '${package}/lib/defused/defused --daemon'"
    )

    # --daemon binds the socket 0666 itself, unlike systemd's Accept=yes
    # (mode 0644) -- see issue #3. wait_until_succeeds rather than succeed:
    # bind() and chmod() are separate syscalls in create_listening_socket(),
    # so wait_for_file above can observe the socket a moment before its mode
    # is updated.
    machine.wait_until_succeeds(
        "stat -c '%a' /run/defused/defused.sock | grep -qx 666"
    )

    machine.succeed("test -e /dev/fuse")
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
