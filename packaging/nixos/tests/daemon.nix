# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

let
  inherit (common) package;
in
common.mkTest {
  name = "daemon";

  # Deliberately not common.baseNode: the whole point of --daemon is running
  # without systemd Accept=yes socket activation, so the unit here is a plain,
  # always-running service that execs `defused --daemon` directly.
  # RuntimeDirectory= is still required: --daemon does not create /run/defused
  # itself, it just binds a socket inside a directory that must already exist.
  nodes.machine =
    { ... }:
    {
      boot.kernelPackages = common.kernelPackages;
      boot.kernelModules = [ "fuse" ];

      environment.systemPackages = [ package ];

      systemd.services.defused = {
        description = "defused FUSE mount service (fork-daemon mode)";
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          ExecStart = "${package}/lib/defused/defused --daemon";
          RuntimeDirectory = "defused";
        };
      };

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  script = ''
    boot(machine, socket=False)
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
    # bind() and chmod() are separate syscalls in listen_socket(),
    # so wait_for_file above can observe the socket a moment before its mode
    # is updated.
    machine.wait_until_succeeds(
        "stat -c '%a' /run/defused/defused.sock | grep -qx 666"
    )

    machine.succeed("test -e /dev/fuse")
    mkmnt(machine, "/home/alice/daemon-mnt-a", "/home/alice/daemon-mnt-b")

    mount(
        machine,
        "/home/alice/daemon-mnt-a",
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
        "/home/alice/daemon-mnt-b",
        "fsname=daemonfs,subtype=daemon",
        " - fuse.daemon daemonfs ",
        "rw",
        "nosuid",
        "nodev",
        "user_id=",
        "group_id=",
    )

    machine.succeed("systemctl is-active defused.service")
    machine.succeed("journalctl -u defused.service --no-pager | grep -F defused")
  '';
}
