# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
}:

let
  package = self.packages.${system}.defused;
in
pkgs.testers.nixosTest {
  name = "defused";

  nodes.machine =
    { ... }:
    {
      imports = [ self.nixosModules.defused ];

      services.defused = {
        enable = true;
        package = package;
        extraArgs = [ "--mount-max=77" ];
      };

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("defused.socket")

    machine.succeed("test -S /run/defused/defused.sock")
    machine.succeed("test -x ${package}/lib/defused/defused")
    machine.succeed("test -x ${package}/bin/fusermount3")

    machine.succeed(
        "grep '^ExecStart=' /etc/systemd/system/defused@.service | "
        "grep -F '${package}/lib/defused/defused'"
    )
    machine.succeed(
        "grep '^ExecStart=' /etc/systemd/system/defused@.service | "
        "grep -F -- '--mount-max=77'"
    )

    machine.succeed(
        "su - alice -c '${package}/bin/fusermount3 -V' | "
        "grep -F 'fusermount3 version:' | grep -F '(defused)'"
    )

    machine.succeed("install -d -o alice -g users /home/alice/mnt")
    status, output = machine.execute(
        "su - alice -c '${package}/bin/fusermount3 -u /home/alice/mnt' 2>&1"
    )
    assert status != 0, "unmounting a non-FUSE directory unexpectedly succeeded"
    assert "is not a FUSE mount" in output, output

    machine.succeed("journalctl -u 'defused@*' --no-pager | grep -F defused")
  '';
}
