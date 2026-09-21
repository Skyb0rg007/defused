# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

common.mkTest {
  name = "simple";

  script = ''
    boot(machine)

    machine.succeed("test -S /run/defused/defused.sock")
    machine.succeed("test -x ${common.package}/lib/defused/defused")
    machine.succeed("test -x ${common.package}/bin/fusermount3")

    machine.succeed(
        "grep '^ExecStart=' /etc/systemd/system/defused@.service | "
        "grep -F '${common.package}/lib/defused/defused'"
    )

    machine.succeed(
        "su - alice -c '${common.package}/bin/fusermount3 -V' | "
        "grep -F 'fusermount3 version:' | grep -F '(defused)'"
    )

    mkmnt(machine, "/home/alice/mnt")
    status, output = machine.execute(
        "su - alice -c '${common.package}/bin/fusermount3 -u /home/alice/mnt' 2>&1"
    )
    assert status != 0, "unmounting a non-FUSE directory unexpectedly succeeded"
    assert "is not a FUSE mount" in output, output

    machine.succeed("journalctl -u 'defused@*' --no-pager | grep -F defused")
  '';
}
