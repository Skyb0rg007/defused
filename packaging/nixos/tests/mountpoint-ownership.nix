# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

common.mkTest {
  name = "mountpoint-ownership";

  script = ''
    boot(machine)

    machine.succeed("install -d -m 0777 -o root -g root /srv/root-owned-mnt")
    refuse(
        machine,
        "/srv/root-owned-mnt",
        "fsname=denied",
        run="runuser -u alice -- env DEFUSED_FUSE_DEVICE=/dev/null",
    )

    machine.succeed(
        "journalctl -u 'defused@*' --no-pager | "
        "grep -F 'website.soss.defused.NotAllowed'"
    )
  '';
}
