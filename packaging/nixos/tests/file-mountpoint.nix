# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

common.mkTest {
  name = "file-mountpoint";

  script = ''
    boot(machine)
    machine.succeed("test -e /dev/fuse")
    machine.succeed("install -o alice -g users -m 0600 /dev/null /home/alice/file-mnt")

    mount(
        machine,
        "/home/alice/file-mnt",
        "fsname=filefs,subtype=file",
        " /home/alice/file-mnt ",
        " - fuse.file filefs ",
    )
  '';
}
