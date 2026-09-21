# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

common.mkTest {
  name = "mount-namespace";

  script = ''
    boot(machine)
    machine.succeed("test -e /dev/fuse")
    mkmnt(machine, "/home/alice/ns-mnt")
    machine.succeed("rm -f /tmp/defused-ready /tmp/defused-release")

    hold(
        machine,
        "/home/alice/ns-mnt",
        "fsname=nsfs,subtype=ns",
        " - fuse.ns nsfs ",
        run="unshare --mount --propagation private --fork runuser -u alice --",
        timeout=60,
        suffix=" &",
    )
    machine.wait_until_succeeds("test -s /tmp/defused-ready")

    # The mount is real inside the namespace, and invisible outside it.
    machine.succeed("grep -F ' - fuse.ns nsfs ' /tmp/defused-ready")
    machine.fail("grep -F ' /home/alice/ns-mnt ' /proc/self/mountinfo")

    machine.succeed("touch /tmp/defused-release")
    wait_unmounted(machine, "/home/alice/ns-mnt")
  '';
}
