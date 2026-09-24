# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, pkgs, ... }:

let
  # statmount() reports a mount's subtype from Linux 6.13; before that only
  # "fuse" is compared, and a dead fuse.second mount looks like fuse.first.
  subtypes = pkgs.lib.versionAtLeast common.kernelVersion "6.13";
in
common.mkTest {
  name = "auto-unmount";

  # Like libfuse's should_auto_unmount(): once the server is gone, only a
  # mount still of the type fusermount3 made, and whose server is gone too,
  # is unmounted.
  script = ''
    boot(machine)

    mkmnt(machine, "/home/alice/mnt")
    machine.succeed("install -d /root/mnt")

    for who, mnt, run in [
        ("alice", "/home/alice/mnt", "runuser -u alice --"),
        ("root", "/root/mnt", ""),
    ]:
        with subtest(f"{who}: the mount goes when its server does"):
            helper(machine, "auto-unmount", mnt, "none", run=run)

        if ${if subtypes then "True" else "False"}:
            with subtest(f"{who}: a mount of another subtype is left alone"):
                helper(machine, "auto-unmount", mnt, "other-type", run=run)

        with subtest(f"{who}: a mount whose server still answers is left alone"):
            helper(machine, "auto-unmount", mnt, "live-server", run=run)
  '';
}
