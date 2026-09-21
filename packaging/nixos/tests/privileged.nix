# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
  kernelPackages,
}:

let
  common = import ./common.nix {
    inherit
      self
      pkgs
      system
      kernelPackages
      ;
  };
  inherit (common) package mountHelper;
in
pkgs.testers.nixosTest {
  name = "defused-privileged-${kernelPackages.kernel.version}";

  # Deliberately not common.baseNode, and not services.defused.enable: a
  # caller that is root or holds CAP_SYS_ADMIN gets a `defused --child`
  # spawned by fusermount3 and never talks to the service, so neither the
  # socket unit nor the service exist on this machine at all.
  nodes.machine =
    { ... }:
    {
      boot.kernelPackages = kernelPackages;
      boot.kernelModules = [ "fuse" ];

      environment.systemPackages = [ package ];

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")

    machine.fail("test -e /run/defused/defused.sock")
    machine.succeed("test -x ${package}/lib/defused/defused")

    helper = "timeout 45s ${pkgs.python3}/bin/python3 ${mountHelper} "

    with subtest("root mounts and unmounts without the service"):
        machine.succeed("install -d /root/mnt")
        machine.succeed(
            helper + "assert-mount /root/mnt __empty__ "
            "' - fuse fuse ' rw nosuid nodev user_id=0 group_id=0"
        )
        machine.succeed(helper + "assert-unmount /root/mnt __empty__")

    with subtest("privileged options need no service policy"):
        machine.succeed(
            helper + "assert-mount /root/mnt allow_other "
            "' - fuse fuse ' allow_other"
        )

    with subtest("suid, dev and blkdev work like libfuse's root path"):
        machine.succeed(
            helper + "assert-mount /root/mnt suid ' - fuse fuse ' rw '!nosuid'"
        )
        machine.succeed(
            helper + "assert-mount /root/mnt dev ' - fuse fuse ' rw '!nodev'"
        )
        machine.succeed("truncate -s 1M /root/blk.img")
        dev = machine.succeed("losetup -f --show /root/blk.img").strip()
        machine.succeed(
            helper + f"assert-mount /root/mnt blkdev,fsname={dev} "
            f"' - fuseblk {dev} ' rw"
        )
        machine.succeed(f"losetup -d {dev}")

    with subtest("the mountpoint need not be owned by the caller"):
        machine.succeed("install -d -o alice -g users /home/alice/mnt")
        machine.succeed(
            helper + "assert-mount /home/alice/mnt fsname=alicefs "
            "' - fuse alicefs ' user_id=0"
        )

    with subtest("the mountpoint's filesystem type is not restricted"):
        # cgroup2 is not in the allowlist the service applies to
        # unprivileged callers (check_nonroot_fstype() in util.c).
        machine.succeed("mkdir /sys/fs/cgroup/defused-test")
        machine.succeed(
            helper + "assert-mount /sys/fs/cgroup/defused-test __empty__ "
            "' - fuse fuse '"
        )
        machine.succeed("rmdir /sys/fs/cgroup/defused-test")

    with subtest("unmounting a non-mount is still refused"):
        status, output = machine.execute(
            "${package}/bin/fusermount3 -u /root/mnt 2>&1"
        )
        assert status != 0, "unmounting a plain directory unexpectedly succeeded"
        assert "is not a FUSE mount" in output, output

    with subtest("CAP_SYS_ADMIN without uid 0 takes the same path"):
        uid = machine.succeed("id -u alice").strip()
        machine.succeed("install -d -o alice -g users /home/alice/mnt-cap")
        machine.succeed(
            "timeout 45s setpriv --reuid=alice --regid=users --init-groups "
            "--inh-caps=+sys_admin --ambient-caps=+sys_admin -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-mount /home/alice/mnt-cap __empty__ "
            f"' - fuse fuse ' user_id={uid} group_id="
        )

    with subtest("no service ever ran"):
        machine.fail("journalctl --no-pager -o cat | grep -F 'defused@'")
  '';
}
