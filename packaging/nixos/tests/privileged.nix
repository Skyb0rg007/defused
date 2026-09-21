# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ common, ... }:

let
  inherit (common) package;
in
common.mkTest {
  name = "privileged";

  # Deliberately not common.baseNode, and not services.defused.enable: a
  # caller that is root or holds CAP_SYS_ADMIN gets a `defused --child`
  # spawned by fusermount3 and never talks to the service, so neither the
  # socket unit nor the service exist on this machine at all.
  nodes.machine =
    { ... }:
    {
      boot.kernelPackages = common.kernelPackages;
      boot.kernelModules = [ "fuse" ];

      environment.systemPackages = [ package ];

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  script = ''
    boot(machine, socket=False)

    machine.fail("test -e /run/defused/defused.sock")
    machine.succeed("test -x ${package}/lib/defused/defused")

    with subtest("root mounts and unmounts without the service"):
        machine.succeed("install -d /root/mnt")
        mount(
            machine, "/root/mnt", "__empty__",
            " - fuse fuse ", "rw", "nosuid", "nodev", "user_id=0", "group_id=0",
            run="",
        )
        mount_unmount(machine, "/root/mnt", run="")

    with subtest("privileged options need no service policy"):
        mount(machine, "/root/mnt", "allow_other", " - fuse fuse ", "allow_other", run="")

    with subtest("suid, dev and blkdev work like libfuse's root path"):
        mount(machine, "/root/mnt", "suid", " - fuse fuse ", "rw", "!nosuid", run="")
        mount(machine, "/root/mnt", "dev", " - fuse fuse ", "rw", "!nodev", run="")
        machine.succeed("truncate -s 1M /root/blk.img")
        dev = machine.succeed("losetup -f --show /root/blk.img").strip()
        mount(machine, "/root/mnt", f"blkdev,fsname={dev}", f" - fuseblk {dev} ", "rw", run="")
        machine.succeed(f"losetup -d {dev}")

    with subtest("the mountpoint need not be owned by the caller"):
        mkmnt(machine, "/home/alice/mnt")
        mount(machine, "/home/alice/mnt", "fsname=alicefs", " - fuse alicefs ", "user_id=0", run="")

    with subtest("the mountpoint's filesystem type is not restricted"):
        # cgroup2 is not in the allowlist the service applies to
        # unprivileged callers (check_nonroot_fstype() in util.c).
        machine.succeed("mkdir /sys/fs/cgroup/defused-test")
        mount(machine, "/sys/fs/cgroup/defused-test", "__empty__", " - fuse fuse ", run="")
        machine.succeed("rmdir /sys/fs/cgroup/defused-test")

    with subtest("unmounting a non-mount is still refused"):
        status, output = machine.execute(
            "${package}/bin/fusermount3 -u /root/mnt 2>&1"
        )
        assert status != 0, "unmounting a plain directory unexpectedly succeeded"
        assert "is not a FUSE mount" in output, output

    with subtest("CAP_SYS_ADMIN without uid 0 takes the same path"):
        uid = machine.succeed("id -u alice").strip()
        mkmnt(machine, "/home/alice/mnt-cap")
        mount(
            machine, "/home/alice/mnt-cap", "__empty__",
            " - fuse fuse ", f"user_id={uid}", "group_id=",
            run="setpriv --reuid=alice --regid=users --init-groups "
                "--inh-caps=+sys_admin --ambient-caps=+sys_admin --",
        )

    with subtest("no service ever ran"):
        machine.fail("journalctl --no-pager -o cat | grep -F 'defused@'")
  '';
}
