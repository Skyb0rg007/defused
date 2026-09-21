# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""A caller that is root or holds CAP_SYS_ADMIN never talks to the service.

fusermount3 performs the request itself instead, with the caller's own
privileges and none of the service's policy. The socket is masked here so
nothing could fall back to it unnoticed.
"""

from harness import (
    FUSERMOUNT3,
    SOCKET,
    boot,
    execute,
    fail,
    mkmnt,
    mount,
    mount_unmount,
    subtest,
    succeed,
)


def run():
    # Stopped before anything connects, so no defused@ instance can have run,
    # and masked so nothing can start one. Stop first: systemctl stop on a
    # masked unit is a no-op and would leave the socket listening.
    succeed("systemctl stop defused.socket")
    succeed("systemctl mask defused.socket")
    boot(socket=False)

    fail(f"test -e {SOCKET}")
    # Nothing below execs the service binary: the privileged path is
    # fusermount3 alone.
    succeed(f"test -x {FUSERMOUNT3}")

    with subtest("root mounts and unmounts without the service"):
        succeed("install -d /root/mnt")
        mount(
            "/root/mnt",
            "__empty__",
            " - fuse fuse ",
            "rw",
            "nosuid",
            "nodev",
            "user_id=0",
            "group_id=0",
            run="",
        )
        mount_unmount("/root/mnt", run="")

    with subtest("privileged options need no service policy"):
        mount("/root/mnt", "allow_other", " - fuse fuse ", "allow_other", run="")

    with subtest("suid, dev and blkdev work like libfuse's root path"):
        mount("/root/mnt", "suid", " - fuse fuse ", "rw", "!nosuid", run="")
        mount("/root/mnt", "dev", " - fuse fuse ", "rw", "!nodev", run="")
        succeed("truncate -s 1M /root/blk.img")
        dev = succeed("losetup -f --show /root/blk.img").strip()
        mount("/root/mnt", f"blkdev,fsname={dev}", f" - fuseblk {dev} ", "rw", run="")
        succeed(f"losetup -d {dev}")

    with subtest("the mountpoint need not be owned by the caller"):
        mkmnt("/home/alice/mnt")
        mount("/home/alice/mnt", "fsname=alicefs", " - fuse alicefs ", "user_id=0", run="")

    with subtest("the mountpoint's filesystem type is not restricted"):
        # cgroup2 is not in the allowlist the service applies to
        # unprivileged callers.
        succeed("mkdir /sys/fs/cgroup/defused-test")
        mount("/sys/fs/cgroup/defused-test", "__empty__", " - fuse fuse ", run="")
        succeed("rmdir /sys/fs/cgroup/defused-test")

    with subtest("unmounting a non-mount is still refused"):
        status, output = execute(f"{FUSERMOUNT3} -u /root/mnt")
        assert status != 0, "unmounting a plain directory unexpectedly succeeded"
        assert "is not a FUSE mount" in output, output

    with subtest("CAP_SYS_ADMIN without uid 0 takes the same path"):
        uid = succeed("id -u alice").strip()
        mkmnt("/home/alice/mnt-cap")
        mount(
            "/home/alice/mnt-cap",
            "__empty__",
            " - fuse fuse ",
            f"user_id={uid}",
            "group_id=",
            run="setpriv --reuid=alice --regid=alice --init-groups "
            "--inh-caps=+sys_admin --ambient-caps=+sys_admin --",
        )

    with subtest("no service instance ever ran"):
        # By unit, not by message: this test's own output is in the journal
        # too, and it mentions defused@ several times.
        fail("journalctl --no-pager -u 'defused@*' | grep -F defused")
