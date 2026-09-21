# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""`defused --daemon`: the service without systemd socket activation.

It binds and listens on the socket itself and forks a child per connection,
which is how defused runs on a system without systemd -- so this test takes
the socket unit out of the picture entirely.
"""

from harness import (
    DEFUSED,
    SOCKET,
    boot,
    fail,
    mkmnt,
    mount,
    subtest,
    succeed,
    wait_until_succeeds,
)


def run():
    boot(socket=False)

    with subtest("no socket unit is involved"):
        succeed("systemctl stop defused.socket")
        succeed("systemctl mask defused.socket")
        fail(f"test -e {SOCKET}")

    with subtest("the daemon creates the socket itself"):
        # --daemon does not create /run/defused, it binds inside it, so the
        # transient unit carries the same RuntimeDirectory= the socket unit
        # would have set up.
        succeed(
            "systemd-run --unit=defused-daemon --description='defused --daemon' "
            "--property=RuntimeDirectory=defused "
            f"{DEFUSED} --daemon"
        )
        wait_until_succeeds("systemctl is-active defused-daemon.service")
        wait_until_succeeds(f"test -S {SOCKET}")

    with subtest("it binds the socket 0666, unlike Accept=yes (issue #3)"):
        # wait_until_succeeds rather than succeed: bind() and chmod() are
        # separate syscalls, so the socket can appear a moment before its
        # mode is updated.
        wait_until_succeeds(f"stat -c '%a' {SOCKET} | grep -qx 666")

    with subtest("a forked child mounts like the socket-activated service"):
        mkmnt("/home/alice/daemon-mnt-a", "/home/alice/daemon-mnt-b")
        mount(
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
            "/home/alice/daemon-mnt-b",
            "fsname=daemonfs,subtype=daemon",
            " - fuse.daemon daemonfs ",
            "rw",
            "nosuid",
            "nodev",
            "user_id=",
            "group_id=",
        )

    with subtest("the daemon is still running, and logged"):
        succeed("systemctl is-active defused-daemon.service")
        succeed("journalctl -u defused-daemon.service --no-pager | grep -F defused")
