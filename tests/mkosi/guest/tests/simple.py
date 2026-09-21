# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""The installed layout, the socket unit, and a refused unmount."""

from harness import (
    DEFUSED,
    FUSERMOUNT3,
    SOCKET,
    boot,
    execute,
    fail,
    mkmnt,
    subtest,
    succeed,
)


def run():
    boot()

    with subtest("meson install put everything where an FHS distro expects it"):
        succeed(f"test -S {SOCKET}")
        succeed(f"test -x {DEFUSED}")
        succeed(f"test -x {FUSERMOUNT3}")
        succeed("test -f /usr/lib/systemd/system/defused.socket")
        succeed("test -f /usr/lib/systemd/system/defused@.service")
        succeed("test -f /etc/apparmor.d/defused")

    with subtest("the shipped unit runs the installed binary"):
        succeed(f"systemctl cat defused@.service | grep '^ExecStart=' | grep -F '{DEFUSED}'")
        succeed("systemctl cat defused.socket | grep -Fx 'Accept=yes'")
        succeed(f"systemctl cat defused.socket | grep -Fx 'ListenSequentialPacket={SOCKET}'")

    with subtest("fusermount3 -V reports itself as defused's"):
        succeed(
            f"runuser -u alice -- {FUSERMOUNT3} -V | "
            "grep -F 'fusermount3 version:' | grep -F '(defused)'"
        )

    with subtest("unmounting a directory that is not a FUSE mount is refused"):
        mkmnt("/home/alice/mnt")
        status, output = execute(f"runuser -u alice -- {FUSERMOUNT3} -u /home/alice/mnt")
        assert status != 0, "unmounting a non-FUSE directory unexpectedly succeeded"
        assert "is not a FUSE mount" in output, output

    with subtest("the service instance that refused it logged to the journal"):
        succeed("journalctl -u 'defused@*' --no-pager | grep -F defused")
        # Nothing ran as root: the service is the only privileged component.
        fail(f"test -u {FUSERMOUNT3}")
