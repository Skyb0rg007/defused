# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""The shipped AppArmor profile: loaded, attached, and sufficient.

The unit's AppArmorProfile=-defused attaches it to every instance, so a
profile that is missing a permission shows up as a mount that fails rather
than as a denial nobody reads.
"""

import json

from harness import (
    DEFUSED,
    SOCKET,
    TESTDIR,
    audit_grep,
    boot,
    fail,
    mkmnt,
    mount,
    subtest,
    succeed,
    wait_until_fails,
    wait_until_succeeds,
)


def run():
    boot()
    succeed("systemctl is-active apparmor.service")

    with subtest("the defused profile is loaded in enforce mode"):
        succeed("grep -Fx 'defused (enforce)' /sys/kernel/security/apparmor/profiles")
        status = json.loads(succeed("aa-status --json"))
        assert status["profiles"].get("defused") == "enforce", status["profiles"].get("defused")
        # Load it again and look for that record: the boot-time one is long
        # out of the kernel ring buffer, which took several hundred profile
        # loads from the distribution's own policy right after it.
        succeed("apparmor_parser --replace --skip-cache /etc/apparmor.d/defused")
        succeed(audit_grep('apparmor="STATUS"', 'operation="profile_replace"', 'name="defused"'))

    with subtest("the profile declares no attachment path"):
        fail(
            "apparmor_parser --preprocess /etc/apparmor.d/defused | "
            "grep -E '^ *profile +defused +[\"/]'"
        )

    with subtest("defused@ instances run confined"):
        # Accept=yes ties one instance to each connection, so holding one
        # open keeps an instance around to inspect. stdio detached, or the
        # harness waits for the holder to exit.
        succeed(
            f"runuser -u alice -- python3 {TESTDIR}/hold-connection.py {SOCKET} "
            ">/dev/null 2>&1 </dev/null &"
        )
        pid = wait_until_succeeds("pgrep -o -x defused").strip()
        succeed(f"grep -F 'defused@' /proc/{pid}/cgroup")
        succeed(f"grep -Fx 'defused (enforce)' /proc/{pid}/attr/apparmor/current")
        # aa-status keys processes by executable, not by profile name.
        processes = json.loads(succeed("aa-status --json"))["processes"]
        entries = [p for p in processes.get(DEFUSED, []) if str(p["pid"]) == pid]
        assert entries, f"{DEFUSED} has no process {pid}: {processes}"
        assert entries[0]["profile"] == "defused", entries
        assert entries[0]["status"] == "enforce", entries
        succeed("pkill -f '[h]old-connection.py'")
        wait_until_fails("pgrep -x defused")

    with subtest("a confined defused@ can mount and lazily unmount"):
        mkmnt("/home/alice/aa-mnt")
        mount(
            "/home/alice/aa-mnt",
            "fsname=aafs,subtype=aa",
            " - fuse.aa aafs ",
            "rw",
            "nosuid",
            "nodev",
            "user_id=",
            "group_id=",
        )

    with subtest("no AppArmor denials for the defused profile"):
        fail(audit_grep('apparmor="DENIED"', 'profile="defused'))

    # Last: it deliberately produces the records the subtest above forbids.
    with subtest("the profile actually mediates"):
        # The profile grants no write anywhere. Without this, "no denials"
        # would pass just as well for a profile that was never consulted.
        fail("aa-exec -p defused -- /usr/bin/touch /tmp/aa-probe")
        fail("test -e /tmp/aa-probe")
        succeed(audit_grep('apparmor="DENIED"', 'profile="defused"', 'name="/tmp/aa-probe"'))
