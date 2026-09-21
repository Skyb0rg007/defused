# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Real libfuse filesystems, mounted through the helper paths libfuse execs.

`meson install` puts defused's fusermount3 exactly where the distribution's
setuid helper was, so every libfuse program uses it without knowing: this is
the FHS equivalent of the NixOS suite's /run/wrappers/bin takeover. The
mounts run under no_new_privs, where a setuid helper could not work at all.
"""

from harness import (
    FUSERMOUNT,
    FUSERMOUNT3,
    TESTDIR,
    boot,
    fail,
    mkmnt,
    mounted,
    refuse,
    subtest,
    succeed,
    wait_unmounted,
)

NNP = "timeout 45s runuser -u alice -- setpriv --no-new-privs --"


def run():
    boot()

    with subtest(f"{FUSERMOUNT3} is defused's, and not setuid"):
        succeed(f"test -x {FUSERMOUNT3}")
        fail(f"test -u {FUSERMOUNT3}")
        succeed(
            f"runuser -u alice -- {FUSERMOUNT3} -V | "
            "grep -F 'fusermount3 version:' | grep -F '(defused)'"
        )
        # The distribution's fuse3 package is otherwise intact.
        succeed("test -e /etc/fuse.conf")

    with subtest("the setuid helper's AppArmor profile does not confine it"):
        # The distribution attaches that profile to this path, and it grants
        # libfuse's helper the mounts it may perform -- not the socket
        # defused's client connects to. Replacing the binary means replacing
        # the profile; see tests/mkosi/mkosi.postinst.chroot.
        fail(
            "grep -E '^fusermount3 \\((enforce|complain)\\)$' "
            "/sys/kernel/security/apparmor/profiles"
        )

    with subtest(f"{FUSERMOUNT} is the same binary, for libfuse2"):
        succeed(f"test -x {FUSERMOUNT}")
        fail(f"test -u {FUSERMOUNT}")
        succeed(f"test \"$(readlink -f {FUSERMOUNT})\" = {FUSERMOUNT3}")
        succeed(
            f"runuser -u alice -- {FUSERMOUNT} -V | "
            "grep -F 'fusermount version:' | grep -F '(defused)'"
        )

    with subtest("a libfuse3 filesystem mounts through defused under no_new_privs"):
        mkmnt("/home/alice/lower", "/home/alice/mnt")
        succeed("echo hello > /home/alice/lower/file && chown alice:alice /home/alice/lower/file")
        # setpriv: libfuse's own setuid helper would fail here with EPERM.
        succeed(f"{NNP} fuse-overlayfs -o lowerdir=/home/alice/lower /home/alice/mnt")
        line = mounted("/home/alice/mnt")
        assert " - fuse.fuse-overlayfs " in line, line
        assert "nosuid" in line and "nodev" in line, line
        succeed('test "$(runuser -u alice -- cat /home/alice/mnt/file)" = hello')
        succeed("journalctl -u 'defused@*' --no-pager | grep -F defused")

    with subtest("a libfuse2 filesystem mounts through defused as well"):
        mkmnt("/home/alice/mnt2")
        succeed(f"{NNP} {TESTDIR}/fuse2-hello /home/alice/mnt2")
        line = mounted("/home/alice/mnt2")
        # libfuse2's fuse_main() derives subtype= from the program name.
        assert " - fuse.fuse2-hello " in line, line
        assert "nosuid" in line and "nodev" in line, line
        succeed("test \"$(runuser -u alice -- cat /home/alice/mnt2/hello)\" = 'Hello World!'")
        succeed(f"{NNP} {FUSERMOUNT} -u /home/alice/mnt2")
        wait_unmounted("/home/alice/mnt2")

    with subtest("but allow_other still needs --allow-other"):
        mkmnt("/home/alice/mnt-other")
        refuse("/home/alice/mnt-other", "allow_other")

    with subtest("and unmounts through it"):
        succeed(f"{NNP} {FUSERMOUNT3} -u /home/alice/mnt")
        wait_unmounted("/home/alice/mnt")
