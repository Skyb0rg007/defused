# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""What a test running inside the VM is written against.

The names mirror the NixOS test prelude in packaging/nixos/tests/common.nix
so the two suites read alike, except that a test here runs on the machine it
is testing: `succeed("...")` is the local equivalent of `machine.succeed`,
and there is one machine, reconfigured in place where a NixOS test would
declare a second node.
"""

import contextlib
import os
import shlex
import subprocess
import sys
import time

TESTDIR = "/usr/lib/defused-test"
HELPER = f"python3 {TESTDIR}/mount-helper.py"
# /tmp, not /run: the helper writes them as the unprivileged user.
READY, RELEASE = "/tmp/defused-ready", "/tmp/defused-release"
USER = "alice"
# What `meson install --prefix=/usr` produced, and the paths libfuse execs.
FUSERMOUNT3 = "/usr/bin/fusermount3"
FUSERMOUNT = "/usr/bin/fusermount"
DEFUSED = "/usr/lib/defused/defused"
SOCKET = "/run/defused/defused.sock"
DROPIN = "/run/systemd/system/defused@.service.d/50-test.conf"


class TestFailure(Exception):
    """A check that did not hold. Nothing else is expected to raise it."""


def log(msg):
    print(msg, flush=True)


### Running commands ###


def execute(cmd, timeout=90):
    """Run cmd under a shell; return (status, combined output)."""
    log(f"+ {cmd}")
    try:
        proc = subprocess.run(
            ["/bin/sh", "-c", cmd],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise TestFailure(f"command timed out after {timeout}s: {cmd}") from e
    if proc.stdout:
        sys.stdout.write(proc.stdout if proc.stdout.endswith("\n") else proc.stdout + "\n")
        sys.stdout.flush()
    return proc.returncode, proc.stdout


def succeed(cmd, **kw):
    status, output = execute(cmd, **kw)
    if status != 0:
        raise TestFailure(f"command failed with {status}: {cmd}")
    return output


def fail(cmd, **kw):
    status, output = execute(cmd, **kw)
    if status == 0:
        raise TestFailure(f"command unexpectedly succeeded: {cmd}")
    return output


def wait_until_succeeds(cmd, timeout=60, **kw):
    deadline = time.monotonic() + timeout
    while True:
        status, output = execute(cmd, **kw)
        if status == 0:
            return output
        if time.monotonic() >= deadline:
            raise TestFailure(f"command never succeeded within {timeout}s: {cmd}")
        time.sleep(0.5)


def wait_until_fails(cmd, timeout=60, **kw):
    deadline = time.monotonic() + timeout
    while True:
        status, _ = execute(cmd, **kw)
        if status != 0:
            return
        if time.monotonic() >= deadline:
            raise TestFailure(f"command never failed within {timeout}s: {cmd}")
        time.sleep(0.5)


@contextlib.contextmanager
def subtest(name):
    log(f"\n### subtest: {name} ###")
    yield


### Mounting, through tests/mount-helper.py ###


def helper(*args, run=f"runuser -u {USER} --", timeout=45, suffix=""):
    argv = " ".join(shlex.quote(str(a)) for a in args)
    return succeed(f"timeout {timeout}s {run} {HELPER} {argv}{suffix}", timeout=timeout + 45)


def mount(mnt, opts="__empty__", *tokens, **kw):
    """Mount, check the mountinfo line against tokens, lazily unmount."""
    helper("assert-mount", mnt, opts, *tokens, **kw)


def mount_unmount(mnt, opts="__empty__", **kw):
    """Mount, then unmount without -z, and check the mount is gone."""
    helper("assert-unmount", mnt, opts, **kw)


def hold(mnt, opts, *tokens, logfile="/run/defused-hold.log", timeout=120, **kw):
    """Mount in the background and return once the mount is live.

    The helper holds it until release() creates RELEASE. Its output goes to
    a file rather than the pipe this harness reads: a backgrounded command
    that kept the pipe open would hang the call that started it.
    """
    succeed(f"rm -f {READY} {RELEASE}")
    helper(
        "hold-mount",
        mnt,
        opts,
        READY,
        RELEASE,
        *tokens,
        timeout=timeout,
        suffix=f" >{logfile} 2>&1 &",
        **kw,
    )
    wait_until_succeeds(f"test -s {READY}")
    return succeed(f"cat {READY}").strip()


def release(mnt=None):
    """Let a held mount go, and wait for the helper holding it to finish."""
    succeed(f"touch {RELEASE}")
    # A bracket so the pattern does not match the shell running pgrep.
    wait_until_fails("pgrep -f '[m]ount-helper.py'")
    if mnt is not None:
        wait_unmounted(mnt)


def refuse(mnt, opts, expected="not allowed by the defused service", **kw):
    helper("expect-failure", mnt, opts, expected, **kw)


def mkmnt(*paths, user=USER):
    for path in paths:
        succeed(f"install -d -o {user} -g {user} {shlex.quote(path)}")


def mounted(mnt):
    """The /proc/self/mountinfo line for mnt; fails if it is not mounted."""
    return succeed(f"grep -F ' {mnt} ' /proc/self/mountinfo").strip()


def wait_unmounted(mnt):
    wait_until_succeeds(f"! grep -F ' {mnt} ' /proc/self/mountinfo")


### The service ###


def configure(max_mounts=None, allow_groups=None, allow_other=False, extra_args=None):
    """Set the policy the way the README tells an administrator to.

    A drop-in on the installed unit, overriding the environment its
    ExecStart= expands, followed by a daemon-reload. Accept=yes means the
    next connection gets an instance started from the new configuration, so
    nothing has to be restarted.
    """
    env = []
    if max_mounts is not None:
        env.append(f"Environment=DEFUSED_MAX_MOUNTS={max_mounts}")
    if allow_groups is not None:
        env.append(f"Environment=DEFUSED_ALLOW_GROUPS={','.join(allow_groups)}")
    args = list(extra_args or [])
    if allow_other:
        args.append("--allow-other")
    if args:
        env.append(f"Environment=DEFUSED_EXTRA_ARGS={' '.join(args)}")
    succeed(f"mkdir -p {os.path.dirname(DROPIN)}")
    with open(DROPIN, "w", encoding="utf-8") as f:
        f.write("[Service]\n" + "".join(line + "\n" for line in env))
    succeed(f"cat {DROPIN}")
    succeed("systemctl daemon-reload")


def stop_service():
    """Leave the machine with no service to talk to, socket file included."""
    succeed("systemctl stop defused.socket")
    fail(f"test -e {SOCKET}")


def wait_for_socket():
    wait_until_succeeds("systemctl is-active defused.socket")
    wait_until_succeeds(f"test -S {SOCKET}")


def audit_grep(*patterns):
    """A command matching an audit record wherever this boot put it.

    The kernel prints audit records to the ring buffer until journald
    claims the audit socket and to the journal after that, and which one a
    given record reaches is a race with the rest of the boot. Reading the
    journal by transport rather than by message also keeps a pattern from
    matching the echo of the command that carries it.
    """
    greps = "".join(f" | grep -F {shlex.quote(p)}" for p in patterns)
    return f"journalctl --no-pager _TRANSPORT=audit{greps} || dmesg{greps}"


def diagnose():
    """Print what a failure usually turns out to be about."""
    log("\n### diagnostics ###")
    for cmd in (
        f"stat -c '%a %U:%G %n' /run/defused {SOCKET} || true",
        "systemctl --no-pager --failed || true",
        "systemctl --no-pager status defused.socket || true",
        "journalctl -b --no-pager -u defused.socket -u 'defused@*' || true",
        "dmesg | grep -i apparmor | tail -10 || true",
        "journalctl --no-pager _TRANSPORT=audit | tail -10 || true",
        "grep -F fuse /proc/self/mountinfo || true",
    ):
        execute(cmd)


### The machine ###


def kernel_version():
    return os.uname().release


def boot(socket=True):
    """What a test does first: the runner unit is ordered after the boot.

    The FUSE module is not autoloaded by anything in the image, exactly as
    the NixOS tests load it with boot.kernelModules.
    """
    log(f"# kernel {kernel_version()}")
    log(succeed("systemctl --failed --no-legend --no-pager") or "(no failed units)")
    succeed("modprobe fuse")
    succeed("test -e /dev/fuse")
    if socket:
        wait_for_socket()
