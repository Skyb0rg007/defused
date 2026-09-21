# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Drive fusermount3 the way libfuse does, and check what it mounted.

Used by both VM test suites -- packaging/nixos/tests/ and tests/mkosi/ --
so the two check the same things. $DEFUSED_FUSERMOUNT3 names the binary to
drive; the default is the FHS path libfuse itself execs.
"""

import array
import os
import select
import socket
import struct
import subprocess
import sys
import time

fusermount3 = os.environ.get("DEFUSED_FUSERMOUNT3") or "/usr/bin/fusermount3"
FUSE_INIT = 26
FUSE_KERNEL_VERSION = 7
FUSE_KERNEL_MINOR_VERSION = 31

def echo(stdout, stderr):
    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)

def recv_fd(sock):
    sock.settimeout(10)
    fds = array.array("i")
    msg, ancdata, flags, addr = sock.recvmsg(1, socket.CMSG_SPACE(fds.itemsize))
    if msg != b"\0":
        raise RuntimeError(f"unexpected comm fd message: {msg!r}")
    for level, ctype, data in ancdata:
        if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
            fds.frombytes(data[:fds.itemsize])
            return fds[0]
    raise RuntimeError("fusermount3 did not send a FUSE fd")

def run_fusermount3(args, comm_sock=None):
    pass_fds = []
    if comm_sock is not None:
        pass_fds = [comm_sock.fileno()]
        args = ["--comm-fd", str(comm_sock.fileno())] + args
    try:
        proc = subprocess.run(
            [fusermount3] + args,
            pass_fds=pass_fds,
            text=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired as e:
        echo(e.stdout, e.stderr)
        raise RuntimeError(f"fusermount3 timed out: {args!r}") from e
    echo(proc.stdout, proc.stderr)
    return proc

def mount_fuse(mountpoint, opts):
    if opts == "__empty__":
        opts = ""
    local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        proc = subprocess.Popen(
            [fusermount3, "--comm-fd", str(remote.fileno()), "-o", opts, mountpoint],
            pass_fds=[remote.fileno()],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        remote.close()
    try:
        fuse_fd = recv_fd(local)
    except Exception:
        echo(*proc.communicate(timeout=10))
        raise
    finally:
        local.close()
    echo(*proc.communicate(timeout=10))
    if proc.returncode != 0:
        os.close(fuse_fd)
        raise RuntimeError(f"fusermount3 mount failed with {proc.returncode}")
    return fuse_fd

def init_fuse(fuse_fd):
    ready, _, _ = select.select([fuse_fd], [], [], 10)
    if not ready:
        raise RuntimeError("timed out waiting for FUSE_INIT")
    data = os.read(fuse_fd, 135168)
    if len(data) < 40:
        raise RuntimeError(f"short FUSE request: {data!r}")
    length, opcode, unique, nodeid, uid, gid, pid, extlen, padding = struct.unpack(
        "<IIQQIIIHH", data[:40]
    )
    if opcode != FUSE_INIT:
        raise RuntimeError(f"unexpected FUSE opcode: {opcode}")
    out = struct.pack(
        "<IIIIHHIIHHIIH11H",
        FUSE_KERNEL_VERSION,
        FUSE_KERNEL_MINOR_VERSION,
        0,
        0,
        16,
        12,
        131072,
        1,
        32,
        0,
        0,
        0,
        0,
        *([0] * 11),
    )
    os.write(fuse_fd, struct.pack("<IiQ", 16 + len(out), 0, unique) + out)

def unmount_fuse(mountpoint, lazy=False):
    args = ["-u"] + (["-z"] if lazy else []) + [mountpoint]
    proc = run_fusermount3(args)
    if proc.returncode != 0:
        raise RuntimeError(f"fusermount3 unmount failed with {proc.returncode}")

def mountinfo_line(mountpoint):
    """The /proc/self/mountinfo line for mountpoint, or None if unmounted."""
    mountpoint = os.path.abspath(mountpoint)
    with open("/proc/self/mountinfo", encoding="utf-8") as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 5 and fields[4] == mountpoint:
                return line.strip()
    return None

def mountinfo_for(mountpoint):
    line = mountinfo_line(mountpoint)
    if line is None:
        raise RuntimeError(f"no mountinfo entry for {mountpoint}")
    return line

def assert_tokens(line, tokens):
    """A token starting with '!' must be absent from the line."""
    missing = [t for t in tokens if not t.startswith("!") and t not in line]
    present = [t for t in tokens if t.startswith("!") and t[1:] in line]
    if missing or present:
        raise AssertionError(
            f"missing {missing!r}, unexpected {present!r} in mountinfo line: {line}"
        )

def assert_mount(mountpoint, opts, tokens, ready=None, release=None):
    """Mount, check the mountinfo line against tokens, lazily unmount.

    Given ready/release, write the line to the ready path and hold the
    mount open until the release path appears, so another process can
    observe it live.
    """
    fuse_fd = mount_fuse(mountpoint, opts)
    try:
        init_fuse(fuse_fd)
        line = mountinfo_for(mountpoint)
        print(line, flush=True)
        assert_tokens(line, tokens)
        if ready:
            with open(ready, "w", encoding="utf-8") as f:
                f.write(line + "\n")
            while not os.path.exists(release):
                time.sleep(0.1)
    finally:
        try:
            unmount_fuse(mountpoint, lazy=True)
        except RuntimeError as e:
            print(e, file=sys.stderr)
        os.close(fuse_fd)

def assert_unmount(mountpoint, opts):
    fuse_fd = mount_fuse(mountpoint, opts)
    try:
        init_fuse(fuse_fd)
        print(mountinfo_for(mountpoint), flush=True)
        try:
            unmount_fuse(mountpoint, lazy=False)
        except RuntimeError:
            unmount_fuse(mountpoint, lazy=True)
            raise
        line = mountinfo_line(mountpoint)
        if line is not None:
            raise AssertionError(f"still mounted after unmount: {line}")
    finally:
        os.close(fuse_fd)

def expect_failure(mountpoint, opts, expected):
    local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        proc = run_fusermount3(["-o", opts, mountpoint], remote)
    finally:
        remote.close()
        local.close()
    output = proc.stdout + proc.stderr
    if proc.returncode == 0:
        raise AssertionError("fusermount3 unexpectedly succeeded")
    if expected not in output:
        raise AssertionError(f"missing {expected!r} from output: {output!r}")

mode = sys.argv[1]
if mode == "assert-mount":
    assert_mount(sys.argv[2], sys.argv[3], sys.argv[4:])
elif mode == "assert-unmount":
    assert_unmount(sys.argv[2], sys.argv[3])
elif mode == "hold-mount":
    assert_mount(sys.argv[2], sys.argv[3], sys.argv[6:], sys.argv[4], sys.argv[5])
elif mode == "expect-failure":
    expect_failure(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    raise SystemExit(f"unknown mode: {mode}")