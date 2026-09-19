# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Mount and unmount a FUSE mountpoint as root through fusermount3.

libfuse mounts directly with mount(2) when it runs as root, so a real FUSE
client never reaches the privileged `defused --child` path; this drives
fusermount3 --comm-fd by hand instead, the way libfuse would for an
unprivileged caller. Usage: child-mount.py /usr/bin/fusermount3 MOUNTPOINT
"""

import array
import os
import socket
import subprocess
import sys

fusermount3, mountpoint = sys.argv[1], os.path.abspath(sys.argv[2])


def mountinfo_line():
    with open("/proc/self/mountinfo", encoding="utf-8") as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 5 and fields[4] == mountpoint:
                return line.strip()
    return None


local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
proc = subprocess.Popen(
    [fusermount3, "--comm-fd", str(remote.fileno()), "-o", "fsname=childfs", mountpoint],
    pass_fds=[remote.fileno()],
)
remote.close()

fds = array.array("i")
local.settimeout(10)
msg, ancdata, _, _ = local.recvmsg(1, socket.CMSG_SPACE(fds.itemsize))
for level, ctype, data in ancdata:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        fds.frombytes(data[: fds.itemsize])
local.close()
if proc.wait(10) != 0:
    sys.exit(f"fusermount3 exited with {proc.returncode}")
if msg != b"\0" or not fds:
    sys.exit(f"fusermount3 did not send a FUSE fd (got {msg!r})")

line = mountinfo_line()
if line is None:
    sys.exit(f"{mountpoint} is not in /proc/self/mountinfo")
print(line)
if " - fuse childfs " not in f" {line} " or "user_id=0," not in line:
    sys.exit(f"{mountpoint} is not a root FUSE mount of childfs")

subprocess.run([fusermount3, "-u", mountpoint], check=True)
os.close(fds[0])
if mountinfo_line() is not None:
    sys.exit(f"{mountpoint} is still mounted after fusermount3 -u")
