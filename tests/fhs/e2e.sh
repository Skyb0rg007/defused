#!/bin/sh
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

# End-to-end test of defused as installed on an FHS distro (Debian, Ubuntu).
#
# Run as root, after `meson install --prefix=/usr` and with the service
# listening on /run/defused/defused.sock -- from the systemd socket unit or
# from `defused --daemon`, this script does not care which. Mounts go through
# fuse-overlayfs, so the installed fusermount3 is driven by a real libfuse
# client rather than by defused's own tests. Needs fuse-overlayfs, python3,
# runuser and setpriv (util-linux).

set -eu

user=${DEFUSED_TEST_USER:-defused-test}
socket=/run/defused/defused.sock
# libfuse execs fusermount3 by this absolute path, so this is the one that
# has to be defused's, whatever else is on $PATH.
fusermount3=/usr/bin/fusermount3
# libfuse2 execs this one; the same binary serves both.
fusermount=/usr/bin/fusermount
defused=/usr/lib/defused/defused
here=$(dirname "$0")

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Both bound each step, so a hang fails the test instead of the CI job.
as_user() {
    timeout 30 runuser -u "$user" -- "$@"
}

as_root() {
    timeout 30 "$@"
}

mountinfo() {
    awk -v mnt="$1" '$5 == mnt' /proc/self/mountinfo
}

# check_mount <description> <uid> <runner>...
#
# Mounts a fuse-overlayfs of $lower on $mnt as <runner> (a command prefix),
# checks the mount looks right and is readable, then unmounts it with
# fusermount3 -u.
check_mount() {
    desc=$1
    uid=$2
    shift 2
    echo "# $desc"
    "$@" fuse-overlayfs -o lowerdir="$lower" "$mnt"
    line=$(mountinfo "$mnt")
    [ -n "$line" ] || fail "$mnt is not in /proc/self/mountinfo"
    echo "$line"
    case " $line " in
    *" - fuse.fuse-overlayfs "*) ;;
    *) fail "$mnt is not a fuse.fuse-overlayfs mount" ;;
    esac
    case "$line" in
    *"user_id=$uid,"*) ;;
    *) fail "$mnt is not mounted with user_id=$uid" ;;
    esac
    [ "$("$@" cat "$mnt/hello")" = hello ] ||
        fail "cannot read through the mount on $mnt"
    "$@" "$fusermount3" -u "$mnt"
    [ -z "$(mountinfo "$mnt")" ] || fail "$mnt is still mounted after fusermount3 -u"
}

[ "$(id -u)" -eq 0 ] || fail "run this as root"
[ -S "$socket" ] || fail "$socket is not a socket: is defused running?"
[ -x "$defused" ] || fail "$defused is not installed"
[ -x "$fusermount3" ] || fail "$fusermount3 is not installed"
[ -x "$fusermount" ] || fail "$fusermount is not installed"
for tool in fuse-overlayfs python3 runuser setpriv; do
    command -v "$tool" >/dev/null || fail "$tool is not installed"
done

getent passwd "$user" >/dev/null || useradd --create-home --shell /bin/sh "$user"
home=$(getent passwd "$user" | cut -d: -f6)
uid=$(id -u "$user")
lower=$home/lower
mnt=$home/mnt

echo "# $fusermount3 is defused's, for root and for $user"
"$fusermount3" -V | grep -F '(defused)'
as_user "$fusermount3" -V | grep -F '(defused)'

echo "# $fusermount is the same binary, reporting libfuse2's name"
as_user "$fusermount" -V | grep -F 'fusermount version:' | grep -F '(defused)'

echo "# unmounting a directory that is not a FUSE mount is rejected"
as_user mkdir -p "$home/notfuse"
if output=$(as_user "$fusermount3" -u "$home/notfuse" 2>&1); then
    fail "fusermount3 -u on a plain directory succeeded"
fi
echo "$output"
case "$output" in
*"is not a FUSE mount"*) ;;
*) fail "unexpected fusermount3 -u output" ;;
esac

echo "# a setuid-root copy of $fusermount3 refuses to run"
# Next to the installed binary, so a nosuid /tmp cannot hide the setuid bit.
suidcopy=$(dirname "$defused")/fusermount3-setuid-test
trap 'rm -f "$suidcopy"' EXIT
install -m 4755 "$fusermount3" "$suidcopy"
if output=$(as_user "$suidcopy" -V 2>&1); then
    fail "setuid-root fusermount3 ran"
fi
rm -f "$suidcopy"
echo "$output"
case "$output" in
*"refusing to run setuid"*) ;;
*) fail "unexpected setuid fusermount3 output" ;;
esac

as_user mkdir -p "$lower" "$mnt"
echo hello | as_user tee "$lower/hello" >/dev/null

check_mount "unprivileged mount through the service" "$uid" as_user
check_mount "unprivileged mount with no_new_privs, where a setuid helper cannot work" \
    "$uid" as_user setpriv --no-new-privs --

echo "# root mount and unmount, performed by fusermount3 itself"
rootmnt=$(mktemp -d)
as_root python3 "$here/child-mount.py" "$fusermount3" "$rootmnt"
rmdir "$rootmnt"

echo "PASS"
