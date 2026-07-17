#!/bin/sh
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Manual/integration smoke test for the defused Varlink protocol.
#
# Unlike tests/test_client.c and tests/test_protocol.c, this drives a real,
# already-running defused service with varlinkctl(1) directly -- the same
# way any other Varlink client would -- instead of going through
# fusermount3 or a purpose-built C harness. It only exercises the wire
# protocol: Mount, then Unmount.
#
# Requirements:
#  - varlinkctl from systemd >= 258 (for "--push-fd").
#  - A defused service reachable at $DEFUSED_SOCKET
#    (default /run/defused/defused.sock).
#  - Caller must be allowed to open /dev/fuse and be authorized by
#    defused's polkit policy to mount (see
#    examples/50-defused-mount-policy.rules).
#
# The mount created here never gets a real FUSE server behind it, so the
# service replies once defused attaches it and stops there: nothing ever
# answers the kernel's FUSE_INIT request. That's fine, since this test only
# checks that defused created and later tore down the mount, not that it
# is usable.

set -eu

socket="${DEFUSED_SOCKET:-/run/defused/defused.sock}"
mnt_dir=$(mktemp -d "${TMPDIR:-/tmp}/defused-varlink-test.XXXXXX")

cleanup() {
    rmdir "$mnt_dir" 2>/dev/null || true
}
trap cleanup EXIT

is_mounted() {
    grep -q " $mnt_dir " /proc/self/mountinfo
}

echo "== mountpoint: $mnt_dir"

if is_mounted; then
    echo "$mnt_dir is already a mountpoint before the test started" >&2
    exit 1
fi

# defused validates that this fd is /dev/fuse opened O_RDWR; --push-fd's
# path form always opens read-only, so open it ourselves on fd 3 instead.
exec 3<>/dev/fuse

mount_reply=$(varlinkctl --json=short \
    --push-fd=3 \
    --push-fd="$mnt_dir" \
    call "$socket" website.soss.defused.Mount \
    '{"fuseFileDescriptor":0,"mountpointFileDescriptor":1,"mountFlags":0,"maxRead":0,"blockSize":0,"fsName":"","subtype":""}')

exec 3<&-

echo "== Mount reply: $mount_reply"
case "$mount_reply" in
    *'"status":0'*) ;;
    *)
        echo "Mount was rejected by defused" >&2
        exit 1
        ;;
esac

if ! is_mounted; then
    echo "defused reported success but $mnt_dir was not mounted" >&2
    exit 1
fi
echo "== mountpoint created"

parent_dir=$(dirname "$mnt_dir")
base_name=$(basename "$mnt_dir")

exec 4<"$parent_dir"

umount_reply=$(varlinkctl --json=short \
    --push-fd=4 \
    call "$socket" website.soss.defused.Unmount \
    "{\"parentFileDescriptor\":0,\"name\":\"$base_name\",\"lazy\":false}")

exec 4<&-

echo "== Unmount reply: $umount_reply"
case "$umount_reply" in
    *'"status":0'*) ;;
    *)
        echo "Unmount was rejected by defused" >&2
        exit 1
        ;;
esac

if is_mounted; then
    echo "defused reported success but $mnt_dir is still mounted" >&2
    exit 1
fi

echo "== OK: mount + unmount round-trip succeeded"
