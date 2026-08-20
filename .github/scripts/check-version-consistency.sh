#!/bin/sh
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: MIT-0

# meson.build's version : '...' is the project's single conceptual source of
# truth, but packaging/defused.spec's Version: and debian/changelog's top
# entry are separate, hand-maintained copies (unlike the old Nix-based
# packaging, which regex-extracted the version from meson.build directly).
# Nothing enforces these three stay in sync, and a drift has a real, confusing
# failure mode: release.yml's rpm job names its source tarball from
# meson.build's version, but rpmbuild looks for
# Source0: %{name}-%{version}.tar.gz using the spec's own Version:, so a
# forgotten bump fails as a tarball-not-found error far from its actual
# cause. Run this early in CI to fail loudly and clearly instead.
set -eu

meson_version=$(grep -oP "version\s*:\s*'\K[0-9]+\.[0-9]+(\.[0-9]+)?" meson.build)
spec_version=$(grep -oP '^Version:\s*\K\S+' packaging/defused.spec)
changelog_version=$(grep -oPm1 '^defused \(\K[0-9]+\.[0-9]+(\.[0-9]+)?(?=-)' debian/changelog)

echo "meson.build:              $meson_version"
echo "packaging/defused.spec:   $spec_version"
echo "debian/changelog (top):   $changelog_version"

status=0

if [ "$meson_version" != "$spec_version" ]; then
	echo "::error file=packaging/defused.spec::Version ($spec_version) does not match meson.build's version ($meson_version)"
	status=1
fi

if [ "$meson_version" != "$changelog_version" ]; then
	echo "::error file=debian/changelog::top entry's upstream version ($changelog_version) does not match meson.build's version ($meson_version)"
	status=1
fi

exit "$status"
