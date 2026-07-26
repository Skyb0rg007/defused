# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

Name:           defused
Version:        0.1
Release:        1%{?dist}
Summary:        Setuid-less replacement for fusermount3

# Most of the project's own code is GPL-2.0-or-later; src/util.{c,h} carry
# code copied from libfuse under GPL-2.0-only, with two functions in
# src/util.c further carved out as LGPL-2.1-only (see the SPDX-SnippetBegin
# annotations in that file); the systemd units, example polkit rule, and CI
# workflows are MIT-0. `reuse lint`'s "Used licenses" summary is the source
# of truth for this expression.
License:        GPL-2.0-or-later AND GPL-2.0-only AND LGPL-2.1-only AND MIT-0
URL:            https://github.com/Skyb0rg007/defused
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  gcc
BuildRequires:  pkgconfig(libseccomp)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  systemd-rpm-macros
Requires:       polkit
# rpmbuild's automatic Requires generator also picks up the real per-symbol
# floor from the built binaries (e.g. "libsystemd.so.0(LIBSYSTEMD_258)"), but
# src/defused.h's Varlink usage needing a systemd this recent is significant
# enough -- current Fedora satisfies it, but current Debian stable and
# Ubuntu LTS don't -- to also spell out explicitly here. systemd-libs is the
# Fedora package that owns libsystemd.so.0 (confirmed via
# `rpm -qf /usr/lib64/libsystemd.so.0`). See README.md's Installation
# section.
Requires:       systemd-libs >= 258

%description
defused replaces libfuse's setuid-root fusermount3 helper with a
socket-activated system service (listening on /run/defused/defused.sock)
plus a fusermount3-compatible client binary that talks to it over a Unix
domain socket.

Because the setuid-root binary is gone, FUSE mounts keep working under the
no_new_privileges process flag used by sandboxing techniques such as
seccomp-bpf and landlock, and the privilege to mount FUSE filesystems can be
granted per-sandbox by bind-mounting the socket into a container's namespace
instead of relying on /usr/bin placement.

%prep
%autosetup -p1

%build
%meson
%meson_build

%install
%meson_install

%post
%systemd_post %{name}.socket

%preun
%systemd_preun %{name}.socket

%postun
%systemd_postun_with_restart %{name}.socket

%files
%license LICENSES/GPL-2.0-or-later.txt LICENSES/GPL-2.0-only.txt LICENSES/LGPL-2.1-only.txt LICENSES/MIT-0.txt
%doc README.md
%{_bindir}/fusermount3
%dir %{_prefix}/lib/defused
%{_prefix}/lib/defused/defused
%{_unitdir}/defused.service
%{_unitdir}/defused.socket
%{_datadir}/polkit-1/actions/website.soss.defused.policy
%dir %{_datadir}/doc/%{name}/examples
%{_datadir}/doc/%{name}/examples/50-defused-mount-policy.rules

%changelog
* Sat Jul 25 2026 Skye Soss <skye@soss.website> - 0.1-1
- Initial package.
