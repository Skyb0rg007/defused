# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: MIT-0
#
# spec file for openSUSE and Fedora

# Fedora uses SELinux, so the AppArmor profile is only packaged for openSUSE.
%if 0%{?suse_version}
%bcond_without apparmor
%else
%bcond_with apparmor
%endif

# The libfuse versions that defused is tested against.
# This is used in the Provides: section.
%global libfuse3_series 3.18
%global libfuse2_series 2.9

Name:           defused
Version:        0
Release:        0
Summary:        A setuid-less fusermount implementation
License:        GPL-2.0-only
URL:            https://github.com/Skyb0rg007/defused
Source:         %{name}-%{version}.tar.xz

BuildRequires:  gcc
BuildRequires:  meson >= 1.3.0
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(libcap)
BuildRequires:  pkgconfig(libseccomp)
BuildRequires:  systemd-rpm-macros
%if 0%{?suse_version}
BuildRequires:  linux-glibc-devel
%else
BuildRequires:  kernel-headers
%endif
%if %{with apparmor}
BuildRequires:  apparmor-rpm-macros
%endif

Requires:       %{name}-service = %{version}-%{release}
Provides:       fuse3 = %{libfuse3_series}
Provides:       fuse = %{libfuse2_series}
Conflicts:      fuse3
Conflicts:      fuse

%description
The kernel's FUSE implementation needs privileges to mount, which libfuse
normally obtains from a setuid fusermount3 helper. A setuid helper cannot be
used by a process that has set no_new_privileges, which rules out seccomp-bpf
and Landlock sandboxing in FUSE clients.

defused replaces the setuid bit with a system service on a Unix socket:
clients ask it to mount and it hands back the /dev/fuse descriptor.

This package holds /usr/bin/fusermount3 and /usr/bin/fusermount as clients of
that service in place of libfuse's setuid helpers. libfuse execs these by
absolute path, so installing this package is what lets an existing FUSE client
mount without setuid and under no_new_privileges. It also installs mount.fuse
and umount.fuse helpers that mount(8) and umount(8) run for fuse.* filesystems,
so fstab entries work too.

Mounts fail until the service's socket is enabled:
systemctl enable --now defused.socket

%package service
Summary:        System service that performs FUSE mounts for defused clients
%{?systemd_ordering}

%description service
The defused system service and its systemd units. It listens on
/run/defused/defused.sock and mounts/unmounts FUSE filesystems on behalf of its
clients.

%if %{with apparmor}
%package apparmor
Summary:        AppArmor profile for the defused service
BuildArch:      noarch
Requires:       apparmor-abstractions
Supplements:    (%{name}-service and apparmor-abstractions)

%description apparmor
The AppArmor profile that confines the defused service.
%endif

%prep
%autosetup -n %{name}-%{version}

%build
%meson
%meson_build

%install
%meson_install
%if %{without apparmor}
rm -r %{buildroot}%{_sysconfdir}/apparmor.d
%endif

%check
%meson_test

%if 0%{?suse_version}
%pre service
%service_add_pre %{name}.socket

%post service
%service_add_post %{name}.socket

%preun service
%service_del_preun %{name}.socket

%postun service
%service_del_postun_without_restart %{name}.socket
%else
%post service
%systemd_post %{name}.socket

%preun service
%systemd_preun %{name}.socket

%postun service
%systemd_postun %{name}.socket
%endif

%if %{with apparmor}
%post apparmor
%apparmor_reload %{apparmor_profilesdir}/%{name}
%endif

%files
%license LICENSES/GPL-2.0-or-later.txt LICENSES/MIT-0.txt
%doc README.md
%{_bindir}/fusermount
%{_bindir}/fusermount3
%{_sbindir}/mount.fuse
%{_sbindir}/umount.fuse

%files service
%license LICENSES/GPL-2.0-only.txt LICENSES/MIT-0.txt
%doc README.md
%{_libexecdir}/defused
%{_unitdir}/%{name}@.service
%{_unitdir}/%{name}.socket

%if %{with apparmor}
%files apparmor
%license LICENSES/MIT-0.txt
%dir %{apparmor_profilesdir}
%config(noreplace) %{apparmor_profilesdir}/%{name}
%endif

%changelog
