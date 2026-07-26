# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

project(
  'defused',
  'c',
  meson_version : '>= 1.3.0',
  version : '0.1',
  default_options : ['warning_level=3'],
)

cc = meson.get_compiler('c')
seccomp_dep = cc.find_library('seccomp', has_headers : ['seccomp.h'])
systemd_dep = dependency('libsystemd')
libfuse_fusermount3 = find_program(get_option('libfuse_fusermount3'))

# Separate from the libsystemd link dependency above: the "systemd" pkg-config
# module (shipped by the systemd package itself, e.g. libsystemd-dev on
# Debian or systemd-devel on Fedora) exposes install-path variables like
# systemdsystemunitdir but its .pc file hardcodes ${prefix} to wherever that
# systemd package happens to live (e.g. a Nix store path under nixpkgs)
# rather than deriving it from this project's own -Dprefix. Overriding
# "prefix" explicitly makes the unit directory follow our own --prefix like
# every other install_dir in this file.
systemd_pc_dep = dependency('systemd', required : false)
if systemd_pc_dep.found()
  systemd_system_unit_dir = systemd_pc_dep.get_variable(
    pkgconfig : 'systemdsystemunitdir',
    pkgconfig_define : ['prefix', get_option('prefix')],
  )
else
  systemd_system_unit_dir = get_option('prefix') / 'lib/systemd/system'
endif

# XXX: Check for function availability
common_c_args = ['-DHAVE_CLOSE_RANGE']
fusermount3_c_args = common_c_args + [
  '-DDEFUSED_VERSION="@0@"'.format(meson.project_version()),
  '-DLIBFUSE_FUSERMOUNT3="@0@"'.format(libfuse_fusermount3.full_path()),
]

sandbox_lib = static_library(
  'defused-sandbox',
  'src/defused-sandbox.c',
  c_args : ['-ffreestanding'],
  dependencies : [seccomp_dep],
  install : false,
)

defused_exe = executable(
  'defused',
  'src/defused.c',
  'src/defused-varlink.c',
  'src/util.c',
  c_args : common_c_args,
  dependencies : [seccomp_dep, systemd_dep],
  link_with : sandbox_lib,
  install_dir : get_option('prefix') / 'lib/defused',
  install : true,
)

fusermount3_exe = executable(
  'fusermount3',
  'src/fusermount3.c',
  'src/defused-varlink.c',
  'src/util.c',
  c_args : fusermount3_c_args,
  dependencies : [systemd_dep],
  install : true,
)

install_data(
  'packaging/polkit/website.soss.defused.policy',
  install_dir : get_option('datadir') / 'polkit-1/actions',
)

# NB: the systemd unit's ExecStart= is hardcoded to /usr/lib/defused/defused,
# so packages including these units must be configured with -Dprefix=/usr for
# the installed executable_dir above to actually match.
#
# defused@.service is a template unit: defused.socket's Accept=yes means
# systemd instantiates one defused@<connection>.service per connection
# rather than running a single persistent defused.service.
install_data(
  'packaging/systemd/defused@.service',
  'packaging/systemd/defused.socket',
  install_dir : systemd_system_unit_dir,
)

# Reference/example only -- not installed as a live policy, see doc/protocol.md.
install_data(
  'packaging/polkit/examples/50-defused-mount-policy.rules',
  install_dir : get_option('datadir') / 'doc' / meson.project_name() / 'examples',
)

## Tests ##

test_protocol_exe = executable(
  'test-protocol',
  'tests/test_protocol.c',
  'src/defused-varlink.c',
  dependencies : [systemd_dep],
  include_directories : include_directories('src'),
)

test('protocol', test_protocol_exe, args : [defused_exe])

test_client_exe = executable(
  'test-client',
  'tests/test_client.c',
  'src/defused-varlink.c',
  dependencies : [systemd_dep],
  include_directories : include_directories('src'),
)

test_fusermount3_exe = executable(
  'test-fusermount3',
  'src/fusermount3.c',
  'src/defused-varlink.c',
  'src/util.c',
  c_args : common_c_args + [
    '-DDEFUSED_TEST',
    '-DDEFUSED_VERSION="@0@"'.format(meson.project_version()),
    '-DLIBFUSE_FUSERMOUNT3="@0@"'.format(test_client_exe.full_path()),
  ],
  dependencies : [systemd_dep],
)

test('client', test_client_exe, args : [test_fusermount3_exe])

test_mountns_exe = executable(
  'test-mountns',
  'tests/test_mountns.c',
  'src/defused-varlink.c',
  dependencies : [systemd_dep],
  include_directories : include_directories('src'),
)

test('mountns', test_mountns_exe, args : [defused_exe])

test_sandbox_exe = executable(
  'test-sandbox',
  'tests/test_sandbox.c',
  'src/defused-sandbox.c',
  c_args : ['-DDEFUSED_TEST', '-ffreestanding'],
  dependencies : [seccomp_dep],
  include_directories : include_directories('src'),
)

test('sandbox', test_sandbox_exe)
