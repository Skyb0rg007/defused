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

seccomp_dep = dependency('libseccomp')

# Not $libdir: the AppArmor profile hard-codes this path.
defused_install_dir = get_option('prefix') / 'lib/defused'
systemd_unit_dir = get_option('prefix') / 'lib/systemd/system'

fusermount3_c_args = [
  '-DDEFUSED_VERSION="@0@"'.format(meson.project_version()),
]

# The request handling both binaries share: shape checks, the FUSE
# superblock, and -- for a privileged fusermount3 -- carrying it out.
defused_mount_sources = ['src/defused-mount.c', 'src/defused-proto.c']

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
  defused_mount_sources,
  dependencies : [seccomp_dep],
  link_with : sandbox_lib,
  install_dir : defused_install_dir,
  install : true,
)

fusermount3_exe = executable(
  'fusermount3',
  'src/fusermount3.c',
  defused_mount_sources,
  c_args : fusermount3_c_args,
  install : true,
)

install_symlink(
  'fusermount',
  install_dir : get_option('bindir'),
  pointing_to : 'fusermount3',
)

unit_conf = configuration_data()
unit_conf.set('DEFUSED_PATH', defused_install_dir / 'defused')
configure_file(
  input : 'packaging/systemd/defused@.service.in',
  output : 'defused@.service',
  configuration : unit_conf,
  install : true,
  install_dir : systemd_unit_dir,
)
install_data('packaging/systemd/defused.socket', install_dir : systemd_unit_dir)

install_data(
  'packaging/apparmor/defused',
  install_dir : get_option('sysconfdir') / 'apparmor.d',
)

## Tests ##

# Backstop above each test's own alarm() (see tests/test_util.h).
test_timeout = 120
test_inc = include_directories('src')

# These three speak the wire protocol, so each links its implementation and
# takes the binary it drives as its single argument.
protocol_tests = {}
foreach name : ['protocol', 'client', 'mountns']
  protocol_tests += {
    name: executable(
      'test-' + name,
      'tests/test_@0@.c'.format(name),
      'src/defused-proto.c',
      include_directories : test_inc,
    ),
  }
endforeach

test_fusermount3_exe = executable(
  'test-fusermount3',
  'src/fusermount3.c',
  defused_mount_sources,
  c_args : [
    '-DDEFUSED_TEST',
    '-DDEFUSED_VERSION="@0@"'.format(meson.project_version()),
  ],
)

# The shared request handling, driven directly: the privileged path has no
# IPC left to intercept, so its shape checks are tested here instead.
test_perform_exe = executable(
  'test-perform',
  'tests/test_perform.c',
  defused_mount_sources,
  include_directories : test_inc,
)

test('perform', test_perform_exe, timeout : test_timeout)

foreach name, driven : {
  'protocol': defused_exe,
  'client': test_fusermount3_exe,
  'mountns': defused_exe,
}
  test(name, protocol_tests[name], args : [driven], timeout : test_timeout)
endforeach

test_sandbox_exe = executable(
  'test-sandbox',
  'tests/test_sandbox.c',
  'src/defused-sandbox.c',
  'src/defused-proto.c',
  c_args : ['-DDEFUSED_TEST', '-ffreestanding'],
  dependencies : [seccomp_dep],
  include_directories : test_inc,
)

test('sandbox', test_sandbox_exe, timeout : test_timeout)
