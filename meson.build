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
seccomp_dep = dependency('libseccomp')
# sd-varlink fd passing (SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT,
# sd_varlink_get_n_fds) is new in systemd 258.
systemd_dep = dependency('libsystemd', version : '>= 258')

# Not $libdir: the AppArmor profile hard-codes this path.
defused_install_dir = get_option('prefix') / 'lib/defused'
systemd_unit_dir = get_option('prefix') / 'lib/systemd/system'

common_c_args = []
if cc.has_function('close_range', prefix : '#include <unistd.h>', args : ['-D_GNU_SOURCE'])
  common_c_args += ['-DHAVE_CLOSE_RANGE']
endif
fusermount3_c_args = common_c_args + [
  '-DDEFUSED_VERSION="@0@"'.format(meson.project_version()),
  # Spawned as `defused --child` by privileged callers.
  '-DDEFUSED_PATH="@0@"'.format(defused_install_dir / 'defused'),
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
  'src/defused-daemon.c',
  'src/defused-policy.c',
  'src/defused-varlink.c',
  'src/util.c',
  c_args : common_c_args,
  dependencies : [seccomp_dep, systemd_dep],
  link_with : sandbox_lib,
  install_dir : defused_install_dir,
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

# libfuse2's fusermount speaks the same helper protocol, so the same binary
# serves both; it reports its own name from argv[0].
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

# Backstop above each test's own alarm() (see tests/test_timeout.h).
test_timeout = 120

test_protocol_exe = executable(
  'test-protocol',
  'tests/test_protocol.c',
  'src/defused-varlink.c',
  c_args : common_c_args,
  dependencies : [systemd_dep],
  include_directories : include_directories('src'),
)

test('protocol', test_protocol_exe, args : [defused_exe], timeout : test_timeout)

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
    # test-client doubles as the fake `defused --child` for privileged callers.
    '-DDEFUSED_PATH="@0@"'.format(test_client_exe.full_path()),
  ],
  dependencies : [systemd_dep],
)

test('client', test_client_exe, args : [test_fusermount3_exe], timeout : test_timeout)

test_mountns_exe = executable(
  'test-mountns',
  'tests/test_mountns.c',
  'src/defused-varlink.c',
  dependencies : [systemd_dep],
  include_directories : include_directories('src'),
)

test('mountns', test_mountns_exe, args : [defused_exe], timeout : test_timeout)

test_sandbox_exe = executable(
  'test-sandbox',
  'tests/test_sandbox.c',
  'src/defused-sandbox.c',
  c_args : ['-DDEFUSED_TEST', '-ffreestanding'],
  dependencies : [seccomp_dep],
  include_directories : include_directories('src'),
)

test('sandbox', test_sandbox_exe, timeout : test_timeout)
