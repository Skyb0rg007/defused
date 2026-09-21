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
# sd-varlink fd passing (SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT,
# sd_varlink_get_n_fds) is new in systemd 258.
systemd_dep = dependency('libsystemd', version : '>= 258')

# Not $libdir: the AppArmor profile hard-codes this path.
defused_install_dir = get_option('prefix') / 'lib/defused'
systemd_unit_dir = get_option('prefix') / 'lib/systemd/system'

fusermount3_c_args = [
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
  'src/defused-varlink.c',
  dependencies : [seccomp_dep, systemd_dep],
  link_with : sandbox_lib,
  install_dir : defused_install_dir,
  install : true,
)

# Needs libsystemd's headers for defused_proto.h, but none of its code.
activate_exe = executable(
  'defused-activate',
  'src/defused-activate.c',
  dependencies : [
    systemd_dep.partial_dependency(compile_args : true, includes : true),
  ],
  install_dir : defused_install_dir,
  install : true,
)

fusermount3_exe = executable(
  'fusermount3',
  'src/fusermount3.c',
  'src/defused-varlink.c',
  c_args : fusermount3_c_args,
  dependencies : [systemd_dep],
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

# These three speak the Varlink protocol, so each links the client helpers
# and takes the binary it drives as its single argument.
varlink_tests = {}
foreach name : ['protocol', 'client', 'mountns']
  varlink_tests += {
    name: executable(
      'test-' + name,
      'tests/test_@0@.c'.format(name),
      'src/defused-varlink.c',
      dependencies : [systemd_dep],
      include_directories : test_inc,
    ),
  }
endforeach

test_fusermount3_exe = executable(
  'test-fusermount3',
  'src/fusermount3.c',
  'src/defused-varlink.c',
  c_args : [
    '-DDEFUSED_TEST',
    '-DDEFUSED_VERSION="@0@"'.format(meson.project_version()),
    # test-client doubles as the fake `defused --child` for privileged callers.
    '-DDEFUSED_PATH="@0@"'.format(varlink_tests['client'].full_path()),
  ],
  dependencies : [systemd_dep],
)

# test-protocol also drives defused-activate, so it takes a second path.
foreach name, driven : {
  'protocol': [defused_exe, activate_exe],
  'client': [test_fusermount3_exe],
  'mountns': [defused_exe],
}
  test(name, varlink_tests[name], args : driven, timeout : test_timeout)
endforeach

test_sandbox_exe = executable(
  'test-sandbox',
  'tests/test_sandbox.c',
  'src/defused-sandbox.c',
  c_args : ['-DDEFUSED_TEST', '-ffreestanding'],
  dependencies : [seccomp_dep],
  include_directories : test_inc,
)

test('sandbox', test_sandbox_exe, timeout : test_timeout)
