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

# XXX: Check for function availability
common_c_args = ['-DHAVE_CLOSE_RANGE']

defused_exe = executable(
  'defused',
  'src/defused.c',
  'src/util.c',
  c_args : common_c_args,
  dependencies : [seccomp_dep, systemd_dep],
  install_dir : get_option('prefix') / 'lib/defused',
  install : true,
)

fusermount3_exe = executable(
  'fusermount3',
  'src/fusermount3.c',
  'src/util.c',
  c_args : common_c_args + ['-DDEFUSED_VERSION="@0@"'.format(meson.project_version())],
  install : true,
)

install_data(
  'data/website.soss.defused.policy',
  install_dir : get_option('datadir') / 'polkit-1/actions',
)

## Tests ##

test_protocol_exe = executable(
  'test-protocol',
  'tests/test_protocol.c',
  include_directories : include_directories('src'),
)

test('protocol', test_protocol_exe, args : [defused_exe])

test_client_exe = executable(
  'test-client',
  'tests/test_client.c',
  include_directories : include_directories('src'),
)

test('client', test_client_exe, args : [fusermount3_exe])

test_mountns_exe = executable(
  'test-mountns',
  'tests/test_mountns.c',
  include_directories : include_directories('src'),
)

test('mountns', test_mountns_exe, args : [defused_exe])
