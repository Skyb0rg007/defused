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

# XXX: Check for function availability
common_c_args = ['-DHAVE_CLOSE_RANGE']

defused_exe = executable(
  'defused',
  'src/defused.c',
  'src/util.c',
  c_args : common_c_args,
  install : true,
)

fusermount3_exe = executable(
  'fusermount3',
  'src/fusermount3.c',
  'src/util.c',
  c_args : common_c_args + ['-DDEFUSED_VERSION="@0@"'.format(meson.project_version())],
  install : true,
)

