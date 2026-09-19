<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# Contributing

## Build and test

If possible, use a Nix dev shell to make the tools available.
Otherwise, the project has runtime dependencies on libseccomp and libsystemd
(258 or later), build-time dependencies on meson and ninja.
You should also install treefmt, nixfmt, and clang-tools for development.

```sh
meson setup build
meson compile -C build
meson test -C build
```

Each Meson test spawns a `defused`/`fusermount3` binary and drives it
via the wire protocol/namespaces (`test_mountns.c` uses
`unshare(CLONE_NEWUSER|CLONE_NEWNS)` to obtain the privileges needed to run
defused within its namespace).

A test that cannot run in a given environment exits 77, which Meson reports
as a skip rather than a pass: `mountns` needs nested user namespaces,
`sandbox` needs loadable seccomp filters, and `client` needs a usable
`/dev/null`. A skip means that case was not checked at all, so a change to
those areas still wants a run somewhere they are available.

Every test bounds its own runtime with `alarm()` (see `tests/test_timeout.h`)
and has a Meson timeout above that, so a hang fails the test instead of
running until CI kills the job.

Before considering a change verified, run the full check, not just
`meson test`:

```sh
nix flake check
```

This covers three things:

- `checks.<system>.meson-tests` builds the package, which runs `meson test`
  in the Nix build sandbox (the package sets `doCheck = true`);
  `meson-tests-no-polkit` does the same for a `-Dpolkit=false` build.
- The NixOS VM test suite in `packaging/nixos/tests/`, which is where the
  privileged mount and unmount paths are actually exercised. Every VM test
  runs once per kernel listed in `packaging/nixos/tests/default.nix`, so the
  kernel-version fallbacks are exercised on a kernel that really lacks the
  newer interface.
- `reuse lint`, to ensure that all files have SPDX headers.

CI runs the first and third, but only evaluates the VM tests rather than
running them, so this local run is the only thing that exercises them.

Pass `--print-build-logs` (`-L`) to see the Meson test output as it runs;
without it a passing build prints nothing.

## Coding style

C code follows the systemd coding style for resource management: a resource
is released by a `_cleanup_` attribute on the variable holding it, not by a
`goto out` label. `src/common.h` provides `_cleanup_close_`,
`_cleanup_free_`, `_cleanup_fclose_`, `_cleanup_close_pair_`, and
`DEFINE_TRIVIAL_CLEANUP_FUNC()` for other release functions; libsystemd's own
`*_unrefp` helpers work with `_cleanup_()` directly. Hand a resource off with
`TAKE_FD()`/`TAKE_PTR()`, close one early with `fd = safe_close(fd);`, and
initialize unset fds to `-EBADF`. `src/util.c` is copied from libfuse and
keeps libfuse's style instead.

## Formatting and licensing

`treefmt` runs `clang-format` and `nixfmt` to format the code.

Every source file needs an SPDX header as this project follows the
[REUSE](reuse.software) standard.

Code adapted from libfuse must keep its original copyright.
Original defused code should be `GPL-2.0-or-later`.
Files which are not integral to the project (example configs, CI files,
systemd units) should be `MIT-0`.

## AI contributions

Git commits should include a trailer `Assisted-By: ai-agent-label`
that mentions any AI models used when creating the commit.
It must not contain a `Co-Authored-By:` trailer.

Be sure to manually review any AI-written code.
Especially when it comes to comments, AI loves to write lengthy descriptions
of all of the different decisions they tried and backed away from.
Save those for git commit messages.
