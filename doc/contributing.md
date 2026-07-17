<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# Contributing

## Build and test

If possible, use a Nix dev shell to make the tools available.
Otherwise, the project has runtime dependencies on libseccomp and libsystemd,
build-time dependencies on meson and ninja.
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

Before considering a change verified, run the full check, not just
`meson test`:

```sh
nix flake check
```

This is what CI runs.
This will build the project, run the normal tests, and then also
run the NixOS VM test suite (in `nixos/tests/`).
It will also run `reuse lint` to ensure that all files have SPDX headers.

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
