<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: GPL-2.0-or-later
-->

# The mkosi VM test suite

Builds an image of an FHS distribution with defused installed the way a
distribution package installs it, and boots one VM per test to exercise the
privileged mount and unmount paths for real.

It covers the same ground as the NixOS tests in
[packaging/nixos/tests](../../packaging/nixos/tests), with one test file per
NixOS test and the same assertions, on a machine that is nothing like a
NixOS one: `/usr/bin/fusermount3` is a real path that the distribution's own
`fuse3` package also claims, systemd units come from
`/usr/lib/systemd/system`, and AppArmor arrives with a policy of its own.
That is where packaging problems live, and neither the NixOS tests nor the
unit tests can see them.

## Running

```sh
sudo tests/mkosi/run-tests           # build the image, then run every test
sudo tests/mkosi/run-tests --list
sudo tests/mkosi/run-tests -j 4 simple policy
sudo tests/mkosi/run-tests -B apparmor    # reuse the image as built
```

Needs `mkosi` (25 or later), `qemu-system-x86_64`, `sfdisk` and root: mkosi
builds the image as root and qemu reads it. `mkosi dependencies` prints the
rest, which is what `.github/workflows/test-mkosi.yml` installs:

```sh
sudo apt-get install --no-install-recommends $(mkosi -C tests/mkosi dependencies)
```

Everything the image itself contains comes from the distribution packages
named in `mkosi.conf`. The build needs network access to the distribution's
archive; the VMs get no network at all.

A run without KVM works -- at around 90 seconds per test instead of 15 --
so this suite runs anywhere qemu does. Each VM takes `--ram` megabytes for
itself, so keep `jobs * ram` inside the host's memory: qemu dies in obscure
ways once the host starts swapping.

Every run leaves the full console log of each VM in
`mkosi.output/logs/<test>.log`, whether it passed or not, and a failing test
prints a traceback followed by the state of the service, its journal and the
AppArmor denials, so the log is usually enough to say what happened.

## How it works

`mkosi build` produces a disk image, a kernel and an initrd from
`mkosi.conf`:

- `mkosi.build.chroot` builds defused inside the image with the
  distribution's own toolchain, runs `meson test`, and installs it with
  `meson install --prefix=/usr`.
- `mkosi.postinst.chroot` makes the machine the tests expect: the users they
  mount as, the socket unit enabled, and the AppArmor rules an FHS
  distribution has to add.

`run-tests` then boots that image once per test with
`systemd.unit=defused-test.service` and `systemd.setenv=DEFUSED_TEST=<test>`
on the kernel command line. The unit runs `guest/run-test`, which imports
`guest/tests/<test>.py`, runs it, prints

```
DEFUSED-TEST-RESULT: PASS <test>
```

on the serial console, and powers the machine off. The runner reads that
line; the exit status `systemctl exit` hands back needs a vsock, which a
container-based CI job does not have.

The VMs are booted with qemu directly, from the kernel, initrd and image
mkosi split out, because `mkosi vm` needs systemd running on the host.
`mkosi vm` is still the way to poke at the machine by hand:

```sh
cd tests/mkosi
sudo mkosi vm                        # boots to a root shell
sudo mkosi vm --kernel-command-line-extra=\
"systemd.unit=defused-test.service systemd.setenv=DEFUSED_TEST=policy"
```

## Layout

| Path | What it is |
| --- | --- |
| `mkosi.conf` | the image: distribution, packages, build and runtime settings |
| `mkosi.build.chroot` | builds and installs defused and the guest half of this suite |
| `mkosi.postinst.chroot` | users, the enabled socket unit, AppArmor policy |
| `run-tests` | the host side: builds the image, boots a VM per test, reports |
| `guest/run-test` | the entry point inside the VM |
| `guest/harness.py` | what a test is written against, mirroring the NixOS prelude |
| `guest/tests/*.py` | one file per test |
| `guest/fuse2-hello.c` | a libfuse2 filesystem, for the `fusermount` name |
| `../mount-helper.py` | drives fusermount3 like libfuse; shared with the NixOS tests |

## Writing a test

Add `guest/tests/<name>.py` with a `run()`; `run-tests` picks it up by
filename. The harness gives a test the same vocabulary the NixOS prelude
gives one there -- `mount`, `mount_unmount`, `hold`, `refuse`, `mkmnt`,
`mounted`, `wait_unmounted` -- over the same `mount-helper.py`, plus
`succeed`, `fail` and `execute` for commands on the machine itself.

Each test gets its own boot, so it can reconfigure the machine as it likes:
`configure()` writes the drop-in the README documents for the policy
options, and a test that wants no service at all stops and masks the socket
(see `privileged.py`). Where a NixOS test declares a second node, a test
here reconfigures in place and carries on -- `policy.py` does both halves.

## What this does not cover

The NixOS suite runs every test against two kernels and two builds (glibc
and a static musl one); this runs one image. To vary it, pass mkosi's own
options through:

```sh
sudo tests/mkosi/run-tests -- --distribution=debian --release=testing
```

Anything with a kernel new enough for defused will do; the kernel comes
with the distribution, so the version-dependent paths in defused are
covered by the choice of distribution rather than by a matrix. A test that
would otherwise have to encode a kernel version should probe the kernel for
what it needs instead: the versions a distribution ships do not always
behave the way the version number says.

## Distribution packaging notes

What the image has to do about AppArmor, and what it turns out not to have
to do -- the first of which a defused package for such a distribution would
have to do as well:

- **The AppArmor profile attached to `/usr/bin/fusermount3`.** Ubuntu's
  `apparmor` package ships one, written for libfuse's setuid helper: it
  grants that binary the mounts it may perform and nothing else. Defused
  takes over the path, inherits the confinement, and is denied the one thing
  its client does -- connecting to `/run/defused/defused.sock`. Since
  defused's `fusermount3` is not setuid and performs no privileged
  operation, `mkosi.postinst.chroot` disables that profile; the privileged
  half is the service, which the `defused` profile confines.
- **The `defused` profile itself needs nothing added.** It declares no
  attachment path, so `AppArmorProfile=defused` in the unit is what pulls it
  in, and what it grants is enough to start and run the service from
  `/usr/lib/defused/defused` -- the one rule the image adds in
  `/etc/apparmor.d/local/defused` is for the mediation probe in
  `apparmor.py`, which has to exec something under a profile that grants no
  exec of its own.

## Local overrides

`mkosi.local.conf` is read before `mkosi.conf` and is not tracked by git,
which is where machine-specific settings go:

```ini
[Build]
Incremental=yes
WorkspaceDirectory=/var/tmp/mkosi
```

A workspace outside the checkout is required where the checkout is on a
filesystem mkosi cannot build an overlay on, such as a container's overlayfs.
