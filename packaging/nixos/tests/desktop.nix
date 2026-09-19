# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
  kernelPackages,
}:

let
  common = import ./common.nix {
    inherit
      self
      pkgs
      system
      kernelPackages
      ;
  };
  inherit (common) package mountHelper;
  inherit (pkgs) lib;
in
pkgs.testers.nixosTest {
  name = "defused-desktop-${kernelPackages.kernel.version}";

  nodes.machine =
    { ... }:
    {
      imports = [ common.baseNode ];

      # What services.flatpak, xdg.portal, services.gvfs and the Plasma
      # module all turn on: a setuid libfuse fusermount3 in /run/wrappers/bin,
      # which is where nixpkgs' libfuse looks for its helper.
      programs.fuse.enable = true;

      # Not the blanket grant from baseNode: a desktop runs on the module's
      # own default, the recommended rule.
      security.polkit.extraConfig = lib.mkForce "";

      # A stock libfuse filesystem, to mount through that helper.
      environment.systemPackages = [ pkgs.fuse-overlayfs ];
    };

  testScript =
    { nodes, ... }:
    assert lib.filter (lib.hasInfix "defused") nodes.machine.warnings == [ ];
    ''
      start_all()

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("defused.socket")
      machine.succeed("test -e /dev/fuse")

      with subtest("/run/wrappers/bin/fusermount3 is defused's, and not setuid"):
          machine.succeed("test -x /run/wrappers/bin/fusermount3")
          machine.fail("test -u /run/wrappers/bin/fusermount3")
          machine.succeed(
              "runuser -u alice -- /run/wrappers/bin/fusermount3 -V | "
              "grep -F 'fusermount3 version:' | grep -F '(defused)'"
          )
          # Only the fuse3 wrapper is taken over; programs.fuse is otherwise intact.
          machine.succeed("test -u /run/wrappers/bin/fusermount")
          machine.succeed("test -e /etc/fuse.conf")

      with subtest("the recommended polkit rule is installed"):
          machine.succeed(
              "cmp /etc/polkit-1/rules.d/50-defused-mount-policy.rules "
              "${../../polkit/examples/50-defused-mount-policy.rules}"
          )
          machine.fail("grep -F defused /etc/polkit-1/rules.d/10-nixos.rules")

      with subtest("the system path prefers defused's fusermount3 too"):
          machine.succeed(
              "test \"$(readlink -f /run/current-system/sw/bin/fusermount3)\" = "
              "${package}/bin/fusermount3"
          )

      with subtest("a libfuse filesystem mounts through defused under no_new_privs"):
          machine.succeed("install -d -o alice -g users /home/alice/lower /home/alice/mnt")
          machine.succeed("echo hello > /home/alice/lower/file && chown alice:users /home/alice/lower/file")
          # setpriv: libfuse's own setuid helper would fail here with EPERM.
          machine.succeed(
              "timeout 45s runuser -u alice -- setpriv --no-new-privs -- "
              "${pkgs.fuse-overlayfs}/bin/fuse-overlayfs "
              "-o lowerdir=/home/alice/lower /home/alice/mnt"
          )
          line = machine.succeed("grep -F ' /home/alice/mnt ' /proc/self/mountinfo").strip()
          print(line)
          assert " - fuse.fuse-overlayfs " in line, line
          assert "nosuid" in line and "nodev" in line, line
          machine.succeed("test \"$(runuser -u alice -- cat /home/alice/mnt/file)\" = hello")
          machine.succeed("journalctl -u 'defused@*' --no-pager | grep -F defused")

      with subtest("but allow_other still needs an administrator"):
          machine.succeed("install -d -o alice -g users /home/alice/mnt-other")
          machine.succeed(
              "timeout 45s runuser -u alice -- "
              "${pkgs.python3}/bin/python3 ${mountHelper} "
              "expect-failure /home/alice/mnt-other allow_other "
              "'not allowed by the defused service'"
          )

      with subtest("and unmounts through it"):
          machine.succeed(
              "timeout 45s runuser -u alice -- setpriv --no-new-privs -- "
              "/run/wrappers/bin/fusermount3 -u /home/alice/mnt"
          )
          machine.wait_until_succeeds("! grep -F ' /home/alice/mnt ' /proc/self/mountinfo")
    '';
}
