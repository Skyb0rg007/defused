# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ pkgs, common, ... }:

let
  inherit (common) package;
  inherit (pkgs) lib;

  # A libfuse2 filesystem, from libfuse2's own example: nixpkgs has no
  # packaged fuse2 filesystem left. It execs /run/wrappers/bin/fusermount.
  fuse2Hello =
    pkgs.runCommandCC "fuse2-hello"
      {
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.fuse ];
      }
      ''
        mkdir -p $out/bin
        $CC -o $out/bin/fuse2-hello ${pkgs.fuse.src}/example/hello.c \
          $(pkg-config --cflags --libs fuse)
      '';
in
common.mkTest {
  name = "desktop";

  nodes.machine =
    { ... }:
    {
      imports = [ common.baseNode ];

      # What services.flatpak, xdg.portal, services.gvfs and the Plasma
      # module all turn on: a setuid libfuse fusermount3 in /run/wrappers/bin,
      # which is where nixpkgs' libfuse looks for its helper.
      programs.fuse.enable = true;

      # Not the allow_other grant from baseNode: a desktop runs on the
      # module's own defaults.
      services.defused.allowOther = lib.mkForce false;

      # Stock libfuse3 and libfuse2 filesystems, to mount through the helpers.
      environment.systemPackages = [
        pkgs.fuse-overlayfs
        fuse2Hello
      ];
    };

  script =
    { nodes, ... }:
    assert lib.filter (lib.hasInfix "defused") nodes.machine.warnings == [ ];
    ''
      boot(machine)
      machine.succeed("test -e /dev/fuse")

      with subtest("/run/wrappers/bin/fusermount3 is defused's, and not setuid"):
          machine.succeed("test -x /run/wrappers/bin/fusermount3")
          machine.fail("test -u /run/wrappers/bin/fusermount3")
          machine.succeed(
              "runuser -u alice -- /run/wrappers/bin/fusermount3 -V | "
              "grep -F 'fusermount3 version:' | grep -F '(defused)'"
          )
          # programs.fuse is otherwise intact.
          machine.succeed("test -e /etc/fuse.conf")

      with subtest("/run/wrappers/bin/fusermount is defused's too, for libfuse2"):
          machine.succeed("test -x /run/wrappers/bin/fusermount")
          machine.fail("test -u /run/wrappers/bin/fusermount")
          machine.succeed(
              "runuser -u alice -- /run/wrappers/bin/fusermount -V | "
              "grep -F 'fusermount version:' | grep -F '(defused)'"
          )

      with subtest("the system path prefers defused's helpers too"):
          for name in ("fusermount", "fusermount3"):
              machine.succeed(
                  f"test \"$(readlink -f /run/current-system/sw/bin/{name})\" = "
                  "${package}/bin/fusermount3"
              )

      with subtest("a libfuse filesystem mounts through defused under no_new_privs"):
          mkmnt(machine, "/home/alice/lower", "/home/alice/mnt")
          machine.succeed("echo hello > /home/alice/lower/file && chown alice:users /home/alice/lower/file")
          # setpriv: libfuse's own setuid helper would fail here with EPERM.
          machine.succeed(
              "timeout 45s runuser -u alice -- setpriv --no-new-privs -- "
              "${pkgs.fuse-overlayfs}/bin/fuse-overlayfs "
              "-o lowerdir=/home/alice/lower /home/alice/mnt"
          )
          line = mounted(machine, "/home/alice/mnt")
          print(line)
          assert " - fuse.fuse-overlayfs " in line, line
          assert "nosuid" in line and "nodev" in line, line
          machine.succeed("test \"$(runuser -u alice -- cat /home/alice/mnt/file)\" = hello")
          machine.succeed("journalctl -u 'defused@*' --no-pager | grep -F defused")

      with subtest("a libfuse2 filesystem mounts through defused as well"):
          mkmnt(machine, "/home/alice/mnt2")
          machine.succeed(
              "timeout 45s runuser -u alice -- setpriv --no-new-privs -- "
              "${fuse2Hello}/bin/fuse2-hello /home/alice/mnt2"
          )
          line = mounted(machine, "/home/alice/mnt2")
          print(line)
          # libfuse2's fuse_main() derives subtype= from the program name.
          assert " - fuse.fuse2-hello " in line, line
          assert "nosuid" in line and "nodev" in line, line
          machine.succeed(
              "test \"$(runuser -u alice -- cat /home/alice/mnt2/hello)\" "
              "= 'Hello World!'"
          )
          machine.succeed(
              "timeout 45s runuser -u alice -- setpriv --no-new-privs -- "
              "/run/wrappers/bin/fusermount -u /home/alice/mnt2"
          )
          wait_unmounted(machine, "/home/alice/mnt2")

      with subtest("but allow_other still needs --allow-other"):
          mkmnt(machine, "/home/alice/mnt-other")
          refuse(machine, "/home/alice/mnt-other", "allow_other")

      with subtest("and unmounts through it"):
          machine.succeed(
              "timeout 45s runuser -u alice -- setpriv --no-new-privs -- "
              "/run/wrappers/bin/fusermount3 -u /home/alice/mnt"
          )
          wait_unmounted(machine, "/home/alice/mnt")
    '';
}
