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

  # Accept=yes ties one defused@ instance to each connection, so holding one
  # open keeps an instance around to inspect.
  holdConnection = pkgs.writeText "defused-hold-connection.py" ''
    import socket
    import sys
    import time

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sys.argv[1])
    time.sleep(120)
  '';

  # Only the mediation probe needs this: the profile grants no execute of its own.
  probeRules = pkgs.apparmorRulesFromClosure { name = "defused-test-probe"; } [ pkgs.coreutils ];
in
pkgs.testers.nixosTest {
  name = "defused-apparmor";

  nodes.machine =
    { ... }:
    {
      imports = [ common.baseNode ];
      security.apparmor.enable = true;
      security.apparmor.includes."local/defused" = ''
        include "${probeRules}"
      '';
    };

  testScript =
    { nodes, ... }:
    let
      socketPath = nodes.machine.systemd.sockets.defused.socketConfig.ListenStream;
    in
    ''
      start_all()

      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("apparmor.service")
      machine.wait_for_unit("defused.socket")

      with subtest("the defused profile is loaded in enforce mode"):
          machine.succeed("grep -Fx 'defused (enforce)' /sys/kernel/security/apparmor/profiles")
          machine.succeed(
              "${pkgs.apparmor-bin-utils}/bin/aa-status --json | "
              "${pkgs.jq}/bin/jq -e '.profiles.defused == \"enforce\"'"
          )
          machine.succeed(
              "journalctl -k --no-pager | grep -F 'apparmor=\"STATUS\"' | "
              "grep -F 'operation=\"profile_load\"' | grep -F 'name=\"defused\"'"
          )

      with subtest("the profile declares no attachment path"):
          machine.fail(
              "${pkgs.apparmor-parser}/bin/apparmor_parser --preprocess "
              "${package}/etc/apparmor.d/defused | grep -E '^ *profile +defused +[\"/]'"
          )

      with subtest("defused@ instances run confined"):
          # stdio detached, or the test driver blocks until the holder exits.
          machine.succeed(
              "runuser -u alice -- ${pkgs.python3}/bin/python3 ${holdConnection} "
              "${socketPath} >/dev/null 2>&1 </dev/null &"
          )
          pid = machine.wait_until_succeeds("pgrep -o -x defused").strip()
          machine.succeed(f"grep -F 'defused@' /proc/{pid}/cgroup")
          machine.succeed(f"grep -Fx 'defused (enforce)' /proc/{pid}/attr/apparmor/current")
          # aa-status keys processes by executable, not by profile name.
          machine.succeed(
              "${pkgs.apparmor-bin-utils}/bin/aa-status --json | "
              f"${pkgs.jq}/bin/jq -e '.processes[\"${package}/lib/defused/defused\"][] | "
              f"select((.pid | tostring) == \"{pid}\" "
              "and .profile == \"defused\" and .status == \"enforce\")'"
          )
          machine.succeed("pkill -f defused-hold-connection.py")
          machine.wait_until_fails("pgrep -x defused")

      with subtest("a confined defused@ can mount and lazily unmount"):
          machine.succeed("test -e /dev/fuse")
          machine.succeed("install -d -o alice -g users /home/alice/aa-mnt")
          machine.succeed(
              "timeout 45s runuser -u alice -- "
              "${pkgs.python3}/bin/python3 ${mountHelper} "
              "assert-mount /home/alice/aa-mnt 'fsname=aafs,subtype=aa' "
              "' - fuse.aa aafs ' rw nosuid nodev user_id= group_id="
          )
          machine.wait_until_succeeds("! grep -F ' /home/alice/aa-mnt ' /proc/self/mountinfo")

      with subtest("no AppArmor denials for the defused profile"):
          # Kernel-mediated denials land in the kernel log; the journal catches
          # any that only a userspace mediator records.
          machine.fail("dmesg | grep -F 'apparmor=\"DENIED\"' | grep -F 'profile=\"defused'")
          machine.fail(
              "journalctl --no-pager | grep -F 'apparmor=\"DENIED\"' | grep -F 'profile=\"defused'"
          )

      # Last: it deliberately produces the records the subtest above forbids.
      with subtest("the profile actually mediates"):
          # The profile grants no write anywhere. Without this, "no denials"
          # would pass just as well for a profile that was never consulted.
          machine.fail(
              "${pkgs.apparmor-bin-utils}/bin/aa-exec -p defused -- "
              "${pkgs.coreutils}/bin/touch /tmp/aa-probe"
          )
          machine.fail("test -e /tmp/aa-probe")
          machine.succeed(
              "dmesg | grep -F 'apparmor=\"DENIED\"' | grep -F 'profile=\"defused\"' | "
              "grep -F 'name=\"/tmp/aa-probe\"'"
          )
    '';
}
