# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
}:

let
  common = import ./common.nix { inherit self pkgs system; };
  inherit (common) package mountHelper;

  # Deliberately not common.baseNode: that node grants
  # website.soss.defused.mount unconditionally so the rest of the test
  # suite can exercise real mounts, which would defeat the point of this
  # test. Built from the same ingredients minus that rule.
  plainNode =
    { ... }:
    {
      imports = [ self.nixosModules.defused ];
      boot.kernelModules = [ "fuse" ];
      services.defused.enable = true;
      services.defused.package = package;
      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };
in
pkgs.testers.nixosTest {
  name = "defused-polkit";

  nodes = {
    # No polkit rule beyond the shipped .policy file's AUTH_ADMIN_KEEP
    # default: there's no interactive agent in a headless VM to answer
    # that challenge, so every mount must be refused.
    denied = plainNode;

    # A custom rule that reads the current-mounts detail defused passes
    # (see doc/protocol.md) to implement its own per-caller mount limit,
    # independent of --mount-max. Proves those details actually reach a
    # rule and are usable, not just that *some* rule can grant the action.
    allowed =
      { ... }:
      {
        imports = [ plainNode ];
        security.polkit.extraConfig = ''
          polkit.addRule(function(action, subject) {
            if (action.id != "website.soss.defused.mount")
              return polkit.Result.NOT_HANDLED;
            if (subject.user != "alice")
              return polkit.Result.NO;
            var current = parseInt(action.lookup("current-mounts"));
            if (current < 3)
              return polkit.Result.YES;
            return polkit.Result.NO;
          });
        '';
      };
  };

  testScript = ''
    start_all()

    # Not waiting on polkit.service here: it's bus-activated (no
    # [Install] section of its own) and only actually pulled in by
    # defused@.service's Wants=/After=polkit.service, which itself only
    # starts once a client connects to defused.socket. So it isn't
    # guaranteed active at this point -- only once the mount attempts
    # below actually happen, at which point systemd's unit ordering
    # guarantees it's up before defused's request handling runs.
    denied.wait_for_unit("multi-user.target")
    denied.wait_for_unit("defused.socket")

    allowed.wait_for_unit("multi-user.target")
    allowed.wait_for_unit("defused.socket")

    with subtest("default AUTH_ADMIN_KEEP denies without an interactive agent"):
        denied.succeed("install -d -o alice -g users /home/alice/mnt")
        denied.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "expect-failure /home/alice/mnt ro "
            "'not allowed by the defused service'"
        )

    with subtest("a custom rule using the current-mounts detail grants the mount"):
        allowed.succeed("install -d -o alice -g users /home/alice/mnt")
        allowed.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-mount /home/alice/mnt __empty__"
        )
  '';
}
