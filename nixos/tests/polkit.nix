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

    # Installs the actual shipped example rule (examples/
    # 50-defused-mount-policy.rules) rather than an ad-hoc one, so this test
    # also proves that specific file is correct, not just that *some* rule
    # using current-mounts can grant the base mount action.
    allowed =
      { ... }:
      {
        imports = [ plainNode ];
        environment.etc."polkit-1/rules.d/50-defused-mount-policy.rules".source =
          ../../examples/50-defused-mount-policy.rules;
      };

    # A rule that explicitly adds "allow_other" to its allowlist, unlike
    # the shipped example -- proves the *grant* side of the
    # privileged-flags mechanism: a rule that does recognize a privileged
    # option can grant it (still subject to the rule's other conditions),
    # it's only rules that *don't* mention it that fall back to
    # AUTH_ADMIN_KEEP.
    allowedOther =
      { ... }:
      {
        imports = [ plainNode ];
        security.polkit.extraConfig = ''
          polkit.addRule(function(action, subject) {
            if (action.id != "website.soss.defused.mount")
              return polkit.Result.NOT_HANDLED;

            var allowedPrivilegedFlags = ["allow_other"];
            var privilegedFlags = action.lookup("privileged-flags");
            if (privilegedFlags) {
              var requested = privilegedFlags.split(",");
              for (var i = 0; i < requested.length; i++) {
                if (allowedPrivilegedFlags.indexOf(requested[i]) < 0)
                  return polkit.Result.AUTH_ADMIN_KEEP;
              }
            }

            return polkit.Result.YES;
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

    allowedOther.wait_for_unit("multi-user.target")
    allowedOther.wait_for_unit("defused.socket")

    with subtest("default AUTH_ADMIN_KEEP denies without an interactive agent"):
        denied.succeed("install -d -o alice -g users /home/alice/mnt")
        denied.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "expect-failure /home/alice/mnt ro "
            "'not allowed by the defused service'"
        )

    with subtest("the sample rule grants an ordinary mount under the limit"):
        allowed.succeed("install -d -o alice -g users /home/alice/mnt")
        allowed.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-mount /home/alice/mnt __empty__"
        )

    with subtest("the sample rule's empty allowlist falls back for allow_other"):
        allowed.succeed("install -d -o alice -g users /home/alice/mnt-other")
        allowed.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "expect-failure /home/alice/mnt-other allow_other "
            "'not allowed by the defused service'"
        )

    with subtest("a rule that allowlists allow_other can grant it"):
        allowedOther.succeed("install -d -o alice -g users /home/alice/mnt-other")
        allowedOther.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-mount /home/alice/mnt-other allow_other "
            "' - fuse fuse ' allow_other"
        )
  '';
}
