# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  package,
  variant,
  kernelPackages,
}:

let
  common = import ./common.nix {
    inherit
      self
      pkgs
      package
      kernelPackages
      ;
  };
  inherit (common) mountHelper;

  # Not common.baseNode: it grants allow_other to everyone.
  policyNode =
    { ... }:
    {
      imports = [ self.nixosModules.defused ];
      boot.kernelPackages = kernelPackages;
      boot.kernelModules = [ "fuse" ];
      services.defused = {
        enable = true;
        package = package;
      };
      users.groups.fusers = { };
      users.users.alice = {
        isNormalUser = true;
        createHome = true;
        extraGroups = [ "fusers" ];
      };
      users.users.bob = {
        isNormalUser = true;
        createHome = true;
      };
    };
in
pkgs.testers.nixosTest {
  name = "defused-policy-${variant}-${kernelPackages.kernel.version}";

  nodes = {
    # Issue #59's policy; the limit is 1 so the test can reach it.
    restricted =
      { ... }:
      {
        imports = [ policyNode ];
        services.defused.allowGroups = [ "fusers" ];
        services.defused.maxMounts = 1;
      };

    # Every user, the default limit, and allow_other granted.
    allowOther =
      { ... }:
      {
        imports = [ policyNode ];
        services.defused.allowOther = true;
      };
  };

  testScript = ''
    start_all()

    for machine in (restricted, allowOther):
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("defused.socket")

    with subtest("the unit carries the policy options"):
        restricted.succeed(
            "systemctl cat defused@.service | grep -F -- '--allow-groups=fusers'"
        )
        allowOther.succeed(
            "systemctl cat defused@.service | grep -F -- '--allow-other'"
        )

    with subtest("a member of --allow-groups mounts and unmounts"):
        restricted.succeed("install -d -o alice -g users /home/alice/mnt-a")
        restricted.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-unmount /home/alice/mnt-a __empty__"
        )

    with subtest("a user outside --allow-groups is refused"):
        restricted.succeed("install -d -o bob -g users /home/bob/mnt")
        restricted.succeed(
            "timeout 45s runuser -u bob -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "expect-failure /home/bob/mnt ro "
            "'not allowed by the defused service'"
        )

    with subtest("allow_other is refused unless --allow-other grants it"):
        restricted.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "expect-failure /home/alice/mnt-a allow_other "
            "'not allowed by the defused service'"
        )
        allowOther.succeed("install -d -o alice -g users /home/alice/mnt-other")
        allowOther.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-mount /home/alice/mnt-other allow_other "
            "' - fuse fuse ' allow_other"
        )

    with subtest("--max-mounts refuses a mount past the limit"):
        restricted.succeed("install -d -o alice -g users /home/alice/mnt-b")
        restricted.succeed(
            "timeout 120s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "hold-mount /home/alice/mnt-a __empty__ "
            "/tmp/defused-ready /tmp/defused-release ' - fuse fuse ' "
            ">/tmp/defused-hold.log 2>&1 &"
        )
        restricted.wait_until_succeeds("test -s /tmp/defused-ready")
        restricted.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "expect-failure /home/alice/mnt-b ro "
            "'not allowed by the defused service'"
        )
        restricted.succeed("touch /tmp/defused-release")
        restricted.wait_until_succeeds(
            "! grep -F ' /home/alice/mnt-a ' /proc/self/mountinfo"
        )

    with subtest("the limit counts live mounts: released, the next one goes through"):
        restricted.succeed(
            "timeout 45s runuser -u alice -- "
            "${pkgs.python3}/bin/python3 ${mountHelper} "
            "assert-mount /home/alice/mnt-b __empty__ ' - fuse fuse '"
        )
  '';
}
