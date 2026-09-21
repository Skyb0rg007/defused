# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ self, common, ... }:

let
  # Not common.baseNode: it grants allow_other to everyone.
  policyNode =
    { ... }:
    {
      imports = [ self.nixosModules.defused ];
      boot.kernelPackages = common.kernelPackages;
      boot.kernelModules = [ "fuse" ];
      services.defused = {
        enable = true;
        package = common.package;
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
common.mkTest {
  name = "policy";

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

  script = ''
    boot(restricted, allowOther)

    with subtest("the unit carries the policy options"):
        restricted.succeed(
            "systemctl cat defused@.service | grep -F -- '--allow-groups=fusers'"
        )
        allowOther.succeed(
            "systemctl cat defused@.service | grep -F -- '--allow-other'"
        )

    with subtest("a member of --allow-groups mounts and unmounts"):
        mkmnt(restricted, "/home/alice/mnt-a")
        mount_unmount(restricted, "/home/alice/mnt-a")

    with subtest("a user outside --allow-groups is refused"):
        mkmnt(restricted, "/home/bob/mnt", user="bob")
        refuse(restricted, "/home/bob/mnt", "ro", run="runuser -u bob --")

    with subtest("allow_other is refused unless --allow-other grants it"):
        refuse(restricted, "/home/alice/mnt-a", "allow_other")
        mkmnt(allowOther, "/home/alice/mnt-other")
        mount(allowOther, "/home/alice/mnt-other", "allow_other", " - fuse fuse ", "allow_other")

    with subtest("--max-mounts refuses a mount past the limit"):
        mkmnt(restricted, "/home/alice/mnt-b")
        hold(
            restricted,
            "/home/alice/mnt-a",
            "__empty__",
            " - fuse fuse ",
            timeout=120,
            suffix=" >/tmp/defused-hold.log 2>&1 &",
        )
        restricted.wait_until_succeeds("test -s /tmp/defused-ready")
        refuse(restricted, "/home/alice/mnt-b", "ro")
        restricted.succeed("touch /tmp/defused-release")
        wait_unmounted(restricted, "/home/alice/mnt-a")

    with subtest("the limit counts live mounts: released, the next one goes through"):
        mount(restricted, "/home/alice/mnt-b", "__empty__", " - fuse fuse ")
  '';
}
