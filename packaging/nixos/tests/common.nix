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
  # Shared with tests/mkosi/, so both VM suites drive fusermount3 the same
  # way. The helper names the FHS path an installed fusermount3 has, which
  # is no path at all here: rewrite it to this variant's build. The assert
  # turns a renamed literal into an eval error rather than a VM that spends
  # its run failing to exec /usr/bin/fusermount3.
  helperSource = builtins.readFile ../../../tests/mount-helper.py;
  fhsHelperPath = "\"/usr/bin/fusermount3\"";
  mountHelper =
    assert pkgs.lib.hasInfix fhsHelperPath helperSource;
    pkgs.writeText "defused-mount-helper.py" (
      builtins.replaceStrings [ fhsHelperPath ] [ "\"${package}/bin/fusermount3\"" ] helperSource
    );

  baseNode =
    { ... }:
    {
      imports = [ self.nixosModules.defused ];

      boot.kernelPackages = kernelPackages;
      boot.kernelModules = [ "fuse" ];

      services.defused = {
        enable = true;
        package = package;
        # These tests exercise defused's own mount plumbing, not the policy:
        # grant allow_other, which mount-options.nix's real mount needs.
        allowOther = true;
      };

      users.users.alice = {
        isNormalUser = true;
        createHome = true;
      };
    };

  # Wrappers around the helper above, so a test says what it is checking
  # instead of respelling the runuser/timeout/python incantation. `run` is
  # the command prefix the helper is launched under, and `suffix` is appended
  # to the shell command unquoted, for redirections and `&`.
  prelude = ''
    import shlex

    HELPER = "${pkgs.python3}/bin/python3 ${mountHelper}"
    READY, RELEASE = "/tmp/defused-ready", "/tmp/defused-release"


    def helper(machine, *args, run="runuser -u alice --", timeout=45, suffix=""):
        argv = " ".join(shlex.quote(str(a)) for a in args)
        return machine.succeed(f"timeout {timeout}s {run} {HELPER} {argv}{suffix}")


    def mount(machine, mnt, opts="__empty__", *tokens, **kw):
        helper(machine, "assert-mount", mnt, opts, *tokens, **kw)


    def mount_unmount(machine, mnt, opts="__empty__", **kw):
        helper(machine, "assert-unmount", mnt, opts, **kw)


    def hold(machine, mnt, opts, *tokens, **kw):
        helper(machine, "hold-mount", mnt, opts, *tokens, **kw)


    def refuse(machine, mnt, opts, expected="not allowed by the defused service", **kw):
        helper(machine, "expect-failure", mnt, opts, expected, **kw)


    def mkmnt(machine, *paths, user="alice"):
        for path in paths:
            machine.succeed(f"install -d -o {user} -g users {path}")


    def mounted(machine, mnt):
        return machine.succeed(f"grep -F ' {mnt} ' /proc/self/mountinfo").strip()


    def wait_unmounted(machine, mnt):
        machine.wait_until_succeeds(f"! grep -F ' {mnt} ' /proc/self/mountinfo")


    def boot(*machines, socket=True):
        start_all()
        for machine in machines:
            machine.wait_for_unit("multi-user.target")
            if socket:
                machine.wait_for_unit("defused.socket")

  '';

  # Every test is the same nixosTest apart from its nodes and script, and
  # every name carries the variant and kernel it was built for.
  mkTest =
    {
      name,
      nodes ? {
        machine = baseNode;
      },
      script,
    }:
    pkgs.testers.nixosTest {
      name = "defused-${name}-${variant}-${kernelPackages.kernel.version}";
      inherit nodes;
      # A script may be a function of the evaluated { nodes, ... }, as the
      # NixOS test driver allows, or a plain string. The wrapper has to
      # declare `nodes` itself: the driver auto-calls testScript with only
      # the arguments its formals name.
      testScript =
        if builtins.isFunction script then { nodes, ... }@args: prelude + script args else prelude + script;
    };
in
{
  inherit
    package
    mountHelper
    baseNode
    kernelPackages
    mkTest
    ;
  kernelVersion = kernelPackages.kernel.version;
}
