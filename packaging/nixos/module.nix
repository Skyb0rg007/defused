# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{ self }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.defused;
  package = cfg.package;

  # Granted and bounded alike: the service needs exactly these, and nothing
  # it execs should be able to regain more.
  capabilities = [
    "CAP_DAC_READ_SEARCH"
    "CAP_SYS_ADMIN"
    "CAP_SYS_CHROOT"
    "CAP_SYS_PTRACE"
  ];

  # The same binary under either libfuse's helper name, unprivileged: the
  # wrapper is only here to take over the path libfuse execs.
  mkWrapper = name: {
    enable = true;
    program = name;
    source = "${package}/bin/${name}";
    owner = "root";
    group = "root";
    permissions = "u+rx,g+x,o+x";
    capabilities = "";
    setuid = false;
    setgid = false;
  };
in
{
  options = {
    services.defused = {
      enable = lib.mkEnableOption "defused FUSE mount service";

      package = lib.mkOption {
        type = lib.types.package;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.defused;
        defaultText = lib.literalExpression "inputs.defused.packages.${pkgs.stdenv.hostPlatform.system}.defused";
        description = "The defused package to use.";
      };

      replaceFusermount3 = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Install defused's fusermount3 as {file}`/run/wrappers/bin/fusermount3`,
          where libfuse looks for it, in place of the setuid helper from
          {option}`programs.fuse`.
        '';
      };

      replaceFusermount = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Install defused's helper as {file}`/run/wrappers/bin/fusermount`
          too, where libfuse2 looks for it, in place of the setuid helper
          from {option}`programs.fuse`. The same binary serves both libfuse
          generations.
        '';
      };

      maxMounts = lib.mkOption {
        type = lib.types.ints.positive;
        default = 100;
        description = ''
          Refuse a mount once this many FUSE filesystems are mounted,
          like {option}`programs.fuse.mountMax`.
        '';
      };

      allowGroups = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "fuse" ];
        description = ''
          Groups whose members may mount and unmount.
          Empty allows every user.
        '';
      };

      allowOther = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Let callers set the `allow_other` mount option, the equivalent
          of {option}`programs.fuse.userAllowOther`.
        '';
      };

      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          Additional command-line arguments passed to defused, after the
          policy options the settings above generate.
        '';
      };
    };

  };

  config = lib.mkIf cfg.enable {
    # hiPrio: programs.fuse also puts a fusermount and a fusermount3 into the
    # system path, and defused ships both names too.
    environment.systemPackages = [
      (if cfg.replaceFusermount3 || cfg.replaceFusermount then lib.hiPrio package else package)
    ];

    warnings =
      # One per helper defused was told not to take over while programs.fuse
      # still defines it as a setuid wrapper.
      lib.flatten (
        lib.mapAttrsToList
          (
            option: helper:
            lib.optional (config.programs.fuse.enable && !cfg.${option}) ''
              services.defused.${option} is off while programs.fuse is on, so
              /run/wrappers/bin/${helper} is libfuse's setuid helper and the
              programs looking there use it instead of defused. Programs
              started with no_new_privs still cannot mount.
            ''
          )
          {
            replaceFusermount3 = "fusermount3";
            replaceFusermount = "fusermount";
          }
      )
      ++
        lib.optional
          (
            config.programs.fuse.enable
            && (cfg.replaceFusermount3 || cfg.replaceFusermount)
            && (config.programs.fuse.userAllowOther || config.programs.fuse.mountMax != 1000)
          )
          ''
            programs.fuse.userAllowOther and programs.fuse.mountMax only
            configure libfuse's fusermount, which services.defused has
            replaced; for defused, use services.defused.maxMounts and
            allowOther.
          '';

    # mkForce: programs.fuse defines the same wrappers, as setuid libfuse.
    # Every submodule option is set so none of its definition survives.
    security.wrappers = lib.mkMerge [
      (lib.mkIf cfg.replaceFusermount3 {
        fusermount3 = lib.mkForce (mkWrapper "fusermount3");
      })
      (lib.mkIf cfg.replaceFusermount { fusermount = lib.mkForce (mkWrapper "fusermount"); })
    ];

    security.apparmor = {
      policies.defused.path = "${package}/etc/apparmor.d/defused";
      includes."local/defused" = ''
        include "${pkgs.apparmorRulesFromClosure { name = "defused"; } [ package ]}"
        ${package}/lib/defused/defused mr,
      '';
    };

    systemd.sockets.defused = {
      description = "defused FUSE mount service listening socket";
      documentation = [ "https://github.com/Skyb0rg007/defused" ];
      wantedBy = [ "sockets.target" ];

      socketConfig = {
        Accept = true;
        ListenSequentialPacket = "/run/defused/defused.sock";
        RuntimeDirectory = "defused";
      };
    };

    systemd.services."defused@" = {
      description = "defused FUSE mount service";
      documentation = [ "https://github.com/Skyb0rg007/defused" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            "${package}/lib/defused/defused"
            "--max-mounts=${toString cfg.maxMounts}"
            "--allow-groups=${lib.concatStringsSep "," cfg.allowGroups}"
          ]
          ++ lib.optional cfg.allowOther "--allow-other"
          ++ cfg.extraArgs
        );
        AmbientCapabilities = capabilities;
        CapabilityBoundingSet = capabilities;
        NoNewPrivileges = true;
        AppArmorProfile = if config.security.apparmor.enable then "defused" else "-defused";

        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        ProtectHostname = true;
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
