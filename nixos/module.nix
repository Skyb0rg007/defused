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

      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          Additional command-line arguments passed to defused. defused
          currently takes no flags beyond --help -- mount policy is decided
          per request by polkit, see security.polkit.extraConfig and
          examples/50-defused-mount-policy.rules. Kept for forward
          compatibility.
        '';
      };
    };

  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ package ];

    # defused asks polkit whether a client may create a FUSE mount at all
    # (see doc/protocol.md); polkitd has to actually be running for that
    # check to ever succeed, rather than fail closed.
    security.polkit.enable = lib.mkDefault true;

    systemd.sockets.defused = {
      description = "defused FUSE mount service listening socket";
      documentation = [ "https://github.com/Skyb0rg007/defused" ];
      wantedBy = [ "sockets.target" ];

      socketConfig = {
        Accept = true;
        ListenStream = "/run/defused/defused.sock";
        RuntimeDirectory = "defused";
      };
    };

    systemd.services."defused@" = {
      description = "defused FUSE mount service";
      documentation = [ "https://github.com/Skyb0rg007/defused" ];
      wants = [ "polkit.service" ];
      after = [ "polkit.service" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs ([ "${package}/lib/defused/defused" ] ++ cfg.extraArgs);
      };
    };
  };
}
