# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
}:

let
  inherit (pkgs) lib;

  # Every test runs on both, so the service's kernel-version fallbacks are
  # taken for real: PIDFD_GET_INFO (6.13), socket inode xattrs (7.0).
  kernels = [
    pkgs.linuxPackages_6_12
    pkgs.linuxPackages_7_2
  ];

  tests = {
    simple = ./simple.nix;
    daemon = ./daemon.nix;
    mount-namespace = ./mount-namespace.nix;
    mountpoint-ownership = ./mountpoint-ownership.nix;
    mount-options = ./mount-options.nix;
    file-mountpoint = ./file-mountpoint.nix;
    non-lazy-unmount = ./non-lazy-unmount.nix;
    polkit = ./polkit.nix;
    builtin-policy = ./builtin-policy.nix;
    apparmor = ./apparmor.nix;
    privileged = ./privileged.nix;
    desktop = ./desktop.nix;
  };

  # "linux-6_12": stable across point releases.
  kernelSuffix =
    kernelPackages:
    "linux-"
    + lib.replaceStrings [ "." ] [ "_" ] (lib.versions.majorMinor kernelPackages.kernel.version);
in
lib.listToAttrs (
  lib.concatMap (
    name:
    map (
      kernelPackages:
      lib.nameValuePair "${name}-${kernelSuffix kernelPackages}" (
        import tests.${name} {
          inherit
            self
            pkgs
            system
            kernelPackages
            ;
        }
      )
    ) kernels
  ) (lib.attrNames tests)
)
