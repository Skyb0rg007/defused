# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  description = "defused -- a setuid-less fusermount";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = lib.platforms.linux;
      forAllSystems = lib.genAttrs systems;
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.gitTracked ./.;
      };
    in
    {
      nixosModules = {
        default = import ./nixos/module.nix { inherit self; };
        defused = self.nixosModules.default;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        (import ./nixos/tests {
          inherit self pkgs system;
        })
        // {
          reuse-lint = pkgs.runCommand "defused-reuse-lint" { nativeBuildInputs = [ pkgs.reuse ]; } ''
            cd ${src}
            reuse lint
            touch $out
          '';
        }
      );

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.defused;
          defused = pkgs.stdenv.mkDerivation {
            pname = "defused";
            version = "0.1.0";
            inherit src;
            nativeBuildInputs = [
              pkgs.meson
              pkgs.ninja
            ];
            buildInputs = [
              pkgs.libseccomp
            ];
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [
              self.packages.${system}.defused
            ];
            packages = [
              pkgs.treefmt
              pkgs.nixfmt
              pkgs.clang-tools
              pkgs.reuse
              pkgs.fuse
            ];
            shellHook = ''
              export NIX_CFLAGS_COMPILE="-U_FORTIFY_SOURCE $NIX_CFLAGS_COMPILE"
            '';
          };
        }
      );
    };
}
