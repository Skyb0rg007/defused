# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  description = "defused -- a setuid-less fusermount";
  nixConfig = {
    extra-substituters = [ "https://defused.cachix.org" ];
    extra-trusted-public-keys = [ "defused.cachix.org-1:/YD+2Bmle49JSliBhGRqTKpLYhvruoFyMPPU071YCAY=" ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      # Each output body takes the platform it is being built for.
      forAllSystems =
        f:
        lib.genAttrs lib.platforms.linux (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
          }
        );
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.gitTracked ./.;
      };

      staticPackages =
        pkgs:
        pkgs.pkgsStatic.extend (
          _: prev: {
            # Its test suite defines fgetxattr()/fsetxattr(), which collide
            # with musl's static libc.
            libcap_ng = prev.libcap_ng.overrideAttrs (_: {
              doCheck = false;
            });
          }
        );

      mkDefused =
        pkgs:
        pkgs.stdenv.mkDerivation {
          pname = "defused";
          version = "0.1.0";
          inherit src;
          nativeBuildInputs = [
            pkgs.meson
            pkgs.ninja
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.libseccomp
            # <linux/mount.h> and <asm/socket.h>: the new mount API and
            # SO_PEERPIDFD, which musl does not declare itself.
            pkgs.linuxHeaders
          ];

          doCheck = true;
          # Keep Meson's per-test timeouts; nixpkgs disables them by default.
          dontAddTimeoutMultiplier = true;

          meta = {
            description = "SETUID-less fusermount3 implementation";
            license = lib.licenses.gpl2Only;
            platforms = lib.platforms.linux;
          };
        };
    in
    {
      nixosModules = {
        default = import ./packaging/nixos/module.nix { inherit self; };
        defused = self.nixosModules.default;
      };

      checks = forAllSystems (
        { system, pkgs }:
        (import ./packaging/nixos/tests {
          inherit self pkgs system;
        })
        // {
          # doCheck = true, so building the package runs `meson test`.
          meson-tests = self.packages.${system}.defused;
          meson-tests-static = self.packages.${system}.defused-static;

          reuse-lint = pkgs.runCommand "defused-reuse-lint" { nativeBuildInputs = [ pkgs.reuse ]; } ''
            cd ${src}
            reuse lint
            touch $out
          '';
        }
      );

      packages = forAllSystems (
        { system, pkgs }:
        {
          default = self.packages.${system}.defused;
          defused = mkDefused pkgs;
          # Runs on a musl system with no shared libraries at all.
          defused-static = (mkDefused (staticPackages pkgs)).overrideAttrs (_: {
            pname = "defused-static";
          });
        }
      );

      devShells = forAllSystems (
        { system, pkgs }:
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
              pkgs.fuse3
              pkgs.act
            ];
            shellHook = ''
              export NIX_CFLAGS_COMPILE="-U_FORTIFY_SOURCE $NIX_CFLAGS_COMPILE"
            '';
          };
        }
      );
    };
}
