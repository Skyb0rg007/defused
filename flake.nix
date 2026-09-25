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
    # Fil-C packaged as a Nix cross toolchain. It pins its own nixpkgs fork
    # -- stock lib.systems does not know the gnufilc0 ABI tag -- so it cannot
    # follow ours, and it only defines x86_64-linux.
    filnix.url = "github:mbrock/filnix";
  };

  outputs =
    {
      self,
      nixpkgs,
      filnix,
    }:
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
            # Not pkgs.meson: filnix's ports overlay leaves it unspliced, which
            # would build meson -- and a Python -- with Fil-C to run it here.
            pkgs.buildPackages.meson
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

      # filnix exposes Fil-C as a cross target of its own nixpkgs, so
      # everything under defused -- libseccomp, libc -- is compiled with
      # Fil-C as well, and the Meson suite runs against a binary that
      # bounds- and type-checks every load and store.
      filcPackages = lib.mapAttrs (_: filnixOutputs: filnixOutputs.pkgsFilc) filnix.legacyPackages;
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
        // lib.optionalAttrs (filcPackages ? ${system}) {
          meson-tests-filc = self.packages.${system}.defused-filc;
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
        // lib.optionalAttrs (filcPackages ? ${system}) {
          # Memory-safe; see doc/contributing.md for filnix's binary cache,
          # without which this builds the Fil-C compiler from source.
          defused-filc = (mkDefused filcPackages.${system}).overrideAttrs (_: {
            pname = "defused-filc";
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
