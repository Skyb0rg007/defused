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
      systems = lib.platforms.linux;
      forAllSystems = lib.genAttrs systems;
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.gitTracked ./.;
      };

      # pkgsStatic needs nudging before libsystemd can go into a static
      # binary at all.
      staticPackages =
        pkgs:
        pkgs.pkgsStatic.extend (
          final: prev: {
            # Its test suite defines fgetxattr()/fsetxattr(), which collide
            # with musl's static libc.
            libcap_ng = prev.libcap_ng.overrideAttrs (_: {
              doCheck = false;
            });
            # systemd only installs libsystemd.a when asked, and nixpkgs
            # marks the package unsupported on static platforms because
            # systemd itself needs NSS (systemd#20600). defused uses only
            # sd-varlink, sd-event and sd-daemon, which do not.
            systemdLibs = prev.systemdLibs.overrideAttrs (old: {
              mesonFlags = (old.mesonFlags or [ ]) ++ [ "-Dstatic-libsystemd=true" ];
              env = (old.env or { }) // {
                NIX_CFLAGS_LINK =
                  # systemd builds libsystemd.so and libsystemd-shared.so
                  # whatever we ask for, and -shared cannot be combined with
                  # the -static the static stdenv adds.
                  lib.replaceStrings [ " -static" ] [ "" ] (old.env.NIX_CFLAGS_LINK or "")
                  # libucontext.a has no .note.GNU-stack, which systemd turns
                  # from a linker warning into an error.
                  + " -Wl,--no-warn-execstack";
              };
              # libsystemd.pc lists no private dependencies, so a static
              # link never hears about the libucontext systemd needs on musl.
              postInstall = (old.postInstall or "") + ''
                echo "Libs.private: -L${final.libucontext}/lib -lucontext" >>"$dev/lib/pkgconfig/libsystemd.pc"
              '';
              # Something in the musl build puts a bash reference in $dev.
              disallowedRequisites = [ ];
              meta = old.meta // {
                badPlatforms = [ ];
              };
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
            pkgs.systemdLibs
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
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
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
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.defused;
          defused = mkDefused pkgs;
          # Runs on a musl system with no shared libraries at all.
          defused-static = (mkDefused (staticPackages pkgs)).overrideAttrs (old: {
            pname = "defused-static";
            # Without this Meson takes libsystemd.so over libsystemd.a.
            mesonFlags = (old.mesonFlags or [ ]) ++ [ "-Dprefer_static=true" ];
          });
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
