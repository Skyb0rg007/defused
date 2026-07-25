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

      # meson.build's version : '...' is the single source of truth for the
      # project version; extract it here rather than hand-maintaining a
      # second copy in packaging/nfpm.yaml.
      version =
        let
          matched = builtins.match ".*version[ \t]*:[ \t]*'([0-9]+\\.[0-9]+(\\.[0-9]+)?)'.*" (
            builtins.readFile ./meson.build
          );
        in
        if matched == null then
          throw "flake.nix: could not extract version from meson.build"
        else
          builtins.elemAt matched 0;

      # nfpm's arch names, keyed by Nix system string. Extend this alongside
      # `systems` above if support for more architectures is added.
      nfpmArchBySystem = {
        x86_64-linux = "amd64";
        aarch64-linux = "arm64";
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
          reuse-lint = pkgs.runCommand "defused-reuse-lint" { nativeBuildInputs = [ pkgs.reuse ]; } ''
            cd ${src}
            reuse lint
            touch $out
          '';

          packaging =
            pkgs.runCommand "defused-packaging-check"
              {
                nativeBuildInputs = [
                  pkgs.dpkg
                  pkgs.rpm
                ];
              }
              ''
                set -eu
                export HOME="$TMPDIR"

                echo "== .deb info =="
                dpkg-deb --info ${self.packages.${system}.deb}
                echo "== .deb contents =="
                dpkg-deb --contents ${self.packages.${system}.deb} | tee deb-contents.txt
                grep -qF usr/bin/fusermount3 deb-contents.txt
                grep -qF usr/lib/defused/defused deb-contents.txt
                grep -qF usr/lib/systemd/system/defused.service deb-contents.txt
                grep -qF usr/lib/systemd/system/defused.socket deb-contents.txt
                grep -qF usr/share/polkit-1/actions/website.soss.defused.policy deb-contents.txt

                echo "== .rpm info =="
                rpm -qip ${self.packages.${system}.rpm}
                echo "== .rpm contents =="
                rpm -qlp ${self.packages.${system}.rpm} | tee rpm-contents.txt
                grep -qF /usr/bin/fusermount3 rpm-contents.txt
                grep -qF /usr/lib/defused/defused rpm-contents.txt
                grep -qF /usr/lib/systemd/system/defused.service rpm-contents.txt
                grep -qF /usr/lib/systemd/system/defused.socket rpm-contents.txt
                grep -qF /usr/share/polkit-1/actions/website.soss.defused.policy rpm-contents.txt

                touch $out
              '';
        }
      );

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          defused = pkgs.stdenv.mkDerivation {
            pname = "defused";
            inherit version src;
            nativeBuildInputs = [
              pkgs.meson
              pkgs.ninja
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.libseccomp
              pkgs.systemdLibs
            ];
            mesonFlags = [
              (lib.mesonOption "libfuse_fusermount3" (lib.getExe' pkgs.fuse3 "fusermount3"))
            ];

            meta = {
              description = "SETUID-less fusermount3 implementation";
              license = lib.licenses.gpl2Only;
              platforms = lib.platforms.linux;
            };
          };

          # A /usr-prefixed build of defused, staged into $out as a destdir
          # tree (rather than $out itself acting as the install prefix) --
          # .deb/.rpm packages need the on-disk layout to match
          # units/defused.service's hardcoded ExecStart=/usr/lib/defused/defused
          # (see meson.build), which only resolves when built with
          # -Dprefix=/usr.
          #
          # This can't just be `defused.overrideAttrs` adding "-Dprefix=/usr"
          # to mesonFlags: nixpkgs' mesonConfigurePhase setup hook already
          # passes its own "--prefix=$prefix" (conflicting with a second
          # -Dprefix), and unconditionally pins --bindir/--libdir/etc. to
          # paths under $out regardless of --prefix, which would still
          # scatter files under $out instead of staging a coherent /usr tree
          # under DESTDIR. So this drives meson directly instead of going
          # through that hook.
          defusedFhs = pkgs.stdenv.mkDerivation {
            pname = "defused-fhs";
            inherit version src;
            nativeBuildInputs = defused.nativeBuildInputs;
            buildInputs = defused.buildInputs;

            configurePhase = ''
              runHook preConfigure
              meson setup build -Dprefix=/usr --buildtype=plain
              runHook postConfigure
            '';

            buildPhase = ''
              runHook preBuild
              ninja -C build
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              DESTDIR="$out" meson install -C build --no-rebuild
              runHook postInstall
            '';
          };

          nfpmArch =
            nfpmArchBySystem.${system} or (throw "flake.nix: no nfpm arch mapping for system ${system}");

          mkNfpmPackage =
            { packager, extension }:
            pkgs.runCommand "defused-${extension}-${version}-${nfpmArch}" { nativeBuildInputs = [ pkgs.nfpm ]; }
              ''
                export DEFUSED_VERSION=${lib.escapeShellArg version}
                export DEFUSED_ARCH=${lib.escapeShellArg nfpmArch}
                cd ${defusedFhs}
                nfpm package -f ${src}/packaging/nfpm.yaml -p ${packager} -t "$out"
              '';
        in
        {
          default = self.packages.${system}.defused;
          inherit defused;

          deb = mkNfpmPackage {
            packager = "deb";
            extension = "deb";
          };

          rpm = mkNfpmPackage {
            packager = "rpm";
            extension = "rpm";
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
              pkgs.fuse3
            ];
            shellHook = ''
              export NIX_CFLAGS_COMPILE="-U_FORTIFY_SOURCE $NIX_CFLAGS_COMPILE"
            '';
          };
        }
      );
    };
}
