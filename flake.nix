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

      # The dynamic linker path a real (non-Nix) distro's glibc actually
      # installs itself at, keyed by Nix system string. defusedFhs's
      # binaries get patched to point here instead of their build-time
      # /nix/store interpreter -- see defusedFhs below.
      glibcInterpreterBySystem = {
        x86_64-linux = "/lib64/ld-linux-x86-64.so.2";
        aarch64-linux = "/lib/ld-linux-aarch64.so.1";
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
                  pkgs.cpio
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

                # Guard against the packaged binaries embedding a Nix store
                # path (e.g. an unpatched PT_INTERP/RUNPATH) -- those don't
                # exist off-NixOS, so a real install of the .deb/.rpm would
                # be unable to execute at all. See defusedFhs in flake.nix.
                echo "== scanning extracted .deb for /nix/store references =="
                mkdir -p extracted-deb
                dpkg-deb -x ${self.packages.${system}.deb} extracted-deb
                if grep -rlaF /nix/store extracted-deb; then
                  echo "ERROR: /nix/store reference(s) found in .deb contents (see above)" >&2
                  exit 1
                fi

                echo "== scanning extracted .rpm for /nix/store references =="
                mkdir -p extracted-rpm
                rpm2cpio ${self.packages.${system}.rpm} | cpio -idm --quiet -D extracted-rpm
                if grep -rlaF /nix/store extracted-rpm; then
                  echo "ERROR: /nix/store reference(s) found in .rpm contents (see above)" >&2
                  exit 1
                fi

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
              "-Dlibfuse_fusermount3=${pkgs.fuse3}/bin/fusermount3"
            ];
          };

          glibcInterpreter =
            glibcInterpreterBySystem.${system}
              or (throw "flake.nix: no glibc interpreter mapping for system ${system}");

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
          #
          # nixpkgs' gcc-wrapper/dynamic linker always bakes Nix store paths
          # into the built binaries (PT_INTERP + RUNPATH) regardless of how
          # the configure/build/install phases are driven -- that's
          # orthogonal to the -Dprefix issue above and isn't something any
          # combination of meson flags fixes. Off-Nix systems don't have
          # that interpreter path, so the binaries would fail to execute at
          # all. patchelf the two binaries in postInstall to point at the
          # target distro's real dynamic linker and drop the Nix store
          # RUNPATH, so they fall back to the standard system library search
          # path (where the target distro's own libseccomp/libsystemd --
          # already declared as nfpm runtime deps -- will be found).
          #
          # This does NOT make the binaries portable to arbitrarily old
          # distros: they're still linked against nixpkgs' glibc symbol
          # versions. See README.md's Installation section for the actual
          # minimum distro versions this implies.
          defusedFhs = pkgs.stdenv.mkDerivation {
            pname = "defused-fhs";
            inherit version src;
            nativeBuildInputs = defused.nativeBuildInputs ++ [
              pkgs.patchelf
              pkgs.python3
            ];
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
                            for exe in "$out/usr/bin/fusermount3" "$out/usr/lib/defused/defused"; do
                              # patchelf --remove-rpath only unlinks the DT_RUNPATH tag;
                              # the bytes of the old rpath string physically remain in
                              # the file's now-unreferenced .dynstr tail, so grep-based
                              # scans (see checks.<system>.packaging) would still flag
                              # a Nix store reference even after the tag is gone.
                              # Capture the old value first and overwrite those bytes
                              # in place (same length, so no file offsets shift).
                              oldRpath=$(patchelf --print-rpath "$exe")
                              patchelf --set-interpreter '${glibcInterpreter}' --remove-rpath "$exe"
                              if [ -n "$oldRpath" ]; then
                                python3 -c '
              import sys
              path, old = sys.argv[1], sys.argv[2].encode()
              with open(path, "rb") as f:
                  data = f.read()
              data = data.replace(old, b"X" * len(old))
              with open(path, "wb") as f:
                  f.write(data)
              ' "$exe" "$oldRpath"
                              fi
                            done
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
