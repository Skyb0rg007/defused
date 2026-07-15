# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: GPL-2.0-or-later

{
  self,
  pkgs,
  system,
}:

{
  simple = import ./simple.nix {
    inherit self pkgs system;
  };

  mount-namespace = import ./mount-namespace.nix {
    inherit self pkgs system;
  };

  mountpoint-ownership = import ./mountpoint-ownership.nix {
    inherit self pkgs system;
  };

  mount-options = import ./mount-options.nix {
    inherit self pkgs system;
  };

  file-mountpoint = import ./file-mountpoint.nix {
    inherit self pkgs system;
  };
}
