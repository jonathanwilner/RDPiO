# Home Manager module for rdpio (W365 / AVD client).
#
# Consumed from the flake:
#   homeManagerModules.default = import ./modules/home-manager/rdpio.nix self;
#
# Usage:
#   programs.rdpio.enable = true;                       # install the bundle
#   programs.rdpio.terminal = "ghostty";                # optional pin
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.rdpio;
in
{
  options.programs.rdpio = {
    enable = lib.mkEnableOption "RDPiO — Windows 365 / AVD RDP client (FreeRDP integration)";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.rdpio-w365;
      defaultText = "self.packages.<system>.rdpio-w365";
      description = "The rdpio bundle to install (rdpio + RDPECAM FreeRDP + launchers + desktop entries).";
    };

    terminal = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
    default = null;
      example = "ghostty";
      description = ''
        Terminal the W365 launcher entries re-exec into when started from a
        launcher (fuzzel, DMS). Defaults to auto-detection: $TERMINAL, then
        ghostty, alacritty, kitty, xterm, foot, wezterm.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];

    # The launcher honors $TERMINAL before its built-in order; pinning it
    # here makes the desktop entries deterministic per-host.
    home.sessionVariables = lib.mkIf (cfg.terminal != null) {
      TERMINAL = cfg.terminal;
    };
  };
}
