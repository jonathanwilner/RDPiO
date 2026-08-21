{
  description = "RDPiO — GPU-accelerated RDP client; Windows 365 / AVD on Linux through FreeRDP";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # FreeRDP is pinned on its own nixpkgs revision (NOT followable): the ARM
  # gateway + AAD path needs FreeRDP ≥ 3.25 — nixpkgs freerdp 3.24 stalls for
  # minutes before its sign-in prompt — and consumers that follow their own
  # nixpkgs must not silently downgrade the bundled client. rdpio itself
  # builds fine on any nixpkgs.
  inputs.nixpkgs-freerdp.url = "github:NixOS/nixpkgs/ffb3c9b700e759be2ef13237c9d8f953b32a1e46";

  outputs =
    { self, nixpkgs, nixpkgs-freerdp }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;

      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      version = cargoToml.workspace.package.version;
      # Build stamp embedded into the binary (build.rs honors RDPIO_BUILD).
      buildStamp = "nix-${self.shortRev or "dirty"}";
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          # Dedicated pin: see inputs.nixpkgs-freerdp — the bundled FreeRDP
          # must stay ≥ 3.25 even when a consumer's nixpkgs is older.
          pkgsFreerdp = nixpkgs-freerdp.legacyPackages.${system};
        in
        rec {
          # The rdpio client itself. Pure-Rust workspace (bundled SQLite +
          # mimalloc compile with the stdenv toolchain; no system deps).
          rdpio = pkgs.rustPlatform.buildRustPackage {
            pname = "rdpio";
            inherit version;
            src = lib.cleanSourceWith {
              src = ./.;
              filter =
                path: type:
                let
                  base = baseNameOf path;
                in
                !lib.elem base [
                  "target"
                  ".git"
                  ".github"
                  "result"
                  ".direnv"
                ];
            };
            cargoLock.lockFile = ./Cargo.lock;
            buildAndTestSubdir = "crates/rdp-client";
            # No .git in the sandbox — build.rs prefers this env stamp.
            preBuild = ''
              export RDPIO_BUILD="${buildStamp}"
            '';
            doCheck = false; # tests need a live browser-history fixture env; run via `nix develop`
            meta = with lib; {
              description = "GPU-accelerated RDP client (W365/AVD on Linux via FreeRDP)";
              license = licenses.mit;
              mainProgram = "rdpio";
              platforms = platforms.linux;
            };
          };

          # FreeRDP 3 with the upstream MS-RDPECAM client channel enabled
          # (CHANNEL_RDPECAM_CLIENT=ON; upstream default is OFF). The only
          # change vs stock nixpkgs FreeRDP — no source patching. libusb1 is
          # the one extra dependency the channel's v4l subsystem needs.
          freerdp-ecam = pkgsFreerdp.freerdp.overrideAttrs (old: {
            cmakeFlags = (old.cmakeFlags or [ ]) ++ [
              "-DCHANNEL_RDPECAM_CLIENT=ON"
            ];
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgsFreerdp.libusb1 ];
          });

          # Terminal-aware W365 launcher: pins RDPIO_FREERDP to the
          # RDPECAM-enabled build above and re-execs itself in a terminal
          # when started from a launcher (fuzzel / DMS) with no tty.
          rdpio-w365-launch = pkgs.writeShellScriptBin "rdpio-w365-launch" ''
            set -euo pipefail
            export RDPIO_FREERDP="${freerdp-ecam}/bin/sdl-freerdp"

            # Already have a terminal → run the session here.
            if [ -t 0 ] && [ -t 1 ]; then
              exec "${rdpio}/bin/rdpio" --w365 "$@"
            fi

            # Find a terminal: $TERMINAL first, then the usual suspects.
            run_term() { # run_term <binary> <args-before-command...>
              local bin=$1; shift
              command -v "$bin" >/dev/null 2>&1 || return 1
              exec "$bin" "$@" "${rdpio}/bin/rdpio" --w365 "$@"
            }
            if [ -n "''${TERMINAL:-}" ]; then
              run_term "$TERMINAL" -e
            fi
            for t in ghostty alacritty kitty xterm; do
              run_term "$t" -e && exit 0
            done
            run_term foot ""
            run_term wezterm start --
            echo "rdpio: no terminal found (tried \$TERMINAL, ghostty, alacritty, kitty, xterm, foot, wezterm)" >&2
            exit 1
          '';

          # The consumable bundle: rdpio + RDPECAM FreeRDP + launchers +
          # XDG desktop entries (picked up by fuzzel, DMS, GNOME, …).
          rdpio-w365 = pkgs.symlinkJoin {
            name = "rdpio-w365-${version}";
            paths = [
              rdpio
              rdpio-w365-launch
              (pkgs.makeDesktopItem {
                name = "rdpio-w365";
                desktopName = "Windows 365 (Cloud PC)";
                comment = "Sign in to Windows 365 and connect to your Cloud PC through FreeRDP";
                exec = "rdpio-w365-launch";
                icon = "rdpio-w365";
                terminal = false;
                categories = [
                  "Network"
                  "RemoteAccess"
                ];
                startupNotify = true;
                keywords = [
                  "rdp"
                  "w365"
                  "cloud pc"
                  "avd"
                  "remote"
                ];
              })
              (pkgs.makeDesktopItem {
                name = "rdpio-w365-doctor";
                desktopName = "Windows 365 Connection Doctor";
                comment = "Diagnose the rdpio Windows 365 integration (FreeRDP, camera, tokens)";
                exec = "rdpio-w365-launch --w365-doctor";
                icon = "rdpio-w365";
                terminal = false;
                categories = [ "Network" ];
                keywords = [
                  "rdp"
                  "w365"
                  "doctor"
                ];
              })
              (pkgs.stdenv.mkDerivation {
                name = "rdpio-w365-icon-${version}";
                dontUnpack = true;
                installPhase = ''
                  install -Dm644 ${./assets/rdpio-w365.svg} \
                    $out/share/icons/hicolor/scalable/apps/rdpio-w365.svg
                '';
              })
            ];
            meta = rdpio.meta // {
              description = "rdpio with RDPECAM-enabled FreeRDP and W365 launchers";
              mainProgram = "rdpio-w365-launch";
            };
          };

          default = rdpio-w365;
        }
      );

      overlays.default =
        final: prev:
        let
          ours = self.packages.${final.system};
        in
        {
          inherit (ours) rdpio rdpio-w365 freerdp-ecam;
        };

      # `programs.rdpio.enable = true;` — installs the bundle (desktop
      # entries included). Optional: programs.rdpio.terminal to pin the
      # terminal used by the launcher entries.
      homeManagerModules.default = import ./modules/home-manager/rdpio.nix self;

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.rustc
              pkgs.cargo
              pkgs.rustfmt
              pkgs.clippy
              pkgs.pkg-config
              pkgs.v4l-utils # camera diagnostics
              self.packages.${system}.freerdp-ecam
            ];
            # rdpio's FreeRDP launcher prefers sdl-freerdp3/sdl-freerdp; the env
            # var pins the exact RDPECAM-enabled build from this flake.
            RDPIO_FREERDP = "${self.packages.${system}.freerdp-ecam}/bin/sdl-freerdp";
          };
        }
      );
    };
}
