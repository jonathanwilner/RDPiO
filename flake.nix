{
  description = "RDPiO — Linux dev shell with an RDPECAM-enabled FreeRDP 3";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      # FreeRDP 3 with the upstream MS-RDPECAM client channel enabled
      # (CHANNEL_RDPECAM_CLIENT=ON; upstream default is OFF). This is the only
      # change vs stock nixpkgs FreeRDP — no source patching. libusb1 is the
      # one extra dependency the channel's v4l subsystem needs (uvc_h264.c).
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          freerdp-ecam = pkgs.freerdp.overrideAttrs (old: {
            cmakeFlags = (old.cmakeFlags or [ ]) ++ [
              "-DCHANNEL_RDPECAM_CLIENT=ON"
            ];
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.libusb1 ];
          });
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
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
        });
    };
}
