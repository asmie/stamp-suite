{
  description = "stamp-suite — Simple Two-Way Active Measurement Protocol (STAMP)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "stamp-suite";
            version = "0.6.1";

            src = self;


            cargoHash = "sha256-9xwRzJyuz2BMk+1ThemzKqO/gVsX+aLhBL2oLWMyVwc=";

            meta = with pkgs.lib; {
              description = "Simple Two-Way Active Measurement Protocol (STAMP) implementation";
              homepage = "https://github.com/asmie/stamp-suite";
              license = licenses.mit;
              mainProgram = "stamp-suite";
            };
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
          ];
        };
      }
    );
}
