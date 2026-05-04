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

        # Cargo features compiled into the nix-built binary and exercised
        # by the check phase. Mirrors `cargo build/test --all-features`.
        allFeatures = [ "ttl-nix" "ttl-pnet" "metrics" "snmp" ];
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "stamp-suite";
            version = "0.7.0";

            src = self;

            cargoHash = "sha256-5vNX7e0MLRK7Z+hNqJ4ded1cBYMBi1FOAU7XgiNhsns=";

            buildFeatures = allFeatures;
            # Honour --all-features for the cargo test phase too so the
            # metrics / snmp feature-gated tests run alongside the rest.
            cargoTestFlags = [ "--all-features" ];

            meta = with pkgs.lib; {
              description = "Simple Two-Way Active Measurement Protocol (STAMP) implementation";
              homepage = "https://github.com/asmie/stamp-suite";
              license = licenses.mit;
              mainProgram = "stamp-suite";
              platforms = platforms.unix;
            };
          };
        };

        # `nix flake check` exercises the package build (which includes the
        # cargo test phase) plus a clippy-with-warnings-as-errors gate that
        # mirrors CI.
        checks = {
          build = self.packages.${system}.default;

          clippy = pkgs.rustPlatform.buildRustPackage {
            pname = "stamp-suite-clippy";
            version = "0.7.0";
            src = self;
            cargoHash = "sha256-5vNX7e0MLRK7Z+hNqJ4ded1cBYMBi1FOAU7XgiNhsns=";
            buildFeatures = allFeatures;
            nativeBuildInputs = [ pkgs.clippy ];
            buildPhase = ''
              cargo clippy --all --all-features --tests -- -D warnings
            '';
            doCheck = false;
            installPhase = "mkdir -p $out";
          };

          fmt = pkgs.runCommand "stamp-suite-fmt"
            { nativeBuildInputs = [ pkgs.rustfmt pkgs.cargo ]; } ''
            cd ${self}
            cargo fmt --all -- --check
            touch $out
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
          ];
        };
      }
    );
}
