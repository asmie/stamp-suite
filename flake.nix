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
        allFeatures = [ "ttl-nix" "ttl-pnet" "metrics" "snmp" "hwtstamp" "control" ];

        # Shared by the package and lint derivations. After a Cargo.lock change,
        # temporarily use pkgs.lib.fakeHash, build, then copy the reported hash.
        cargoDepsHash = "sha256-hxgGBIIz0FiSKbHftMZ5CsZ0yV4Aq4BXpfnwnWlNEu8=";
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "stamp-suite";
            version = "1.0.0";

            src = self;

            cargoHash = cargoDepsHash;

            buildFeatures = allFeatures;
            # Honour --all-features for the cargo test phase too so the
            # metrics / snmp feature-gated tests run alongside the rest.
            cargoTestFlags = [ "--all-features" ];

            postInstall = ''
              install -Dm644 dist/man/stamp-suite.1 $out/share/man/man1/stamp-suite.1
              install -Dm644 mibs/STAMP-SUITE-MIB.mib $out/share/snmp/mibs/STAMP-SUITE-MIB.mib
              mkdir -p $out/share/doc/stamp-suite
              cp README.md CHANGELOG.md SECURITY.md LICENSE doc/usage.md doc/architecture.md doc/security.md $out/share/doc/stamp-suite/
              mkdir -p $out/share/doc/stamp-suite/examples
              cp examples/*.toml $out/share/doc/stamp-suite/examples/
            '' + pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
              install -Dm644 dist/systemd/stamp-suite.service $out/lib/systemd/system/stamp-suite.service
              substituteInPlace $out/lib/systemd/system/stamp-suite.service \
                --replace-fail /usr/bin/stamp-suite $out/bin/stamp-suite
            '';

            meta = with pkgs.lib; {
              description = "Simple Two-Way Active Measurement Protocol (STAMP) implementation";
              homepage = "https://github.com/asmie/stamp-suite";
              license = licenses.mit;
              mainProgram = "stamp-suite";
              platforms = platforms.unix;
            };
          };
        };

        # Flake checks: build/tests, Clippy and formatting.
        checks = {
          build = self.packages.${system}.default;

          clippy = pkgs.rustPlatform.buildRustPackage {
            pname = "stamp-suite-clippy";
            version = "1.0.0";
            src = self;
            cargoHash = cargoDepsHash;
            buildFeatures = allFeatures;
            nativeBuildInputs = [ pkgs.clippy ];
            buildPhase = ''
              cargo clippy --locked --all-features --all-targets -- -D warnings
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
