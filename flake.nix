{
  description = "A development environment for a rust project.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {inherit system overlays;};
      rusttoolchain =
        pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
    in rec {
      # nix develop
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [rusttoolchain pkg-config openssl go];
        # Go's cgo and Rust's cc crate each pull in different Apple SDK
        # versions via DEVELOPER_DIR / DEVELOPER_DIR_FOR_TARGET. Go 1.25+
        # refuses to build when both are set with different values. Unsetting
        # the target-specific one lets cgo fall back to DEVELOPER_DIR.
        shellHook = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
          unset DEVELOPER_DIR_FOR_TARGET
        '';
      };
    });
}
