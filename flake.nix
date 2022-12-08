{

  description = "virtual environments";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };


  outputs = { self, flake-utils, rust-overlay, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system: {
      devShell =
        let
          pkgs = import nixpkgs {
            inherit system;

            overlays = [ rust-overlay.overlays.default ];
          };

        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            openssl_3
            pkg-config
            rust-bin.stable.latest.default
          ];
        };
    });
}
