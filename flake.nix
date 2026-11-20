{
  description = "huginn-net development environment";

  inputs = {
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      crane,
      flake-utils,
      nixpkgs,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rustfmt"
            "clippy"
          ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        commonArgs = {
          src = ./.;
          strictDeps = true;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libpcap ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      in
      {
        packages.default = craneLib.buildPackage (
          commonArgs
          // {
            pname = "huginn-net-examples";
            doCheck = false;
            inherit cargoArtifacts;
            cargoBuildExtraArgs = "--workspace --examples";
            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              install -m755 target/release/examples/cli{,-http,-tcp,-tls} $out/bin/
              runHook postInstall
            '';
          }
        );

        devShells.default = pkgs.mkShell {
          packages = [
            toolchain
          ]
          ++ (with pkgs; [
            cargo-audit
            cargo-deny
            cargo-sort
            jq
            libpcap
            pkg-config
          ]);
        };

        formatter = pkgs.nixfmt;
      }
    );
}
