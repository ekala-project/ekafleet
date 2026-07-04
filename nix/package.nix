{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  perl,
  protobuf,
}:

rustPlatform.buildRustPackage {
  pname = "ekaos-fleet";
  version =
    let
      cargo_toml = builtins.readFile ../Cargo.toml;
      cargo_info = builtins.fromTOML cargo_toml;
    in
    cargo_info.package.version;

  cargoLock.lockFile = ../Cargo.lock;
  src = ../.;

  nativeBuildInputs = [
    perl
    pkg-config
    protobuf
  ];

  buildInputs = [
    openssl
  ];

  doCheck = false;

  meta = with lib; {
    description = "EkaOS Fleet";
    mainProgram = "ekafleet";
  };
}
