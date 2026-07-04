{
  stdenv,
  fenix,
  pkg-config,
  openssl,
  protobuf,
}:

stdenv.mkDerivation {
  name = "dev";

  nativeBuildInputs = [
    (fenix.default.withComponents [
      "cargo"
      "clippy"
      "rust-std"
      "rustc"
      "rustfmt-preview"
    ])
    pkg-config
    protobuf
  ];
  buildInputs = [ openssl ];
}
