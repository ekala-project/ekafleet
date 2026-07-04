final: prev: with final; {
  dev-shell = callPackage ./dev-shell.nix { };

  ekaos-fleet = callPackage ./package.nix { };
}
