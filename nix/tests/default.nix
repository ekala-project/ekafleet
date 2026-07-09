{ pkgs, lib }:

{
  module-basic = import ./module-basic.nix { inherit pkgs lib; };
  cli-operations = import ./cli-operations.nix { inherit pkgs lib; };
  rest-api = import ./rest-api.nix { inherit pkgs lib; };
  server-agent = import ./server-agent.nix { inherit pkgs lib; };
}
