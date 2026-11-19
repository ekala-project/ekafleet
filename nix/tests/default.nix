{ pkgs, lib }:

{
  module-basic = import ./module-basic.nix { inherit pkgs lib; };
  cli-operations = import ./cli-operations.nix { inherit pkgs lib; };
  rest-api = import ./rest-api.nix { inherit pkgs lib; };
  server-agent = import ./server-agent.nix { inherit pkgs lib; };
  deploy-closure = import ./deploy-closure.nix { inherit pkgs lib; };
  mesh = import ./mesh.nix { inherit pkgs lib; };
  colocated = import ./colocated.nix { inherit pkgs lib; };
  dns = import ./dns.nix { inherit pkgs lib; };
  secrets = import ./secrets.nix { inherit pkgs lib; };
  volumes = import ./volumes.nix { inherit pkgs lib; };
  oci-container = import ./oci-container.nix { inherit pkgs lib; };
  oci-registry = import ./oci-registry.nix { inherit pkgs lib; };
  metrics-alerts = import ./metrics-alerts.nix { inherit pkgs lib; };
  fleet-operations = import ./fleet-operations.nix { inherit pkgs lib; };
  lifecycle = import ./lifecycle.nix { inherit pkgs lib; };
  fleet-module = import ./fleet-module.nix { inherit pkgs lib; };
}
