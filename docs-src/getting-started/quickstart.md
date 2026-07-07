# Quick Start

This guide walks through setting up a minimal fleet with one server and one agent.

## 1. Start the Server

On your first machine, start ekafleet in server mode:

```bash
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal
```

By default, the server listens on:
- `0.0.0.0:7400` — gRPC (agent connections + Attest RPC)
- `0.0.0.0:7402` — HTTP API (health, metrics)

The `--domain` flag sets the SPIFFE trust domain (default: `fleet.internal`). The server generates a persistent identity and SPIFFE SVID (`spiffe://<domain>/server/<server-id>`).

## 2. Create a Join Token

Generate a one-time join token for SPIFFE node attestation:

```bash
ekafleet token create --type=agent
```

This token can only be used once. After successful attestation, it is consumed and cannot be replayed.

## 3. Join an Agent

On another machine, start the agent with the join token:

```bash
ekafleet agent --join server-ip:7400 --join-token <TOKEN> --ca-cert /path/to/ca.pem
```

The agent will:
- Call the `Attest` RPC with the join token to bootstrap its SPIFFE identity
- Receive a node SVID (`spiffe://<domain>/agent/<node-id>`) and persist it to disk
- Establish a mTLS gRPC connection using the node SVID as client certificate
- Start the SPIFFE Workload API socket at `/run/ekafleet/workload-api.sock`
- Begin sending heartbeats every 5 seconds and reporting status every 10 seconds

Legacy bearer token auth is still supported via `--token` for migration.

## 4. Write Fleet Configuration

Create a `fleet.nix` that defines your services and machines:

```nix
{ pkgs }:
{
  fleet = {
    name = "my-fleet";
    domain = "fleet.internal";

    services.web = {
      command = "${pkgs.my-web-app}/bin/server";
      ports.http = {
        port = 8080;
        healthCheck.path = "/health";
      };
      resources = {
        cpu.request = 500;
        memory.request = 512;
      };
      scheduling = {
        replicas = 2;
        type = "service";
      };
    };

    machines.node-1 = {
      targetHost = "10.0.1.1";
      labels = { role = "app"; };
      capacity = { cpu = 4000; memory = 8192; };
    };

    machines.node-2 = {
      targetHost = "10.0.1.2";
      labels = { role = "app"; };
      capacity = { cpu = 4000; memory = 8192; };
    };
  };
}
```

## 5. Plan and Apply

Preview what will change:

```bash
ekafleet plan --config fleet.nix
```

Apply the deployment:

```bash
ekafleet apply --config fleet.nix
```

Or run in continuous reconciliation mode:

```bash
ekafleet apply --config fleet.nix --watch
```

## 6. Check Status

```bash
ekafleet status
```

This shows fleet health, connected nodes, and service placement.
