# Quick Start

This guide walks through setting up a minimal fleet with one server and one agent.

## Local Development Mode

For testing fleet configurations without real machines, TLS, or WireGuard:

```bash
ekafleet dev
```

This starts server + agent in a single process on `127.0.0.1`. A dev token is printed at startup. The data directory defaults to `/tmp/ekafleet-dev`.

```bash
# Check status
curl -H "Authorization: Bearer dev-token" http://127.0.0.1:7402/v1/status

# JSON output for scripting
ekafleet status --server 127.0.0.1:7400 --output json
```

## Production Setup

For production, use the NixOS module (see [NixOS Module Reference](../reference/nixos-module.md)) which deploys the process-isolated topology automatically. The steps below show the manual CLI approach for understanding or non-NixOS environments.

### 1. Start the Server

On your first machine, start ekafleet in server mode:

```bash
ekafleet server --data-dir /var/lib/ekafleet --domain fleet.internal
```

By default, the server listens on:
- `0.0.0.0:7400` — gRPC (`FleetControl` for the CLI and agents, `FleetBootstrap` for node joins)
- `0.0.0.0:7402` — HTTP API (health, metrics)

The `--domain` flag sets the SPIFFE trust domain (default: `fleet.internal`). The server generates a persistent identity and SPIFFE SVID (`spiffe://<domain>/server/<server-id>`).

For process isolation, run the CA signer separately:

```bash
# Terminal 1: CA signer (holds private key, no network)
ekafleet ca-signer --data-dir /var/lib/ekafleet-ca --domain fleet.internal

# Terminal 2: Control plane (connects to CA via socket)
ekafleet server --data-dir /var/lib/ekafleet-server --ca-socket /run/ekafleet-ca/ca.sock
```

## 2. Create a Join Token

Ask the server for a one-time join token bound to the new node's name (the CLI
authenticates with the admin token via `EKAFLEET_TOKEN`):

```bash
ekafleet token create --type agent --node web-1 --ttl 1h > join-token
```

The token can be used once, only by an agent joining as `web-1`, and expires
after `--ttl` (default 1h, maximum 7d). The server stores only its SHA-256 hash.

## 3. Join an Agent

On another machine, start the agent with the join token:

```bash
ekafleet agent --join server-ip:7400 --node-name web-1 \
  --join-token-file ./join-token --ca-cert /path/to/ca.pem
```

`--node-name` defaults to the hostname. The agent will:
- Generate a key locally and call `FleetBootstrap.Attest` with the join token and a CSR
- Receive a 24-hour node SVID (`spiffe://<domain>/agent/<node-name>`) and persist it to disk (key mode 0400)
- Establish a mTLS gRPC connection using the node SVID as client certificate, renewing the SVID over that connection at half-life
- Start the SPIFFE Workload API socket at `/run/ekafleet/workload-api.sock`
- Begin sending heartbeats every 5 seconds and reporting status every 10 seconds

Restarts reuse the persisted SVID; the join token is no longer needed. An agent
offline for longer than 24 hours needs a new join token. Bearer-token agents
(`--token`) are only accepted by `ekafleet dev`.

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
