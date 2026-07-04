# Quick Start

This guide walks through setting up a minimal fleet with one server and one agent.

## 1. Start the Server

On your first machine, start ekafleet in server mode:

```bash
ekafleet server --data-dir /var/lib/ekafleet
```

By default, the server listens on:
- `0.0.0.0:7400` — gRPC (agent connections)
- `0.0.0.0:7402` — HTTP API (health, metrics)

## 2. Create a Join Token

Generate an authentication token for agents:

```bash
ekafleet token create --type=agent
```

## 3. Join an Agent

On another machine, start the agent and join the server:

```bash
ekafleet agent --join server-ip:7400 --token <TOKEN>
```

The agent will:
- Generate a unique node ID (persisted in `/var/lib/ekafleet/node-id`)
- Establish a bidirectional gRPC stream to the server
- Begin sending heartbeats every 5 seconds
- Report its status every 10 seconds

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
