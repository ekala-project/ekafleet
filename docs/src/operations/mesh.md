# Mesh Networking

ekafleet manages a kernel WireGuard mesh network for encrypted inter-service communication.

## How It Works

1. Each machine gets a mesh IP from the fleet config (`10.100.{index}.1/16`)
2. The agent creates a WireGuard interface, generates a keypair, and assigns the IP
3. Peer lists are pushed from the server whenever machines join or leave
4. All inter-service traffic flows encrypted over the mesh

## WireGuard Interface

The agent manages a `wg-ekafleet` interface:

```bash
# View interface status
wg show wg-ekafleet

# View assigned peers
wg show wg-ekafleet peers
```

Configuration happens automatically — no manual WireGuard setup required.

## Peer Management

When the server sends a `PeerUpdate` message, the agent:

1. Adds new peers with their public key, endpoint, and allowed IPs
2. Updates peers whose keys or endpoints have changed
3. Removes peers that are no longer in the fleet
4. Configures persistent keepalive (25 seconds) for NAT traversal

## Mesh IP Assignment

IPs are deterministic based on the machine's index in the fleet:

```text
Machine 1:  10.100.0.1/16
Machine 2:  10.100.0.2/16
Machine 3:  10.100.0.3/16
...
```

## Security

The WireGuard mesh provides encryption at the network layer. Combined with mTLS at the application layer, this provides defense-in-depth:

- **WireGuard** — Encrypts all traffic between machines
- **mTLS** — Authenticates and encrypts service-to-service traffic
- **nftables** — Enforces network policy as a third layer
