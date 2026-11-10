# Mesh Networking

ekafleet manages a kernel WireGuard mesh network for encrypted inter-service communication.

## How It Works

1. The agent is started with `--wireguard-endpoint <ip:port> --mesh-index <n>`
   (NixOS: `services.ekafleet.agent.wireguard.endpoint` and `.meshIndex`). Without
   them the agent leaves WireGuard alone. The agent must hold a node SVID, so it
   must have joined with a join token.
2. The agent creates the `wg-fleet` interface, generates a keypair, assigns its mesh
   IP and listens on the endpoint's port.
3. It sends the server a **peer advert** (its node ID, WireGuard public key,
   endpoint, `/32` mesh address and a timestamp) signed with its node SVID key.
4. The server verifies the advert and relays the full set of adverts to every agent.
   Each agent verifies every advert again before configuring the peer.
5. All inter-service traffic flows encrypted over the mesh.

```bash
wg show wg-fleet          # interface status
wg show wg-fleet peers    # installed peers
```

Open the WireGuard UDP port (default 51820) in the firewall; the module does not do it for you.

## Signed Peer Adverts

A WireGuard public key is only useful if you know whose it is. Each advert is signed
with the advertising node's SVID private key (ECDSA P-256). The signature covers the
context string `ekafleet-wireguard-advert-v1` followed by the node ID, public key,
endpoint, mesh address and `issued_at` timestamp. The advert carries the node's SVID
certificate chain.

An advert is accepted only if:

- the certificate chain verifies to the fleet CA and is within its validity period;
- the certificate's SPIFFE ID is `spiffe://<domain>/agent/<node_id>` for the advertised node;
- the signature is valid;
- the mesh address is a single `/32` (wider ranges would capture other nodes' traffic);
- the key and address are not already used by another node; and
- `issued_at` is newer than the node's previous advert.

The server also requires that the advert arrives on the advertising node's own mTLS
control stream (bearer-token agents cannot advertise) and that `issued_at` is within
the last five minutes. Agents verify relayed adverts against the CA certificate they
were configured with (`--ca-cert`), not against anything the server sends. A
compromised server can therefore withhold peers but cannot substitute a key.

## Peer Management

When the server sends a `PeerUpdate` message, the agent:

1. Drops adverts that fail verification, and its own advert
2. Adds new peers with their public key, endpoint, and allowed IP
3. Updates peers whose keys or endpoints have changed (removing the old key)
4. Removes peers that are no longer in the update; the server withdraws a node's
   advert when its control stream closes
5. Configures persistent keepalive (25 seconds) for NAT traversal

## Mesh IP Assignment

The mesh address comes from the node's `--mesh-index`:

```text
index 1:    10.100.0.1
index 2:    10.100.0.2
index 258:  10.100.1.2
```

Indexes are assigned by hand and must be unique. The server refuses an advert whose
address another node already holds.

> **Limitations:** adverts are signed when the agent connects, and node SVIDs last one
> hour without renewal, so an agent must reconnect with a valid SVID to stay in the mesh.

## Security

The WireGuard mesh provides encryption at the network layer. Combined with mTLS at the application layer, this provides defense-in-depth:

- **WireGuard** — Encrypts all traffic between machines
- **mTLS** — Authenticates and encrypts service-to-service traffic
- **nftables** — Enforces network policy as a third layer
