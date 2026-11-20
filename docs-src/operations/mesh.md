# Mesh Networking

ekafleet manages a kernel WireGuard mesh network for encrypted inter-service communication.

## How It Works

1. The server assigns each node a mesh IP in `10.100.0.0/16`, recorded in Raft
2. The agent creates a WireGuard interface, generates a keypair, assigns the IP, and advertises its key signed with its node SVID
3. The server pushes every node's verified advertisement to the others whenever nodes join or leave
4. All inter-service traffic flows encrypted over the mesh

## WireGuard Interface

The agent manages a `wg-fleet` interface:

```bash
# View interface status
wg show wg-fleet

# View assigned peers and their allowed IPs
wg show wg-fleet allowed-ips
```

Configuration happens automatically — no manual WireGuard setup required.

## Peer Management

When the server sends a `PeerUpdate` message, the agent:

1. Adds new peers with their public key, endpoint, and allowed IPs: the peer's mesh address, plus the namespace addresses of its replicas (see below)
2. Updates peers whose keys or endpoints have changed
3. Removes peers that are no longer in the fleet
4. Configures persistent keepalive (25 seconds) for NAT traversal

## Mesh IP Assignment

The server allocates the first free address of `10.100.0.0/16` to a node when it first joins, and keeps it in Raft, so the address survives restarts and failover. A node removed from the configuration gives its address back.

## Namespace Networks

Services in a non-default [namespace](../reference/fleet-config.md#namespaces) run in a network namespace per node, `ekafleet-<namespace>`, on a subnet of `10.200.0.0/16` unique to the namespace. Each replica has its own address on it. Replicas of one namespace on different nodes reach each other over a VXLAN tunnel carried by the mesh.

Each namespace network has an uplink to its host: a veth pair, `nu-<hash>` on the host and `uplink0` inside, carrying the namespace's default route. The agent routes the subnet back in, enables IPv4 forwarding, and loads an `inet ekafleet-uplink` nftables table. That table enforces:

| From a namespace to | |
|---------------------|---|
| Outside networks (internet, LAN) | Allowed, masqueraded behind the node's address. Restrict with `egressRules`. |
| The node itself (any of its addresses) | Dropped, except replies. Fleet DNS answers inside the namespace, on its gateway. |
| The mesh (other nodes, their services) | Dropped, except replies. |
| Another namespace | Dropped. |

| Into a namespace from | |
|-----------------------|---|
| Its node (ingress proxy, `curl`) | Allowed, to the replica's namespace address. |
| Other nodes, over the mesh | Allowed. The server adds each replica's namespace address to its node's allowed IPs, so every node routes it over `wg-fleet`. |
| Anywhere else (forwarded) | Dropped. |

So an [ingress route](proxy.md) on any node reaches a namespaced service. To restrict who may connect, give the service `identity.allowedCallers` ([network policy](network-policy.md)); ingress proxies count as callers of the services they route to.

Inspect the host side with:

```sh
nft list table inet ekafleet-uplink
ip route show dev wg-fleet          # namespace addresses routed to peers
ip netns exec ekafleet-<namespace> ip route
```

A drop in any nftables table is final, so the host firewall cannot reopen these paths. If something else on the host sets the forward policy to drop, allow forwarding for `nu-*` interfaces.

## Security

The WireGuard mesh provides encryption at the network layer. Combined with mTLS at the application layer, this provides defense-in-depth:

- **WireGuard** — Encrypts all traffic between machines
- **mTLS** — Authenticates and encrypts service-to-service traffic
- **nftables** — Enforces network policy as a third layer

## Firewall

Fleet DNS answers and ingress backends are mesh addresses, so nodes connect to each other's service ports over `wg-fleet`. The NixOS module therefore trusts that interface by default (`services.ekafleet.agent.mesh.trustInterface`). Only peers whose WireGuard keys were advertised under a valid node SVID can send on it.

With `trustInterface = false`, only the volume-migration port (TCP 7403) is open on the mesh. Service ports then have to be listed in `networking.firewall.interfaces.wg-fleet.allowedTCPPorts`.
