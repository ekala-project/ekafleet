# Network Policy

ekafleet enforces network policy via nftables rules derived from service identity contracts. This replaces Cilium/Calico.

## Default Deny

The base policy is **default deny** between services. Only explicitly allowed traffic is permitted.

## Identity Contracts

Services declare who can call them and what they call:

```nix
services.api-server = {
  identity = {
    allowedCallers = [ "web-frontend" ];  # who can call this service
    allowedTargets = [ "postgres" ];      # what this service calls
  };
};
```

From these contracts, ekafleet generates nftables rules that allow traffic between the specified services on their declared ports.

## How Rules Are Generated

1. Service identity contracts are read from the fleet configuration
2. Service placements map services to WireGuard mesh IPs
3. For each allowed caller/target pair, an nftables rule is generated:
   - Source IP: caller's mesh IP
   - Destination IP: target's mesh IP
   - Allowed ports: from the target's port declarations

## Base Rules

The default nftables table (`inet ekafleet`) includes:

| Rule | Purpose |
|------|---------|
| `ct state established,related accept` | Allow return traffic |
| `iif lo accept` | Allow loopback |
| `udp dport 51820 accept` | Allow WireGuard |
| `udp dport 7401 accept` | Allow gossip |
| `tcp dport 7400 accept` | Allow gRPC |
| `tcp dport 7402 accept` | Allow HTTP API |

## Defense in Depth

Network policy is the third layer of security:

1. **mTLS** — Primary: service identity verified via SPIFFE certificates
2. **WireGuard** — All traffic encrypted at the network layer
3. **nftables** — Backup: restricts traffic even if other layers fail
