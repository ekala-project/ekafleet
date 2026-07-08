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

## Egress Policy

In addition to ingress rules (who can call a service), ekafleet supports egress rules that control what external destinations a service can reach. This prevents compromised services from exfiltrating data to arbitrary internet hosts.

Egress rules are applied to the nftables `output` chain:

```nix
services.api-server = {
  identity = {
    allowedCallers = [ "web-frontend" ];
    allowedTargets = [ "postgres" ];
    # Egress rules restrict outbound traffic
    egressRules = [
      { destCidr = "10.0.0.0/8"; action = "allow"; }   # Allow internal network
      { destCidr = "0.0.0.0/0"; destPorts = [ 443 ];    # Allow HTTPS to internet
        action = "allow"; }
      # All other outbound traffic is dropped by default
    ];
  };
};
```

Egress rules support:
- **Allow/Deny actions** — Explicitly allow or block traffic to a CIDR range
- **Port filtering** — Restrict outbound traffic to specific destination ports
- **Default policy** — When egress rules are configured, unlisted destinations are dropped

## Defense in Depth

Network policy is the third layer of security:

1. **mTLS** — Primary: service identity verified via SPIFFE certificates
2. **WireGuard** — All traffic encrypted at the network layer
3. **nftables** — Backup: restricts traffic even if other layers fail
