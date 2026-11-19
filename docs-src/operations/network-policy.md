# Network Policy

ekafleet turns service identity contracts into nftables rules on every agent. Policy is **opt-in**: a service that declares no `allowedCallers` and no `egressRules` stays reachable and unrestricted, as on a plain host. The host's own input chain stays NixOS's (`networking.firewall`); ekafleet adds its rules in a separate table, `inet ekafleet`.

## Ingress: allowedCallers

```nix
services.api = {
  ports.http = { port = 8080; };
  identity.allowedCallers = [ "web" ];
};
```

With `allowedCallers` set, traffic to the service's declared ports is dropped unless it comes from:

- a node running a replica of a listed service (matched by that node's WireGuard mesh IP);
- for services in a [namespace](../reference/fleet-config.md#namespaces), a replica of a listed service in the same namespace (matched by the replica's namespace IP);
- a node whose ingress proxy serves a route to the service, so public routes keep working.

On the host, the rules match traffic arriving over `wg-fleet` only. In a namespace network, they match traffic to the replica's namespace IP; loopback is never filtered. An empty set of sources (no caller is placed yet) drops all mesh traffic to those ports.

The rules follow placement: the leader recomputes them every few seconds and sends each node its own, so a caller that moves to a new node is allowed there without a new apply.

`allowedCallers` is also checked at the application layer: workloads that use mTLS see the caller's SPIFFE ID (see [SPIFFE](spiffe.md#authorization-allowedcallers--allowedtargets)). `allowedTargets` is documentation and an mTLS hint only; nftables does not enforce it. Restrict outbound traffic with `egressRules`.

## Egress: egressRules

```nix
services.api.identity.egressRules = [
  { destCidr = "10.0.0.0/8"; }                                    # allow (default action)
  { destCidr = "0.0.0.0/0"; destPorts = [ 443 ]; }                # HTTPS anywhere
  { destCidr = "169.254.169.254/32"; action = "deny"; }
];
```

Rules apply to the processes of the service's systemd unit, matched by its cgroup (`socket cgroupv2`), in order; the first match wins. Once a service has egress rules, every other outbound connection from it is dropped. Loopback and replies to established connections are always allowed. `destCidr` is IPv4.

The agent re-checks the unit cgroups every five seconds and reloads the rules when a restart replaced one.

## What the agent loads

For each network (the host, and each namespace's network namespace) the agent renders one `inet ekafleet` table and loads it atomically with `nft -f -` (inside a namespace via `nsenter`). It reloads only when the rendered rules or cgroups change, and replaces tables it no longer needs with empty ones. Inspect them with:

```sh
nft list table inet ekafleet
ip netns exec ekafleet-<namespace> nft list table inet ekafleet
```

## Defense in depth

1. **mTLS** — service identity verified with SPIFFE certificates
2. **WireGuard** — all traffic between nodes encrypted
3. **nftables** — restricts traffic even if the other layers fail
