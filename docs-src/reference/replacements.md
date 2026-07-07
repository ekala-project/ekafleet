# What ekafleet Replaces

ekafleet consolidates many separate tools into a single binary.

| External Tool | Capability | ekafleet Subsystem |
|---------------|-----------|-------------------|
| **Nomad** | Scheduling, deployment, scaling | `scheduler` + `deployer` + `scaling` |
| **Consul DNS** | Service discovery | `dns_authority` + `dns_resolver` |
| **Consul Connect** | Service mesh, mTLS | `wireguard` + `certs` + `nftables` |
| **Consul KV** | Distributed config | `raft` state (server) |
| **Vault KV** | Static secrets | `secrets_store` |
| **Vault PKI** | Certificate authority | `ca_root` + `certs` |
| **Vault Dynamic** | Database credentials | `secrets_store` (dynamic engine) |
| **SPIRE** | Workload attestation | `ca_root` (Nix store path verification) |
| **cert-manager** | TLS automation | `certs` (auto-renewal) |
| **external-dns** | DNS record management | `dns_authority` |
| **nginx / Traefik** | Reverse proxy, ingress | `proxy_l7` |
| **Prometheus** | Metrics collection | `metrics` |
| **WireGuard tools** | Mesh networking | `wireguard` |
| **Cilium / Calico** | Network policy | `nftables` |
| **deploy-rs** | NixOS deployment | `deployer` + `nix_eval` |

## Key Differences

### vs. Nomad

- ekafleet is Nix-native: configuration is pure Nix, deployments use Nix store paths
- No separate Consul dependency for service discovery
- Built-in secret management (no separate Vault)
- Implements Nomad-equivalent scheduling: priority, constraints, affinities, spread, node pools
- Adds Kubernetes-inspired features: taints/tolerations, topology spread constraints, inter-service affinity

### vs. Kubernetes

- Single binary, no cluster of controllers
- No container runtime required — services run directly via systemd
- Nix-based configuration instead of YAML manifests
- WireGuard mesh instead of overlay networks
- Implements K8s-equivalent scheduling: taints/tolerations, topology spread constraints (maxSkew/minDomains), pod (service) affinity/anti-affinity
- Simpler resource model: no QoS classes, no runtime classes

### vs. deploy-rs

- ekafleet adds scheduling, health checks, and rolling deployments
- Continuous reconciliation rather than one-shot deployment
- Built-in service discovery and secrets
