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
| **SPIRE** | Workload attestation, Workload API | `ca_root` + `attestation` + `workload_api` (full SPIFFE Workload API, node attestation, CSR signing) |
| **cert-manager** | TLS automation | `certs` (auto-renewal) |
| **external-dns** | DNS record management | `dns_authority` |
| **nginx / Traefik** | Reverse proxy, ingress | `proxy_l7` + `proxy_l4` (circuit breaking, retries) |
| **Prometheus** | Metrics collection | `metrics` |
| **WireGuard tools** | Mesh networking | `wireguard` |
| **Cilium / Calico** | Network policy | `nftables` |
| **deploy-rs** | NixOS deployment | `deployer` + `nix_eval` |
| **OPA / Gatekeeper** | Policy engine | `policy` (built-in admission rules) |
| **Alertmanager** | Alert evaluation | `alerting` (built-in threshold rules + webhook delivery) |
| **consul-template** | Config rendering | `template` (built-in with fleet context) |
| **Kubernetes Dashboard** | Fleet visibility | REST API + SSE streaming |
| **rsync / Velero** | Data migration, backup | `storage` (volume snapshots, rsync-based migration) |

## Key Differences

### vs. Nomad

- ekafleet is Nix-native: configuration is pure Nix, deployments use Nix store paths
- No separate Consul dependency for service discovery
- Built-in secret management (no separate Vault)
- Implements Nomad-equivalent scheduling: priority, constraints, affinities, spread, node pools
- Adds Kubernetes-inspired features: taints/tolerations, topology spread constraints, inter-service affinity, disruption budgets
- Built-in RBAC with admin/operator/viewer roles

### vs. Kubernetes

- Single binary, no cluster of controllers
- No container runtime required — services run directly via systemd
- Nix-based configuration instead of YAML manifests
- WireGuard mesh instead of overlay networks
- Implements K8s-equivalent features: taints/tolerations, topology spread constraints (maxSkew/minDomains), pod (service) affinity/anti-affinity, separate liveness/readiness/startup probes, disruption budgets, lifecycle hooks (preStop/postStart), persistent volumes, RBAC
- Simpler resource model: no QoS classes, no runtime classes
- Built-in config templating (similar to consul-template)
- REST API alongside gRPC for CI/CD integration

### vs. deploy-rs

- ekafleet adds scheduling, health checks, and rolling deployments
- Continuous reconciliation rather than one-shot deployment
- Built-in service discovery and secrets
- Event timeline and deployment history tracking
