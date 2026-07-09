# Feature Comparison

Detailed comparison of ekafleet against Kubernetes, Nomad, Consul, Vault, and other tools in the fleet orchestration domain.

## Comparison Summary

ekafleet is a single binary that consolidates capabilities from 10+ separate tools. The tables below show feature-by-feature coverage.

### Legend

| Symbol | Meaning |
|--------|---------|
| **Yes** | Fully implemented with real logic |
| *Partial* | Foundation exists, some functionality not yet wired |
| No | Not implemented |
| N/A | Not applicable to this tool's model |

---

## Scheduling & Placement

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| Priority-based scheduling | **Yes** | **Yes** (PriorityClass) | **Yes** (1-100) | ekafleet: 1-100, higher first |
| Preemption | **Yes** | **Yes** (PostFilter) | **Yes** (delta >= 10) | ekafleet: evicts services with priority delta >= 10 |
| Bin-packing | **Yes** | **Yes** (MostAllocated) | **Yes** | Per-pool configurable (binpack/spread) |
| Spread scheduling | **Yes** | **Yes** (TopologySpreadConstraints) | **Yes** | With target percentages, maxSkew, minDomains |
| Label constraints | **Yes** | **Yes** (nodeSelector, nodeAffinity) | **Yes** (constraint) | Operators: =, !=, in, not_in, >, <, regexp, semver, set_contains |
| Taints & tolerations | **Yes** | **Yes** | No | NoSchedule, PreferNoSchedule, NoExecute effects |
| Node affinity | **Yes** | **Yes** | **Yes** | Soft preference with configurable weights |
| Inter-service affinity | **Yes** | **Yes** (podAffinity) | No | Co-locate/separate by topology key |
| Anti-affinity | **Yes** | **Yes** (podAntiAffinity) | No | Negative weight affinities |
| Node pools | **Yes** | **Yes** (node groups) | **Yes** (node pools) | Pool-specific scheduling algorithms |
| Resource requests/limits | **Yes** | **Yes** | **Yes** | CPU (millicores), memory (MB), disk (MB) |
| Resource quotas | **Yes** | **Yes** (ResourceQuota) | **Yes** (Quota) | Per-pool/namespace CPU, memory, disk, instance limits |
| Disruption budgets | **Yes** | **Yes** (PDB) | No | minAvailable / maxUnavailable (absolute or %) |
| Namespaces | **Yes** | **Yes** | **Yes** | Service-level isolation with scoped naming |
| Distinct hosts | **Yes** | **Yes** (podAntiAffinity) | **Yes** (distinct_hosts) | Scoring penalty for same-machine placement |
| GPU/device scheduling | **Yes** | **Yes** (device plugins) | **Yes** (device) | |
| Pod overhead | No | **Yes** (RuntimeClass) | No | |
| Multiple schedulers | No | **Yes** (scheduling profiles) | No | |

## Workload Types

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| Long-running services | **Yes** (service) | **Yes** (Deployment) | **Yes** (service) | |
| Stateful services | **Yes** (stateful) | **Yes** (StatefulSet) | No | Sticky placement preference |
| Run-on-all-nodes | **Yes** (system) | **Yes** (DaemonSet) | **Yes** (system) | |
| Run-to-completion | **Yes** (batch) | **Yes** (Job) | **Yes** (batch) | |
| System batch | **Yes** (sysbatch) | No | **Yes** (sysbatch) | Run once on every matching node |
| Cron/periodic jobs | **Yes** | **Yes** (CronJob) | **Yes** (periodic) | Cron expression, concurrency policy (allow/forbid/replace) |
| Parameterized/dispatch jobs | **Yes** | No | **Yes** | |

## Deployment Strategies

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| Rolling updates | **Yes** | **Yes** | **Yes** | maxParallel batch sizing |
| Canary deployments | **Yes** | *Partial* (manual) | **Yes** | Auto-promote when healthy |
| Blue-green deployments | **Yes** | *Partial* (via Argo) | **Yes** | Deploy all, then switch traffic |
| Health-gated progression | **Yes** | **Yes** (readiness) | **Yes** | minHealthyTime + healthyDeadline |
| Auto-revert on failure | **Yes** | **Yes** (rollback) | **Yes** | Automatic rollback to previous version |
| Progress deadline | **Yes** | **Yes** | No | Overall deployment timeout |
| Deployment history | **Yes** | **Yes** (ReplicaSet history) | **Yes** (job versions) | Per-service deployment records |
| Dependency ordering | **Yes** | No (needs Argo) | No | Topological sort by identity contracts |
| Disruption budget enforcement | **Yes** | **Yes** | No | Limits batch size during rolling updates |
| Config diff / plan | **Yes** | **Yes** (kubectl diff) | **Yes** (nomad plan) | |

## Health Checking

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| HTTP probes | **Yes** | **Yes** | **Yes** (Consul) | Path-based, status code validation |
| TCP probes | **Yes** | **Yes** | **Yes** (Consul) | Port connectivity check |
| Exec probes | **Yes** | **Yes** | **Yes** (Consul) | Custom command execution |
| gRPC probes | **Yes** | **Yes** | No | |
| Liveness probes | **Yes** | **Yes** | No | Failures trigger restart |
| Readiness probes | **Yes** | **Yes** | No | Failures remove from load balancing |
| Startup probes | **Yes** | **Yes** | No | Suppresses liveness during init |
| Configurable thresholds | **Yes** | **Yes** | **Yes** | Healthy/unhealthy consecutive counts |
| Health-aware DNS | **Yes** | **Yes** (Endpoints) | **Yes** (Consul) | Unhealthy instances removed from DNS |

## Lifecycle Management

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| Pre-stop hooks | **Yes** | **Yes** (preStop) | **Yes** (kill_signal) | Run command before shutdown |
| Post-start hooks | **Yes** | **Yes** (postStart) | No | Run command after start |
| Configurable stop signal | **Yes** | **Yes** (STOPSIGNAL) | **Yes** (kill_signal) | SIGTERM, SIGQUIT, etc. |
| Termination grace period | **Yes** | **Yes** (terminationGracePeriodSeconds) | **Yes** (kill_timeout) | Seconds before force-kill |
| Restart policy (local) | **Yes** | **Yes** (restartPolicy) | **Yes** | Attempts, interval, delay, mode |
| Reschedule policy (cross-node) | **Yes** | **Yes** (eviction) | **Yes** | Delay functions: constant/exponential/fibonacci |
| Migration policy (drain) | **Yes** | **Yes** (PDB) | **Yes** | maxParallel, health gates |
| Node drain | **Yes** | **Yes** (kubectl drain) | **Yes** (node drain) | Reschedule services off a machine |
| Maintenance windows | **Yes** | **Yes** (cordon) | **Yes** (eligibility) | Mark nodes ineligible without draining |

## Networking & Service Mesh

| Feature | ekafleet | Kubernetes | Consul Connect | Notes |
|---------|----------|------------|----------------|-------|
| Service discovery (DNS) | **Yes** | **Yes** (CoreDNS) | **Yes** | A + SRV records, health-aware |
| Mesh encryption | **Yes** (WireGuard) | **Yes** (CNI) | **Yes** (mTLS) | Kernel-level WireGuard tunnel |
| Ingress proxy (L7 HTTP) | **Yes** | **Yes** (Ingress/Gateway) | **Yes** (Envoy) | All methods, headers, body |
| L4 TCP proxy | **Yes** | **Yes** (Service type LB) | **Yes** (Envoy) | Raw byte forwarding for databases, gRPC |
| Network policy (ingress) | **Yes** | **Yes** (NetworkPolicy) | **Yes** (Intentions) | nftables rules from identity contracts |
| Network policy (egress) | **Yes** | **Yes** (NetworkPolicy) | **Yes** (Intentions) | nftables output chain rules |
| Circuit breaking | **Yes** | No (needs Istio) | **Yes** (via Envoy) | Closed/Open/HalfOpen state machine |
| Retry logic | **Yes** | No (needs Istio) | **Yes** (via Envoy) | Exponential backoff |
| Rate limiting | **Yes** | No (needs Istio) | **Yes** (via Envoy) | Token bucket per-service |
| Session affinity | **Yes** | **Yes** (sessionAffinity) | No | Client IP-based sticky sessions |
| Traffic splitting | **Yes** | *Partial* (Gateway API) | **Yes** (resolver) | Weighted canary traffic |
| External service registration | **Yes** | **Yes** (ExternalName) | **Yes** | Non-fleet services in DNS catalog |
| Distributed tracing | **Yes** | No (needs Istio) | **Yes** (via Envoy) | W3C Trace Context propagation |
| mTLS enforcement | **Yes** | No (needs Istio) | **Yes** | SPIFFE ID-based caller authorization |
| Gossip-based discovery | **Yes** | No | **Yes** (Serf) | SWIM protocol for agent-to-agent |
| Multi-region federation | **Yes** | *Partial* (Federation v2) | **Yes** (WAN) | Cross-cluster service discovery |

## Security & Identity

| Feature | ekafleet | Kubernetes | Vault + Consul | Notes |
|---------|----------|------------|----------------|-------|
| RBAC | **Yes** | **Yes** | **Yes** (ACL) | Admin/operator/viewer roles |
| Audit logging | **Yes** | **Yes** | **Yes** | Structured control-plane action trail |
| SPIFFE X.509-SVIDs | **Yes** | No (needs SPIRE) | No (needs SPIRE) | Native SPIFFE identity for every workload |
| SPIFFE Workload API | **Yes** | No (needs SPIRE) | No (needs SPIRE) | Standard UDS-based API for SVID delivery |
| Node attestation | **Yes** | **Yes** (kubelet) | **Yes** (Consul) | Join token attestation (one-time use) |
| mTLS everywhere | **Yes** | No (needs Istio) | **Yes** (Connect) | Agent-server and service-to-service |
| Identity contracts | **Yes** | No (needs NetworkPolicy) | **Yes** (Intentions) | allowedCallers/allowedTargets per service |
| Trust domain federation | **Yes** | No (needs SPIRE) | No (needs SPIRE) | Cross-cluster SPIFFE trust |
| PKI for arbitrary domains | **Yes** | **Yes** (cert-manager) | **Yes** (Vault PKI) | Issue TLS certs for custom domain names |
| CSR flow (key never leaves workload) | **Yes** | No (needs SPIRE) | No | ECDSA P-256, PKCS#10 CSR signed by CA |

## Secrets Management

| Feature | ekafleet | Kubernetes | Vault | Notes |
|---------|----------|------------|-------|-------|
| Static secrets (encrypted at rest) | **Yes** | **Yes** (Secrets) | **Yes** (KV) | AES-256-GCM encryption |
| Dynamic database credentials | **Yes** | No (needs Vault) | **Yes** | PostgreSQL, MySQL auto-provisioned |
| Transit encryption | **Yes** | No | **Yes** | Named encryption keys for app data |
| Secret versioning | **Yes** | No | **Yes** (KV v2) | Retain previous versions |
| Secret rollback | **Yes** | No | **Yes** | Rollback to prior version |
| Secret rotation notification | **Yes** | No (needs Reloader) | **Yes** (Agent) | SIGHUP on secret update |
| File-based injection | **Yes** | **Yes** (volumes) | **Yes** (Agent) | Mode 0400, per-service scoped |
| Service-scoped access | **Yes** | **Yes** (RBAC) | **Yes** (policies) | Service only gets its own secrets |
| Encryption key distribution | **Yes** | No | No | Fleet encryption key via mTLS channel |

## Configuration Management

| Feature | ekafleet | Kubernetes | Nomad + Consul | Notes |
|---------|----------|------------|----------------|-------|
| Declarative config | **Yes** (Nix) | **Yes** (YAML) | **Yes** (HCL) | Pure Nix evaluated via `nix eval` |
| Config templating | **Yes** | No (needs Helm) | **Yes** (consul-template) | `{{ service "x" }}`, `{{ secret "y" }}` syntax |
| Config validation | **Yes** | **Yes** (admission) | **Yes** (sentinel) | Structural + organizational policy rules |
| Policy engine | **Yes** | **Yes** (OPA/Gatekeeper) | **Yes** (Sentinel) | Enforce/warn modes for org rules |
| OS-level deployment | **Yes** | No | No | Full NixOS system closure activation |
| Rollback (service) | **Yes** | **Yes** (rollout undo) | **Yes** | Via deployment history |
| Rollback (OS) | **Yes** | N/A | N/A | Via Nix profile generations |

## Observability & Operations

| Feature | ekafleet | Kubernetes | Nomad + Consul | Notes |
|---------|----------|------------|----------------|-------|
| Prometheus metrics scraping | **Yes** | **Yes** (kube-state-metrics) | **Yes** (Prometheus) | Agent-side scraping, server aggregation |
| Prometheus endpoint | **Yes** | **Yes** | **Yes** | `GET /metrics` |
| Node metrics | **Yes** | **Yes** (metrics-server) | **Yes** | CPU, memory, disk from /proc |
| Fleet-wide aggregation | **Yes** | No (needs Prometheus) | No | Per-service averages/maximums |
| Alerting rules | **Yes** | No (needs Alertmanager) | No (needs Sentinel) | Threshold-based with duration gates |
| Webhook notifications | **Yes** | **Yes** (admission webhooks) | No | Outbound notifications on events |
| Event timeline | **Yes** | **Yes** (Events) | **Yes** (Event Stream) | Queryable event history |
| Deployment history | **Yes** | **Yes** (rollout history) | **Yes** (job versions) | Per-service deployment records |
| Event streaming (real-time) | **Yes** (SSE) | **Yes** (watch) | **Yes** (event stream) | `GET /v1/watch` SSE endpoint |
| Structured logging | **Yes** | **Yes** | **Yes** | `tracing` framework, RUST_LOG control |
| Remote exec | **Yes** | **Yes** (kubectl exec) | **Yes** (alloc exec) | Via systemd-run in service cgroup |
| Log streaming | **Yes** | **Yes** (kubectl logs -f) | **Yes** (alloc logs) | Real-time journalctl streaming |
| Drift detection | **Yes** | No (needs tools) | No | `ekafleet drift` command |
| Capacity planning | **Yes** | No (needs tools) | No | `ekafleet capacity` with pool breakdown |

## Storage

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| Persistent volumes | **Yes** | **Yes** (PV/PVC) | **Yes** (host_volume, CSI) | Local directory-based volumes |
| Volume provisioning | **Yes** | **Yes** (StorageClass) | **Yes** (CSI) | Automatic directory creation |
| Volume snapshots | **Yes** | **Yes** (VolumeSnapshot) | No | cp -a with reflink=auto |
| Data migration on reschedule | **Yes** | **Yes** (StatefulSet) | *Partial* (CSI) | rsync over SSH |
| Reclaim policies | **Yes** | **Yes** (Retain/Delete) | No | Configurable data retention |
| Storage classes | **Yes** | **Yes** | **Yes** | local, nfs, zfs |
| Volume recovery on restart | **Yes** | **Yes** | No | Scans data directory on agent startup |
| CSI drivers | **Yes** | **Yes** | **Yes** | StorageDriver trait with local + NFS drivers |
| Dynamic provisioning | **Yes** | **Yes** | **Yes** | Auto-provision on first schedule |

## High Availability & Clustering

| Feature | ekafleet | Kubernetes | Nomad + Consul | Notes |
|---------|----------|------------|----------------|-------|
| Consensus (server HA) | **Yes** (Raft) | **Yes** (etcd/Raft) | **Yes** (Raft) | 3-node HA cluster |
| Gossip protocol | **Yes** (SWIM) | No | **Yes** (Serf/SWIM) | Failure detection, catalog propagation |
| Leader election | **Yes** (Raft) | **Yes** (etcd) | **Yes** (Raft) | |
| Graceful degradation | **Yes** | **Yes** | **Yes** | Agents continue when server unreachable |
| State snapshots | **Yes** | **Yes** (etcd backup) | **Yes** (snapshot) | Raft snapshot/restore |
| Disaster recovery CLI | **Yes** | **Yes** (etcdctl) | **Yes** (snapshot save/restore) | `ekafleet snapshot` / `ekafleet restore` |
| Multi-region federation | **Yes** | *Partial* (Federation v2) | **Yes** (multi-region) | Cross-cluster discovery and trust |
| Rebalancing / descheduler | **Yes** | **Yes** (descheduler) | No | Advisory reschedule suggestions |
| Self-upgrade orchestration | **Yes** | **Yes** (kubeadm upgrade) | **Yes** | Foundation via snapshot/restore |

## API & Developer Experience

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| gRPC API | **Yes** | No (HTTP+Protobuf) | No | Bidirectional streaming |
| REST API (JSON) | **Yes** | **Yes** | **Yes** | 7 endpoints: status, services, capacity, events, deployments |
| CLI tool | **Yes** | **Yes** (kubectl) | **Yes** | Single binary, all operations |
| Structured output (--output json) | **Yes** | **Yes** (-o json) | **Yes** (-json) | Machine-readable output for scripting |
| Shell completions | **Yes** | **Yes** | **Yes** | bash, zsh, fish via clap_complete |
| Web UI | **Yes** | **Yes** (Dashboard) | **Yes** | |
| Dev mode (local testing) | **Yes** | **Yes** (minikube/kind) | **Yes** (-dev) | Single-process, no TLS/WireGuard |
| Watch / event streaming | **Yes** (SSE) | **Yes** (watch) | **Yes** (event stream) | Real-time state change notifications |
| Custom resource definitions | **Yes** | **Yes** (CRD) | No | Script hooks at lifecycle points |
| Plugin system | **Yes** | **Yes** (CSI, CNI, CRI) | **Yes** (task drivers) | Script hooks + StorageDriver trait |
| Admission webhooks | **Yes** | **Yes** | No | External webhook + built-in policy engine |

## Deployment & Runtime Model

| Feature | ekafleet | Kubernetes | Nomad | Notes |
|---------|----------|------------|-------|-------|
| Runtime model | systemd units | Containers (CRI) | Task drivers | No container runtime required |
| Config language | Nix | YAML | HCL | Pure Nix, evaluated via `nix eval` |
| Binary size | ~5 MB (static musl) | ~100 MB+ (control plane) | ~100 MB | Single binary, no dependencies |
| Runtime dependencies | None | Container runtime, etcd | None | No JVM, no interpreters |
| OS deployment | **Yes** (Nix closures) | No | No | Full system activation (switch/boot/test) |
| Reconciliation model | Continuous (30s) | Continuous | Evaluation-based | Terraform-inspired eval→plan→apply loop |
| Package management | Nix store | Container images | Artifacts | Reproducible builds via Nix |

---

## What ekafleet Replaces

| External Tool(s) | ekafleet Subsystem | Coverage |
|-------------------|-------------------|----------|
| Nomad | `scheduler` + `deployer` + `scaling` + `reconciler` | Full |
| Consul DNS | `dns_authority` + `dns_resolver` + `external` | Full |
| Consul Connect | `wireguard` + `certs` + `nftables` + `proxy` | Full |
| Consul KV | `raft` state machine + REST KV API | Full |
| Vault KV | `secrets_store` + `versioned` | Full |
| Vault PKI | `ca_root` + `certs` + `pki` | Full |
| Vault Dynamic Secrets | `dynamic` (PostgreSQL, MySQL) | Full |
| SPIRE | `ca_root` + `attestation` + `workload_api` + `federation` | Full |
| cert-manager | `certs` (auto-renewal, CSR flow) | Full |
| external-dns | `dns_authority` | Full |
| nginx / Traefik / Envoy | `proxy_l7` + `proxy_l4` + `circuit` + `ratelimit` | Full |
| Istio / Linkerd | `wireguard` + `mtls` + `circuit` + `tracing_ctx` | *Partial* (no sidecar injection, no traffic policies) |
| Cilium / Calico | `nftables` (ingress + egress) | Full |
| deploy-rs | `deployer` + `nix_eval` + `activation` | Full |
| Prometheus | `metrics` (scraping + aggregation) | *Partial* (no PromQL, no long-term storage) |
| Alertmanager | `alerting` (threshold rules + webhook delivery + dedup + silencing) | Full |
| OPA / Gatekeeper | `policy` (expression evaluator with enforce/warn modes) | Full |
| consul-template | `template` (fleet context rendering) | Full |
| Velero / rsync | `snapshot` + `migrate` | *Partial* (local snapshots, no cloud backup) |
| Kubernetes Dashboard | REST API + SSE + embedded web UI | Full |

## Notable Gaps

Features present in Kubernetes or Nomad that ekafleet does not implement:

| Feature | Available In | Notes |
|---------|-------------|-------|
| Container runtime support | K8s, Nomad | Services run as systemd units, not containers |
| Sidecar injection (automatic) | Istio, Linkerd | Sidecars configurable but WireGuard mesh is the primary model |
| Cloud provider auto-provisioning | K8s | Advisory scaling with webhook notifications; IaC-provisioned machines |
| Service mesh data plane (sidecar) | Istio, Linkerd, Consul Connect | Uses WireGuard + nftables instead of sidecars |
