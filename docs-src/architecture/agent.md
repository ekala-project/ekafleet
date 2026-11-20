# Agent Mode

Start with `ekafleet agent --join <server>:7400 --join-token <TOKEN> --ca-cert <CA>`. The agent runs the data plane on each fleet machine. In production, the NixOS module deploys the agent alongside two isolated companion processes: `ekafleet-workload-api` (serves SPIFFE SVIDs, unprivileged) and `ekafleet-proxy` (service mesh, unprivileged).

## Responsibilities

- **Node identity** — Bootstraps via SPIFFE node attestation; maintains a node SVID for mTLS
- **System activation** — Activates EkaOS/NixOS system closures (full OS deployment)
- **Service supervision** — Generates and manages systemd unit files with lifecycle hooks (pre-stop, post-start, configurable stop signal, grace period), `SPIFFE_ENDPOINT_SOCKET`, and `EKAFLEET_SERVICE` env vars
- **Health checking** — Separate liveness (restart?), readiness (route traffic?), and startup (initializing?) probes; reports to server
- **SPIFFE identity** — Generates ECDSA P-256 keypairs, sends PKCS#10 CSRs, installs X.509-SVIDs (private keys never leave the agent)
- **SPIFFE Workload API** — Serves SVIDs and trust bundles over Unix socket at `/run/ekafleet/workload-api.sock`
- **Secret injection** — Decrypts and writes secrets to local files (mode 0400) using fleet encryption key
- **DNS resolution** — Local UDP listener (127.0.0.53:53) for fleet service discovery
- **Mesh networking** — Manages kernel WireGuard interface and peers
- **Network policy** — Applies nftables rules from identity contracts
- **Metrics collection** — Scrapes Prometheus endpoints from local services
- **L7/L4 proxy** — HTTP reverse proxy with circuit breaking and retries, plus L4 TCP proxy for non-HTTP protocols
- **Config templating** — Renders config file templates with fleet context (service discovery, secrets, metadata)
- **Volume management** — Provisions and manages persistent volumes for stateful services
- **GC root management** — Creates indirect Nix GC roots for deployed service closures (prevents `nix-collect-garbage` from reaping live services); removes roots on service teardown

## Connection Lifecycle

1. Agent validates server address and generates a persistent node ID (`<data-dir>/node-id`)
2. Loads persisted node SVID if available (from previous attestation)
3. If no node SVID and `--join-token` provided: calls `Attest` RPC to bootstrap SPIFFE identity
4. Opens a mTLS gRPC connection using node SVID as client certificate (or falls back to bearer token with `--token`)
5. Sends initial heartbeat to identify itself
6. Receives trust bundle (CA certificate) and fleet encryption key from server
7. Starts SPIFFE Workload API socket at `/run/ekafleet/workload-api.sock`
8. Begins receiving commands: desired state, deploy, secrets, DNS, certs, peers, policy

## Periodic Tasks

| Task | Interval | Purpose |
|------|----------|---------|
| Heartbeat | 5 seconds | Report liveness + available resources (CPU/mem/disk) |
| Status report | 10 seconds | Report running services |
| Health report | 10 seconds | Report service health check results |
| SVID renewal | 60 seconds | Re-request certificates nearing expiry (generates fresh CSR + keypair) |
| Workload API | Continuous | Serve SVIDs and bundles to workloads via Unix socket |

## Message Handling

When the agent receives a `DesiredState` message:

1. **System activation** — If `system_path` changed, activate the new closure via `{toplevel}/bin/activate switch`
2. **SVID requests** — Generate keypair + PKCS#10 CSR for each service, send to server for signing
3. **Health checks** — Start health checking for services with health_check specs
4. **Service reconciliation** — Start/stop/restart systemd units to match desired state

Other messages:

| Message | Handler |
|---------|---------|
| `Deploy` | Update service store path, re-reconcile |
| `Secret` | Decrypt and write to `<data-dir>/secrets/<svc>/<name>` |
| `Dns` | Update local resolver cache |
| `Cert` | Pair server-signed cert with local keypair, install SVID |
| `TrustBundle` | Update trust domain + CA bundle in all SPIFFE directories |
| `FleetKey` | Install fleet encryption key for SecretInjector |
| `AttestChallenge` | Handle attestation challenge (TPM, future) |
| `Peers` | Add/update/remove WireGuard peers |
| `Policy` | Generate and apply nftables rules |

### Server-Initiated Commands

The server can relay operational commands to agents and await responses via a correlation-based request-response mechanism. Each command carries a `correlation_id`; the agent executes the operation and returns an `AgentCommandResponse` with the same ID.

| Command | Handler |
|---------|---------|
| `ExecCommand` | Execute a command in a service's cgroup via `systemd-run --scope` |
| `LogsCommand` | Read journal logs for a service via `journalctl` (tail or follow) |
| `ListGenerationsCommand` | List NixOS system generations from `/nix/var/nix/profiles/` |
| `SwitchGenerationCommand` | Switch to a generation via `nix-env --switch-generation` then activate |
| `DiffGenerationsCommand` | Diff two generations via `nix store diff-closures` |
| `SystemGCCommand` | Run `nix-collect-garbage -d` and report freed bytes |
| `SystemRebootCommand` | Initiate `systemctl reboot` (response sent before reboot) |
| `SystemRebuildCommand` | Run `nixos-rebuild switch` and return output |
| `InspectServiceCommand` | Query `systemctl show` + `systemctl cat` for unit properties |

All command handlers run in spawned tasks to avoid blocking the main message loop. Long-running operations (GC, rebuild) have longer server-side timeouts (up to 600s).

## System Resources

The agent reads actual system resources from `/proc` and reports them:

| Metric | Source |
|--------|--------|
| CPU (millicores) | `/proc/cpuinfo` processor count x 1000 |
| Memory (MB) | `/proc/meminfo` MemAvailable |
| Disk (MB) | `statvfs` on root filesystem |

## When Server is Unreachable

The agent continues operating autonomously:

| Capability | Behavior |
|------------|----------|
| Running services | Continue running |
| Health checks | Continue polling |
| DNS resolution | Serve from cache |
| Certificates | Valid until expiry (default 1 hour) |
| Gossip | Still works between agents |
| System activation | **Blocked** until server returns |
| New deployments | **Blocked** until server returns |

## NACK Semantics

When the agent receives a desired state or deploy command, it validates the configuration before applying. If validation fails, the agent sends a NACK back to the server with the reason. The server will not mark the deployment as successful, and the agent continues running the last-known-good configuration.

## SPIFFE Directory Layout

Each service gets identity material at:

```text
/var/lib/ekafleet/spiffe/<service-name>/
  svid.pem        — leaf certificate
  svid-key.pem    — private key (mode 0400)
  bundle.pem      — CA trust bundle
```

## Process Isolation

In production (via the NixOS module), the agent runs alongside two companion daemons:

| Service | Purpose | Hardening |
|---------|---------|-----------|
| `ekafleet-agent` | Privileged data plane (systemd, WireGuard, nftables, secrets) | Root, `ProtectHome`, `PrivateTmp` |
| `ekafleet-workload-api` | Serves SPIFFE SVIDs to workloads via Unix socket | `DynamicUser`, `PrivateNetwork`, no capabilities |
| `ekafleet-proxy` | L7/L4 service mesh proxy | `DynamicUser`, only `CAP_NET_BIND_SERVICE` |

The agent writes SVIDs to `<data_dir>/spiffe/<service>/` on disk. The standalone `workload-api` process polls this directory every 5 seconds and serves the material to workloads. This ensures that workload private keys are isolated from the privileged agent process (which handles remote exec, container management, and other root-level operations).

For development and quick bootstrapping, `ekafleet agent` embeds the Workload API and proxy in-process.
