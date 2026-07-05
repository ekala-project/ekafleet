# Agent Mode

Start with `ekafleet agent --join <server>:7400 --token <TOKEN>`. The agent runs the data plane on each fleet machine.

## Responsibilities

- **System activation** — Activates EkaOS/NixOS system closures (full OS deployment)
- **Service supervision** — Generates and manages systemd unit files
- **Health checking** — Polls services with HTTP, TCP, or exec probes; reports to server
- **SPIFFE identity** — Requests and installs X.509-SVIDs for each service
- **Secret injection** — Decrypts and writes secrets to local files (mode 0400)
- **DNS resolution** — Local UDP listener (127.0.0.53:53) for fleet service discovery
- **Mesh networking** — Manages kernel WireGuard interface and peers
- **Network policy** — Applies nftables rules from identity contracts
- **Metrics collection** — Scrapes Prometheus endpoints from local services
- **L7 proxy** — HTTP reverse proxy for ingress routing with mTLS enforcement

## Connection Lifecycle

1. Agent validates server address and generates a persistent node ID (`<data-dir>/node-id`)
2. Opens a TLS gRPC connection with bearer token authentication
3. Sends initial heartbeat to identify itself
4. Receives trust bundle (CA certificate) from server
5. Begins receiving commands: desired state, deploy, secrets, DNS, certs, peers, policy

## Periodic Tasks

| Task | Interval | Purpose |
|------|----------|---------|
| Heartbeat | 5 seconds | Report liveness + available resources (CPU/mem/disk) |
| Status report | 10 seconds | Report running services |
| Health report | 10 seconds | Report service health check results |
| SVID renewal | 60 seconds | Re-request certificates nearing expiry |

## Message Handling

When the agent receives a `DesiredState` message:

1. **System activation** — If `system_path` changed, activate the new closure via `{toplevel}/bin/activate switch`
2. **SVID requests** — Request X.509 certificates for each assigned service
3. **Health checks** — Start health checking for services with health_check specs
4. **Service reconciliation** — Start/stop/restart systemd units to match desired state

Other messages:

| Message | Handler |
|---------|---------|
| `Deploy` | Update service store path, re-reconcile |
| `Secret` | Decrypt and write to `<data-dir>/secrets/<svc>/<name>` |
| `Dns` | Update local resolver cache |
| `Cert` | Install SVID via WorkloadManager |
| `TrustBundle` | Update CA bundle in all SPIFFE directories |
| `Peers` | Add/update/remove WireGuard peers |
| `Policy` | Generate and apply nftables rules |

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
