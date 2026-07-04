# Agent Mode

Start with `ekafleet agent --join <server>:7400 --token <TOKEN>`. The agent runs the data plane on each fleet machine.

## Responsibilities

- **Service supervision** — Generates and manages systemd unit files
- **Health checking** — Polls services with HTTP, TCP, or exec probes
- **Status reporting** — Sends heartbeats and service status to server
- **Secret injection** — Writes decrypted secrets to local files (mode 0400)
- **DNS resolution** — Local caching resolver for fleet service discovery
- **Mesh networking** — Manages kernel WireGuard interface and peers
- **Network policy** — Applies nftables rules from identity contracts
- **Metrics collection** — Scrapes Prometheus endpoints from local services
- **L7 proxy** — HTTP reverse proxy for ingress routing

## Connection Lifecycle

1. Agent generates a persistent node ID (stored in `<data-dir>/node-id`)
2. Opens a bidirectional gRPC stream to the server (`StreamControl` RPC)
3. Sends an initial heartbeat to identify itself
4. Begins receiving server commands (desired state, deploy, secrets, DNS, certs, peers, policy)
5. Heartbeats sent every 5 seconds; status reports every 10 seconds

## When Server is Unreachable

The agent continues operating autonomously:

| Capability | Behavior |
|------------|----------|
| Running services | Continue running |
| Health checks | Continue polling |
| DNS resolution | Serve from cache |
| Certificates | Valid until expiry (default 1 hour) |
| Gossip | Still works between agents |
| New deployments | **Blocked** until server returns |

## NACK Semantics

When the agent receives a desired state or deploy command, it validates the configuration before applying. If validation fails, the agent sends a NACK back to the server with the reason. The server will not mark the deployment as successful, and the agent continues running the last-known-good configuration.
