# Custodial Hosting Example

Demonstrates how to use ekafleet as the IaaS layer for a multi-tenant hosting platform where customers select services from a curated catalog.

## Architecture

`<your-fleet-flake>` is a flake that exposes this `fleet.nix` as its `fleet` output (see the quickstart, step 4); the server evaluates it.

```text
Customer UI / API
       │
       ▼
Web Service (generates Nix config from customer choices)
       │
       ▼
fleet.nix (uses nix/lib/catalog.nix templates)
       │
       ▼
ekafleet apply --flake <your-fleet-flake> --watch
       │
       ▼
Agents deploy services with cgroup enforcement, SPIFFE identity, secrets
```

## Service Catalog

The catalog (`nix/lib/catalog.nix`) provides template functions:

| Function | Service Type | Key Options |
|----------|-------------|-------------|
| `mkWebService` | Generic HTTP container | image, port, replicas, healthPath |
| `mkStaticSite` | Static site (nginx) | image, replicas |
| `mkResources` | Resource limits helper | cpuRequest, cpuLimit, memoryRequest, memoryLimit |
| `mkHealthCheck` | Health check helper | port, path |

Domain-specific templates (game servers, databases, caches) should be defined in downstream configuration repos using the helpers above.

## Multi-Tenant Isolation

Each customer's services are isolated via:

- **Namespace-scoped tokens**: `ekafleet acl token create --role viewer --namespace customer-a` creates a token that can only access `customer-a`'s services
- **Resource limits**: Each service template sets CPU/memory limits that are enforced via systemd cgroup controls (CPUQuota, MemoryMax)
- **SPIFFE identity**: Each service gets its own X.509-SVID for mTLS
- **RBAC**: Viewers can only read; Operators can deploy; Admins manage tokens

## Usage

```bash
# Deploy all customer services
ekafleet apply --flake <your-fleet-flake>

# Create a namespace-scoped token for Customer A
ekafleet acl token create --role viewer --namespace customer-a --description "Customer A dashboard"

# Continuous reconciliation
ekafleet apply --flake <your-fleet-flake> --watch
```
