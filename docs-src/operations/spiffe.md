# SPIFFE & Workload Identity

ekafleet implements the SPIFFE (Secure Production Identity Framework For Everyone) model as a first-class citizen. Every service and node receives an X.509-SVID that cryptographically proves its identity. Workloads can consume identities via the standard SPIFFE Workload API or filesystem.

## SPIFFE IDs

Each entity gets a SPIFFE identity within the fleet's trust domain:

| Entity | SPIFFE ID Format |
|--------|-----------------|
| Service | `spiffe://<domain>/service/<service-name>` |
| Agent node | `spiffe://<domain>/agent/<node-id>` |
| Server | `spiffe://<domain>/server/<server-id>` |

The trust domain defaults to `fleet.internal` and is configurable via `--domain` on the server.

## Certificate Lifecycle

### Proper CSR Flow

The agent generates its own ECDSA P-256 keypair and sends a PKCS#10 Certificate Signing Request to the server. The private key never leaves the agent:

```text
Agent generates keypair + PKCS#10 CSR
    |
Agent sends CertificateRequest (with real CSR)
    |
Server validates: is this service assigned to this node?
    |
Server signs the CSR (using the public key from CSR)
    |
Server returns CertificateResponse (cert PEM only, no private key)
    |
Agent pairs cert with its local private key
    |
Agent installs SVID to filesystem
    |
Background renewal checks every 60s (renews 5min before expiry)
```

### SVID File Layout

Each service gets its identity material at a well-known path:

```text
/var/lib/ekafleet/spiffe/<service-name>/
  svid.pem        -- leaf certificate (PEM)
  svid-key.pem    -- private key (PEM, mode 0400)
  bundle.pem      -- CA trust bundle (PEM)
```

This layout is compatible with:
- Envoy SDS (file-based)
- go-spiffe / rust-spiffe libraries
- Any application that reads PEM cert/key files

### Certificate Properties

| Property | Value |
|----------|-------|
| Key type | ECDSA (P-256) |
| Default TTL | 1 hour |
| SAN | `spiffe://<domain>/service/<name>` |
| Extended Key Usage | ServerAuth, ClientAuth |
| Key Usage | DigitalSignature |

## SPIFFE Workload API

ekafleet exposes the standard SPIFFE Workload API v2 over a Unix domain socket at `/run/ekafleet/workload-api.sock`. This allows workloads to use standard SPIFFE libraries without any ekafleet-specific code.

### Supported RPCs

| RPC | Status |
|-----|--------|
| `FetchX509SVID` | Implemented (streaming) |
| `FetchX509Bundles` | Implemented (streaming) |
| `FetchJWTSVID` | Implemented |
| `ValidateJWTSVID` | Implemented |
| `FetchJWTBundles` | Implemented (streaming) |

### Workload Attestation

The Workload API identifies callers via Unix socket peer credentials:

1. Extract the caller's PID from `SO_PEERCRED`
2. Map PID to systemd cgroup (`/proc/<pid>/cgroup`) to find `ekafleet-<name>.service`
3. Fallback: check `EKAFLEET_SERVICE` env var in `/proc/<pid>/environ`
4. Return the SVID for the identified service

### Using the Workload API

The `SPIFFE_ENDPOINT_SOCKET` environment variable is automatically set in all managed service unit files:

```
SPIFFE_ENDPOINT_SOCKET=unix:///run/ekafleet/workload-api.sock
```

#### Go (go-spiffe)

```go
import "github.com/spiffe/go-spiffe/v2/workloadapi"

ctx := context.Background()
source, err := workloadapi.NewX509Source(ctx)
if err != nil {
    log.Fatal(err)
}
defer source.Close()

svid, err := source.GetX509SVID()
// svid.ID = spiffe://fleet.internal/service/my-app
```

#### Rust (rust-spiffe)

```rust
use spiffe::WorkloadApiClient;

let mut client = WorkloadApiClient::default().await?;
let svids = client.fetch_x509_svid().await?;
```

## JWT-SVID

In addition to X.509-SVIDs, ekafleet supports JWT-SVIDs for token-based authentication between services.

### Fetching a JWT-SVID

```bash
# Via the Workload API (programmatic)
# The FetchJWTSVID RPC returns a signed JWT with the workload's SPIFFE ID
```

JWT claims:
- `sub` — SPIFFE ID (e.g., `spiffe://fleet.internal/service/my-app`)
- `aud` — Requested audience(s)
- `iat` — Issued at (Unix timestamp)
- `exp` — Expiration (1 hour TTL)

JWTs are signed with HMAC-SHA256 using the fleet signing key. Validation is performed via the `ValidateJWTSVID` RPC, which verifies the signature, expiration, and audience.

### JWT Bundles

The `FetchJWTBundles` RPC returns a JWKS (JSON Web Key Set) stream identifying the signing key. Clients use this to discover key material for local validation.

### Filesystem Access

Workloads can also read SVIDs directly from the filesystem:

```nix
services.my-app = {
  environment = {
    TLS_CERT = "/var/lib/ekafleet/spiffe/my-app/svid.pem";
    TLS_KEY = "/var/lib/ekafleet/spiffe/my-app/svid-key.pem";
    TLS_CA = "/var/lib/ekafleet/spiffe/my-app/bundle.pem";
  };
};
```

## Node Attestation

Agents bootstrap their identity using SPIFFE-style node attestation, replacing static bearer tokens.

### Join Token Attestation

The simplest attestation method. An admin generates a one-time join token, and the agent presents it during bootstrap:

```bash
# Admin generates a one-time token on the server
ekafleet token create --type agent
# Output: a0b1c2d3e4f5...

# Agent uses the token to bootstrap (one-time use)
ekafleet agent --join server:7400 --join-token a0b1c2d3e4f5... --ca-cert /path/to/ca.pem
```

After successful attestation:
1. The token is consumed and deleted (cannot be replayed)
2. The agent receives a node SVID (`spiffe://<domain>/agent/<node-id>`)
3. The node SVID is persisted to disk
4. All subsequent connections use mTLS with the node SVID

### Attestation Flow

```text
Admin:     ekafleet token create --type agent  ->  prints "abc123..."
Agent:     boots, calls Attest RPC with join token + CSR
Server:    validates token (one-time use), deletes it
Server:    issues node SVID signed by fleet CA
Agent:     receives node SVID, persists to disk
Agent:     connects via mTLS using node SVID (no bearer token needed)
```

### Future Attestation Methods

- **Nix store path attestation**: Verify the agent binary's Nix store path
- **TPM attestation**: Hardware-backed identity via TPM 2.0

## mTLS Agent-Server Communication

After attestation, agents authenticate to the server using mutual TLS:

- **Agent presents**: Node SVID as client certificate
- **Server presents**: Server SVID (`spiffe://<domain>/server/<server-id>`)
- **Both verify**: Against the fleet CA trust bundle

Legacy bearer token authentication is still supported for migration.

## Trust Bundle

The CA certificate (trust bundle) is distributed to all agents on connection. When the CA rotates, the new bundle is pushed and propagated to all service directories.

Applications use `bundle.pem` to verify peer certificates during mTLS handshakes.

## Authorization (allowedCallers / allowedTargets)

Service identity contracts define who can talk to whom:

```nix
services.api-server = {
  identity = {
    allowedCallers = [ "web-frontend" "api-gateway" ];
    allowedTargets = [ "postgres" "redis" ];
  };
};
```

The `SpiffeAuthorizer` enforces these policies:
- Extracts the caller's SPIFFE ID from the peer certificate
- Checks it against the target service's `allowedCallers` list
- Denies by default if no policy is defined

### Enforcement Layers

| Layer | Mechanism | Level |
|-------|-----------|-------|
| Network | nftables rules | L3/L4 (IP + port) |
| Transport | mTLS certificate validation | L4 (TLS) |
| Application | SPIFFE ID authorization | L7 (identity) |

## Workload Attestation (Certificate Issuance)

Before issuing a certificate, the server validates:

1. **Node assignment** -- The requesting agent must be assigned the service
2. **Service name format** -- Alphanumeric, dashes, dots, underscores (max 253 chars)
3. **CSR validity** -- PKCS#10 signature verified (proves requester holds private key)
4. **Nix store path** -- If provided, must be a valid `/nix/store/` path

## Automatic Renewal

A background task on each agent checks every 60 seconds for SVIDs within 5 minutes of expiry. Expiring SVIDs are automatically re-requested from the server with a fresh CSR and keypair.

Services experience zero downtime during renewal -- the new certificate is written atomically and the old one remains valid until expiry. Connected Workload API clients receive the new SVID via their streaming connection.

## Configurable Trust Domain

The trust domain is configurable via the `--domain` flag on the server (default: `fleet.internal`). The domain flows to all components:

```bash
ekafleet server --domain my-org.internal --token $TOKEN
```

Agents receive the authoritative trust domain from the server's `TrustBundleUpdate` message.

## Trust Domain Federation

ekafleet supports SPIFFE trust domain federation for cross-cluster mTLS. This allows services in different clusters (each with their own CA and trust domain) to authenticate each other without sharing a single CA.

To federate with a peer cluster:

1. Exchange CA bundles between clusters
2. Register the foreign trust domain on each side
3. Services with SPIFFE IDs from either trust domain will be accepted during mTLS verification

The combined trust bundle (local CA + all federated foreign CAs) is used for TLS verification, so services can transparently communicate across cluster boundaries.

## PKI for Arbitrary Domains

In addition to SPIFFE SVIDs, the CA can issue TLS certificates for arbitrary domain names (e.g., public-facing HTTPS endpoints):

- Specify the domain name and optional Subject Alternative Names (SANs)
- The certificate is signed by the fleet CA with a configurable TTL
- Useful for services that need HTTPS certificates for public domain names, not just SPIFFE identity

## Secret Key Bootstrapping

The fleet encryption key (AES-256-GCM, 32 bytes) is automatically generated and persisted by the server. When agents connect, the key is distributed over the mTLS-encrypted channel via a `FleetKeyUpdate` message. The agent uses this key for decrypting secrets received from the server.
