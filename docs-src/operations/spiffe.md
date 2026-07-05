# SPIFFE & Workload Identity

ekafleet implements the SPIFFE (Secure Production Identity Framework For Everyone) model for service-to-service authentication. Every service receives an X.509-SVID that cryptographically proves its identity.

## SPIFFE IDs

Each service gets a SPIFFE identity in the format:

```
spiffe://fleet.internal/service/<service-name>
```

This identity is embedded as a SAN URI in the service's X.509 certificate.

## Certificate Lifecycle

```text
Agent receives DesiredState with service list
    ↓
Agent sends CertificateRequest for each service
    ↓
Server validates: is this service assigned to this node?
    ↓
Server issues X.509 leaf cert (signed by fleet CA)
    ↓
Agent installs SVID to filesystem
    ↓
Background renewal checks every 60s (renews 5min before expiry)
```

### SVID File Layout

Each service gets its identity material at a well-known path:

```text
/var/lib/ekafleet/spiffe/<service-name>/
  svid.pem        — leaf certificate (PEM)
  svid-key.pem    — private key (PEM, mode 0400)
  bundle.pem      — CA trust bundle (PEM)
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
| SAN | `spiffe://fleet.internal/service/<name>` |
| Extended Key Usage | ServerAuth, ClientAuth |
| Key Usage | DigitalSignature |

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

## Workload Attestation

Before issuing a certificate, the server validates:

1. **Node assignment** — The requesting agent must be assigned the service
2. **Service name format** — Alphanumeric, dashes, dots, underscores (max 253 chars)
3. **Nix store path** — If provided, must be a valid `/nix/store/` path

## Automatic Renewal

A background task on each agent checks every 60 seconds for SVIDs within 5 minutes of expiry. Expiring SVIDs are automatically re-requested from the server.

Services experience zero downtime during renewal — the new certificate is written atomically and the old one remains valid until expiry.

## Using SVIDs in Services

### Environment Variables

Set in service configuration to point at SVID paths:

```nix
services.my-app = {
  environment = {
    TLS_CERT = "/var/lib/ekafleet/spiffe/my-app/svid.pem";
    TLS_KEY = "/var/lib/ekafleet/spiffe/my-app/svid-key.pem";
    TLS_CA = "/var/lib/ekafleet/spiffe/my-app/bundle.pem";
  };
};
```

### Programmatic Access (go-spiffe, rust-spiffe)

Libraries that implement the SPIFFE Workload API can read from the filesystem:

```go
source := workloadapi.NewX509Source(
    workloadapi.WithClientOptions(
        workloadapi.WithAddr("unix:///var/lib/ekafleet/spiffe/my-app/"),
    ),
)
```
