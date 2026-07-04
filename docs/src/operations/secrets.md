# Secrets Management

ekafleet includes a built-in secret store, replacing Vault for most use cases.

## Secret Types

### Static Secrets

Key-value secrets stored encrypted in Raft state and distributed to agents for assigned services only.

```nix
secrets.api-key = {
  type = "static";
};
```

### Dynamic Secrets

Generated unique credentials per service instance with automatic rotation.

```nix
secrets.db = {
  type = "dynamic";
  engine = "postgresql";
  role = "rw";
};
```

## How It Works

1. Secrets are stored encrypted in the Raft state machine (server-side)
2. Each secret is scoped to a specific service
3. When a service is deployed to an agent, its secrets are pushed via gRPC
4. The agent writes decrypted secrets to files with restrictive permissions (mode `0400`)
5. Secret files are placed at `<data-dir>/secrets/<service>/<secret-name>`
6. Services authenticate via their SPIFFE certificate to access their secrets

## Access Control

Secrets are scoped to services. A service can only access secrets declared in its configuration. The server only pushes secrets to agents that are running the assigned service.

## Secret Injection Path

```text
/var/lib/ekafleet/secrets/
├── api-server/
│   ├── api-key
│   └── db
└── web-frontend/
    └── session-secret
```

## Versioning

Each secret has a version number that increments on every update. The agent tracks injected versions to avoid unnecessary file writes. When a new version is pushed, the agent writes the updated value and the service can detect the change.
