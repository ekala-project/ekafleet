# Secrets Management

ekafleet includes a built-in secret store, replacing Vault for most use cases.

## Secret Types

### Static Secrets

Key-value secrets stored encrypted (AES-256-GCM) in Raft state and distributed to agents for assigned services only.

```nix
secrets.api-key = {
  type = "static";
};
```

### Dynamic Secrets

Generates unique database credentials per service instance with automatic rotation. Credentials are provisioned directly in the database and revoked on lease expiry.

```nix
secrets.db = {
  type = "dynamic";
  engine = "postgresql";
  role = "rw";
};
```

**Supported databases:**

| Engine | Connection URL | Provisioning |
|--------|---------------|-------------|
| PostgreSQL | `postgres://admin:pass@host:5432/db` | CREATE ROLE + GRANT |
| MySQL | `mysql://root:pass@host:3306/db` | CREATE USER + GRANT |

**Role mappings:**

| Role name | Permissions granted |
|-----------|-------------------|
| `readonly` / `ro` / `read` | SELECT |
| `readwrite` / `rw` / `write` | SELECT, INSERT, UPDATE, DELETE |
| `admin` / `superuser` / `all` | ALL PRIVILEGES |

**Lifecycle:**

1. Server registers the database engine with admin connection URL
2. On service deploy, server generates random username + password
3. Server connects to DB and runs `CREATE ROLE`/`USER` + `GRANT`
4. Credentials + service connection URL distributed to agent
5. On lease expiry (default 1 hour), server runs `DROP ROLE`/`USER`

**Safety features:**
- `CONNECTION LIMIT 10` prevents credential abuse
- `VALID UNTIL` (Postgres) / `PASSWORD EXPIRE` (MySQL) for DB-enforced expiry
- Existing connections terminated on revocation
- SQL injection prevented via identifier/literal escaping

### Transit Encryption

Provides encrypt/decrypt operations using named keys — application secrets never leave the server.

```nix
# Services call the transit API to encrypt/decrypt data
# without having access to the raw encryption key
```

**Operations:**
- `create_key(name)` — create a named AES-256-GCM key
- `encrypt(key_name, plaintext)` — encrypt with named key
- `decrypt(key_name, ciphertext)` — decrypt with named key

Useful for services that need to encrypt data at rest but shouldn't hold the encryption key directly.

## How It Works

1. Secrets are stored encrypted (AES-256-GCM) in the Raft state machine
2. Each secret is scoped to a specific service
3. When a service is deployed, its secrets are pushed via gRPC (`SecretUpdate` message)
4. The agent decrypts and writes secrets to files with restrictive permissions (mode `0400`)
5. Services access their SPIFFE certificate to prove identity for secret access

## Encryption

All secrets are encrypted at rest using AES-256-GCM with:
- 12-byte random nonces (unique per encryption)
- Authenticated encryption (tampered ciphertext is rejected)
- Fleet-wide encryption key

The Raft log and snapshots are also encrypted — secrets never appear as plaintext on disk.

## Access Control

Secrets are scoped to services. A service can only access secrets declared in its configuration. The server only pushes secrets to agents that are running the assigned service.

## Secret Injection Path

```text
/var/lib/ekafleet/secrets/
├── api-server/
│   ├── api-key          (static secret)
│   └── db               (dynamic: contains connection URL)
└── web-frontend/
    └── session-secret
```

## Versioning & Rollback

Each secret has a version number that increments on every update. The agent tracks injected versions to avoid unnecessary file writes. When a new version is pushed, the agent writes the updated value atomically.

Previous versions are retained (up to a configurable limit, default 5) allowing rollback to a prior value if a secret update breaks authentication:

```bash
# List available versions
curl -H "Authorization: Bearer $TOKEN" http://server:7402/v1/secrets/api-server/db-password/versions

# Rollback to a specific version
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://server:7402/v1/secrets/api-server/db-password/rollback?version=3
```

## Secret Rotation Notification

When a secret is updated on disk, the agent can signal the service to reload without restart. By default, `SIGHUP` is sent to the service's systemd unit after writing the new secret value. This enables zero-downtime credential rotation.

The signal is only sent when the secret value actually changes (not on no-op version checks). If the signal delivery fails (e.g., process not running), the failure is logged but does not block the secret injection.

## Dynamic Secret Connection URLs

For dynamic secrets, the injected file contains a ready-to-use connection URL:

```
postgres://v-api-server-rw-a1b2c3d4:randompassword@db.host:5432/myapp
```

Services can read this directly from the secret file and connect without additional configuration.

## Integration with sops-nix / agenix

Machine-level secrets (SSH host keys, bootstrap credentials) are handled by sops-nix or agenix. These activate during system switch and are complementary to ekafleet's service-level runtime secrets:

| Concern | sops-nix / agenix | ekafleet |
|---------|-------------------|----------|
| When | At activation (boot/switch) | At runtime (hot) |
| Rotation | Requires rebuild | Automatic |
| Scope | Per-machine | Per-service |
| Dynamic DB creds | No | Yes |
