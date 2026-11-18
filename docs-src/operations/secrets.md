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

Transit keys let services encrypt data (for example, columns before they are written to a database) without ever holding a key. The server keeps each key in Raft, sealed under the fleet key, and does the encryption and decryption itself.

```bash
ekafleet transit key create orders            # in namespace "default"
ekafleet --namespace shop transit key create carts
echo -n 4242424242424242 | ekafleet transit encrypt orders
# ekafleet:v1:3q2+7w...
ekafleet transit decrypt orders <<< 'ekafleet:v1:3q2+7w...'
ekafleet transit key rotate orders            # new values use v2; v1 values still decrypt
ekafleet transit key list
ekafleet transit key delete orders --yes      # values encrypted with it are lost
```

Ciphertext is `ekafleet:v<version>:<base64>` (AES-256-GCM with a random nonce). The key name and version are authenticated, so a value only decrypts with the key and version that made it. Plaintext is limited to 1 MiB.

**Who may use a key:**

- Operators and admins, with `Read` to list keys, `ManageSecrets` to create, rotate, or delete them (audited), and `Transit` to encrypt and decrypt. A namespace-scoped token only sees its namespace's keys; keys it creates go in that namespace.
- Workloads, authenticating over mTLS with their service SVID (`spiffe://<domain>/service/<name>`). A service may only use the keys it lists in `transitKeys`, and only keys in its own namespace. Workloads can't list or manage keys.

```nix
services.checkout = {
  namespace = "shop";
  transitKeys = [ "carts" ];
  # ...
};
```

A workload calls the `TransitEncrypt` and `TransitDecrypt` RPCs with its SVID, or runs the CLI:

```bash
ekafleet --ca-cert bundle.pem --server fleet:7400 \
  transit encrypt carts --cert svid.pem --key-file svid-key.pem < cart.json
```

Rotating the fleet key reseals every version of every transit key along with the static secrets. Rotating a transit key never rewrites existing ciphertext; re-encrypt values yourself if old versions must stop being used.

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
- AAD binding (`service_name\x00secret_name`) prevents ciphertext from being swapped between services
- Fleet master key (server-side only)

The Raft log and snapshots are also encrypted — secrets never appear as plaintext on disk.

Each agent receives a unique encryption key derived from the fleet master key via HKDF-SHA256, using the agent's SPIFFE ID as context. The server re-encrypts secrets under the agent's derived key before distribution, so compromising one agent's key does not expose secrets destined for other agents.

### Key Rotation

The fleet master key can be rotated at runtime without downtime:

```bash
# Via gRPC (using grpcurl or any gRPC client)
grpcurl -H "Authorization: Bearer $TOKEN" \
  server:7400 fleet.FleetControl/RotateFleetKey
```

When rotation is triggered, the server:

1. Generates a new 256-bit master key
2. Re-encrypts all stored secrets under the new key (atomic operation)
3. Persists the new key to disk
4. Pushes new HKDF-derived keys to every connected agent

The response reports how many agents were notified. Agents that reconnect after rotation receive the current key automatically. Secret plaintext values are unchanged — only the encryption key protecting them is rotated.

Rotate the fleet key periodically or after any suspected compromise of an agent node.

## Access Control

Secrets are scoped to services. A service can only access secrets declared in its configuration. The server only pushes secrets to agents that are running the assigned service.

## Secret Injection Path

The agent writes each secret of a service (mode `0400`) under `/run/ekafleet/secrets/<service>/`, and binds that directory read-only at `/run/secrets` inside the service, so a service reads its secret `api-key` at `/run/secrets/api-key`.

## Versioning & Rollback

Each secret has a version number that increments on every update; agents only rewrite a secret file when they receive a newer version. The server keeps the 9 versions before the current one, sealed like the current value and resealed with it when the fleet key rotates. Deleting a secret also deletes its earlier versions.

```bash
ekafleet secret versions api-server db-password
# Secret api-server/db-password
#   current: 7
#   earlier: 6, 5, 4

ekafleet secret rollback api-server db-password 5
# Secret api-server/db-password: version 5 restored as version 8
```

A rollback stores the old value as a new version, so agents pick it up like any other update. Listing versions needs `Read`; rolling back needs `ManageSecrets` (and is audited).

## Secret Rotation Notification

When a secret's value changes, the agent rewrites the file and restarts the services on that node that declare it, so they read the new value (templates that use it are re-rendered first).

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
