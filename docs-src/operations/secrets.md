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

Dynamic secrets are database credentials the server issues per service: a database user of its own, replaced before its lease runs out, and dropped when it's replaced or no longer declared. A secret engine names a database server and the database to grant access to; its admin connection URL is a fleet secret, so it never appears in the configuration.

```nix
fleet.secretEngines.orders-db = {
  adminUrlSecret = "orders-db-admin";   # ekafleet secret set _fleet orders-db-admin
  database = "orders";
};

fleet.services.api.secrets.db = {
  type = "dynamic";
  engine = "orders-db";
  role = "readwrite";                   # readonly | readwrite | admin
  ttl = 86400;                          # seconds (default 86400, at least 300)
};
```

```bash
echo -n 'postgres://admin:pw@db.internal:5432/postgres?sslmode=require' \
  | ekafleet secret set _fleet orders-db-admin
```

The service reads JSON at `/run/secrets/db`:

```json
{"username": "ek_3f9a1c0b7d2e", "password": "…", "url": "postgres://ek_3f9a1c0b7d2e:…@db.internal:5432/orders?sslmode=require"}
```

The URL keeps the admin URL's scheme, host, port and query, with the issued credentials and the engine's database.

**Supported databases:** PostgreSQL (`postgres://`, `postgresql://`) and MySQL (`mysql://`).

| Role | Privileges on the engine's database |
|------|-------------------------------------|
| `readonly` | `SELECT` |
| `readwrite` | `SELECT, INSERT, UPDATE, DELETE` |
| `admin` | `ALL PRIVILEGES` |

**Lifecycle:**

1. When a configuration declaring the secret is applied, the server creates a random user through the admin connection, with its password set to expire at the end of the lease (`VALID UNTIL` on PostgreSQL; on MySQL `PASSWORD EXPIRE INTERVAL`, rounded up to whole days).
2. The credentials are stored in Raft, sealed under the fleet key like a static secret, and delivered to the nodes running the service. The service starts once they arrive.
3. Two thirds of the way through the lease, the server issues a new user. Nodes receive it and restart the service, as for any changed secret.
4. The replaced user is dropped (its sessions ended) when its lease expires, leaving the last third of the lease for the restart.
5. When a service or secret is removed from the configuration, its user is dropped at once. If the database is unreachable, issuing and dropping are retried every 30 seconds; current credentials stay in place meanwhile.

Changing a secret's `engine` or `role` issues a new user right away. Dynamic secrets can't be set, deleted or rolled back with `ekafleet secret`; instead:

```bash
ekafleet secret leases [SERVICE]      # issued users, renewal and expiry times, users waiting to be dropped
ekafleet secret revoke api db         # drop the user now and issue a new one
```

Issued users get `CONNECTION LIMIT 10` (PostgreSQL) or `MAX_USER_CONNECTIONS 10` (MySQL). Each renewal restarts the service on every node at about the same time, so choose a `ttl` long enough that this is rare.

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

## Integration with sops-nix / agenix

Machine-level secrets (SSH host keys, bootstrap credentials) are handled by sops-nix or agenix. These activate during system switch and are complementary to ekafleet's service-level runtime secrets:

| Concern | sops-nix / agenix | ekafleet |
|---------|-------------------|----------|
| When | At activation (boot/switch) | At runtime (hot) |
| Rotation | Requires rebuild | Automatic |
| Scope | Per-machine | Per-service |
| Dynamic DB creds | No | Yes |
