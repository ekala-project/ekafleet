# High Availability

A single ekafleet server keeps the fleet's state in an encrypted Raft log on its own disk. To keep running when a server fails, run three or five servers. They replicate that log with Raft (openraft) and elect a leader among themselves. A cluster of `2n+1` servers keeps working while `n` of them are down.

## What replicates

Everything in the fleet state machine replicates: configuration revisions, deployments, secrets and transit keys (sealed under the fleet key), DNS and mesh assignments, KV, cloud instances, API tokens from `ekafleet acl token create`, and join tokens. A join token used on one server is refused on every other. A token passed with `--token`/`tokenFile` stays local to its server, so each server keeps its own bootstrap admin token.

Each server writes the log to its own disk, encrypted under its own `raft-key`.

## Leader-only control plane

The leader alone runs the control plane. It serves the CLI, the HTTP API and agent streams, and runs the reconciler, secret delivery, dynamic leases, DNS, ingress, autoscaling, alerting and federation. Followers replicate and vote. They refuse every other request with `UNAVAILABLE` and name the leader's gRPC address in the `x-ekafleet-leader` header (HTTP: the same response header, status 503).

- **Agents** follow the header to the leader, and reconnect to the new leader after a failover. Give agents every server address (`ekafleet agent --join s1:7400,s2:7400,s3:7400`) so that they can still reach a server when one is down.
- **The CLI** follows it too, so `--server` can name any server.
- `ekafleet raft status` is answered by every server, leader or not.

When a server becomes leader, it starts the controllers for its term and stops them as soon as it loses leadership. If its store lacks service closures of the current revision, it rebuilds them from the locked flake reference before it serves the binary cache.

## Servers talk over mTLS

Raft traffic shares the gRPC port (7400). Each side authenticates the other with a server SVID (`spiffe://<domain>/server/...`). Bearer tokens, agent SVIDs and workload SVIDs are refused.

## Shared keys

All servers of a cluster must hold the same fleet key, binary cache signing key, root CA and JWT-SVID signing key. The first server creates them. You carry them to the other servers in a key bundle sealed with a passphrase (PBKDF2 + AES-256-GCM):

```sh
# On the first server (add --ca-dir when the CA runs in ekafleet ca-signer)
ekafleet keys export --data-dir /var/lib/ekafleet-server --ca-dir /var/lib/ekafleet-ca \
  --domain fleet.internal --passphrase-file ./bundle-pass --out ./key-bundle

# On each new server, before its first start
ekafleet keys import --bundle ./key-bundle --passphrase-file ./bundle-pass \
  --data-dir /var/lib/ekafleet-server --domain fleet.internal
```

Rules for the bundle:

- The passphrase must be at least 12 characters.
- Export refuses while a fleet key rotation is in progress.
- Import keeps keys that are already present when they are identical, or when the local fleet key is a newer rotation.
- Import refuses a server that made keys of its own.

With the NixOS module, set `services.ekafleet.server.keyBundleFile` and `keyBundlePassphraseFile`. Both are delivered with `LoadCredential`, and the bundle is imported before every start of the server and the CA signer.

### Fleet key rotation

A rotation (the `RotateFleetKey` RPC; there is no CLI command for it yet) runs on the leader. Before it commits, the leader stages the new key on the other servers and goes ahead only once a majority of the voting servers hold it. Otherwise the rotation fails with `UNAVAILABLE`, and nothing changes. The committed state records a check value of the key (an HMAC, not the key). A server whose key does not match adopts its staged copy, or fetches the key from a peer over server mTLS. Until it has the current key it refuses to seal anything new. So a rotation survives the loss of the leader right after it commits.

## Forming a cluster

Start every server with the same `--peers` and its own `--node-id`:

```sh
ekafleet server --node-id 1 --peers 1=10.0.0.1:7400,2=10.0.0.2:7400,3=10.0.0.3:7400 ...
```

```nix
services.ekafleet.server = {
  nodeId = 1;
  peers = { "1" = "10.0.0.1:7400"; "2" = "10.0.0.2:7400"; "3" = "10.0.0.3:7400"; };
  keyBundleFile = "/run/keys/ekafleet-key-bundle";             # servers 2 and 3
  keyBundlePassphraseFile = "/run/keys/ekafleet-bundle-pass";
};
```

`--peers` is read on first boot only. The server with the lowest id forms the cluster once a majority of the listed servers (itself included) answer and none of them belongs to a cluster yet; until then it serves as a follower and keeps asking. The others join the cluster it forms. Because an existing cluster always holds a majority, a server whose disk was replaced always meets a member of it and waits to be added with `ekafleet raft add`, rather than forming a rival cluster, even while the others are down. Addresses are the gRPC addresses servers reach each other on, and they must not be `0.0.0.0`.

## Changing membership

```sh
ekafleet raft status                       # servers, leader, replication progress
ekafleet raft add 4 10.0.0.4:7400          # start server 4 first (--node-id 4, key bundle)
ekafleet raft remove 2
```

A new server joins as a learner. It becomes a voter only once it has caught up with the log. ekafleet never removes the last voting server. These commands need the `admin` role (`ManageCluster`).

To replace a failed server, remove it, then add the replacement under a new id.
