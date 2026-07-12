# OCI Containers

ekafleet can run OCI container images alongside native Nix process services. Containers execute via `systemd-nspawn` under the same `ekafleet-<name>.service` unit naming convention, preserving cgroup-based workload attestation, journald logging, and all existing lifecycle semantics.

## When to Use Containers

Native Nix services remain the recommended default -- they provide content-addressed reproducibility and zero runtime overhead. Use OCI containers when:

- A workload is only distributed as a container image (third-party software)
- A team ships OCI images from a separate CI pipeline
- You need to run images built by `dockerTools.buildImage` with filesystem isolation

Both modes coexist in the same fleet. A service is either a native process or a container -- never both.

## Configuration

Set the `container` field instead of `command` on a service:

```nix
services.redis = {
  container = {
    image = "docker.io/library/redis:7.4@sha256:abc123...";
    pullPolicy = "IfNotPresent";   # Always | IfNotPresent | Never
  };

  ports.redis = {
    port = 6379;
    healthCheck = {
      interval = 10;
      timeout = 3;
    };
  };

  resources = {
    cpu = { request = 500; };
    memory = { request = 1024; limit = 2048; };
  };

  scheduling = {
    replicas = 3;
    type = "service";
  };
};
```

The `command` and `container` fields are mutually exclusive. Validation rejects configurations where both or neither are set.

## ContainerConfig Reference

```nix
container = {
  image = "string";             # OCI image reference (required)
  pullPolicy = "Always";        # Always | IfNotPresent | Never (default: Always)
  entrypoint = [ "string" ];    # Override image entrypoint (optional)
  args = [ "string" ];          # Override image CMD (optional)
  workingDir = "/app";          # Override working directory (optional)
  bindMounts = [                # Additional host bind mounts (optional)
    "/host/path:/container/path:ro"
  ];
  registryAuthSecret = "name";  # Secret containing registry credentials (optional)
};
```

### Pull Policies

| Policy | Behavior |
|--------|----------|
| `Always` | Check the registry for a newer digest on every reconciliation cycle |
| `IfNotPresent` | Pull only if the image is not cached locally |
| `Never` | Fail if the image is not already present locally |

### Image References

Image references follow standard Docker/OCI format:

```
[registry/]repository[:tag][@sha256:hex]
```

For production deployments, pin images by digest to ensure reproducibility:

```nix
image = "ghcr.io/org/app:v2.1@sha256:a1b2c3d4e5f6...";
```

Mutable tags like `:latest` work but sacrifice the content-addressing guarantees that Nix store paths provide.

## How It Works

### Image Pipeline

1. **Pull** -- The agent's native OCI registry client fetches the manifest and layers
2. **Verify** -- Each blob is SHA-256 verified against the manifest digest
3. **Store** -- Layers are cached in a content-addressable store at `/var/lib/ekafleet/oci/`
4. **Unpack** -- Layers are extracted in order into a rootfs, handling OCI whiteout files
5. **Bundle** -- A `config.json` is generated from the image config and ekafleet parameters

### Execution

The supervisor generates a systemd unit that invokes `systemd-nspawn`:

```ini
[Unit]
Description=ekafleet container: redis
After=network.target
Wants=machines.target

[Service]
Type=simple
ExecStart=systemd-nspawn \
  --oci-bundle=/var/lib/ekafleet/oci/bundles/redis \
  --machine=ekafleet-redis \
  --network-namespace-path=/proc/1/ns/net \
  --register=yes \
  --keep-unit
ExecStop=machinectl terminate ekafleet-redis
KillMode=mixed
```

Key properties:

- **Host networking** (`--network-namespace-path=/proc/1/ns/net`) -- the container shares the host network stack, so nftables policies work unchanged
- **machined registration** (`--register=yes`) -- enables `machinectl shell` for exec-into-container
- **Same cgroup** (`--keep-unit`) -- the container runs inside the `ekafleet-redis.service` cgroup, so workload attestation via `/proc/<pid>/cgroup` works identically to native services
- **journald logging** -- container stdout/stderr goes to the unit's journal

### Exec into Containers

`exec_in_service` automatically detects whether a service is a container by probing `machinectl status`. For containers, it routes through `machinectl shell` instead of `systemd-run`:

```bash
# Via CLI (works for both native and container services)
ekafleet exec redis -- redis-cli ping
```

### Garbage Collection

Unused image layers and bundles are cleaned up when:

- A service is removed from the desired state
- A service's image reference changes (old layers become unreferenced)

The GC runs during reconciliation and tracks which blobs are referenced by active service manifests.

## SPIFFE Identity

Container services receive the same SPIFFE identity as native services. The identity is based on the service name, not the execution mode:

```
spiffe://fleet.internal/service/redis
```

The SPIFFE Workload API socket is bind-mounted into the container at its default path. Workload attestation works because the container's processes run inside the `ekafleet-<name>.service` cgroup -- the existing cgroup-based PID mapping resolves correctly.

Secrets are bind-mounted read-only at `/run/secrets` inside the container.

## Deployment Strategies

All deployment strategies (rolling, canary, blue-green) work identically for container services. The deployer operates on placements and health gates, not execution mechanics.

Version changes are detected by comparing the image reference string. When the image reference changes (including digest), the supervisor restarts the unit with the new OCI bundle.

## Limitations

- **No bridge networking** -- containers use host networking only. Private container networks are not supported.
- **No image signing verification** -- images are verified by digest but not by cryptographic signature (cosign/notation support is planned).
- **Rollback depends on cache** -- unlike Nix generations which are always local, container rollback requires the previous image to be in the local cache or pullable from the registry.
- **No rootless containers** -- systemd-nspawn runs as root. Workload isolation relies on cgroup v2 resource controls and namespace separation.

## Nix-Built Container Images

For the strongest reproducibility guarantees, build OCI images with Nix:

```nix
services.my-app = {
  container = {
    image = "my-app:latest";
    pullPolicy = "Never";  # image is pre-loaded from Nix
  };
};
```

Build and load the image on the agent:

```nix
# In your flake
packages.my-app-image = pkgs.dockerTools.buildImage {
  name = "my-app";
  tag = "latest";
  copyToRoot = pkgs.buildEnv {
    name = "root";
    paths = [ pkgs.my-app ];
  };
  config.Entrypoint = [ "${pkgs.my-app}/bin/server" ];
};
```

This combines Nix's content-addressing with container namespace isolation.
