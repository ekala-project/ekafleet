# System Activation

ekafleet handles full OS-level deployments alongside service orchestration. When the server pushes a new system closure to an agent, the agent activates it — switching the running system to the new configuration.

## How It Works

The agent accepts two parameters for system deployment:

- **toplevel** — the Nix store path of the system closure (output of `system.build.toplevel`)
- **activate script** — the executable to run for activation (defaults to `{toplevel}/bin/activate`)

This design works with both EkaOS and NixOS system closures.

## Activation Flow

```text
Server builds closure
    ↓
nix-copy-closure to agent machine
    ↓
Server pushes DesiredState with system_path
    ↓
Agent receives new system_path
    ↓
nix-env --profile /nix/var/nix/profiles/system --set <path>
    ↓
{toplevel}/bin/activate switch
    ↓
System activated (services restarted, /etc updated, etc.)
    ↓
/run/current-system symlink updated
```

## Activation Actions

| Action | Behavior |
|--------|----------|
| `switch` | Activate now and set as boot default |
| `boot` | Set as boot default only (activates on next reboot) |
| `test` | Activate in current session (don't change boot default) |

The default action is `switch` — the system is activated immediately and will persist across reboots.

## EkaOS vs NixOS

Both are supported, but EkaOS is the preferred target:

| Feature | EkaOS | NixOS |
|---------|-------|-------|
| Port contracts | Yes | No |
| Service mesh integration | Native | Requires manual config |
| Activation script | `{toplevel}/bin/activate` | `{toplevel}/bin/switch-to-configuration` |
| Health-aware DNS | From port contracts | Manual |
| Proxy routing | From port contracts | Manual |

EkaOS closures provide port contracts (`ports.*.hostname`, `ports.*.healthCheck`) that directly feed ekafleet's proxy router, DNS authority, and health checker.

## Rollback

Each activation creates a new Nix profile generation. To rollback:

```bash
# Rollback a specific machine
ekafleet rollback app-1

# Rollback all machines
ekafleet rollback --all

# Rollback to a specific generation
ekafleet rollback --all --to=3
```

The agent resolves the previous generation from `/nix/var/nix/profiles/system-N-link` and re-activates it.

## Machine Secrets (sops-nix / agenix)

Machine-level secrets managed by sops-nix or agenix are activated automatically. Their activation scripts are inside the system closure — when ekafleet runs the activate script, those decrypt and install secrets as part of the normal activation process.

| Layer | Tool | When |
|-------|------|------|
| Machine secrets | sops-nix / agenix | At activation (boot/switch) |
| Service secrets | ekafleet secrets | At runtime (on deploy, hot rotation) |

The machine's age/GPG private key must be present before activation (provisioned at bootstrap time).

## No-Op Detection

If the agent is already running the desired system path, activation is skipped entirely. This makes reconciliation idempotent — the server can push the same desired state repeatedly without triggering unnecessary reboots or service restarts.

## Integration with Service Deployment

System activation happens *before* service reconciliation in the `DesiredState` handler:

1. Activate system closure (if changed)
2. Request SPIFFE SVIDs for assigned services
3. Start health checks
4. Reconcile service units via supervisor

This ensures the OS is at the correct version before services are started.
