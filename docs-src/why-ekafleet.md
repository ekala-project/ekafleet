# Why Ekafleet?

Running a production fleet today means assembling infrastructure from parts. A scheduler here, a service mesh there, a secret store bolted on the side. Each tool has its own configuration language, its own failure modes, its own upgrade cadence. Operators become integration engineers, spending more time wiring tools together than solving the problems those tools were meant to address.

The existing options are impressive engineering achievements. Kubernetes has become the de facto standard for container orchestration. The HashiCorp stack (Nomad, Consul, Vault) offers flexibility across workload types. NixOps and Colmena brought declarative deployment to NixOS machines. But none of these were designed for what ekafleet sets out to do: orchestrate entire NixOS systems as a single, coherent operation.

## The Problem with Tool Sprawl

Consider what a typical production fleet requires beyond just scheduling workloads:

- Service discovery and DNS
- TLS certificate management
- Secret storage and rotation
- Workload identity and attestation
- Network policy enforcement
- Mesh encryption between services
- Reverse proxy and ingress
- Health checking and auto-remediation
- Metrics collection and alerting
- Deployment strategies (canary, blue-green)
- Configuration templating

In the Kubernetes world, this means deploying CoreDNS, cert-manager, Vault (or Sealed Secrets), SPIRE, Cilium (or Calico), Istio (or Linkerd), an ingress controller, Prometheus, Alertmanager, and ArgoCD. Each one is a separate deployment to maintain, monitor, and upgrade. Each has its own CRDs, its own documentation, its own release schedule. The control plane alone consumes hundreds of megabytes and dozens of pods before a single workload runs.

The HashiCorp path is lighter but still fragmented. Nomad handles scheduling. Consul handles discovery and the service mesh. Vault handles secrets and PKI. Three separate binaries, three separate Raft clusters, three separate configuration languages, three separate upgrade procedures. And you still need additional tooling for metrics, alerting, and ingress.

For NixOS operators specifically, these tools introduce a fundamental mismatch. Kubernetes is container-first — it expects OCI images, not Nix store paths. Nomad is more flexible but still doesn't understand system closures. Neither can activate a NixOS generation, roll back an OS configuration, or evaluate fleet state from a Nix expression.

## What Ekafleet Does Differently

ekafleet starts from a different premise: a fleet orchestrator should be a single, coherent system rather than a collection of independently-developed components stitched together at deployment time.

### One Binary, Everything

ekafleet ships as a single ~5MB statically-linked binary with zero runtime dependencies. No JVM. No container runtime. No interpreters. This one binary provides scheduling, deployment orchestration, service discovery, DNS, certificate authority, secret management, workload identity (SPIFFE), mesh networking (WireGuard), network policy (nftables), reverse proxy, health checking, metrics collection, alerting, and a policy engine.

The operational surface area collapses from a dozen services to one. There is one configuration language, one state model, one reconciliation loop, one thing to upgrade. When something goes wrong, there is one place to look.

### Nix-Native from the Ground Up

Fleet configuration is pure Nix. Not YAML translated through Helm templates. Not HCL with string interpolation. Nix — with all the composition, abstraction, and type safety that implies.

ekafleet evaluates `fleet.nix` via `nix eval --json`, producing a complete desired state for the cluster. This means fleet definitions benefit from the same reproducibility guarantees as NixOS system configurations. You can compose service definitions from shared libraries, parameterize deployments with functions, and validate configuration at evaluation time rather than at apply time.

More importantly, ekafleet deploys full NixOS system closures. It doesn't just restart a service binary — it activates an entire system generation. OS-level packages, kernel parameters, systemd units, firewall rules, user accounts — everything converges to the declared state. And because it's Nix, rolling back means switching to a previous generation. The entire OS state is versioned, not just the application.

### Security as Architecture

Most orchestration systems bolt security on after the fact. You deploy your cluster, then add SPIRE for identity. You configure your mesh, then layer on mTLS. You stand up Vault, then figure out how to inject secrets into workloads. Each layer is an independent integration point with its own failure modes.

ekafleet treats security as foundational architecture:

**SPIFFE is a first-class citizen.** Every workload receives an X.509-SVID (Secure Verifiable Identity Document) through the standard SPIFFE Workload API. This isn't an add-on — it's woven into the system's core. Services request identities through a proper CSR flow: the workload generates its own ECDSA P-256 keypair locally, submits a PKCS#10 Certificate Signing Request, and receives back a signed certificate. Private keys never leave the machine where the workload runs. Any standard SPIFFE library (go-spiffe, rust-spiffe) works out of the box via the Unix domain socket at `/run/ekafleet/workload-api.sock`.

**Defense in depth is the default posture.** Transport encryption via kernel WireGuard tunnels between all fleet machines. Service identity via mTLS with SPIFFE SVIDs. Network policy via nftables rules generated from identity contracts. Secrets encrypted at rest with AES-256-GCM. Each layer operates independently — compromising one doesn't compromise the others.

**Identity contracts enforce least-privilege networking.** Services declare `allowedCallers` and `allowedTargets`. The default posture is deny-all. ekafleet generates nftables rules that enforce these contracts at the kernel level. A compromised service cannot reach endpoints it wasn't explicitly authorized to contact.

### System Orchestration, Not Container Orchestration

Kubernetes orchestrates containers. ekafleet orchestrates systems.

Services run as systemd units, supervised by the init system that already manages everything else on a Linux machine. No container runtime sits between your workload and the kernel. No overlay filesystem adds latency to disk I/O. No virtual networking adds hops to packet paths.

This isn't a limitation — it's a design choice. NixOS already provides the isolation and reproducibility that containers were invented to deliver. Store paths are immutable. Dependencies are explicit. Builds are reproducible. The container abstraction adds overhead without adding capability in this context.

ekafleet's supervisor manages service lifecycle with the same primitives Kubernetes offers — liveness, readiness, and startup probes; pre-stop and post-start hooks; configurable restart policies; graceful termination periods — but executes them through systemd rather than a container runtime.

### Continuous Reconciliation

ekafleet follows a Terraform-inspired reconciliation model: Evaluate, Refresh, Plan, Apply. Every 30 seconds in continuous mode, it evaluates the Nix fleet definition, queries agents for actual state, computes the diff, and converges. Drift is detected and corrected automatically.

This is fundamentally different from one-shot deployment tools like NixOps or deploy-rs, which apply a configuration and walk away. If a service crashes and doesn't restart, if a node goes down and workloads need rescheduling, if a new machine joins and needs services placed on it — ekafleet handles these continuously without operator intervention.

## Who Ekafleet Is For

**Teams running NixOS or ekaOS in production.** If your infrastructure is already Nix-based, ekafleet extends that philosophy to fleet orchestration. Your deployment tool finally speaks the same language as your system configuration.

**Security-conscious organizations.** If you need workload identity, mutual TLS, network policy enforcement, encrypted secrets, and audit logging — and you want these as inherent properties rather than integration projects — ekafleet provides them from the first boot.

**Operators tired of maintaining tool sprawl.** If you've spent more time upgrading Vault, debugging Consul gossip, and reconciling Nomad job definitions than actually shipping features, a single binary with a single configuration language is a meaningful reduction in operational burden.

**Multi-region deployments.** ekafleet supports cluster federation with SPIFFE trust domain federation and cross-cluster service discovery. Workloads in one region can authenticate and communicate with workloads in another through standard SPIFFE identity.

**Cost-conscious infrastructure.** A 5MB binary with no runtime dependencies runs on minimal hardware. No etcd cluster consuming memory. No container runtime consuming CPU. No sidecar proxies doubling your pod count.

## What Ekafleet Is Not

Honesty about scope builds trust, so here's what ekafleet explicitly does not attempt:

**It is not a container orchestrator.** If your workloads are packaged as OCI images and you need the container ecosystem (registries, runtime classes, sidecar injection), Kubernetes is the right choice. ekafleet manages systemd services built from Nix store paths.

**It is not a general-purpose cloud platform.** ekafleet doesn't provision machines from cloud providers (though it provides advisory scaling signals via webhooks). Infrastructure provisioning remains the domain of Terraform, OpenTofu, or NixOps.

**It is not a full observability platform.** ekafleet collects metrics and evaluates alerting rules, but it doesn't provide long-term storage, PromQL queries, or dashboards. It's designed to feed metrics into your existing observability stack, not replace Prometheus and Grafana entirely.

These boundaries are intentional. ekafleet does one thing well: orchestrating fleets of NixOS machines with security and simplicity as foundational properties. Everything else is left to tools purpose-built for those problems.

## The Result

A production fleet where:

- Configuration is a single Nix expression, version-controlled and reproducible
- Every workload has a cryptographic identity from its first second of life
- Network policy is enforced at the kernel level by default
- Secrets are encrypted at rest and delivered over authenticated channels
- The entire OS converges to declared state every 30 seconds
- Rolling back means switching a Nix generation
- One 5MB binary replaces a dozen infrastructure services
- Operators debug one system instead of twelve

That's why ekafleet.
