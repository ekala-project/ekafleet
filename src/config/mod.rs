pub mod scheduling;
pub use scheduling::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level fleet configuration as produced by `nix eval --json .#fleet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FleetConfig {
    pub name: String,
    pub domain: String,
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub machines: HashMap<String, MachineConfig>,
    #[serde(default)]
    pub node_pools: HashMap<String, NodePoolConfig>,
    /// Webhooks notified of fleet events (deploys, drains, configuration
    /// changes, nodes connecting and leaving).
    #[serde(default)]
    pub webhooks: Vec<EventWebhook>,
    /// Admission webhooks for validating deployments.
    #[serde(default)]
    pub admission_webhooks: Vec<AdmissionWebhook>,
    /// Organizational policy rules evaluated during plan/apply.
    #[serde(default)]
    pub policies: Vec<crate::server::policy::PolicyRule>,
    /// Fleet-wide OCI image signature policy. When set, it applies to every
    /// container image pulled by any service in the fleet, rather than being
    /// configured per-service.
    #[serde(default)]
    pub signature_policy: Option<SignaturePolicyConfig>,
    /// Alert rules evaluated by the server against the metrics agents ship.
    /// Versioned (and rolled back) with the rest of the configuration.
    #[serde(default)]
    pub alerts: Vec<AlertRuleConfig>,
    /// Namespaces with settings, keyed by name. Services may use namespaces
    /// that are not listed here; those have no quota.
    #[serde(default)]
    pub namespaces: HashMap<String, NamespaceConfig>,
    /// Database engines that issue `dynamic` secrets, keyed by name.
    #[serde(default)]
    pub secret_engines: HashMap<String, SecretEngineConfig>,
    /// Services running outside the fleet (managed databases, SaaS
    /// endpoints), resolvable as `<name>.external.<domain>`.
    #[serde(default)]
    pub external_services: HashMap<String, ExternalServiceConfig>,
}

/// A service outside the fleet that fleet DNS answers for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalServiceConfig {
    /// `ip:port` endpoints (IPv4).
    pub addresses: Vec<String>,
    /// Checked by the server; failing addresses are left out of DNS.
    #[serde(default)]
    pub health_check: Option<ExternalHealthCheck>,
}

impl ExternalServiceConfig {
    /// The parsed addresses; [`validate`] rejects configurations where any
    /// does not parse.
    pub fn endpoints(&self) -> Vec<std::net::SocketAddrV4> {
        self.addresses
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect()
    }
}

/// How the server checks an external service's addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalHealthCheck {
    /// `tcp` (connect) or `http` (GET `path`, any 2xx/3xx passes).
    #[serde(rename = "type")]
    pub check_type: String,
    /// HTTP request path.
    #[serde(default)]
    pub path: Option<String>,
    /// Seconds between checks.
    #[serde(default = "default_external_interval")]
    pub interval: u64,
    /// Seconds before a check fails.
    #[serde(default = "default_external_timeout")]
    pub timeout: u64,
}

fn default_external_interval() -> u64 {
    10
}

fn default_external_timeout() -> u64 {
    2
}

/// A database server that issues dynamic credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretEngineConfig {
    /// Fleet secret (`ekafleet secret set _fleet <name>`) holding the admin
    /// connection URL, e.g. `postgres://admin:pw@db:5432/postgres`.
    pub admin_url_secret: String,
    /// Database services get access to.
    pub database: String,
}

/// Settings of a namespace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NamespaceConfig {
    #[serde(default)]
    pub quota: NamespaceQuota,
}

/// Limits on what a namespace's services may request in total, checked
/// when a configuration is applied. Requests are counted per instance, at
/// the most instances a service can run (its autoscaling maximum, or every
/// eligible machine for system jobs). Unset limits are unlimited.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NamespaceQuota {
    /// Total CPU requests, in millicores.
    #[serde(default)]
    pub cpu: Option<u64>,
    /// Total memory requests, in MB.
    #[serde(default)]
    pub memory: Option<u64>,
    /// Total disk requests, in MB.
    #[serde(default)]
    pub disk: Option<u64>,
    /// Total instances.
    #[serde(default)]
    pub instances: Option<u64>,
    /// Number of services.
    #[serde(default)]
    pub services: Option<u64>,
}

/// A namespace name: usable as a DNS label and in network namespace and
/// interface names.
pub fn validate_namespace_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid namespace name '{name}': use 1-32 lowercase letters, digits and inner dashes"
        ))
    }
}

/// A Prometheus metric or label name (without `:`).
fn label_name_ok(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_metric_name(s: &str) -> bool {
    label_name_ok(s) && !s.starts_with("__")
}

fn validate_autoscale(name: &str, service: &ServiceConfig, errors: &mut Vec<String>) {
    let Some(autoscale) = &service.scheduling.autoscale else {
        return;
    };
    let mut error = |e: String| errors.push(format!("service '{name}' autoscale: {e}"));
    if service.scheduling.job_type != JobType::Service {
        error("only service jobs can autoscale".into());
    }
    if autoscale.min == 0 || autoscale.min > autoscale.max {
        error(format!(
            "need 1 <= min <= max, not min {} and max {}",
            autoscale.min, autoscale.max
        ));
    }
    if autoscale.rules.is_empty() {
        error("rules is empty".into());
    }
    if !(15..=86400).contains(&autoscale.scale_down_delay_seconds) {
        error("scaleDownDelaySeconds must be between 15 and 86400".into());
    }
    for rule in &autoscale.rules {
        if !rule.target.is_finite() || rule.target <= 0.0 {
            error(format!("rule '{}': target must be positive", rule.metric));
        }
        let request = |r: &Option<ResourceValue>| r.as_ref().map_or(0, |r| r.request);
        match rule.metric.as_str() {
            "cpu" if request(&service.resources.cpu) == 0 => {
                error("rule 'cpu' needs resources.cpu.request".into())
            }
            "memory" if request(&service.resources.memory) == 0 => {
                error("rule 'memory' needs resources.memory.request".into())
            }
            "cpu" | "memory" => {}
            metric if service.metrics.is_none() => error(format!(
                "rule '{metric}' needs the service's metrics endpoint"
            )),
            metric if !valid_metric_name(metric) => {
                error(format!("rule '{metric}': invalid metric name"))
            }
            _ => {}
        }
    }
}

fn validate_namespaces_and_admission(config: &FleetConfig, errors: &mut Vec<String>) {
    for name in config.namespaces.keys() {
        if let Err(e) = validate_namespace_name(name) {
            errors.push(format!("namespaces: {e}"));
        }
    }
    for (service, cfg) in &config.services {
        if !cfg.namespace.is_empty()
            && let Err(e) = validate_namespace_name(&cfg.namespace)
        {
            errors.push(format!("service '{service}': {e}"));
        }
    }
    for (name, service) in &config.services {
        validate_autoscale(name, service, errors);
    }
    for service in config.services.keys() {
        if service.starts_with('_') {
            errors.push(format!(
                "service '{service}': names starting with '_' are reserved"
            ));
        }
    }
    let mut names = std::collections::HashSet::new();
    for webhook in &config.webhooks {
        if !names.insert(webhook.name.as_str()) {
            errors.push(format!("webhooks: duplicate name '{}'", webhook.name));
        }
        if let Err(e) = validate_webhook_url(&webhook.url) {
            errors.push(format!("webhook '{}': url {e}", webhook.name));
        }
        if webhook.events.is_empty() {
            errors.push(format!("webhook '{}': events is empty", webhook.name));
        }
        for pattern in &webhook.events {
            if !valid_event_pattern(pattern) {
                errors.push(format!(
                    "webhook '{}': invalid event pattern '{pattern}' (use a type like \
                     'deploy.failed', a prefix like 'deploy.*', or '*')",
                    webhook.name
                ));
            }
        }
        if let Some(secret) = &webhook.secret
            && let Err(e) = crate::secrets::validate_name("secret", secret)
        {
            errors.push(format!("webhook '{}': {e}", webhook.name));
        }
    }
    let mut names = std::collections::HashSet::new();
    for webhook in &config.admission_webhooks {
        if !names.insert(webhook.name.as_str()) {
            errors.push(format!(
                "admissionWebhooks: duplicate name '{}'",
                webhook.name
            ));
        }
        if let Err(e) = validate_webhook_url(&webhook.url) {
            errors.push(format!("admission webhook '{}': url {e}", webhook.name));
        }
        if !(1..=60).contains(&webhook.timeout_seconds) {
            errors.push(format!(
                "admission webhook '{}': timeoutSeconds must be between 1 and 60",
                webhook.name
            ));
        }
    }
}

/// A threshold alert on a node or service metric.
///
/// Metrics named `node_*` are node metrics, evaluated once per node; any
/// other metric is scraped from services (see [`MetricsEndpoint`]) and
/// evaluated once per service instance. Every breaching series fires and
/// resolves on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertRuleConfig {
    /// Unique rule name; the `alertname` label of its alerts.
    pub name: String,
    pub metric: String,
    #[serde(default)]
    pub op: AlertOp,
    pub threshold: f64,
    /// How long a series must breach before its alert fires.
    #[serde(default = "default_alert_for_seconds")]
    pub for_seconds: u64,
    /// Only evaluate instances of this service.
    #[serde(default)]
    pub service: Option<String>,
    /// Only evaluate this node.
    #[serde(default)]
    pub node: Option<String>,
    #[serde(default)]
    pub severity: AlertSeverity,
    /// Extra labels attached to the alerts (for routing and silences).
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Human-readable summary annotation.
    #[serde(default)]
    pub summary: Option<String>,
    /// Alertmanager-compatible webhook receiving firing and resolved alerts.
    #[serde(default)]
    pub webhook_url: Option<String>,
}

fn default_alert_for_seconds() -> u64 {
    60
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertOp {
    #[default]
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

impl AlertOp {
    pub fn holds(self, value: f64, threshold: f64) -> bool {
        match self {
            AlertOp::Gt => value > threshold,
            AlertOp::Gte => value >= threshold,
            AlertOp::Lt => value < threshold,
            AlertOp::Lte => value <= threshold,
            AlertOp::Eq => value == threshold,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            AlertOp::Gt => ">",
            AlertOp::Gte => ">=",
            AlertOp::Lt => "<",
            AlertOp::Lte => "<=",
            AlertOp::Eq => "==",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    #[default]
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
        }
    }
}

/// A Prometheus metrics endpoint the hosting agent scrapes every 15
/// seconds, on the service's loopback (inside its network namespace).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetricsEndpoint {
    pub port: u16,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".into()
}

/// Fleet-wide cosign image signature policy applied to the cosign signature of
/// every container image before its layers are pulled. Supports both static-key
/// and sigstore keyless (Fulcio/Rekor) verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignaturePolicyConfig {
    /// PEM-encoded public key (ECDSA P-256 or Ed25519, SPKI format) for
    /// static-key verification. Mutually exclusive with `keyless`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_pem: Option<String>,
    /// Keyless (Fulcio/Rekor) verification parameters. Mutually exclusive with
    /// `public_key_pem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyless: Option<KeylessPolicyConfig>,
    /// When true, an image that has no valid signature is rejected. When false
    /// the policy is advisory: verification is attempted and failures are
    /// logged, but the pull is allowed to proceed.
    #[serde(default = "default_true")]
    pub enforce: bool,
}

/// Configuration for sigstore keyless (Fulcio/Rekor) verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeylessPolicyConfig {
    /// PEM bundle of trusted Fulcio root/intermediate CA certificates. A signing
    /// certificate must chain to one of these.
    pub fulcio_roots_pem: String,
    /// Accepted signer identities. A signing certificate must match one.
    pub identities: Vec<KeylessIdentityConfig>,
    /// PEM-encoded Rekor transparency-log public key. A keyless signature
    /// must carry a Rekor bundle signed by it: the logged time is what proves
    /// the short-lived signing certificate was valid when used.
    pub rekor_public_key_pem: String,
}

/// An accepted keyless signer identity (SAN subject + OIDC issuer).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeylessIdentityConfig {
    /// The Subject Alternative Name identity (email or URI), matched exactly.
    pub subject: String,
    /// The OIDC issuer that authenticated the signer, matched exactly.
    pub issuer: String,
}

impl SignaturePolicyConfig {
    /// Parse this configuration into a runtime signature policy.
    pub fn to_runtime_policy(
        &self,
    ) -> Result<
        crate::agent::oci::signature::SignaturePolicy,
        crate::agent::oci::signature::SignatureError,
    > {
        use crate::agent::oci::signature::{
            KeylessIdentity, KeylessPolicy, SignatureError, SignaturePolicy, parse_public_key_pem,
        };

        match (&self.public_key_pem, &self.keyless) {
            (Some(pem), None) => {
                let key = parse_public_key_pem(pem)?;
                Ok(SignaturePolicy::Key(key))
            }
            (None, Some(keyless)) => {
                let fulcio_roots = parse_cert_bundle_pem(&keyless.fulcio_roots_pem)?;
                let rekor_public_key = parse_rekor_key_pem(&keyless.rekor_public_key_pem)?;
                let identities = keyless
                    .identities
                    .iter()
                    .map(|i| KeylessIdentity {
                        subject: i.subject.clone(),
                        issuer: i.issuer.clone(),
                    })
                    .collect();
                Ok(SignaturePolicy::Keyless(Box::new(KeylessPolicy {
                    fulcio_roots,
                    identities,
                    rekor_public_key,
                })))
            }
            (Some(_), Some(_)) => Err(SignatureError::InvalidKey(
                "signature policy sets both publicKeyPem and keyless; choose one".into(),
            )),
            (None, None) => Err(SignatureError::InvalidKey(
                "signature policy must set either publicKeyPem or keyless".into(),
            )),
        }
    }
}

/// Parse a PEM bundle of one or more X.509 certificates into their DER bytes.
fn parse_cert_bundle_pem(
    pem: &str,
) -> Result<Vec<Vec<u8>>, crate::agent::oci::signature::SignatureError> {
    use crate::agent::oci::signature::SignatureError;

    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let mut out = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| SignatureError::InvalidKey(format!("invalid CA PEM: {e}")))?;
        out.push(cert.as_ref().to_vec());
    }
    if out.is_empty() {
        return Err(SignatureError::InvalidKey(
            "Fulcio root bundle contained no certificates".into(),
        ));
    }
    Ok(out)
}

/// Parse the Rekor transparency-log key (ECDSA P-256 SPKI PEM) into the raw
/// point the verifier uses.
fn parse_rekor_key_pem(pem: &str) -> Result<Vec<u8>, crate::agent::oci::signature::SignatureError> {
    use crate::agent::oci::signature::{SignatureError, SigningKey, parse_public_key_pem};
    match parse_public_key_pem(pem)? {
        SigningKey::EcdsaP256(point) => Ok(point),
        SigningKey::Ed25519(_) => Err(SignatureError::InvalidKey(
            "the Rekor key must be ECDSA P-256".into(),
        )),
    }
}

/// Script hooks executed at various deployment lifecycle points.
/// A webhook POSTed every fleet event whose type matches one of `events`.
///
/// Bodies are the event as JSON. With `secret` set, each carries
/// `X-Ekafleet-Signature: sha256=<hex HMAC-SHA256 of the body>`, keyed by
/// the fleet-level static secret of that name (`ekafleet secret set _fleet
/// <secret>`); events are not sent while it has no value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventWebhook {
    pub name: String,
    pub url: String,
    /// Event types (`deploy.failed`), prefixes (`deploy.*`) or `*`.
    pub events: Vec<String>,
    #[serde(default)]
    pub secret: Option<String>,
}

impl EventWebhook {
    pub fn wants(&self, kind: &str) -> bool {
        self.events.iter().any(|p| event_matches(p, kind))
    }
}

/// Whether event type `kind` matches `pattern`: equal, `*`, or `prefix.*`
/// for `prefix` and every type under it.
pub fn event_matches(pattern: &str, kind: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix(".*") {
        Some(prefix) => {
            kind == prefix
                || kind
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
        }
        None => pattern == kind,
    }
}

fn valid_event_pattern(pattern: &str) -> bool {
    let body = pattern.strip_suffix(".*").unwrap_or(pattern);
    pattern == "*"
        || (!body.is_empty()
            && body.split('.').all(|part| {
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            }))
}

/// Configuration for an admission webhook that validates deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdmissionWebhook {
    /// Unique name for this webhook.
    pub name: String,
    /// URL to POST admission review requests to.
    pub url: String,
    /// Policy when the webhook is unreachable or returns an error.
    #[serde(default)]
    pub fail_policy: FailPolicy,
    /// Request timeout in seconds.
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,
}

/// Policy for handling webhook failures (unreachable, timeout, error).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailPolicy {
    /// Reject the request if the webhook fails.
    #[default]
    Fail,
    /// Allow the request even if the webhook fails.
    Ignore,
}

fn default_webhook_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Command to execute for native (Nix) process services.
    /// Required unless `container` is set.
    #[serde(default)]
    pub command: Option<String>,
    /// OCI container configuration. When set, the service runs as a
    /// systemd-nspawn container instead of a native process.
    #[serde(default)]
    pub container: Option<ContainerConfig>,
    #[serde(default)]
    pub ports: HashMap<String, PortConfig>,
    #[serde(default)]
    pub secrets: HashMap<String, SecretConfig>,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub scheduling: SchedulingConfig,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    /// Configuration file templates rendered by the agent and bind-mounted
    /// read-only into the service at their `destPath`, by name.
    #[serde(default)]
    pub templates: HashMap<String, TemplateConfig>,
    /// Lifecycle hooks and shutdown configuration.
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
    /// Persistent volumes to attach to this service.
    #[serde(default)]
    pub volumes: Vec<VolumeConfig>,
    /// Sidecar processes to run alongside this service.
    #[serde(default)]
    pub sidecars: Vec<SidecarConfig>,
    /// Namespace this service belongs to. Empty or "default" means host
    /// networking. Non-default namespaces get isolated network namespaces.
    #[serde(default)]
    pub namespace: String,
    /// Prometheus endpoint scraped by the hosting agent.
    #[serde(default)]
    pub metrics: Option<MetricsEndpoint>,
    /// Store paths the service needs, built by the server at apply time.
    /// Never read from the fleet configuration itself.
    #[serde(skip)]
    pub store_paths: Vec<String>,
    /// Transit keys the service's workloads may encrypt and decrypt with
    /// (authenticated by their service SVID).
    #[serde(default, rename = "transitKeys")]
    pub transit_keys: Vec<String>,
}

/// OCI container configuration for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContainerConfig {
    /// OCI image reference (e.g. "ghcr.io/org/app:v1.0@sha256:...").
    pub image: String,
    /// Pull policy: "Always", "IfNotPresent", or "Never".
    #[serde(default)]
    pub pull_policy: ContainerPullPolicy,
    /// Override the image's entrypoint.
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    /// Override the image's CMD.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Working directory inside the container.
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Additional bind mounts (host_path:container_path[:ro]).
    #[serde(default)]
    pub bind_mounts: Vec<String>,
    /// Registry credentials secret name (references a secret in the service's secrets).
    #[serde(default)]
    pub registry_auth_secret: Option<String>,
}

/// A parsed `bindMounts` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountSpec {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

impl ContainerConfig {
    /// Parse `bindMounts` (`/host:/container[:ro|:rw]`).
    pub fn parsed_bind_mounts(&self) -> Result<Vec<BindMountSpec>, String> {
        self.bind_mounts
            .iter()
            .map(|m| parse_bind_mount(m))
            .collect()
    }
}

fn parse_bind_mount(mount: &str) -> Result<BindMountSpec, String> {
    let parts: Vec<&str> = mount.split(':').collect();
    let (host, container, read_only) = match parts.as_slice() {
        [host, container] | [host, container, "rw"] => (*host, *container, false),
        [host, container, "ro"] => (*host, *container, true),
        _ => {
            return Err(format!(
                "bind mount '{mount}' must be /host:/container[:ro]"
            ));
        }
    };
    for path in [host, container] {
        if !is_plain_bind_path(path) {
            return Err(format!(
                "bind mount '{mount}': '{path}' must be an absolute path without '..', spaces or quoting"
            ));
        }
    }
    Ok(BindMountSpec {
        host_path: host.to_string(),
        container_path: container.to_string(),
        read_only,
    })
}

/// Whether `path` can appear in a bind mount: the paths end up on a unit's
/// ExecStart line, so they must be absolute, without `..`, quoting, escapes,
/// separators or systemd specifiers.
pub fn is_plain_bind_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.split('/').any(|c| c == "..")
        && !path.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, ':' | ',' | '%' | '\\' | '"' | '\'')
        })
}

/// Pull policy for OCI container images.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerPullPolicy {
    /// Always check the registry for a newer image.
    #[default]
    Always,
    /// Only pull if the image is not present locally.
    IfNotPresent,
    /// Never pull from the registry; fail if not present locally.
    Never,
}

/// A persistent volume to attach to a stateful service.
/// Volumes survive service restarts and are migrated when a stateful
/// service is rescheduled (if the storage backend supports it).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VolumeConfig {
    /// Volume name (unique within the service).
    pub name: String,
    /// Mount path inside the service's filesystem namespace.
    pub mount_path: String,
    /// Requested storage size in megabytes.
    #[serde(default = "default_volume_size")]
    pub size_mb: u64,
    /// Storage class; only "local" (a directory on the node) is supported.
    #[serde(default = "default_storage_class")]
    pub storage_class: String,
    /// Access mode: "ReadWriteOnce" (default) or "ReadWriteMany".
    #[serde(default)]
    pub access_mode: VolumeAccessMode,
    /// If true, the volume is not deleted when the service is destroyed.
    #[serde(default = "default_true")]
    pub reclaim_retain: bool,
}

fn default_volume_size() -> u64 {
    1024
}
fn default_storage_class() -> String {
    "local".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum VolumeAccessMode {
    #[default]
    ReadWriteOnce,
    ReadWriteMany,
}

/// A configuration file template rendered with fleet context (service
/// discovery, secrets, metadata) and visible to the service at `dest_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemplateConfig {
    /// Template source: inline content with `{{ }}` placeholders.
    pub source: String,
    /// Destination path where the rendered file is written.
    pub dest_path: String,
    /// File permissions (octal, e.g., "0644"). Defaults to "0644".
    #[serde(default = "default_file_perms")]
    pub perms: String,
    /// Signal sent to the service when the rendered file changes (e.g.
    /// `SIGHUP`); unset restarts the service instead.
    #[serde(default)]
    pub change_signal: Option<String>,
}

fn default_file_perms() -> String {
    "0644".to_string()
}

/// A template's octal `perms` as permission bits.
pub fn template_mode(perms: &str) -> Option<u32> {
    u32::from_str_radix(perms.trim_start_matches("0o"), 8)
        .ok()
        .filter(|mode| *mode <= 0o777)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PortConfig {
    pub port: u16,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// Unified health check (used when liveness/readiness are not specified separately).
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Liveness probe: failures trigger a service restart.
    #[serde(default)]
    pub liveness: Option<HealthCheckConfig>,
    /// Readiness probe: failures remove the instance from load balancing
    /// but do not restart it.
    #[serde(default)]
    pub readiness: Option<HealthCheckConfig>,
    /// Startup probe: suppresses liveness checks until the service finishes
    /// initializing. Once the startup probe passes, liveness takes over.
    #[serde(default)]
    pub startup: Option<HealthCheckConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_interval")]
    pub interval: u32,
    #[serde(default = "default_timeout")]
    pub timeout: u32,
    #[serde(default = "default_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_interval() -> u32 {
    10
}
fn default_timeout() -> u32 {
    5
}
fn default_threshold() -> u32 {
    3
}

/// A secret a service declares, delivered at `/run/secrets/<name>`.
/// `type = "static"` secrets are values set with `ekafleet secret set`;
/// `"dynamic"` ones are database credentials issued by `engine` with
/// `role`, replaced before `ttl` seconds pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretConfig {
    #[serde(rename = "type", default = "default_secret_type")]
    pub secret_type: String,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl SecretConfig {
    pub fn is_dynamic(&self) -> bool {
        self.secret_type == "dynamic"
    }

    /// Lease length of a dynamic secret.
    pub fn ttl(&self) -> u64 {
        self.ttl.unwrap_or(crate::secrets::dynamic::DEFAULT_TTL)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentityConfig {
    #[serde(default)]
    pub allowed_callers: Vec<String>,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceConfig {
    #[serde(default)]
    pub cpu: Option<ResourceValue>,
    #[serde(default)]
    pub memory: Option<ResourceValue>,
    #[serde(default)]
    pub disk: Option<ResourceValue>,
    /// Extended/device resources (e.g., `{"gpu": 1, "fpga": 2}`).
    #[serde(default)]
    pub extended: HashMap<String, u64>,
    /// Systemd cgroup v2 resource controls for fine-grained resource management.
    #[serde(default)]
    pub cgroup_controls: Option<CgroupControlsConfig>,
}

/// Systemd cgroup v2 resource controls. These are translated directly into
/// systemd unit directives for per-service resource management.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CgroupControlsConfig {
    /// CPU scheduling weight (1-10000, default: 100).
    /// Higher values get more CPU time relative to other services.
    #[serde(default = "default_cpu_weight")]
    pub cpu_weight: u32,
    /// Soft memory limit in MB. When exceeded, the kernel reclaims memory
    /// under pressure but does not kill the process.
    #[serde(default)]
    pub memory_high: Option<u64>,
    /// Hard memory limit in MB. Exceeding this triggers OOM based on oomPolicy.
    #[serde(default)]
    pub memory_max: Option<u64>,
    /// IO scheduling weight (1-10000, default: 100).
    #[serde(default = "default_io_weight")]
    pub io_weight: u32,
    /// Maximum number of tasks (threads + processes) for this service.
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// OOM policy: "stop" (default), "kill", or "continue".
    #[serde(default = "default_oom_policy")]
    pub oom_policy: String,
}

fn default_cpu_weight() -> u32 {
    100
}
fn default_io_weight() -> u32 {
    100
}
fn default_oom_policy() -> String {
    "stop".to_string()
}

impl ResourceConfig {
    /// Translate declared resources into the proto [`CgroupControls`] the agent
    /// renders into systemd unit directives. Explicit `cgroupControls` take
    /// precedence; where they are unset, hard limits are derived from the
    /// declared `cpu.limit` (millicores → `CPUQuota` percent-of-a-core) and
    /// `memory.limit` (MB → `MemoryMax`). Returns `None` when nothing at all is
    /// declared, so the agent leaves the service uncapped.
    pub fn to_cgroup_controls(&self) -> Option<crate::proto::CgroupControls> {
        let explicit = self.cgroup_controls.as_ref();

        // Derive a hard CPU cap from cpu.limit (millicores). 1000 mc == 1 core
        // == CPUQuota=100%. A limit below 1 mc rounds up to 1% so a declared
        // limit is never silently dropped to "unlimited".
        let derived_cpu_quota = self
            .cpu
            .as_ref()
            .and_then(|c| c.limit)
            .filter(|&l| l > 0)
            .map(|mc| mc.div_ceil(10).max(1) as u32);

        // Derive a hard memory cap from memory.limit (MB).
        let derived_mem_max = self
            .memory
            .as_ref()
            .and_then(|m| m.limit)
            .filter(|&l| l > 0);

        let cpu_weight = explicit.map(|c| c.cpu_weight).unwrap_or(0);
        let io_weight = explicit.map(|c| c.io_weight).unwrap_or(0);
        let tasks_max = explicit.and_then(|c| c.tasks_max).unwrap_or(0);
        let memory_high_mb = explicit.and_then(|c| c.memory_high).unwrap_or(0);
        let oom_policy = explicit.map(|c| c.oom_policy.clone()).unwrap_or_default();

        // Explicit memory_max wins over the derived limit.
        let memory_max_mb = explicit
            .and_then(|c| c.memory_max)
            .or(derived_mem_max)
            .unwrap_or(0);

        let cpu_quota_percent = derived_cpu_quota.unwrap_or(0);

        // If nothing is declared at all, leave the service uncapped.
        if cpu_weight == 0
            && io_weight == 0
            && tasks_max == 0
            && memory_high_mb == 0
            && memory_max_mb == 0
            && cpu_quota_percent == 0
            && oom_policy.is_empty()
        {
            return None;
        }

        Some(crate::proto::CgroupControls {
            cpu_weight,
            memory_high_mb,
            memory_max_mb,
            io_weight,
            tasks_max,
            oom_policy,
            cpu_quota_percent,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceValue {
    #[serde(default)]
    pub request: u64,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MachineConfig {
    pub target_host: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub capacity: CapacityConfig,
    /// Node pool this machine belongs to. Defaults to "default".
    #[serde(default = "default_pool")]
    pub pool: String,
    /// Capacity reserved for OS/system use. Scheduler uses capacity - reserved.
    #[serde(default)]
    pub reserved: CapacityConfig,
    /// Taints repel services that don't tolerate them.
    #[serde(default)]
    pub taints: Vec<Taint>,
    /// Extended/device resources available on this machine (e.g., `{"gpu": 4, "fpga": 2}`).
    #[serde(default)]
    pub extended_resources: HashMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityConfig {
    #[serde(default)]
    pub cpu: u64,
    #[serde(default)]
    pub memory: u64,
    #[serde(default)]
    pub disk: u64,
}

fn default_pool() -> String {
    "default".to_string()
}

/// Configuration for a node pool — a named group of machines with shared labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NodePoolConfig {
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub scaling: Option<PoolScalingConfig>,
    #[serde(default)]
    pub scheduler_algorithm: Option<SchedulerAlgorithm>,
    #[serde(default)]
    pub memory_oversubscription: bool,
    /// Cloud provider configuration for autoscaling this pool.
    /// When set, pool scaling decisions will provision/destroy cloud VMs.
    #[serde(default)]
    pub cloud: Option<CloudProviderConfig>,
}

/// Cloud provider configuration for a node pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudProviderConfig {
    /// Cloud provider type: "aws", "azure", or "gcp".
    pub provider: CloudProviderType,
    /// Cloud region (e.g., "us-east-1", "eastus", "us-central1").
    pub region: String,
    /// Instance type / VM size (e.g., "c6i.xlarge", "Standard_D4s_v3", "n2-standard-4").
    pub instance_type: String,
    /// Static machine image ID (e.g., AMI ID, managed image name, GCE image name).
    /// Mutually exclusive with `image`. One of `image_id` or `image` must be set.
    #[serde(default)]
    pub image_id: Option<String>,
    /// Managed image configuration. When set, ekafleet builds NixOS disk images
    /// from the referenced Nix configuration and registers them with the cloud
    /// provider automatically. Mutually exclusive with `image_id`.
    #[serde(default)]
    pub image: Option<CloudImageConfig>,
    /// Subnet ID for network placement (AWS/GCP).
    #[serde(default)]
    pub subnet_id: Option<String>,
    /// Security group IDs (AWS).
    #[serde(default)]
    pub security_group_ids: Vec<String>,
    /// SSH key name for instance access.
    #[serde(default)]
    pub ssh_key_name: Option<String>,
    /// Availability zone (e.g., "us-east-1a", "us-central1-a").
    #[serde(default)]
    pub zone: Option<String>,
    /// Root disk size in GB.
    #[serde(default)]
    pub disk_size_gb: Option<u64>,
    /// Azure resource group name (required for Azure).
    #[serde(default)]
    pub resource_group: Option<String>,
    /// GCP project ID (required for GCP).
    #[serde(default)]
    pub project: Option<String>,
    /// Expected machine capacity for scheduling before the agent reports
    /// real resources. CPU in millicores, memory/disk in MB.
    pub machine_capacity: CapacityConfig,
    /// IAM instance profile ARN (AWS), managed identity resource ID (Azure),
    /// or service account email (GCP).
    #[serde(default)]
    pub iam_instance_profile: Option<String>,
    /// Spot/preemptible instance configuration.
    #[serde(default)]
    pub spot: Option<SpotConfig>,
    /// Maximum time (seconds) to wait for an instance to reach running state.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_launch_timeout")]
    pub launch_timeout_seconds: u64,
    /// Maximum time (seconds) to wait for an agent to join after instance
    /// creation. Instances that fail to join within this window are terminated.
    /// Default: 600 (10 minutes).
    #[serde(default = "default_join_timeout")]
    pub join_timeout_seconds: u64,
    /// Seconds to wait after marking a node unschedulable before terminating
    /// it during scale-down. Gives the reconciler time to reschedule services.
    /// Default: 30.
    #[serde(default = "default_drain_wait")]
    pub drain_wait_seconds: u64,
}

/// Configuration for ekafleet-managed cloud images. When present in a pool's
/// cloud config, ekafleet builds NixOS disk images from the referenced Nix
/// configuration, uploads them to cloud storage, and registers them as
/// AMIs / managed images / GCE images.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudImageConfig {
    /// Nix flake reference for the NixOS system configuration.
    /// Must expose `config.system.build.toplevel` and a disk image attribute.
    /// e.g., ".#nixosConfigurations.cloud-worker"
    pub nixos_config: String,
    /// Nix attribute path for the disk image build under the NixOS config.
    /// Defaults per provider: aws → "amazonImage", azure → "azureImage", gcp → "gceImage".
    #[serde(default)]
    pub disk_image_attr: Option<String>,
    /// Image name prefix for cloud registration. Default: "<fleet-name>-<pool-name>".
    #[serde(default)]
    pub name_prefix: Option<String>,
    /// S3 bucket for AWS image import (required for AWS provider).
    #[serde(default)]
    pub s3_bucket: Option<String>,
    /// GCS bucket for GCP image upload (required for GCP provider).
    #[serde(default)]
    pub gcs_bucket: Option<String>,
    /// Azure storage account name for VHD upload (required for Azure provider).
    #[serde(default)]
    pub storage_account: Option<String>,
    /// Azure storage container name. Default: "ekafleet-images".
    #[serde(default)]
    pub storage_container: Option<String>,
    /// Number of previous images to retain per pool for rollback. Default: 2.
    /// The current active image is always kept; this controls how many older
    /// generations are preserved before cleanup.
    #[serde(default = "default_image_retain_count")]
    pub retain_count: u32,
    /// Maximum age (in seconds) for unused images before automatic cleanup.
    /// Default: 604800 (7 days). Images older than this that are not the
    /// current active image and not within retain_count are deleted.
    #[serde(default = "default_image_max_age")]
    pub max_age_seconds: u64,
}

/// Spot/preemptible instance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpotConfig {
    /// Whether to use spot/preemptible instances.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum price per hour (AWS spot). If omitted, uses on-demand price cap.
    #[serde(default)]
    pub max_price: Option<String>,
    /// Fallback to on-demand if spot capacity is unavailable. Default: true.
    #[serde(default = "default_true")]
    pub fallback_to_on_demand: bool,
}

fn default_launch_timeout() -> u64 {
    300
}

fn default_join_timeout() -> u64 {
    600
}

fn default_drain_wait() -> u64 {
    30
}

fn default_image_retain_count() -> u32 {
    2
}

fn default_image_max_age() -> u64 {
    604800 // 7 days
}

/// Supported cloud provider types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProviderType {
    Aws,
    Azure,
    Gcp,
}

/// Autoscaling configuration for a node pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PoolScalingConfig {
    pub min_count: u32,
    pub max_count: u32,
    #[serde(default)]
    pub rules: Vec<PoolScalingRule>,
}

/// A pool scaling rule based on aggregate pool metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PoolScalingRule {
    pub metric_name: String,
    pub target_value: f64,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
}

/// Lifecycle hooks and shutdown configuration for a service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LifecycleConfig {
    /// Command to execute before stopping the service (pre-stop hook).
    /// Runs before the shutdown signal is sent. If the command fails,
    /// the service is still stopped.
    #[serde(default)]
    pub pre_stop: Option<Vec<String>>,
    /// Command to execute after the service starts (post-start hook).
    #[serde(default)]
    pub post_start: Option<Vec<String>>,
    /// Signal to send for graceful shutdown. Defaults to "SIGTERM".
    #[serde(default = "default_stop_signal")]
    pub stop_signal: String,
    /// Seconds to wait after sending the stop signal before force-killing.
    /// Defaults to 30 seconds.
    #[serde(default = "default_grace_period")]
    pub termination_grace_period_seconds: u64,
}

fn default_stop_signal() -> String {
    "SIGTERM".to_string()
}
fn default_grace_period() -> u64 {
    30
}

/// A sidecar process that runs alongside the main service.
/// Sidecars share the same lifecycle and are started after the main process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfig {
    /// Sidecar name (unique within the service).
    pub name: String,
    /// Command to execute for this sidecar.
    pub command: String,
    /// Environment variables for the sidecar process.
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

fn default_secret_type() -> String {
    "static".to_string()
}

/// Every secret a service declares (static and dynamic), sorted: what its
/// node delivers to it.
pub fn declared_secrets(service: &ServiceConfig) -> Vec<String> {
    let mut names: Vec<String> = service.secrets.keys().cloned().collect();
    names.sort();
    names
}

/// Whether `service` declares `name` as a dynamic secret.
pub fn is_dynamic_secret(config: &FleetConfig, service: &str, name: &str) -> bool {
    config
        .services
        .get(service)
        .and_then(|s| s.secrets.get(name))
        .is_some_and(SecretConfig::is_dynamic)
}

/// The static secrets a service declares, sorted.
pub fn static_secrets(service: &ServiceConfig) -> Vec<String> {
    let mut names: Vec<String> = service
        .secrets
        .iter()
        .filter(|(_, s)| s.secret_type == "static")
        .map(|(name, _)| name.clone())
        .collect();
    names.sort();
    names
}

/// Whether `path` can be a volume's mount path: absolute, normalized, and
/// not `/` or a system tree the service relies on.
pub fn validate_mount_path(path: &str) -> Result<(), String> {
    use std::path::{Component, Path};
    let p = Path::new(path);
    if !p.is_absolute() || (path.ends_with('/') && path != "/") {
        return Err(format!(
            "mount path '{path}' must be absolute, without a trailing '/'"
        ));
    }
    if p.components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.contains("//")
    {
        return Err(format!("mount path '{path}' must be normalized"));
    }
    const RESERVED: [&str; 7] = ["/", "/nix", "/proc", "/sys", "/dev", "/run/secrets", "/etc"];
    if let Some(reserved) = RESERVED
        .iter()
        .find(|r| p == Path::new(r) || (**r != "/" && **r != "/etc" && p.starts_with(r)))
    {
        return Err(format!("mount path '{path}' is reserved ({reserved})"));
    }
    Ok(())
}

/// Validate a fleet configuration for consistency.
fn validate_container(
    name: &str,
    service: &ServiceConfig,
    container: &ContainerConfig,
    errors: &mut Vec<String>,
) {
    match container
        .image
        .parse::<crate::agent::oci::reference::ImageReference>()
    {
        Ok(image) => {
            if container.pull_policy == ContainerPullPolicy::Never && image.digest.is_none() {
                errors.push(format!(
                    "service '{name}': pullPolicy Never needs an image pinned with @sha256:..."
                ));
            }
        }
        Err(e) => errors.push(format!(
            "service '{name}': invalid image '{}': {e}",
            container.image
        )),
    }
    if let Err(e) = container.parsed_bind_mounts() {
        errors.push(format!("service '{name}': {e}"));
    }
    if let Some(secret) = &container.registry_auth_secret
        && !static_secrets(service).contains(secret)
    {
        errors.push(format!(
            "service '{name}': registryAuthSecret '{secret}' is not a static secret of the service"
        ));
    }
}

fn validate_alerts(config: &FleetConfig, errors: &mut Vec<String>) {
    let mut names = std::collections::HashSet::new();
    for rule in &config.alerts {
        let name = &rule.name;
        let label_ok = label_name_ok;
        if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            errors.push(format!(
                "alert '{name}': name must be 1-128 printable characters"
            ));
        }
        if !names.insert(name.as_str()) {
            errors.push(format!("alert '{name}' is declared twice"));
        }
        if !label_ok(&rule.metric) || rule.metric.starts_with("__") {
            errors.push(format!(
                "alert '{name}': invalid metric name '{}'",
                rule.metric
            ));
        }
        if !rule.threshold.is_finite() {
            errors.push(format!("alert '{name}': threshold must be finite"));
        }
        let node_metric = rule.metric.starts_with("node_");
        if let Some(service) = &rule.service {
            if node_metric {
                errors.push(format!(
                    "alert '{name}': '{}' is a node metric and cannot be filtered by service",
                    rule.metric
                ));
            } else if let Some(svc) = config.services.get(service) {
                if svc.metrics.is_none() {
                    errors.push(format!(
                        "alert '{name}': service '{service}' exposes no metrics endpoint"
                    ));
                }
            } else {
                errors.push(format!("alert '{name}': unknown service '{service}'"));
            }
        }
        for key in rule.labels.keys() {
            if !label_ok(key) || key.starts_with("__") {
                errors.push(format!("alert '{name}': invalid label name '{key}'"));
            } else if matches!(key.as_str(), "alertname" | "severity" | "node" | "service") {
                errors.push(format!(
                    "alert '{name}': label '{key}' is set by the server and cannot be overridden"
                ));
            }
        }
        if let Some(url) = &rule.webhook_url
            && let Err(e) = validate_webhook_url(url)
        {
            errors.push(format!("alert '{name}': webhookUrl: {e}"));
        }
    }
}

/// An absolute http(s) URL with a host, without credentials in it.
pub fn validate_webhook_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("must start with http:// or https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("has no host".into());
    }
    if authority.contains('@') {
        return Err("must not embed credentials".into());
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("must not contain whitespace".into());
    }
    Ok(())
}

fn validate_dynamic_secret(
    config: &FleetConfig,
    service: &str,
    key: &str,
    secret: &SecretConfig,
    errors: &mut Vec<String>,
) {
    let at = format!("service '{service}' secret '{key}'");
    match secret.engine.as_deref() {
        None => errors.push(format!("{at}: a dynamic secret needs an engine")),
        Some(engine) if !config.secret_engines.contains_key(engine) => {
            errors.push(format!("{at}: engine '{engine}' is not in secretEngines"))
        }
        Some(_) => {}
    }
    match secret.role.as_deref() {
        None => errors.push(format!(
            "{at}: a dynamic secret needs a role ({})",
            crate::secrets::dynamic::ROLES.join(", ")
        )),
        Some(role) => {
            if let Err(e) = crate::secrets::dynamic::role_permissions(role) {
                errors.push(format!("{at}: {e}"));
            }
        }
    }
    if secret.ttl() < crate::secrets::dynamic::MIN_TTL {
        errors.push(format!(
            "{at}: ttl must be at least {} seconds",
            crate::secrets::dynamic::MIN_TTL
        ));
    }
}

fn validate_secret_engines(config: &FleetConfig, errors: &mut Vec<String>) {
    let mut engines: Vec<_> = config.secret_engines.iter().collect();
    engines.sort_by_key(|(name, _)| name.as_str());
    for (name, engine) in engines {
        if let Err(e) = crate::secrets::validate_name("secret engine", name) {
            errors.push(e);
        }
        if let Err(e) = crate::secrets::validate_name("secret", &engine.admin_url_secret) {
            errors.push(format!("secret engine '{name}' adminUrlSecret: {e}"));
        }
        if engine.database.is_empty() {
            errors.push(format!("secret engine '{name}' needs a database"));
        }
    }
}

fn validate_external_services(config: &FleetConfig, errors: &mut Vec<String>) {
    let mut services: Vec<_> = config.external_services.iter().collect();
    services.sort_by_key(|(name, _)| name.as_str());
    for (name, service) in services {
        if !is_dns_label(name) {
            errors.push(format!(
                "external service '{name}': name must be a DNS label (a-z, 0-9, '-')"
            ));
        }
        if service.addresses.is_empty() {
            errors.push(format!("external service '{name}' needs addresses"));
        }
        for address in &service.addresses {
            if address.parse::<std::net::SocketAddrV4>().is_err() {
                errors.push(format!(
                    "external service '{name}': address '{address}' is not ip:port (IPv4)"
                ));
            }
        }
        if let Some(check) = &service.health_check {
            match check.check_type.as_str() {
                "tcp" if check.path.is_some() => errors.push(format!(
                    "external service '{name}': healthCheck path is for http checks"
                )),
                "tcp" => {}
                "http" => {
                    if let Some(path) = &check.path
                        && !path.starts_with('/')
                    {
                        errors.push(format!(
                            "external service '{name}': healthCheck path must start with '/'"
                        ));
                    }
                }
                other => errors.push(format!(
                    "external service '{name}': healthCheck type must be 'tcp' or 'http', not '{other}'"
                )),
            }
            if check.interval == 0 || check.timeout == 0 {
                errors.push(format!(
                    "external service '{name}': healthCheck interval and timeout must be positive"
                ));
            }
        }
    }
}

/// Whether `name` is a lower-case DNS label.
pub fn is_dns_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn validate(config: &FleetConfig) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    validate_secret_engines(config, &mut errors);
    validate_external_services(config, &mut errors);

    validate_alerts(config, &mut errors);
    validate_namespaces_and_admission(config, &mut errors);

    if let Some(policy) = &config.signature_policy
        && let Err(e) = policy.to_runtime_policy()
    {
        errors.push(format!("signaturePolicy: {e}"));
    }

    for (name, machine) in &config.machines {
        if machine.pool != "default" && !config.node_pools.contains_key(&machine.pool) {
            errors.push(format!(
                "machine '{}' references undefined pool '{}'",
                name, machine.pool
            ));
        }
        if machine.reserved.cpu > machine.capacity.cpu {
            errors.push(format!(
                "machine '{}' has reserved CPU ({}) exceeding capacity ({})",
                name, machine.reserved.cpu, machine.capacity.cpu
            ));
        }
        if machine.reserved.memory > machine.capacity.memory {
            errors.push(format!(
                "machine '{}' has reserved memory ({}) exceeding capacity ({})",
                name, machine.reserved.memory, machine.capacity.memory
            ));
        }
    }

    for (name, service) in &config.services {
        let mut secrets: Vec<_> = service.secrets.iter().collect();
        secrets.sort_by_key(|(key, _)| key.as_str());
        if !secrets.is_empty()
            && let Err(e) = crate::secrets::validate_name("service", name)
        {
            errors.push(format!("service '{name}' declares secrets: {e}"));
        }
        for (key, secret) in secrets {
            if let Err(e) = crate::secrets::validate_name("secret", key) {
                errors.push(format!("service '{name}' secret '{key}': {e}"));
            }
            match secret.secret_type.as_str() {
                "static" => {
                    if secret.engine.is_some() || secret.role.is_some() || secret.ttl.is_some() {
                        errors.push(format!(
                            "service '{name}' secret '{key}': engine, role and ttl are for dynamic secrets"
                        ));
                    }
                }
                "dynamic" => validate_dynamic_secret(config, name, key, secret, &mut errors),
                other => errors.push(format!(
                    "service '{name}' secret '{key}': type must be 'static' or 'dynamic', not '{other}'"
                )),
            }
        }

        let mut transit_keys = std::collections::HashSet::new();
        for key in &service.transit_keys {
            if let Err(e) = crate::secrets::validate_name("transit key", key) {
                errors.push(format!("service '{name}' transitKeys: {e}"));
            }
            if !transit_keys.insert(key.as_str()) {
                errors.push(format!("service '{name}' lists transit key '{key}' twice"));
            }
        }

        if !service.volumes.is_empty()
            && let Err(e) = crate::secrets::validate_name("service", name)
        {
            errors.push(format!("service '{name}' declares volumes: {e}"));
        }
        let mut volume_names = std::collections::HashSet::new();
        let mut mounts = std::collections::HashSet::new();
        for volume in &service.volumes {
            let v = &volume.name;
            if let Err(e) = crate::secrets::validate_name("volume", v) {
                errors.push(format!("service '{name}' volume '{v}': {e}"));
            }
            if !volume_names.insert(v.as_str()) {
                errors.push(format!("service '{name}' volume '{v}' is declared twice"));
            }
            if let Err(e) = validate_mount_path(&volume.mount_path) {
                errors.push(format!("service '{name}' volume '{v}': {e}"));
            }
            if !mounts.insert(volume.mount_path.as_str()) {
                errors.push(format!(
                    "service '{name}' volume '{v}': mount path '{}' is used twice",
                    volume.mount_path
                ));
            }
            if volume.storage_class != "local" {
                errors.push(format!(
                    "service '{name}' volume '{v}': storage class must be 'local', not '{}'",
                    volume.storage_class
                ));
            }
        }

        let mut dests = std::collections::HashSet::new();
        let mut templates: Vec<_> = service.templates.iter().collect();
        templates.sort_by_key(|(key, _)| key.as_str());
        for (key, template) in templates {
            if let Err(e) = crate::agent::templates::validate_dest(&template.dest_path) {
                errors.push(format!("service '{name}' template '{key}': {e}"));
            }
            if !dests.insert(template.dest_path.as_str()) {
                errors.push(format!(
                    "service '{name}' template '{key}': destination '{}' is used twice",
                    template.dest_path
                ));
            }
            if template_mode(&template.perms).is_none() {
                errors.push(format!(
                    "service '{name}' template '{key}': invalid perms '{}' (octal, at most 0777)",
                    template.perms
                ));
            }
            if let Some(signal) = &template.change_signal
                && let Err(e) = crate::agent::templates::validate_signal(signal)
            {
                errors.push(format!("service '{name}' template '{key}': {e}"));
            }
        }

        if let Some(ref pool) = service.scheduling.pool
            && !config.node_pools.contains_key(pool)
        {
            errors.push(format!(
                "service '{}' prefers undefined pool '{}'",
                name, pool
            ));
        }

        if let Some(container) = &service.container {
            validate_container(name, service, container, &mut errors);
        }

        if let Some(metrics) = &service.metrics {
            if metrics.port == 0 {
                errors.push(format!("service '{name}' metrics: port must not be 0"));
            }
            if !metrics.path.starts_with('/')
                || metrics
                    .path
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
            {
                errors.push(format!(
                    "service '{name}' metrics: path '{}' must start with '/' and contain no whitespace",
                    metrics.path
                ));
            }
        }

        // Exactly one of command or container must be set
        match (&service.command, &service.container) {
            (None, None) => {
                errors.push(format!(
                    "service '{}' must have either 'command' or 'container'",
                    name
                ));
            }
            (Some(_), Some(_)) => {
                errors.push(format!(
                    "service '{}' cannot have both 'command' and 'container'",
                    name
                ));
            }
            _ => {}
        }
    }

    // Validate cloud provider configuration
    for (name, pool) in &config.node_pools {
        if let Some(cloud) = &pool.cloud {
            if cloud.provider == CloudProviderType::Azure && cloud.resource_group.is_none() {
                errors.push(format!(
                    "pool '{}' uses Azure provider but missing 'resourceGroup'",
                    name
                ));
            }
            if cloud.provider == CloudProviderType::Gcp && cloud.project.is_none() {
                errors.push(format!(
                    "pool '{}' uses GCP provider but missing 'project'",
                    name
                ));
            }
            if pool.scaling.is_none() {
                errors.push(format!(
                    "pool '{}' has cloud provider config but no scaling config",
                    name
                ));
            }

            // Exactly one of image_id or image must be set
            match (&cloud.image_id, &cloud.image) {
                (None, None) => {
                    errors.push(format!(
                        "pool '{}' cloud config must have either 'imageId' or 'image'",
                        name
                    ));
                }
                (Some(_), Some(_)) => {
                    errors.push(format!(
                        "pool '{}' cloud config cannot have both 'imageId' and 'image'",
                        name
                    ));
                }
                (None, Some(img)) => {
                    // Validate provider-specific storage requirements for managed images
                    if cloud.provider == CloudProviderType::Aws && img.s3_bucket.is_none() {
                        errors.push(format!(
                            "pool '{}' managed image config requires 's3Bucket' for AWS",
                            name
                        ));
                    }
                    if cloud.provider == CloudProviderType::Gcp && img.gcs_bucket.is_none() {
                        errors.push(format!(
                            "pool '{}' managed image config requires 'gcsBucket' for GCP",
                            name
                        ));
                    }
                    if cloud.provider == CloudProviderType::Azure && img.storage_account.is_none() {
                        errors.push(format!(
                            "pool '{}' managed image config requires 'storageAccount' for Azure",
                            name
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    // Validate periodic is only on batch/sysbatch types
    for (name, service) in &config.services {
        if service.scheduling.periodic.is_some()
            && service.scheduling.job_type != JobType::Batch
            && service.scheduling.job_type != JobType::Sysbatch
        {
            errors.push(format!(
                "service '{}' has periodic config but is not batch/sysbatch type",
                name
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod nix_module_tests {
    use super::*;

    /// The `nix/lib/fleet-module.nix` schema emits every option, including
    /// explicit `null` for unset `Option` fields and camelCase keys. This
    /// round-trip guards that the serde schema stays in lockstep with the Nix
    /// option module: if a field is renamed or its default shape changes on
    /// one side without the other, this deserialization fails.
    #[test]
    fn module_shaped_json_deserializes() {
        // Mirrors the shape produced by evaluating a config through
        // fleet-module.nix (nulls present, renamed keys `type`/secret `type`,
        // nested defaults filled in).
        let json = r#"{
            "name": "example",
            "domain": "fleet.internal",
            "admissionWebhooks": [],
            "policies": [],
            "webhooks": [],
            "namespaces": {"shop": {"quota": {
                "cpu": 500, "memory": null, "disk": null, "instances": null, "services": null
            }}},
            "nodePools": {
                "default": {
                    "labels": {"env": "prod"},
                    "scaling": null,
                    "schedulerAlgorithm": "spread",
                    "memoryOversubscription": false,
                    "cloud": null
                }
            },
            "machines": {
                "node-1": {
                    "targetHost": "10.0.0.1",
                    "labels": {},
                    "capacity": {"cpu": 8000, "memory": 16384, "disk": 200000},
                    "pool": "default",
                    "reserved": {"cpu": 500, "memory": 512, "disk": 0},
                    "taints": [],
                    "extendedResources": {}
                }
            },
            "services": {
                "api": {
                    "command": "run",
                    "container": null,
                    "environment": {"LOG": "info"},
                    "identity": {"allowedCallers": [], "allowedTargets": []},
                    "lifecycle": {
                        "preStop": null, "postStart": null,
                        "stopSignal": "SIGTERM",
                        "terminationGracePeriodSeconds": 30
                    },
                    "ports": {
                        "http": {
                            "port": 8080, "protocol": null, "hostname": null,
                            "healthCheck": null,
                            "liveness": {
                                "path": "/", "interval": 10, "timeout": 5,
                                "healthy_threshold": 3, "unhealthy_threshold": 3
                            },
                            "readiness": null, "startup": null
                        }
                    },
                    "resources": {
                        "cgroupControls": null,
                        "cpu": {"request": 500, "limit": 1000},
                        "disk": null,
                        "extended": {},
                        "memory": {"request": 256, "limit": 512}
                    },
                    "scheduling": {
                        "affinity": [], "constraints": [],
                        "disruptionBudget": {"maxUnavailable": null, "minAvailable": 2},
                        "migrate": {
                            "healthyDeadline": 300, "maxParallel": 1,
                            "migrateOnReschedule": true, "minHealthyTime": 10
                        },
                        "parameterized": null, "periodic": null,
                        "pool": "default", "priority": 50, "replicas": 3,
                        "reschedule": {
                            "attempts": null, "delayFunction": "exponential",
                            "delaySecs": 30, "intervalSecs": 86400, "maxDelaySecs": 3600
                        },
                        "restart": {
                            "attempts": 2, "delaySecs": 15,
                            "intervalSecs": 1800, "mode": "fail"
                        },
                        "serviceAffinity": [],
                        "spread": [{
                            "attribute": "labels.zone", "maxSkew": null,
                            "minDomains": null, "required": false,
                            "targets": [], "weight": 50
                        }],
                        "tolerations": [], "type": "service",
                        "update": {
                            "autoPromote": false, "autoRevert": true,
                            "canary": 0, "healthCheck": "checks",
                            "healthyDeadline": 300, "maxParallel": 1,
                            "minHealthyTime": 10, "progressDeadline": null,
                            "strategy": "rolling"
                        }
                    },
                    "secrets": {},
                    "sidecars": [],
                    "templates": {},
                    "volumes": []
                }
            }
        }"#;

        let config: FleetConfig =
            serde_json::from_str(json).expect("module-shaped JSON must deserialize");
        assert_eq!(config.name, "example");
        assert!(validate(&config).is_ok());
        let svc = &config.services["api"];
        assert_eq!(svc.scheduling.job_type, JobType::Service);
        assert_eq!(svc.scheduling.update.strategy, UpdateStrategy::Rolling);
        assert_eq!(svc.ports["http"].port, 8080);
    }

    #[test]
    fn external_services_are_validated() {
        let config = |services: serde_json::Value| -> FleetConfig {
            serde_json::from_value(serde_json::json!({
                "name": "t",
                "domain": "fleet.test",
                "externalServices": services,
            }))
            .unwrap()
        };
        let ok = config(serde_json::json!({
            "orders-db": {"addresses": ["10.0.0.5:5432"], "healthCheck": {"type": "tcp"}},
            "api": {"addresses": ["10.0.0.6:443"], "healthCheck": {"type": "http", "path": "/h"}},
        }));
        assert!(validate(&ok).is_ok(), "{:?}", validate(&ok));
        assert_eq!(
            ok.external_services["api"]
                .health_check
                .as_ref()
                .unwrap()
                .interval,
            10
        );

        let bad = config(serde_json::json!({
            "Bad.Name": {"addresses": ["10.0.0.5:5432"]},
            "empty": {"addresses": []},
            "host": {"addresses": ["db.example.com:5432", "::1"]},
            "kind": {"addresses": ["10.0.0.5:1"], "healthCheck": {"type": "icmp"}},
            "path": {"addresses": ["10.0.0.5:1"], "healthCheck": {"type": "http", "path": "h"}},
            "tcppath": {"addresses": ["10.0.0.5:1"], "healthCheck": {"type": "tcp", "path": "/"}},
            "zero": {"addresses": ["10.0.0.5:1"], "healthCheck": {"type": "tcp", "interval": 0}},
        }));
        let errors = validate(&bad).unwrap_err();
        assert_eq!(errors.len(), 8, "{errors:#?}");
        let errors = errors.join("\n");
        for expected in [
            "'Bad.Name': name must be a DNS label",
            "'empty' needs addresses",
            "'db.example.com:5432' is not ip:port",
            "type must be 'tcp' or 'http', not 'icmp'",
            "path must start with '/'",
            "path is for http checks",
            "interval and timeout must be positive",
        ] {
            assert!(errors.contains(expected), "{expected}: {errors}");
        }
    }

    #[test]
    fn templates_are_validated() {
        let config = |templates: serde_json::Value| -> FleetConfig {
            serde_json::from_value(serde_json::json!({
                "name": "t",
                "domain": "fleet.test",
                "services": {"api": {"command": "/bin/api", "templates": templates}},
            }))
            .unwrap()
        };
        let ok = config(serde_json::json!({
            "conf": {"source": "x", "destPath": "/etc/api.conf", "perms": "0600", "changeSignal": "SIGHUP"},
        }));
        assert!(validate(&ok).is_ok(), "{:?}", validate(&ok));
        assert_eq!(template_mode("0600"), Some(0o600));

        let bad = config(serde_json::json!({
            "a": {"source": "x", "destPath": "relative"},
            "b": {"source": "x", "destPath": "/etc/x", "perms": "0999"},
            "c": {"source": "x", "destPath": "/etc/x", "changeSignal": "HUP; reboot"},
        }));
        let errors = validate(&bad).unwrap_err().join("\n");
        assert!(
            errors.contains("template 'a': invalid template destination"),
            "{errors}"
        );
        assert!(
            errors.contains("template 'b': invalid perms '0999'"),
            "{errors}"
        );
        assert!(
            errors.contains("template 'c': destination '/etc/x' is used twice"),
            "{errors}"
        );
        assert!(errors.contains("template 'c': invalid signal"), "{errors}");
    }

    #[test]
    fn containers_are_validated() {
        let config = |container: serde_json::Value| -> FleetConfig {
            serde_json::from_value(serde_json::json!({
                "name": "t",
                "domain": "fleet.test",
                "services": {"web": {"container": container, "secrets": {"pull": {}}}},
            }))
            .unwrap()
        };
        let ok = config(serde_json::json!({
            "image": "registry.test:5000/team/web:v1",
            "bindMounts": ["/srv/data:/data", "/etc/ssl/certs:/etc/ssl/certs:ro"],
            "registryAuthSecret": "pull",
        }));
        assert!(validate(&ok).is_ok(), "{:?}", validate(&ok));
        assert_eq!(
            ok.services["web"]
                .container
                .as_ref()
                .unwrap()
                .parsed_bind_mounts()
                .unwrap()[1],
            BindMountSpec {
                host_path: "/etc/ssl/certs".into(),
                container_path: "/etc/ssl/certs".into(),
                read_only: true,
            }
        );

        for (container, expected) in [
            (
                serde_json::json!({"image": "web:v1", "pullPolicy": "Never"}),
                "pullPolicy Never needs an image pinned",
            ),
            (
                serde_json::json!({"image": "web@sha256:nothex"}),
                "invalid image",
            ),
            (
                serde_json::json!({"image": "web", "bindMounts": ["relative:/x"]}),
                "must be an absolute path",
            ),
            (
                serde_json::json!({"image": "web", "bindMounts": ["/a:/b:rw:x"]}),
                "must be /host:/container",
            ),
            (
                serde_json::json!({"image": "web", "bindMounts": ["/a%n:/b"]}),
                "without '..', spaces or quoting",
            ),
            (
                serde_json::json!({"image": "web", "registryAuthSecret": "missing"}),
                "registryAuthSecret 'missing' is not a static secret",
            ),
        ] {
            let errors = validate(&config(container)).unwrap_err().join("\n");
            assert!(errors.contains(expected), "{expected}: {errors}");
        }
    }

    #[test]
    fn signature_policies_must_parse() {
        let mut cfg: FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "signaturePolicy": {"publicKeyPem": "garbage"},
        }))
        .unwrap();
        let errors = validate(&cfg).unwrap_err().join("\n");
        assert!(errors.contains("signaturePolicy:"), "{errors}");

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        cfg.signature_policy.as_mut().unwrap().public_key_pem = Some(key.public_key_pem());
        assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
    }

    #[test]
    fn secrets_are_validated_and_static_ones_listed() {
        let config = |secrets: serde_json::Value| -> FleetConfig {
            serde_json::from_value(serde_json::json!({
                "name": "t",
                "domain": "fleet.test",
                "services": {"api": {"command": "/bin/api", "secrets": secrets}},
            }))
            .unwrap()
        };
        let with_engine = |mut config: FleetConfig| {
            config.secret_engines.insert(
                "pg".into(),
                SecretEngineConfig {
                    admin_url_secret: "pg-admin".into(),
                    database: "shop".into(),
                },
            );
            config
        };
        let ok = with_engine(config(serde_json::json!({
            "token": {},
            "db": {"type": "dynamic", "engine": "pg", "role": "readonly", "ttl": 3600},
            "api-key": {"type": "static"},
            // As the Nix module emits a static secret.
            "plain": {"type": "static", "engine": null, "role": null, "ttl": null},
        })));
        assert!(validate(&ok).is_ok(), "{:?}", validate(&ok));
        assert_eq!(
            static_secrets(&ok.services["api"]),
            ["api-key", "plain", "token"]
        );
        assert_eq!(
            declared_secrets(&ok.services["api"]),
            ["api-key", "db", "plain", "token"]
        );
        assert!(is_dynamic_secret(&ok, "api", "db"));
        assert!(!is_dynamic_secret(&ok, "api", "token"));

        let bad = with_engine(config(serde_json::json!({
            "../x": {},
            "y": {"type": "vault"},
            "a": {"type": "dynamic", "engine": "mysql", "role": "readonly"},
            "b": {"type": "dynamic", "engine": "pg", "role": "rw"},
            "c": {"type": "dynamic", "engine": "pg", "role": "admin", "ttl": 10},
            "d": {"type": "dynamic"},
            "e": {"role": "readonly"},
        })));
        let errors = validate(&bad).unwrap_err().join("\n");
        assert!(errors.contains("secret '../x': secret name"), "{errors}");
        assert!(errors.contains("secret 'y': type must be"), "{errors}");
        assert!(
            errors.contains("secret 'a': engine 'mysql' is not in secretEngines"),
            "{errors}"
        );
        assert!(errors.contains("secret 'b': unknown role 'rw'"), "{errors}");
        assert!(
            errors.contains("secret 'c': ttl must be at least"),
            "{errors}"
        );
        assert!(
            errors.contains("secret 'd': a dynamic secret needs an engine"),
            "{errors}"
        );
        assert!(
            errors.contains("secret 'd': a dynamic secret needs a role"),
            "{errors}"
        );
        assert!(
            errors.contains("secret 'e': engine, role and ttl are for dynamic"),
            "{errors}"
        );
    }

    #[test]
    fn volumes_are_local_named_and_mounted_at_clean_paths() {
        let config = |volumes: serde_json::Value| -> FleetConfig {
            serde_json::from_value(serde_json::json!({
                "name": "t",
                "domain": "fleet.test",
                "services": {"db": {"command": "/bin/db", "volumes": volumes}},
            }))
            .unwrap()
        };
        let ok = config(serde_json::json!([
            {"name": "data", "mountPath": "/var/lib/db"},
            {"name": "wal", "mountPath": "/var/lib/db-wal", "reclaimRetain": false},
        ]));
        assert!(validate(&ok).is_ok(), "{:?}", validate(&ok));

        let bad = config(serde_json::json!([
            {"name": "../x", "mountPath": "/a"},
            {"name": "a", "mountPath": "/a"},
            {"name": "a", "mountPath": "/b/../c"},
            {"name": "n", "mountPath": "/n", "storageClass": "nfs"},
            {"name": "s", "mountPath": "/run/secrets/x"},
            {"name": "r", "mountPath": "relative"},
        ]));
        let errors = validate(&bad).unwrap_err().join("\n");
        for expected in [
            "volume '../x': volume name",
            "volume 'a' is declared twice",
            "mount path '/a' is used twice",
            "'/b/../c' must be normalized",
            "storage class must be 'local', not 'nfs'",
            "'/run/secrets/x' is reserved",
            "'relative' must be absolute",
        ] {
            assert!(
                errors.contains(expected),
                "missing {expected:?} in {errors}"
            );
        }
        assert!(validate_mount_path("/srv/data").is_ok());
        assert!(validate_mount_path("/etc/app").is_ok());
        assert!(validate_mount_path("/etc").is_err());
        assert!(validate_mount_path("/nix/store").is_err());
    }

    #[test]
    fn signature_policy_config_roundtrips_and_defaults_enforce() {
        // `enforce` defaults to true when omitted; static-key mode.
        let json =
            r#"{"publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMEE=\n-----END PUBLIC KEY-----"}"#;
        let cfg: SignaturePolicyConfig =
            serde_json::from_str(json).expect("signature policy must deserialize");
        assert!(cfg.enforce, "enforce should default to true");
        assert!(cfg.public_key_pem.is_some());
        assert!(cfg.keyless.is_none());

        // Explicit false is honored, and the value round-trips.
        let cfg = SignaturePolicyConfig {
            public_key_pem: cfg.public_key_pem,
            keyless: None,
            enforce: false,
        };
        let encoded = serde_json::to_string(&cfg).unwrap();
        let decoded: SignaturePolicyConfig = serde_json::from_str(&encoded).unwrap();
        assert!(!decoded.enforce);
        assert!(decoded.public_key_pem.is_some());
    }

    #[test]
    fn signature_policy_keyless_config_deserializes() {
        let json = r#"{
            "keyless": {
                "fulcioRootsPem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "identities": [
                    {"subject": "ci@example.com", "issuer": "https://accounts.example.com"}
                ],
                "rekorPublicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----"
            },
            "enforce": false
        }"#;
        let cfg: SignaturePolicyConfig =
            serde_json::from_str(json).expect("keyless policy must deserialize");
        assert!(!cfg.enforce);
        assert!(cfg.public_key_pem.is_none());
        let keyless = cfg.keyless.expect("expected keyless mode");
        assert_eq!(keyless.identities.len(), 1);
        assert_eq!(keyless.identities[0].subject, "ci@example.com");
        assert!(keyless.rekor_public_key_pem.contains("PUBLIC KEY"));
        // The Rekor key is required for keyless verification.
        let without_rekor = json.replace(
            r#",
                "rekorPublicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----""#,
            "",
        );
        assert!(serde_json::from_str::<SignaturePolicyConfig>(&without_rekor).is_err());
    }

    #[test]
    fn signature_policy_to_runtime_policy_rejects_invalid_pem() {
        let cfg = SignaturePolicyConfig {
            public_key_pem: Some("not a valid pem".to_string()),
            keyless: None,
            enforce: true,
        };
        assert!(
            cfg.to_runtime_policy().is_err(),
            "invalid PEM must not yield a runtime policy"
        );
    }

    #[test]
    fn keyless_runtime_policy_rejects_empty_fulcio_bundle() {
        let cfg = SignaturePolicyConfig {
            public_key_pem: None,
            keyless: Some(KeylessPolicyConfig {
                fulcio_roots_pem: "no certs here".to_string(),
                identities: vec![KeylessIdentityConfig {
                    subject: "ci@example.com".to_string(),
                    issuer: "https://accounts.example.com".to_string(),
                }],
                rekor_public_key_pem: String::new(),
            }),
            enforce: true,
        };
        assert!(
            cfg.to_runtime_policy().is_err(),
            "an empty Fulcio bundle must be rejected"
        );
    }
}

#[cfg(test)]
mod cgroup_tests {
    use super::*;

    fn rv(request: u64, limit: Option<u64>) -> ResourceValue {
        ResourceValue { request, limit }
    }

    #[test]
    fn no_resources_yields_no_controls() {
        let rc = ResourceConfig::default();
        assert!(rc.to_cgroup_controls().is_none());
    }

    #[test]
    fn requests_without_limits_yield_no_controls() {
        // Requests drive scheduling, not enforcement, so a service that only
        // sets requests must be left uncapped.
        let rc = ResourceConfig {
            cpu: Some(rv(500, None)),
            memory: Some(rv(256, None)),
            ..Default::default()
        };
        assert!(rc.to_cgroup_controls().is_none());
    }

    #[test]
    fn cpu_limit_becomes_cpu_quota_percent() {
        // 1500 millicores == 1.5 cores == CPUQuota=150%.
        let rc = ResourceConfig {
            cpu: Some(rv(500, Some(1500))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_quota_percent, 150);
        assert_eq!(cg.memory_max_mb, 0);
    }

    #[test]
    fn sub_core_cpu_limit_rounds_up() {
        // 250 millicores == 25% of a core; a limit must never round to zero.
        let rc = ResourceConfig {
            cpu: Some(rv(0, Some(250))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_quota_percent, 25);
    }

    #[test]
    fn tiny_cpu_limit_rounds_up_to_one_percent() {
        let rc = ResourceConfig {
            cpu: Some(rv(0, Some(1))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_quota_percent, 1);
    }

    #[test]
    fn memory_limit_becomes_memory_max() {
        let rc = ResourceConfig {
            memory: Some(rv(256, Some(1024))),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.memory_max_mb, 1024);
        assert_eq!(cg.cpu_quota_percent, 0);
    }

    #[test]
    fn explicit_controls_are_carried_through() {
        let rc = ResourceConfig {
            cgroup_controls: Some(CgroupControlsConfig {
                cpu_weight: 200,
                memory_high: Some(512),
                memory_max: Some(2048),
                io_weight: 150,
                tasks_max: Some(64),
                oom_policy: "kill".to_string(),
            }),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_weight, 200);
        assert_eq!(cg.memory_high_mb, 512);
        assert_eq!(cg.memory_max_mb, 2048);
        assert_eq!(cg.io_weight, 150);
        assert_eq!(cg.tasks_max, 64);
        assert_eq!(cg.oom_policy, "kill");
    }

    #[test]
    fn explicit_memory_max_wins_over_derived_limit() {
        // An explicit memory_max takes precedence over the value derived from
        // memory.limit.
        let rc = ResourceConfig {
            memory: Some(rv(256, Some(1024))),
            cgroup_controls: Some(CgroupControlsConfig {
                cpu_weight: default_cpu_weight(),
                memory_high: None,
                memory_max: Some(4096),
                io_weight: default_io_weight(),
                tasks_max: None,
                oom_policy: default_oom_policy(),
            }),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.memory_max_mb, 4096);
    }

    #[test]
    fn derived_cpu_quota_combines_with_explicit_controls() {
        // cpu.limit provides the hard CPU cap while explicit controls provide
        // the weight — both must appear together.
        let rc = ResourceConfig {
            cpu: Some(rv(500, Some(2000))),
            cgroup_controls: Some(CgroupControlsConfig {
                cpu_weight: 300,
                memory_high: None,
                memory_max: None,
                io_weight: default_io_weight(),
                tasks_max: None,
                oom_policy: default_oom_policy(),
            }),
            ..Default::default()
        };
        let cg = rc.to_cgroup_controls().expect("controls expected");
        assert_eq!(cg.cpu_weight, 300);
        assert_eq!(cg.cpu_quota_percent, 200);
    }
}

#[cfg(test)]
mod alert_tests {
    #[test]
    fn autoscaling_needs_requests_metrics_and_sane_bounds() {
        let config: super::FleetConfig = serde_json::from_value(serde_json::json!({
            "name": "t", "domain": "d",
            "services": {
                "api": {
                    "command": "/bin/true",
                    "scheduling": {"autoscale": {"min": 3, "max": 2, "rules": [
                        {"metric": "cpu", "target": 0.5},
                        {"metric": "queue_depth", "target": 10},
                    ]}},
                },
                "job": {
                    "command": "/bin/true",
                    "resources": {"memory": {"request": 64}},
                    "scheduling": {"type": "batch", "autoscale": {"min": 1, "max": 2, "rules": [
                        {"metric": "memory", "target": 0.5},
                    ]}},
                },
            },
        }))
        .unwrap();
        let errors = super::validate(&config).unwrap_err();
        for expected in [
            "service 'api' autoscale: need 1 <= min <= max, not min 3 and max 2",
            "service 'api' autoscale: rule 'cpu' needs resources.cpu.request",
            "service 'api' autoscale: rule 'queue_depth' needs the service's metrics endpoint",
            "service 'job' autoscale: only service jobs can autoscale",
        ] {
            assert!(
                errors.iter().any(|e| e == expected),
                "{expected}: {errors:?}"
            );
        }
        assert_eq!(
            errors.iter().filter(|e| e.contains("autoscale")).count(),
            4,
            "{errors:?}"
        );
    }

    #[test]
    fn event_patterns_match_types_and_prefixes() {
        assert!(super::event_matches("*", "deploy.failed"));
        assert!(super::event_matches("deploy.*", "deploy.failed"));
        assert!(super::event_matches("deploy.*", "deploy"));
        assert!(!super::event_matches("deploy.*", "deployer.x"));
        assert!(super::event_matches("deploy.failed", "deploy.failed"));
        assert!(!super::event_matches("deploy.failed", "deploy.started"));
        for ok in ["*", "deploy.*", "node.left", "deploy.rolled_back"] {
            assert!(super::valid_event_pattern(ok), "{ok}");
        }
        for bad in ["", "deploy*", "*.failed", "Deploy", "a..b", ".*"] {
            assert!(!super::valid_event_pattern(bad), "{bad}");
        }
    }

    use super::*;

    fn fleet(alerts: serde_json::Value) -> FleetConfig {
        serde_json::from_value(serde_json::json!({
            "name": "t",
            "domain": "fleet.test",
            "services": {
                "web": { "command": "web", "metrics": { "port": 9100 } },
                "db": { "command": "db" },
            },
            "alerts": alerts,
        }))
        .unwrap()
    }

    fn errors(config: &FleetConfig) -> Vec<String> {
        validate(config).err().unwrap_or_default()
    }

    #[test]
    fn alert_rules_parse_with_defaults() {
        let config = fleet(serde_json::json!([
            { "name": "disk", "metric": "node_disk_usage_ratio", "threshold": 0.9 },
            {
                "name": "down", "metric": "up", "op": "lt", "threshold": 1,
                "forSeconds": 0, "service": "web", "severity": "critical",
                "labels": { "team": "web" }, "webhookUrl": "https://hooks.test/am",
            },
        ]));
        assert_eq!(errors(&config), Vec::<String>::new());
        let disk = &config.alerts[0];
        assert_eq!(disk.op, AlertOp::Gt);
        assert_eq!(disk.for_seconds, 60);
        assert_eq!(disk.severity, AlertSeverity::Warning);
        assert_eq!(
            config.services["web"].metrics.as_ref().unwrap().path,
            "/metrics"
        );
        assert!(AlertOp::Lt.holds(0.0, 1.0));
        assert!(!AlertOp::Gte.holds(0.5, 1.0));
    }

    #[test]
    fn invalid_alert_rules_are_rejected() {
        let config = fleet(serde_json::json!([
            { "name": "a", "metric": "node_load1", "threshold": 1, "service": "web" },
            { "name": "a", "metric": "bad-name", "threshold": 1 },
            { "name": "b", "metric": "up", "threshold": 1, "service": "db" },
            { "name": "c", "metric": "up", "threshold": 1, "service": "nope" },
            { "name": "d", "metric": "up", "threshold": 1, "labels": { "node": "x" } },
            { "name": "e", "metric": "up", "threshold": 1, "webhookUrl": "ftp://x" },
            { "name": "f", "metric": "up", "threshold": 1, "webhookUrl": "http://u:p@x/" },
        ]));
        let errors = errors(&config).join("\n");
        for expected in [
            "is a node metric and cannot be filtered by service",
            "alert 'a' is declared twice",
            "invalid metric name 'bad-name'",
            "service 'db' exposes no metrics endpoint",
            "unknown service 'nope'",
            "label 'node' is set by the server",
            "must start with http:// or https://",
            "must not embed credentials",
        ] {
            assert!(
                errors.contains(expected),
                "missing '{expected}' in:\n{errors}"
            );
        }
    }

    #[test]
    fn metrics_endpoints_are_validated() {
        let mut config = fleet(serde_json::json!([]));
        config.services.get_mut("web").unwrap().metrics = Some(MetricsEndpoint {
            port: 0,
            path: "metrics".into(),
        });
        let errors = errors(&config).join("\n");
        assert!(errors.contains("port must not be 0"), "{errors}");
        assert!(errors.contains("must start with '/'"), "{errors}");
    }
}
