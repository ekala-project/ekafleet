//! Admission: deciding whether an evaluated, valid configuration may become
//! the next revision.
//!
//! Admission runs at plan (as a dry run) and at apply, after validation and
//! before anything is built or stored. In order:
//!
//! 1. organizational policies: an `enforce` violation rejects, `warn` warns;
//! 2. namespace quotas: the most a namespace's services can request;
//! 3. admission webhooks, which see the change and may reject it.
//!
//! Rollbacks restore a revision that was admitted when it was applied, and
//! are not admitted again.

use std::collections::BTreeMap;

use crate::config::{FleetConfig, JobType, ServiceConfig};

use super::webhook::WebhookClient;

/// Outcome of admission.
#[derive(Debug, Default)]
pub struct Admission {
    pub warnings: Vec<String>,
    /// Empty when the configuration is admitted.
    pub errors: Vec<String>,
}

impl Admission {
    pub fn admitted(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Who asks to admit what.
pub struct Request<'a> {
    pub actor: &'a str,
    pub flake_ref: &'a str,
    /// Plan: webhooks are told nothing will be applied.
    pub dry_run: bool,
}

pub async fn admit(
    client: &WebhookClient,
    desired: &FleetConfig,
    previous: Option<(u64, &FleetConfig)>,
    request: Request<'_>,
) -> Admission {
    let mut admission = Admission::default();
    check_policies(desired, &mut admission).await;
    check_quotas(desired, &mut admission);
    // Webhooks only see changes that passed the server's own checks.
    if admission.admitted() && !desired.admission_webhooks.is_empty() {
        let review = review(desired, previous, &request);
        match super::webhook::review(client, &desired.admission_webhooks, &review).await {
            Ok(warnings) => admission.warnings.extend(warnings),
            Err(e) => admission.errors.push(e),
        }
    }
    admission
}

async fn check_policies(desired: &FleetConfig, admission: &mut Admission) {
    if desired.policies.is_empty() {
        return;
    }
    let engine = super::policy::PolicyEngine::new();
    engine.set_rules(desired.policies.clone()).await;
    let mut names: Vec<_> = desired.services.keys().collect();
    names.sort();
    for name in names {
        match engine.check(name, &desired.services[name]).await {
            Ok(warnings) => admission.warnings.extend(warnings.into_iter().map(|w| {
                format!(
                    "policy '{}' on service '{name}': {}",
                    w.rule_name, w.message
                )
            })),
            Err(violations) => admission.errors.extend(violations.into_iter().map(|v| {
                format!(
                    "policy '{}' on service '{name}': {}",
                    v.rule_name, v.message
                )
            })),
        }
    }
}

/// What a namespace's services can request at most.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Usage {
    pub cpu: u64,
    pub memory: u64,
    pub disk: u64,
    pub instances: u64,
    pub services: u64,
}

fn namespace_of(service: &ServiceConfig) -> &str {
    if service.namespace.is_empty() {
        "default"
    } else {
        &service.namespace
    }
}

/// The most instances a service can run: its autoscaling maximum, its
/// replicas, or for system jobs one per eligible machine.
pub fn max_instances(desired: &FleetConfig, service: &ServiceConfig) -> u64 {
    match service.scheduling.job_type {
        JobType::System | JobType::Sysbatch => {
            // One per eligible machine, counting autoscaled pools at their maximum.
            let in_pool = |pool: &str| service.scheduling.pool.as_deref().is_none_or(|p| p == pool);
            let machines = desired
                .machines
                .values()
                .filter(|m| in_pool(&m.pool))
                .count() as u64;
            let scaled: u64 = desired
                .node_pools
                .iter()
                .filter(|(name, _)| in_pool(name))
                .filter_map(|(_, pool)| pool.scaling.as_ref())
                .map(|s| u64::from(s.max_count))
                .sum();
            machines + scaled
        }
        _ => match &service.scheduling.autoscale {
            Some(autoscale) => u64::from(autoscale.max),
            None => u64::from(service.scheduling.replicas),
        },
    }
}

pub fn namespace_usage(desired: &FleetConfig) -> BTreeMap<String, Usage> {
    let mut usage: BTreeMap<String, Usage> = BTreeMap::new();
    for service in desired.services.values() {
        let instances = max_instances(desired, service);
        let request = |r: &Option<crate::config::ResourceValue>| {
            r.as_ref()
                .map_or(0, |r| r.request)
                .saturating_mul(instances)
        };
        let ns = usage.entry(namespace_of(service).to_string()).or_default();
        ns.cpu = ns.cpu.saturating_add(request(&service.resources.cpu));
        ns.memory = ns.memory.saturating_add(request(&service.resources.memory));
        ns.disk = ns.disk.saturating_add(request(&service.resources.disk));
        ns.instances = ns.instances.saturating_add(instances);
        ns.services += 1;
    }
    usage
}

fn check_quotas(desired: &FleetConfig, admission: &mut Admission) {
    let usage = namespace_usage(desired);
    let mut namespaces: Vec<_> = desired.namespaces.iter().collect();
    namespaces.sort_by_key(|(name, _)| name.as_str());
    for (name, settings) in namespaces {
        let used = usage.get(name).cloned().unwrap_or_default();
        let quota = &settings.quota;
        for (what, used, limit, unit) in [
            ("CPU requests", used.cpu, quota.cpu, "m"),
            ("memory requests", used.memory, quota.memory, "MB"),
            ("disk requests", used.disk, quota.disk, "MB"),
            ("instances", used.instances, quota.instances, ""),
            ("services", used.services, quota.services, ""),
        ] {
            if let Some(limit) = limit
                && used > limit
            {
                admission.errors.push(format!(
                    "namespace '{name}' exceeds its quota: {what} {used}{unit} > {limit}{unit}"
                ));
            }
        }
    }
}

/// The admission review sent to webhooks.
fn review(
    desired: &FleetConfig,
    previous: Option<(u64, &FleetConfig)>,
    request: &Request<'_>,
) -> serde_json::Value {
    let before = |name: &str| previous.and_then(|(_, p)| p.services.get(name));
    let mut created = Vec::new();
    let mut updated = Vec::new();
    for (name, service) in &desired.services {
        match before(name) {
            None => created.push(name.clone()),
            Some(old) if serde_json::to_value(old).ok() != serde_json::to_value(service).ok() => {
                updated.push(name.clone())
            }
            Some(_) => {}
        }
    }
    let mut deleted: Vec<String> = previous
        .map(|(_, p)| {
            p.services
                .keys()
                .filter(|n| !desired.services.contains_key(*n))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    created.sort();
    updated.sort();
    deleted.sort();
    serde_json::json!({
        "apiVersion": "ekafleet/v1",
        "kind": "AdmissionReview",
        "dryRun": request.dry_run,
        "actor": request.actor,
        "flakeRef": request.flake_ref,
        "fleet": desired.name,
        "previousRevision": previous.map(|(r, _)| r),
        "changes": {"created": created, "updated": updated, "deleted": deleted},
        "services": desired.services,
        "namespaces": namespace_usage(desired)
            .into_iter()
            .map(|(name, u)| (name, serde_json::json!({
                "cpu": u.cpu, "memory": u.memory, "disk": u.disk,
                "instances": u.instances, "services": u.services,
            })))
            .collect::<serde_json::Map<_, _>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: serde_json::Value) -> FleetConfig {
        let mut base = serde_json::json!({"name": "t", "domain": "fleet.internal"});
        base.as_object_mut()
            .unwrap()
            .extend(json.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    fn service(namespace: &str, replicas: u32, cpu: u64) -> serde_json::Value {
        serde_json::json!({
            "command": "/bin/true",
            "namespace": namespace,
            "resources": {"cpu": {"request": cpu}, "memory": {"request": 64}},
            "scheduling": {"replicas": replicas},
        })
    }

    #[test]
    fn usage_counts_requests_at_the_most_instances() {
        let desired = config(serde_json::json!({
            "machines": {
                "a": {"targetHost": "a", "capacity": {"cpu": 1000, "memory": 1024}},
                "b": {"targetHost": "b", "capacity": {"cpu": 1000, "memory": 1024}},
            },
            "services": {
                "api": service("shop", 3, 200),
                "web": service("shop", 1, 100),
                "agent": {
                    "command": "/bin/true",
                    "namespace": "shop",
                    "resources": {"cpu": {"request": 50}},
                    "scheduling": {"type": "system"},
                },
                "other": service("", 1, 10),
            },
        }));
        let usage = namespace_usage(&desired);
        assert_eq!(
            usage["shop"],
            Usage {
                cpu: 3 * 200 + 100 + 2 * 50,
                memory: 4 * 64,
                disk: 0,
                instances: 3 + 1 + 2,
                services: 3,
            }
        );
        assert_eq!(usage["default"].services, 1);
    }

    #[tokio::test]
    async fn quotas_and_policies_reject_before_webhooks_are_asked() {
        let desired = config(serde_json::json!({
            "services": {"api": service("shop", 3, 200)},
            "namespaces": {"shop": {"quota": {"cpu": 500, "services": 5}}},
            "policies": [{
                "name": "small",
                "expression": "service.replicas <= 2",
                "message": "too many replicas",
                "enforcement": "warn",
            }],
            // Unreachable: rejecting would fail if it were asked.
            "admissionWebhooks": [{"name": "w", "url": "http://127.0.0.1:1/hook"}],
        }));
        let admission = admit(
            &WebhookClient::new(),
            &desired,
            None,
            Request {
                actor: "test",
                flake_ref: "/f",
                dry_run: true,
            },
        )
        .await;
        assert_eq!(
            admission.errors,
            vec!["namespace 'shop' exceeds its quota: CPU requests 600m > 500m"]
        );
        assert_eq!(admission.warnings.len(), 1, "{:?}", admission.warnings);
        assert!(admission.warnings[0].contains("too many replicas"));
    }

    #[test]
    fn reviews_list_changes_against_the_previous_revision() {
        let previous = config(serde_json::json!({
            "services": {"api": service("", 1, 100), "old": service("", 1, 100), "same": service("", 1, 1)},
        }));
        let desired = config(serde_json::json!({
            "services": {"api": service("", 2, 100), "new": service("", 1, 100), "same": service("", 1, 1)},
        }));
        let review = review(
            &desired,
            Some((7, &previous)),
            &Request {
                actor: "token:abc (ci)",
                flake_ref: "/f",
                dry_run: false,
            },
        );
        assert_eq!(review["previousRevision"], 7);
        assert_eq!(review["changes"]["created"], serde_json::json!(["new"]));
        assert_eq!(review["changes"]["updated"], serde_json::json!(["api"]));
        assert_eq!(review["changes"]["deleted"], serde_json::json!(["old"]));
        assert_eq!(review["actor"], "token:abc (ci)");
        assert_eq!(review["services"]["api"]["scheduling"]["replicas"], 2);
    }
}
