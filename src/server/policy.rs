use std::sync::Arc;

use tokio::sync::RwLock;

/// Policy rule evaluated during plan/apply to enforce organizational constraints.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub name: String,
    /// CEL-like expression that must evaluate to true.
    /// Available variables: service.name, service.replicas, service.resources.cpu, etc.
    pub expression: String,
    /// Error message when the policy is violated.
    pub message: String,
    /// Whether this policy blocks deployment (enforce) or just warns (warn).
    #[serde(default)]
    pub enforcement: PolicyEnforcement,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEnforcement {
    #[default]
    Enforce,
    Warn,
}

/// Evaluates organizational policies against fleet configuration.
#[derive(Clone)]
pub struct PolicyEngine {
    rules: Arc<RwLock<Vec<PolicyRule>>>,
}

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub rule_name: String,
    pub service_name: String,
    pub message: String,
    pub enforcement: PolicyEnforcement,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register policy rules.
    pub async fn set_rules(&self, rules: Vec<PolicyRule>) {
        tracing::info!(count = rules.len(), "Policy rules configured");
        *self.rules.write().await = rules;
    }

    /// Evaluate all policies against a service configuration.
    /// Returns a list of violations.
    pub async fn evaluate(
        &self,
        service_name: &str,
        service: &crate::config::ServiceConfig,
    ) -> Vec<PolicyViolation> {
        let rules = self.rules.read().await;
        let mut violations = Vec::new();

        for rule in rules.iter() {
            if let Some(violation) = evaluate_rule(rule, service_name, service) {
                violations.push(violation);
            }
        }

        violations
    }

    /// Check if any enforcing policy is violated (blocks deployment).
    pub async fn check(
        &self,
        service_name: &str,
        service: &crate::config::ServiceConfig,
    ) -> Result<Vec<PolicyViolation>, Vec<PolicyViolation>> {
        let violations = self.evaluate(service_name, service).await;
        let blocking: Vec<PolicyViolation> = violations
            .iter()
            .filter(|v| v.enforcement == PolicyEnforcement::Enforce)
            .cloned()
            .collect();

        if blocking.is_empty() {
            Ok(violations) // Only warnings
        } else {
            Err(blocking)
        }
    }
}

/// Resolve a dotted path to a value from a ServiceConfig.
fn resolve_path(service: &crate::config::ServiceConfig, path: &str) -> Option<PolicyValue> {
    match path {
        "service.replicas" => Some(PolicyValue::Uint(service.scheduling.replicas as u64)),
        "service.priority" => Some(PolicyValue::Uint(service.scheduling.priority as u64)),
        "service.type" => Some(PolicyValue::Str(format!(
            "{:?}",
            service.scheduling.job_type
        ))),
        "service.pool" => service
            .scheduling
            .pool
            .as_ref()
            .map(|p| PolicyValue::Str(p.clone())),
        "service.resources.cpu.request" => Some(PolicyValue::Uint(
            service
                .resources
                .cpu
                .as_ref()
                .map(|r| r.request)
                .unwrap_or(0),
        )),
        "service.resources.memory.request" => Some(PolicyValue::Uint(
            service
                .resources
                .memory
                .as_ref()
                .map(|r| r.request)
                .unwrap_or(0),
        )),
        "service.resources.disk.request" => Some(PolicyValue::Uint(
            service
                .resources
                .disk
                .as_ref()
                .map(|r| r.request)
                .unwrap_or(0),
        )),
        "service.resources.cpu.limit" => service
            .resources
            .cpu
            .as_ref()
            .and_then(|r| r.limit)
            .map(PolicyValue::Uint),
        "service.resources.memory.limit" => service
            .resources
            .memory
            .as_ref()
            .and_then(|r| r.limit)
            .map(PolicyValue::Uint),
        _ => None,
    }
}

/// Intermediate value type for policy evaluation.
#[derive(Debug)]
enum PolicyValue {
    Uint(u64),
    Str(String),
}

/// Parse a policy expression of the form `<path> <op> <value>`.
fn parse_expression(expr: &str) -> Option<(&str, &str, &str)> {
    // Try two-character operators first
    for op in &[">=", "<=", "!=", "=="] {
        if let Some(idx) = expr.find(op) {
            let path = expr[..idx].trim();
            let value = expr[idx + op.len()..].trim();
            return Some((path, op, value));
        }
    }
    // Single-character operators
    for op in &[">", "<", "="] {
        if let Some(idx) = expr.find(op) {
            let path = expr[..idx].trim();
            let value = expr[idx + op.len()..].trim();
            return Some((path, op, value));
        }
    }
    None
}

/// Evaluate a single policy rule by parsing the expression and comparing resolved values.
fn evaluate_rule(
    rule: &PolicyRule,
    service_name: &str,
    service: &crate::config::ServiceConfig,
) -> Option<PolicyViolation> {
    let expr = &rule.expression;

    let (path, op, expected) = parse_expression(expr)?;
    let actual = resolve_path(service, path)?;

    // The expression describes the *desired* condition.
    // A violation occurs when the condition is *not* met.
    let condition_met = match actual {
        PolicyValue::Uint(actual_val) => {
            let expected_val: u64 = match expected.parse() {
                Ok(v) => v,
                Err(_) => return None,
            };
            match op {
                ">=" | "gte" => actual_val >= expected_val,
                ">" | "gt" => actual_val > expected_val,
                "<=" | "lte" => actual_val <= expected_val,
                "<" | "lt" => actual_val < expected_val,
                "==" | "=" => actual_val == expected_val,
                "!=" => actual_val != expected_val,
                _ => return None,
            }
        }
        PolicyValue::Str(actual_str) => match op {
            "==" | "=" => actual_str == expected,
            "!=" => actual_str != expected,
            _ => return None,
        },
    };

    if !condition_met {
        Some(PolicyViolation {
            rule_name: rule.name.clone(),
            service_name: service_name.to_string(),
            message: rule.message.clone(),
            enforcement: rule.enforcement,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServiceConfig;
    use std::collections::HashMap;

    fn minimal_service(replicas: u32) -> ServiceConfig {
        ServiceConfig {
            command: Some("/bin/svc".into()),
            container: None,
            ports: HashMap::new(),
            secrets: HashMap::new(),
            identity: Default::default(),
            resources: Default::default(),
            scheduling: crate::config::SchedulingConfig {
                replicas,
                ..Default::default()
            },
            environment: HashMap::new(),
            templates: HashMap::new(),
            lifecycle: Default::default(),
            volumes: Vec::new(),
            sidecars: Vec::new(),
            namespace: String::new(),
        }
    }

    #[tokio::test]
    async fn enforces_minimum_replicas() {
        let engine = PolicyEngine::new();
        engine
            .set_rules(vec![PolicyRule {
                name: "min-replicas".into(),
                expression: "service.replicas >= 2".into(),
                message: "Production services must have at least 2 replicas".into(),
                enforcement: PolicyEnforcement::Enforce,
            }])
            .await;

        let result = engine.check("api", &minimal_service(1)).await;
        assert!(result.is_err());

        let result = engine.check("api", &minimal_service(3)).await;
        assert!(result.is_ok());
    }
}
