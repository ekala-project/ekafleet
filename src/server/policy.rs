#![allow(dead_code)]

use std::sync::Arc;

use tokio::sync::RwLock;

/// Policy rule evaluated during plan/apply to enforce organizational constraints.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Evaluate a single policy rule using simple pattern matching.
fn evaluate_rule(
    rule: &PolicyRule,
    service_name: &str,
    service: &crate::config::ServiceConfig,
) -> Option<PolicyViolation> {
    let expr = &rule.expression;

    // Simple built-in policy expressions
    let violated = if expr == "service.replicas >= 2" {
        service.scheduling.replicas < 2
    } else if expr == "service.resources.cpu.request > 0" {
        service
            .resources
            .cpu
            .as_ref()
            .map(|r| r.request)
            .unwrap_or(0)
            == 0
    } else if expr == "service.resources.memory.request > 0" {
        service
            .resources
            .memory
            .as_ref()
            .map(|r| r.request)
            .unwrap_or(0)
            == 0
    } else if let Some(min_str) = expr.strip_prefix("service.replicas >= ") {
        let min: u32 = min_str.trim().parse().unwrap_or(1);
        service.scheduling.replicas < min
    } else {
        false // Unknown expression — no violation
    };

    if violated {
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
            command: "/bin/svc".into(),
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
