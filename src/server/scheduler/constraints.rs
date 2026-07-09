#![allow(dead_code)]

use std::collections::HashMap;

use crate::config::{Constraint, SpreadConfig};

use super::Candidate;

/// Shared operator evaluation logic used by both constraint filtering and affinity scoring.
/// Handles: `=`, `==`, `!=`, `>`, `>=`, `<`, `<=`, `gt`, `gte`, `lt`, `lte`,
/// `regexp`, `matches`, `is_set`, `is_not_set`.
pub(super) fn evaluate_operator(actual: Option<&str>, op: &str, expected: &str) -> bool {
    match op {
        "=" | "==" => actual == Some(expected),
        "!=" => actual != Some(expected),
        ">" | "gt" => actual.is_some_and(|a| match (a.parse::<f64>(), expected.parse::<f64>()) {
            (Ok(av), Ok(ev)) => av > ev,
            _ => a > expected,
        }),
        ">=" | "gte" => actual.is_some_and(|a| match (a.parse::<f64>(), expected.parse::<f64>()) {
            (Ok(av), Ok(ev)) => av >= ev,
            _ => a >= expected,
        }),
        "<" | "lt" => actual.is_some_and(|a| match (a.parse::<f64>(), expected.parse::<f64>()) {
            (Ok(av), Ok(ev)) => av < ev,
            _ => a < expected,
        }),
        "<=" | "lte" => actual.is_some_and(|a| match (a.parse::<f64>(), expected.parse::<f64>()) {
            (Ok(av), Ok(ev)) => av <= ev,
            _ => a <= expected,
        }),
        "regexp" | "matches" => actual.is_some_and(|a| {
            regex::Regex::new(expected)
                .map(|r| r.is_match(a))
                .unwrap_or(false)
        }),
        "is_set" => actual.is_some(),
        "is_not_set" => actual.is_none(),
        _ => false,
    }
}

/// Check if a candidate machine passes all hard constraints.
pub(super) fn passes_constraints(
    candidate: &Candidate,
    constraints: &[Constraint],
    service_name: &str,
) -> bool {
    for constraint in constraints {
        let actual = get_attribute(candidate, &constraint.attribute);
        let expected = &constraint.value;

        let passes = match constraint.op.as_str() {
            // Constraint-specific operators not in evaluate_operator
            "in" => {
                let values: Vec<&str> = expected.split(',').map(|s| s.trim()).collect();
                actual.as_deref().is_some_and(|a| values.contains(&a))
            }
            "not_in" => {
                let values: Vec<&str> = expected.split(',').map(|s| s.trim()).collect();
                actual.as_deref().is_none_or(|a| !values.contains(&a))
            }
            "set_contains" => actual.as_deref().is_some_and(|a| {
                let attr_items: std::collections::HashSet<&str> =
                    a.split(',').map(|s| s.trim()).collect();
                expected
                    .split(',')
                    .map(|s| s.trim())
                    .all(|v| attr_items.contains(v))
            }),
            "set_contains_any" => actual.as_deref().is_some_and(|a| {
                let attr_items: std::collections::HashSet<&str> =
                    a.split(',').map(|s| s.trim()).collect();
                expected
                    .split(',')
                    .map(|s| s.trim())
                    .any(|v| attr_items.contains(v))
            }),
            "distinct_hosts" => !candidate
                .assigned_services
                .iter()
                .any(|s| s == service_name),
            // All common operators delegated to evaluate_operator
            op => {
                let result = evaluate_operator(actual.as_deref(), op, expected);
                // Unknown operators: evaluate_operator returns false, but we
                // preserve the original warn-and-pass behavior for constraints
                if ![
                    "=",
                    "==",
                    "!=",
                    ">",
                    ">=",
                    "<",
                    "<=",
                    "gt",
                    "gte",
                    "lt",
                    "lte",
                    "regexp",
                    "matches",
                    "is_set",
                    "is_not_set",
                ]
                .contains(&op)
                {
                    tracing::warn!(op = %op, "Unknown constraint operator");
                    return true;
                }
                result
            }
        };

        if !passes {
            return false;
        }
    }
    true
}

/// Check if placing on this candidate would violate required spread constraints.
pub(super) fn passes_required_spreads(
    candidate: &Candidate,
    spreads: &[SpreadConfig],
    service_name: &str,
    all_candidates: &[Candidate],
) -> bool {
    for spread in spreads {
        if !spread.required {
            continue;
        }
        if let Some(max_skew) = spread.max_skew {
            let my_attr = get_attribute(candidate, &spread.attribute);
            if let Some(ref my_val) = my_attr {
                // Count instances per domain
                let mut domain_counts: HashMap<String, usize> = HashMap::new();
                for c in all_candidates {
                    if c.assigned_services.contains(&service_name.to_string())
                        && let Some(val) = get_attribute(c, &spread.attribute)
                    {
                        *domain_counts.entry(val).or_insert(0) += 1;
                    }
                }
                // Simulate placing here
                let my_count = domain_counts.get(my_val.as_str()).copied().unwrap_or(0) + 1;
                let min_count = domain_counts.values().copied().min().unwrap_or(0);
                // Check skew: difference between this domain and the minimum
                if my_count.saturating_sub(min_count) > max_skew as usize {
                    return false;
                }
            }
        }
        if let Some(min_domains) = spread.min_domains {
            // Count distinct domains that have instances
            let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();
            for c in all_candidates {
                if c.assigned_services.contains(&service_name.to_string())
                    && let Some(val) = get_attribute(c, &spread.attribute)
                {
                    domains.insert(val);
                }
            }
            // Include the current candidate's domain
            if let Some(val) = get_attribute(candidate, &spread.attribute) {
                domains.insert(val);
            }
            if (domains.len() as u32) < min_domains {
                // Not enough domains yet — this is OK, we're building up
                // Only reject if we would exceed max_skew while under min_domains
            }
        }
    }
    true
}

/// Check if a service tolerates all taints on a candidate machine.
pub(super) fn passes_taints(
    candidate: &Candidate,
    tolerations: &[crate::config::Toleration],
) -> bool {
    use crate::config::{TaintEffect, TolerationOp};

    for taint in &candidate.config.taints {
        if taint.effect == TaintEffect::PreferNoSchedule {
            // Soft taint — handled in scoring, not filtering
            continue;
        }
        let tolerated = tolerations.iter().any(|t| {
            // Key must match (or toleration key is None = match all)
            let key_matches = t.key.as_ref().is_none_or(|k| k == &taint.key);
            // Effect must match (or toleration effect is None = match all)
            let effect_matches = t.effect.as_ref().is_none_or(|e| e == &taint.effect);
            // Operator check
            let op_matches = match t.op {
                TolerationOp::Exists => true,
                TolerationOp::Equal => t.value.as_deref() == taint.value.as_deref(),
            };
            key_matches && effect_matches && op_matches
        });
        if !tolerated {
            return false;
        }
    }
    true
}

/// Resolve a dotted attribute path against a candidate machine.
pub(super) fn get_attribute(candidate: &Candidate, attribute: &str) -> Option<String> {
    let parts: Vec<&str> = attribute.splitn(2, '.').collect();
    match parts[0] {
        "pool" => Some(candidate.pool.clone()),
        "labels" => {
            if parts.len() == 2 {
                candidate.merged_labels.get(parts[1]).cloned()
            } else {
                None
            }
        }
        "capacity" => {
            if parts.len() == 2 {
                match parts[1] {
                    "cpu" => Some(candidate.config.capacity.cpu.to_string()),
                    "memory" => Some(candidate.config.capacity.memory.to_string()),
                    "disk" => Some(candidate.config.capacity.disk.to_string()),
                    _ => None,
                }
            } else {
                None
            }
        }
        "name" => Some(candidate.name.clone()),
        "schedulable" => {
            if parts.len() == 2 {
                match parts[1] {
                    "cpu" => Some(candidate.schedulable_cpu.to_string()),
                    "memory" => Some(candidate.schedulable_memory.to_string()),
                    "disk" => Some(candidate.schedulable_disk.to_string()),
                    _ => None,
                }
            } else {
                None
            }
        }
        "available" => {
            if parts.len() == 2 {
                match parts[1] {
                    "cpu" => Some(candidate.available_cpu().to_string()),
                    "memory" => Some(candidate.available_memory().to_string()),
                    "disk" => Some(candidate.available_disk().to_string()),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}
