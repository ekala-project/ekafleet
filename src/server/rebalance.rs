#![allow(dead_code)]

use std::collections::HashMap;

use super::scheduler;
use super::state::FleetState;
use crate::config::FleetConfig;

/// Evaluate whether workloads should be rebalanced after cluster drift
/// (e.g., after node failures and recoveries, scale-ups).
/// Returns a list of suggested reschedule operations.
pub async fn evaluate_rebalance(
    config: &FleetConfig,
    state: &FleetState,
) -> Vec<RebalanceSuggestion> {
    let mut suggestions = Vec::new();

    // Get current placements from fleet status
    let (_nodes, services, _) = state.fleet_status().await;

    // Compute ideal placement from scratch (empty current placements
    // intentionally — rebalancing evaluates the ideal state without
    // stickiness bias).
    let ideal = scheduler::schedule(
        &config.services,
        &config.machines,
        &config.node_pools,
        &HashMap::new(),
    );

    // Compare actual vs ideal — find services that would be better placed elsewhere
    for svc_status in &services {
        let actual_nodes: Vec<&str> = svc_status
            .instances
            .iter()
            .map(|i| i.node_id.as_str())
            .collect();

        let ideal_nodes: Vec<&str> = ideal
            .placements
            .iter()
            .filter(|p| p.service_name == svc_status.name)
            .map(|p| p.machine_name.as_str())
            .collect();

        // Find instances on nodes that are no longer in the ideal placement
        for actual_node in &actual_nodes {
            if !ideal_nodes.contains(actual_node)
                && let Some(ideal_node) = ideal_nodes.iter().find(|n| !actual_nodes.contains(n))
            {
                suggestions.push(RebalanceSuggestion {
                    service_name: svc_status.name.clone(),
                    from_node: actual_node.to_string(),
                    to_node: ideal_node.to_string(),
                    reason: "better placement available after cluster state change".to_string(),
                });
            }
        }
    }

    if !suggestions.is_empty() {
        tracing::info!(count = suggestions.len(), "Rebalance suggestions computed");
    }

    suggestions
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RebalanceSuggestion {
    pub service_name: String,
    pub from_node: String,
    pub to_node: String,
    pub reason: String,
}
