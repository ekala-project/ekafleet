use super::state::FleetState;
use crate::ca::issuer::CertIssuer;
use crate::metrics::aggregator::MetricsAggregator;
use crate::proto::agent_message::Payload;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{AgentMessage, CertificateResponse, ServerMessage};

pub(super) async fn process_agent_message(
    state: &FleetState,
    node_id: &str,
    msg: AgentMessage,
    cert_issuer: Option<&CertIssuer>,
    metrics: &MetricsAggregator,
) {
    match msg.payload {
        Some(Payload::Heartbeat(hb)) => {
            tracing::debug!(node_id = %hb.node_id, "Heartbeat received");
            state
                .update_heartbeat(node_id, hb.available_resources)
                .await;
            if !hb.mesh_ip.is_empty()
                && let Ok(ip) = hb.mesh_ip.parse::<std::net::Ipv4Addr>()
            {
                state.update_mesh_ip(node_id, ip).await;
            }
        }
        Some(Payload::Health(report)) => {
            tracing::debug!(
                node_id = %report.node_id,
                count = report.services.len(),
                "Health report received"
            );
            state.update_health(node_id, report.services).await;
        }
        Some(Payload::Status(report)) => {
            tracing::debug!(
                node_id = %report.node_id,
                services = report.running_services.len(),
                "Status report received"
            );
            state.update_status(node_id, report.running_services).await;
        }
        Some(Payload::CertRequest(req)) => {
            tracing::debug!(
                node_id = %req.node_id,
                service = %req.service_name,
                "Certificate request received"
            );

            if let Some(issuer) = cert_issuer {
                match issuer
                    .process_request(&req.node_id, &req.service_name, &req.csr)
                    .await
                {
                    Ok((cert, chain, expires_at)) => {
                        let response = ServerMessage {
                            payload: Some(ServerPayload::Cert(CertificateResponse {
                                certificate: cert,
                                chain,
                                expires_at,
                                service_name: req.service_name.clone(),
                            })),
                        };
                        state.send_to_agent(node_id, response).await;
                        tracing::info!(
                            node_id = %req.node_id,
                            service = %req.service_name,
                            "SVID issued"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            node_id = %req.node_id,
                            service = %req.service_name,
                            error = %e,
                            "Certificate request denied"
                        );
                    }
                }
            }
        }
        Some(Payload::Metrics(summary)) => {
            tracing::debug!(
                node_id = %summary.node_id,
                points = summary.points.len(),
                "Metrics received"
            );
            metrics.ingest(&summary.node_id, summary.points).await;
        }
        Some(Payload::Nack(nack)) => {
            tracing::warn!(
                correlation_id = %nack.correlation_id,
                reason = %nack.reason,
                "Agent NACKed a command"
            );
        }
        Some(Payload::AttestResponse(_)) => {
            tracing::debug!("Ignoring attestation response on stream (use Attest RPC)");
        }
        Some(Payload::CommandResponse(resp)) => {
            let cid = resp.correlation_id.clone();
            tracing::debug!(
                correlation_id = %cid,
                success = resp.success,
                "Agent command response received"
            );
            state.complete_request(&cid, resp).await;
        }
        None => {}
    }
}
