use super::state::FleetState;
use crate::ca::issuer::CertIssuer;
use crate::metrics::aggregator::MetricsAggregator;
use crate::proto::agent_message::Payload;
use crate::proto::server_message::Payload as ServerPayload;
use crate::proto::{
    AgentMessage, CertRequestType, CertificateResponse, JwtSvidRequest, JwtSvidResponse,
    ServerMessage,
};

/// Note when a message's self-reported node id disagrees with the stream's
/// authenticated node. The payload field is informational only and is never
/// used for authorization or bookkeeping.
fn check_claimed_node(node_id: &str, claimed: &str, kind: &str) {
    if !claimed.is_empty() && claimed != node_id {
        tracing::warn!(
            node_id = %node_id,
            claimed = %claimed,
            kind,
            "Ignoring mismatched node_id in agent message"
        );
    }
}

/// Answer a JWT-SVID request from the authenticated node `node_id`. Always
/// produces a response so the agent's waiting workload is never left hanging.
async fn issue_jwt_svid(
    node_id: &str,
    req: &JwtSvidRequest,
    cert_issuer: Option<&CertIssuer>,
) -> JwtSvidResponse {
    let mut response = JwtSvidResponse {
        request_id: req.request_id.clone(),
        ..Default::default()
    };
    let Some(issuer) = cert_issuer else {
        response.error = "this server does not issue SVIDs".into();
        return response;
    };
    match issuer
        .issue_jwt_svid(node_id, &req.service_name, &req.audience)
        .await
    {
        Ok((token, expires_at)) => {
            response.token = token;
            response.expires_at = expires_at;
        }
        Err(e) => {
            tracing::warn!(
                node_id = %node_id,
                service = %req.service_name,
                error = %e,
                "JWT-SVID request denied"
            );
            response.error = e.to_string();
        }
    }
    response
}

/// Handle one message from the control stream of `node_id`, the stream's
/// authenticated node. Node ids inside payloads are ignored. `stream_cert`
/// is the DER node SVID the stream authenticated with, if it used mTLS;
/// only such streams may renew it or advertise a mesh peer.
pub(super) async fn process_agent_message(
    state: &FleetState,
    node_id: &str,
    msg: AgentMessage,
    cert_issuer: Option<&CertIssuer>,
    metrics: &MetricsAggregator,
    mesh: &super::mesh::MeshRegistry,
    stream_cert: Option<&[u8]>,
) {
    let mtls = stream_cert.is_some();
    match msg.payload {
        Some(Payload::Heartbeat(hb)) => {
            check_claimed_node(node_id, &hb.node_id, "heartbeat");
            tracing::debug!(node_id = %node_id, "Heartbeat received");
            state
                .update_heartbeat(node_id, hb.available_resources)
                .await;
        }
        Some(Payload::MeshAdvert(peer)) => {
            mesh.handle_advert(state, node_id, peer, stream_cert).await;
        }
        Some(Payload::Health(report)) => {
            check_claimed_node(node_id, &report.node_id, "health");
            tracing::debug!(
                node_id = %node_id,
                count = report.services.len(),
                "Health report received"
            );
            state.update_health(node_id, report.services).await;
        }
        Some(Payload::Status(report)) => {
            check_claimed_node(node_id, &report.node_id, "status");
            tracing::debug!(
                node_id = %node_id,
                services = report.running_services.len(),
                "Status report received"
            );
            state.update_status(node_id, report.running_services).await;
        }
        Some(Payload::CertRequest(req)) => {
            check_claimed_node(node_id, &req.node_id, "cert_request");
            tracing::debug!(
                node_id = %node_id,
                service = %req.service_name,
                "Certificate request received"
            );

            let node_cert = req.request_type == CertRequestType::NodeCert as i32;
            if node_cert && !mtls {
                tracing::warn!(
                    node_id = %node_id,
                    "Node SVID renewal refused: stream is not authenticated by a node SVID"
                );
                return;
            }
            if let Some(issuer) = cert_issuer {
                let issued = if node_cert {
                    issuer.issue_node_svid(node_id, &req.csr).await
                } else {
                    issuer
                        .process_request(node_id, &req.service_name, &req.csr)
                        .await
                };
                match issued {
                    Ok((cert, chain, expires_at)) => {
                        let response = ServerMessage {
                            payload: Some(ServerPayload::Cert(CertificateResponse {
                                certificate: cert,
                                chain,
                                expires_at,
                                service_name: if node_cert {
                                    String::new()
                                } else {
                                    req.service_name.clone()
                                },
                                request_type: req.request_type,
                            })),
                        };
                        state.send_to_agent(node_id, response).await;
                        tracing::info!(
                            node_id = %node_id,
                            service = %req.service_name,
                            node_cert,
                            "SVID issued"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            node_id = %node_id,
                            service = %req.service_name,
                            error = %e,
                            "Certificate request denied"
                        );
                    }
                }
            }
        }
        Some(Payload::JwtSvidRequest(req)) => {
            let response = issue_jwt_svid(node_id, &req, cert_issuer).await;
            state
                .send_to_agent(
                    node_id,
                    ServerMessage {
                        payload: Some(ServerPayload::JwtSvid(response)),
                    },
                )
                .await;
        }
        Some(Payload::Metrics(summary)) => {
            check_claimed_node(node_id, &summary.node_id, "metrics");
            tracing::debug!(
                node_id = %node_id,
                points = summary.points.len(),
                "Metrics received"
            );
            metrics.ingest(node_id, summary.points).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::jwt::JwtSigner;
    use crate::ca::root::RootCa;
    use crate::ca::signer::DirectCaSigner;
    use std::sync::Arc;

    async fn issuer() -> CertIssuer {
        let ca = RootCa::new("test.internal");
        ca.initialize(None, None).await.unwrap();
        let (jwt, _) = JwtSigner::generate().unwrap();
        let issuer = CertIssuer::new(Arc::new(DirectCaSigner::new(ca, jwt)));
        issuer
            .update_assignments("node-1", vec!["web".into()])
            .await;
        issuer
    }

    fn request(service: &str) -> JwtSvidRequest {
        JwtSvidRequest {
            request_id: "r1".into(),
            service_name: service.into(),
            audience: vec!["db".into()],
        }
    }

    #[tokio::test]
    async fn jwt_svid_request_is_answered_with_token() {
        let issuer = issuer().await;
        let resp = issue_jwt_svid("node-1", &request("web"), Some(&issuer)).await;
        assert_eq!(resp.request_id, "r1");
        assert!(resp.error.is_empty(), "{}", resp.error);
        let bundle = issuer.jwt_bundle().await.unwrap();
        crate::ca::jwt::verify_jwt_svid(&resp.token, &bundle, "test.internal", "db").unwrap();
    }

    #[tokio::test]
    async fn refused_jwt_svid_request_still_gets_a_response() {
        let issuer = issuer().await;
        let resp = issue_jwt_svid("node-2", &request("web"), Some(&issuer)).await;
        assert_eq!(resp.request_id, "r1");
        assert!(resp.token.is_empty());
        assert!(resp.error.contains("not assigned"), "{}", resp.error);

        let resp = issue_jwt_svid("node-1", &request("web"), None).await;
        assert!(resp.token.is_empty() && !resp.error.is_empty());
    }
}
