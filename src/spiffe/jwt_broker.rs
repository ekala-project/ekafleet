//! Agent-side JWT-SVID broker.
//!
//! JWT-SVIDs are signed by the server (the agent holds no signing key). When
//! an attested workload asks the Workload API for one, the broker forwards a
//! `JwtSvidRequest` over the control stream, waits for the matching
//! `JwtSvidResponse`, and caches the token per (service, audience set) until
//! half its lifetime has passed.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};

use crate::proto::agent_message::Payload;
use crate::proto::{AgentMessage, JwtSvidRequest, JwtSvidResponse};

/// How long a workload waits for the server to answer.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on cached tokens; expired entries are dropped first.
const MAX_CACHED: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum JwtBrokerError {
    #[error("not connected to the server")]
    NotConnected,
    #[error("timed out waiting for the server")]
    Timeout,
    #[error("server refused the JWT-SVID: {0}")]
    Refused(String),
}

type CacheKey = (String, Vec<String>);

struct CachedToken {
    token: String,
    /// Unix second after which the token is refreshed (half-life).
    refresh_at: u64,
}

#[derive(Default)]
struct BrokerState {
    sender: Option<mpsc::Sender<AgentMessage>>,
    pending: HashMap<String, oneshot::Sender<JwtSvidResponse>>,
    cache: HashMap<CacheKey, CachedToken>,
}

/// Forwards JWT-SVID requests to the server and caches the answers.
#[derive(Default)]
pub struct JwtSvidBroker {
    inner: Mutex<BrokerState>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl JwtSvidBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Route requests over this control-stream sender (set per connection).
    /// Requests waiting on a previous connection fail rather than hang.
    pub async fn set_sender(&self, sender: mpsc::Sender<AgentMessage>) {
        let mut state = self.inner.lock().await;
        state.sender = Some(sender);
        state.pending.clear();
    }

    /// Get a JWT-SVID for `service` valid for `audience`.
    pub async fn fetch(
        &self,
        service: &str,
        audience: &[String],
    ) -> Result<String, JwtBrokerError> {
        let mut audience = audience.to_vec();
        audience.sort();
        audience.dedup();
        let key = (service.to_string(), audience.clone());

        let request_id = uuid::Uuid::new_v4().to_string();
        let (done_tx, done_rx) = oneshot::channel();
        let sender = {
            let mut state = self.inner.lock().await;
            if let Some(cached) = state.cache.get(&key)
                && now_secs() < cached.refresh_at
            {
                return Ok(cached.token.clone());
            }
            let sender = state.sender.clone().ok_or(JwtBrokerError::NotConnected)?;
            state.pending.insert(request_id.clone(), done_tx);
            sender
        };

        let msg = AgentMessage {
            payload: Some(Payload::JwtSvidRequest(JwtSvidRequest {
                request_id: request_id.clone(),
                service_name: service.to_string(),
                audience,
            })),
        };
        if sender.send(msg).await.is_err() {
            self.inner.lock().await.pending.remove(&request_id);
            return Err(JwtBrokerError::NotConnected);
        }

        let response = match tokio::time::timeout(RESPONSE_TIMEOUT, done_rx).await {
            Ok(Ok(response)) => response,
            // The sender was dropped: the connection was replaced.
            Ok(Err(_)) => return Err(JwtBrokerError::NotConnected),
            Err(_) => {
                self.inner.lock().await.pending.remove(&request_id);
                return Err(JwtBrokerError::Timeout);
            }
        };
        if !response.error.is_empty() || response.token.is_empty() {
            return Err(JwtBrokerError::Refused(response.error));
        }

        let now = now_secs();
        let refresh_at = now + response.expires_at.saturating_sub(now) / 2;
        let mut state = self.inner.lock().await;
        if state.cache.len() >= MAX_CACHED {
            state.cache.retain(|_, c| now < c.refresh_at);
            if state.cache.len() >= MAX_CACHED {
                state.cache.clear();
            }
        }
        state.cache.insert(
            key,
            CachedToken {
                token: response.token.clone(),
                refresh_at,
            },
        );
        Ok(response.token)
    }

    /// Deliver the server's answer to the waiting request, if any.
    pub async fn complete(&self, response: JwtSvidResponse) {
        let waiter = self.inner.lock().await.pending.remove(&response.request_id);
        match waiter {
            Some(waiter) => {
                let _ = waiter.send(response);
            }
            None => tracing::debug!(
                request_id = %response.request_id,
                "JWT-SVID response for an unknown or expired request"
            ),
        }
    }

    /// Drop cached tokens of services no longer assigned to this node.
    pub async fn retain_services(&self, services: &[String]) {
        self.inner
            .lock()
            .await
            .cache
            .retain(|(service, _), _| services.contains(service));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Answer every request on `rx` with a token naming its service, or an
    /// error for service "denied". Counts the requests it saw.
    fn fake_server(
        broker: Arc<JwtSvidBroker>,
        mut rx: mpsc::Receiver<AgentMessage>,
        ttl: u64,
    ) -> tokio::task::JoinHandle<usize> {
        tokio::spawn(async move {
            let mut seen = 0;
            while let Some(msg) = rx.recv().await {
                let Some(Payload::JwtSvidRequest(req)) = msg.payload else {
                    continue;
                };
                seen += 1;
                let mut resp = JwtSvidResponse {
                    request_id: req.request_id,
                    ..Default::default()
                };
                if req.service_name == "denied" {
                    resp.error = "not assigned".into();
                } else {
                    resp.token = format!("{}:{}:{seen}", req.service_name, req.audience.join(","));
                    resp.expires_at = now_secs() + ttl;
                }
                broker.complete(resp).await;
            }
            seen
        })
    }

    #[tokio::test]
    async fn fetch_forwards_and_caches_per_audience_set() {
        let broker = Arc::new(JwtSvidBroker::new());
        let (tx, rx) = mpsc::channel(8);
        broker.set_sender(tx).await;
        let server = fake_server(broker.clone(), rx, 300);

        let a = broker
            .fetch("web", &["b".into(), "a".into()])
            .await
            .unwrap();
        assert_eq!(a, "web:a,b:1");
        // Same audience set in another order (and duplicated): cached.
        let again = broker
            .fetch("web", &["a".into(), "b".into(), "a".into()])
            .await
            .unwrap();
        assert_eq!(again, a);
        // A different audience is a different token.
        let other = broker.fetch("web", &["c".into()]).await.unwrap();
        assert_eq!(other, "web:c:2");

        broker.set_sender(mpsc::channel(1).0).await;
        drop(broker);
        assert_eq!(server.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn tokens_past_half_life_are_refreshed() {
        let broker = Arc::new(JwtSvidBroker::new());
        let (tx, rx) = mpsc::channel(8);
        broker.set_sender(tx).await;
        // A zero TTL puts the refresh point at "now".
        let _server = fake_server(broker.clone(), rx, 0);
        let first = broker.fetch("web", &["a".into()]).await.unwrap();
        let second = broker.fetch("web", &["a".into()]).await.unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn refusals_and_disconnects_are_errors() {
        let broker = Arc::new(JwtSvidBroker::new());
        assert!(matches!(
            broker.fetch("web", &["a".into()]).await,
            Err(JwtBrokerError::NotConnected)
        ));

        let (tx, rx) = mpsc::channel(8);
        broker.set_sender(tx).await;
        let _server = fake_server(broker.clone(), rx, 300);
        assert!(matches!(
            broker.fetch("denied", &["a".into()]).await,
            Err(JwtBrokerError::Refused(e)) if e == "not assigned"
        ));
    }

    #[tokio::test]
    async fn reconnect_fails_requests_in_flight() {
        let broker = Arc::new(JwtSvidBroker::new());
        let (tx, mut rx) = mpsc::channel(8);
        broker.set_sender(tx).await;
        let fetch = {
            let broker = broker.clone();
            tokio::spawn(async move { broker.fetch("web", &["a".into()]).await })
        };
        // The request went out but is never answered; then the stream is replaced.
        rx.recv().await.unwrap();
        broker.set_sender(mpsc::channel(1).0).await;
        assert!(matches!(
            fetch.await.unwrap(),
            Err(JwtBrokerError::NotConnected)
        ));
    }

    #[tokio::test]
    async fn unassigned_services_are_evicted() {
        let broker = Arc::new(JwtSvidBroker::new());
        let (tx, rx) = mpsc::channel(8);
        broker.set_sender(tx).await;
        let _server = fake_server(broker.clone(), rx, 300);
        let first = broker.fetch("web", &["a".into()]).await.unwrap();
        broker.retain_services(&["api".into()]).await;
        let second = broker.fetch("web", &["a".into()]).await.unwrap();
        assert_ne!(first, second);
    }
}
