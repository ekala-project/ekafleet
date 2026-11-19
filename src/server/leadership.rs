//! Leader-only control plane.
//!
//! Every server replicates fleet state through Raft, but only the leader
//! runs the control plane: it accepts agent streams, serves the CLI and the
//! HTTP API, and runs the background controllers (reconcile, secrets,
//! leases, DNS, ingress, autoscaling, alerting, federation). A follower
//! refuses those requests with UNAVAILABLE and the leader's address in the
//! [`LEADER_METADATA`] header, which agents and the CLI follow.
//!
//! Leadership is held per term: [`Leadership::spawn_terms`] starts the
//! controllers once this server leads and has confirmed it can serve
//! linearizable reads, and cancels them (dropping agent streams) the moment
//! it stops leading.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tonic::codegen::{BoxFuture, Service, http};
use tonic::server::NamedService;

use crate::raft::consensus::{NodeId, Raft};

/// Response header (gRPC metadata) naming the leader's gRPC address.
pub const LEADER_METADATA: &str = "x-ekafleet-leader";

/// RPCs every server answers, leader or not.
const ANY_SERVER: &[&str] = &["/fleet.FleetControl/RaftStatus"];

/// Whether this server currently leads, and where the leader is if not.
#[derive(Clone)]
pub struct Leadership {
    raft: Raft,
    id: NodeId,
    /// Set once a term's leadership is confirmed; cleared when it ends.
    ready: Arc<AtomicBool>,
}

impl Leadership {
    pub fn new(raft: Raft) -> Self {
        let id = raft.metrics().borrow().id;
        Self {
            raft,
            id,
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// This server leads and its term is confirmed.
    pub fn is_leader(&self) -> bool {
        self.ready.load(Ordering::Acquire)
            && self.raft.metrics().borrow().current_leader == Some(self.id)
    }

    /// The current leader's gRPC address, when known and not this server.
    pub fn leader_addr(&self) -> Option<String> {
        let metrics = self.raft.metrics().borrow().clone();
        let leader = metrics.current_leader.filter(|l| *l != self.id)?;
        metrics
            .membership_config
            .membership()
            .get_node(&leader)
            .map(|node| node.addr.clone())
    }

    /// The refusal for a request this server cannot serve, or `None` when
    /// it leads.
    #[allow(clippy::result_large_err)]
    pub fn refusal(&self) -> Option<tonic::Status> {
        if self.is_leader() {
            return None;
        }
        Some(match self.leader_addr() {
            Some(addr) => {
                let mut metadata = tonic::metadata::MetadataMap::new();
                if let Ok(value) = addr.parse() {
                    metadata.insert(LEADER_METADATA, value);
                }
                tonic::Status::with_metadata(
                    tonic::Code::Unavailable,
                    format!("this server is not the leader; the leader is {addr}"),
                    metadata,
                )
            }
            None => {
                tonic::Status::unavailable("this server is not the leader and none is known yet")
            }
        })
    }

    /// Run `start` for every term this server leads, with a token cancelled
    /// when the term ends; `stop` runs after each term's token is cancelled.
    pub fn spawn_terms<F, G>(&self, shutdown: CancellationToken, start: F, stop: G)
    where
        F: Fn(CancellationToken) + Send + 'static,
        G: Fn() + Send + 'static,
    {
        let this = self.clone();
        tokio::spawn(async move {
            let mut metrics = this.raft.metrics();
            loop {
                // Wait to lead.
                let term = loop {
                    let (leader, term) = {
                        let m = metrics.borrow_and_update();
                        (m.current_leader, m.current_term)
                    };
                    if leader == Some(this.id) {
                        break term;
                    }
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        changed = metrics.changed() => if changed.is_err() { return },
                    }
                };
                // A leader that was just elected may not have committed an
                // entry in its term yet; serving before that could act on
                // stale state.
                if let Err(e) = this.raft.ensure_linearizable().await {
                    tracing::debug!(error = %e, "Leadership not confirmed yet");
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                    }
                    continue;
                }
                tracing::info!(node_id = this.id, term, "Leading the fleet");
                this.ready.store(true, Ordering::Release);
                let term_token = shutdown.child_token();
                start(term_token.clone());

                // Lead until the term ends.
                loop {
                    let still = {
                        let m = metrics.borrow_and_update();
                        m.current_leader == Some(this.id) && m.current_term == term
                    };
                    if !still {
                        break;
                    }
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        changed = metrics.changed() => if changed.is_err() { break },
                    }
                }
                this.ready.store(false, Ordering::Release);
                term_token.cancel();
                stop();
                if shutdown.is_cancelled() {
                    return;
                }
                tracing::warn!(node_id = this.id, term, "No longer leading the fleet");
            }
        });
    }

    /// Wait (up to `timeout`) for this server to lead with a confirmed term.
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            while !self.is_leader() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok()
    }
}

/// What `raft` reports about the cluster, as answered by `RaftStatus`.
pub fn raft_status(raft: &Raft) -> crate::proto::RaftStatusResponse {
    let m = raft.metrics().borrow().clone();
    let membership = m.membership_config.membership();
    let voters: std::collections::BTreeSet<NodeId> = membership.voter_ids().collect();
    let matched = |id: &NodeId| {
        m.replication
            .as_ref()
            .and_then(|r| r.get(id).copied().flatten())
            .map_or(0, |log| log.index)
    };
    let leader_addr = m
        .current_leader
        .and_then(|l| membership.get_node(&l))
        .map(|n| n.addr.clone())
        .unwrap_or_default();
    crate::proto::RaftStatusResponse {
        node_id: m.id,
        leader_id: m.current_leader.unwrap_or(0),
        leader_addr,
        term: m.current_term,
        last_log_index: m.last_log_index.unwrap_or(0),
        last_applied: m.last_applied.map_or(0, |l| l.index),
        state: format!("{:?}", m.state).to_lowercase(),
        members: membership
            .nodes()
            .map(|(id, node)| crate::proto::RaftMember {
                id: *id,
                addr: node.addr.clone(),
                voter: voters.contains(id),
                matched: matched(id),
            })
            .collect(),
    }
}

/// The leader address a follower's refusal names.
pub fn leader_hint(status: &tonic::Status) -> Option<String> {
    if status.code() != tonic::Code::Unavailable {
        return None;
    }
    status
        .metadata()
        .get(LEADER_METADATA)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// The leader address named anywhere in `e`'s chain.
pub fn leader_hint_in(e: &anyhow::Error) -> Option<String> {
    e.chain()
        .find_map(|cause| cause.downcast_ref::<tonic::Status>().and_then(leader_hint))
}

/// Wraps a gRPC service so that followers refuse its RPCs.
#[derive(Clone)]
pub struct LeaderOnly<S> {
    inner: S,
    leadership: Leadership,
}

impl<S> LeaderOnly<S> {
    pub fn new(inner: S, leadership: Leadership) -> Self {
        Self { inner, leadership }
    }
}

impl<S: NamedService> NamedService for LeaderOnly<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B, ResB> Service<http::Request<B>> for LeaderOnly<S>
where
    S: Service<http::Request<B>, Response = http::Response<ResB>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
    ResB: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    ResB::Error: Into<tonic::codegen::StdError>,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        if !ANY_SERVER.contains(&req.uri().path())
            && let Some(status) = self.leadership.refusal()
        {
            return Box::pin(async move { Ok(status.into_http()) });
        }
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let response = inner.call(req).await?;
            Ok(response.map(tonic::body::Body::new))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::consensus::testing::{Router, node};
    use openraft::BasicNode;
    use std::collections::BTreeMap;

    async fn cluster(dir: &std::path::Path) -> (Router, Vec<Raft>) {
        let router = Router::default();
        let members: BTreeMap<NodeId, BasicNode> = (1..=3)
            .map(|id| (id, BasicNode::new(format!("10.0.0.{id}:7400"))))
            .collect();
        let mut rafts = Vec::new();
        for id in 1..=3u64 {
            rafts.push(
                node(&router, id, dir.join(format!("n{id}")).as_path())
                    .await
                    .0,
            );
        }
        rafts[0].initialize(members).await.unwrap();
        (router, rafts)
    }

    #[tokio::test]
    async fn followers_refuse_with_the_leader_address_and_terms_end_on_step_down() {
        let dir = tempfile::tempdir().unwrap();
        let (router, rafts) = cluster(dir.path()).await;
        let leader_id = rafts[0]
            .wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader.is_some(), "leader")
            .await
            .unwrap()
            .current_leader
            .unwrap();
        let shutdown = CancellationToken::new();
        let terms: Vec<_> = rafts
            .iter()
            .map(|raft| {
                let leadership = Leadership::new(raft.clone());
                let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let ended = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let (s, e) = (started.clone(), ended.clone());
                leadership.spawn_terms(
                    shutdown.clone(),
                    move |_| {
                        s.fetch_add(1, Ordering::SeqCst);
                    },
                    move || {
                        e.fetch_add(1, Ordering::SeqCst);
                    },
                );
                (leadership, started, ended)
            })
            .collect();
        let (leader, started, ended) = &terms[(leader_id - 1) as usize];
        assert!(leader.wait_ready(Duration::from_secs(10)).await);
        assert!(leader.refusal().is_none());
        assert_eq!(started.load(Ordering::SeqCst), 1);

        let follower = terms
            .iter()
            .find(|(l, ..)| l.id != leader_id)
            .map(|(l, ..)| l)
            .unwrap();
        let status = follower.refusal().expect("followers refuse");
        assert_eq!(
            leader_hint(&status).as_deref(),
            Some(format!("10.0.0.{leader_id}:7400").as_str())
        );
        let (_, follower_started, _) = terms.iter().find(|(l, ..)| l.id == follower.id).unwrap();
        assert_eq!(follower_started.load(Ordering::SeqCst), 0);

        // Stop the leader: its term ends and the others elect a new one.
        router.remove(leader_id);
        rafts[(leader_id - 1) as usize].shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while ended.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the old leader's term ends");
        assert!(!leader.is_leader());
        let others: Vec<_> = rafts
            .iter()
            .filter(|r| r.metrics().borrow().id != leader_id)
            .collect();
        let new_leader = others[0]
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |m| m.current_leader.is_some_and(|l| l != leader_id),
                "new leader",
            )
            .await
            .unwrap()
            .current_leader
            .unwrap();
        let (next, next_started, _) = &terms[(new_leader - 1) as usize];
        assert!(next.wait_ready(Duration::from_secs(10)).await);
        assert_eq!(next_started.load(Ordering::SeqCst), 1);
        shutdown.cancel();
        for raft in others {
            raft.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn followers_wrap_refusals_as_grpc_responses() {
        let dir = tempfile::tempdir().unwrap();
        let (_router, rafts) = cluster(dir.path()).await;
        // A fresh Leadership is not ready until a term is confirmed, so it
        // refuses even on the leader.
        let leadership = Leadership::new(rafts[0].clone());
        let stub = tower::service_fn(|_req: http::Request<()>| async move {
            Ok::<_, std::convert::Infallible>(http::Response::new(String::from("served")))
        });
        let mut service = LeaderOnly::new(stub, leadership);
        let refused = service
            .call(
                http::Request::builder()
                    .uri("/fleet.FleetControl/Apply")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = tonic::Status::from_header_map(refused.headers()).unwrap();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        let served = service
            .call(
                http::Request::builder()
                    .uri("/fleet.FleetControl/RaftStatus")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(tonic::Status::from_header_map(served.headers()).is_none());
        for raft in rafts {
            raft.shutdown().await.unwrap();
        }
    }
}
