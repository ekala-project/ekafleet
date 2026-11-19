//! High availability against the production server (`server::run`):
//!
//! three servers form a cluster from `--peers` (the first one's keys
//! carried to the others in a key bundle) → followers refuse the control
//! plane and name the leader → ACL and join tokens replicate → the leader
//! dies → the others elect a new one, which accepts the replicated tokens,
//! refuses a join token already used, and seals secrets under the fleet
//! key the old leader rotated.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::{
    CreateAclTokenRequest, CreateJoinTokenRequest, RaftStatusRequest, RaftStatusResponse,
    RotateFleetKeyRequest, SetSecretRequest, StatusRequest,
};
use tonic::transport::{Channel, Endpoint};

const ADMIN_TOKEN: &str = "ha-admin-token";
const DOMAIN: &str = "ha.test";
const PASSPHRASE: &str = "workflow bundle passphrase";

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A server on its own runtime, so stopping it stops everything it runs
/// (Raft included), as a crash would.
struct Server {
    id: u64,
    grpc: SocketAddr,
    dir: PathBuf,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Server {
    fn start(id: u64, grpc: SocketAddr, dir: &Path, peers: &BTreeMap<u64, String>) -> Self {
        let config = ekafleet::server::ServerConfig {
            data_dir: dir.to_path_buf(),
            node_id: id,
            peers: peers.clone(),
            grpc_listen: grpc.to_string(),
            raft_addr: None,
            http_listen: free_addr().to_string(),
            token: ADMIN_TOKEN.into(),
            domain: DOMAIN.into(),
            ca_socket: None,
            allow_bearer_agents: false,
            embedded_agent: None,
            federation_listen: None,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(async move {
            if let Err(e) = ekafleet::server::run(config).await {
                panic!("server {id} exited: {e:#}");
            }
        });
        Self {
            id,
            grpc,
            dir: dir.to_path_buf(),
            runtime: Some(runtime),
        }
    }

    fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }

    fn ca_pem(&self) -> String {
        std::fs::read_to_string(self.dir.join("ca-cert.pem")).unwrap()
    }

    async fn channel(&self) -> Channel {
        let tls = ekafleet::agent::bootstrap::tls_config(&self.grpc.to_string(), &self.ca_pem());
        for _ in 0..200 {
            if let Ok(channel) = Endpoint::from_shared(format!("https://{}", self.grpc))
                .unwrap()
                .tls_config(tls.clone())
                .unwrap()
                .connect()
                .await
            {
                return channel;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server {} does not accept connections", self.id);
    }

    async fn client(
        &self,
        token: &str,
    ) -> FleetControlClient<
        tonic::service::interceptor::InterceptedService<
            Channel,
            impl tonic::service::Interceptor + use<>,
        >,
    > {
        let channel = self.channel().await;
        let bearer: tonic::metadata::MetadataValue<_> = format!("Bearer {token}").parse().unwrap();
        #[allow(clippy::result_large_err)]
        FleetControlClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", bearer.clone());
            Ok(req)
        })
    }

    async fn raft_status(&self) -> Option<RaftStatusResponse> {
        let mut client = self.client(ADMIN_TOKEN).await;
        client
            .raft_status(RaftStatusRequest {})
            .await
            .ok()
            .map(|r| r.into_inner())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The leader every running server in `servers` agrees on, with all of
/// `voters` voting, other than `not`.
async fn agreed_leader(servers: &[&Server], voters: usize, not: u64) -> RaftStatusResponse {
    for _ in 0..300 {
        let mut statuses = Vec::new();
        for server in servers {
            statuses.push(server.raft_status().await);
        }
        if let Some(Some(first)) = statuses.first()
            && first.leader_id != 0
            && first.leader_id != not
            && first.members.iter().filter(|m| m.voter).count() == voters
            && statuses
                .iter()
                .all(|s| s.as_ref().is_some_and(|s| s.leader_id == first.leader_id))
        {
            return first.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the servers did not agree on a leader");
}

async fn wait_for(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} was never created", path.display());
}

async fn join(server: &Server, node: &str, token: &str) -> anyhow::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let mut identity = ekafleet::agent::NodeIdentity::new(dir.path());
    ekafleet::agent::bootstrap::join(
        &server.grpc.to_string(),
        &server.ca_pem(),
        node,
        token,
        &mut identity,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn servers_fail_over_with_replicated_state_and_shared_keys() {
    let root = tempfile::tempdir().unwrap();
    let addrs: BTreeMap<u64, SocketAddr> = (1..=3).map(|id| (id, free_addr())).collect();
    let peers: BTreeMap<u64, String> = addrs.iter().map(|(id, a)| (*id, a.to_string())).collect();
    let dirs: BTreeMap<u64, PathBuf> = (1..=3)
        .map(|id| (id, root.path().join(format!("s{id}"))))
        .collect();

    // The first server makes the cluster's keys; the others start from them.
    let mut servers = vec![Server::start(1, addrs[&1], &dirs[&1], &peers)];
    wait_for(&dirs[&1].join("cache-signing-key.pk8")).await;
    let bundle = ekafleet::server::keybundle::export(&dirs[&1], None, DOMAIN, PASSPHRASE)
        .await
        .unwrap();
    for id in 2..=3 {
        ekafleet::server::keybundle::import(
            &bundle,
            PASSPHRASE,
            &dirs[&id],
            ekafleet::server::keybundle::Scope::All,
            Some(DOMAIN),
        )
        .await
        .unwrap();
        servers.push(Server::start(id, addrs[&id], &dirs[&id], &peers));
    }

    let status = agreed_leader(&servers.iter().collect::<Vec<_>>(), 3, 0).await;
    let leader_id = status.leader_id;
    assert_eq!(status.leader_addr, peers[&leader_id]);
    let leader = &servers[(leader_id - 1) as usize];
    let follower = servers.iter().find(|s| s.id != leader_id).unwrap();

    // Followers serve nothing but Raft status, and name the leader.
    let refused = follower
        .client(ADMIN_TOKEN)
        .await
        .status(StatusRequest::default())
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unavailable);
    assert_eq!(
        refused
            .metadata()
            .get("x-ekafleet-leader")
            .and_then(|v| v.to_str().ok()),
        Some(peers[&leader_id].as_str())
    );

    // State written through the leader before it fails.
    let mut admin = leader.client(ADMIN_TOKEN).await;
    let viewer = admin
        .create_acl_token(CreateAclTokenRequest {
            role: "viewer".into(),
            description: "replicated".into(),
            namespace: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .token;
    let join_token = |node: &str| CreateJoinTokenRequest {
        node_name: node.into(),
        ttl_secs: 0,
    };
    let used = admin
        .create_join_token(join_token("web-1"))
        .await
        .unwrap()
        .into_inner()
        .token;
    let unused = admin
        .create_join_token(join_token("web-2"))
        .await
        .unwrap()
        .into_inner()
        .token;
    join(leader, "web-1", &used).await.unwrap();
    admin
        .set_secret(SetSecretRequest {
            service_name: "web".into(),
            secret_name: "password".into(),
            value: b"before".to_vec(),
        })
        .await
        .unwrap();
    admin
        .rotate_fleet_key(RotateFleetKeyRequest {})
        .await
        .unwrap();

    // An API token works on every server, not only the one that made it.
    let mut replicated = None;
    for _ in 0..100 {
        replicated = follower
            .client(&viewer)
            .await
            .raft_status(RaftStatusRequest {})
            .await
            .ok();
        if replicated.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        replicated.is_some(),
        "the viewer token reached the follower"
    );

    // The leader dies; the other two carry on.
    drop(admin);
    servers[(leader_id - 1) as usize].stop();
    let survivors: Vec<&Server> = servers.iter().filter(|s| s.id != leader_id).collect();
    let status = agreed_leader(&survivors, 3, leader_id).await;
    assert_ne!(status.leader_id, leader_id);
    let new_leader = survivors.iter().find(|s| s.id == status.leader_id).unwrap();

    // Its SVID chains to the same root, and the tokens were replicated.
    new_leader
        .client(&viewer)
        .await
        .raft_status(RaftStatusRequest {})
        .await
        .unwrap();
    let replay = join(new_leader, "web-1", &used).await.unwrap_err();
    assert!(replay.to_string().contains("already used"), "{replay:#}");
    join(new_leader, "web-2", &unused).await.unwrap();

    // The rotated fleet key reached it: it seals new secrets once its copy
    // is current.
    let mut admin = new_leader.client(ADMIN_TOKEN).await;
    let mut sealed = Err(tonic::Status::unknown("not tried"));
    for _ in 0..100 {
        sealed = admin
            .set_secret(SetSecretRequest {
                service_name: "web".into(),
                secret_name: "password".into(),
                value: b"after".to_vec(),
            })
            .await;
        if sealed.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    sealed.unwrap();
}
