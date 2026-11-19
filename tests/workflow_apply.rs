//! Apply → reconcile → rollback against the real `ekafleet server` binary
//! and a joined (simulated) agent:
//!
//! - `Apply` locks and evaluates a flake on the server, records a
//!   configuration revision, and returns once it has been reconciled onto
//!   the agent.
//! - `Rollback` re-applies an earlier revision's configuration as a new
//!   revision.
//! - The server resumes reconciling the recorded revision after a crash,
//!   with no client involved.
//!
//! Needs `nix` with flakes on `PATH` (the dev shell provides it).

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ekafleet::proto::agent_message::Payload;
use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::server_message::Payload as ServerPayload;
use ekafleet::proto::{
    AgentMessage, ApplyRequest, ApplyStatus, CacheNarInfoRequest, CacheNarRequest,
    CreateAclTokenRequest, CreateJoinTokenRequest, DrainRequest, EventsRequest, HealthReport,
    HealthStatus, Heartbeat, ListConfigRevisionsRequest, ListDeploymentsRequest, ListNodesRequest,
    LogsRequest, PlanRequest, RollbackRequest, ScaleRequest, ServiceHealth, ServiceInstance,
    ServiceSpec, ServiceState, SnapshotRequest, StatusReport, StatusRequest,
};
use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint, Identity};

const ADMIN_TOKEN: &str = "apply-admin-token";
const NODE: &str = "web-1";

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Server {
    child: Child,
    grpc: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn crash(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

async fn start(dir: &Path) -> Server {
    let token_file = dir.join("admin-token");
    std::fs::write(&token_file, ADMIN_TOKEN).unwrap();
    let grpc = free_addr();
    let child = Command::new(assert_cmd::cargo::cargo_bin("ekafleet"))
        .args(["server", "--data-dir"])
        .arg(dir.join("data"))
        .args(["--listen", &grpc.to_string()])
        .args(["--http-listen", &free_addr().to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .env_remove("EKAFLEET_TOKEN")
        .env_remove("EKAFLEET_SEAL_PASSPHRASE")
        .env_remove("EKAFLEET_SEAL_PASSPHRASE_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { child, grpc };
    for _ in 0..300 {
        if dir.join("data/ca-cert.pem").exists()
            && tokio::net::TcpStream::connect(grpc).await.is_ok()
        {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start");
}

fn ca_pem(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("data/ca-cert.pem")).unwrap()
}

async fn channel(server: &Server, dir: &Path, identity: Option<Identity>) -> Channel {
    let mut tls = ekafleet::agent::bootstrap::tls_config(&server.grpc.to_string(), &ca_pem(dir));
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    Endpoint::from_shared(format!("https://{}", server.grpc))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

type Ascii = tonic::metadata::MetadataValue<tonic::metadata::Ascii>;

/// Bearer token, and the namespace the request is for (as the CLI's
/// `--namespace` sends it).
#[derive(Clone)]
struct Bearer(Ascii, Option<Ascii>);

impl tonic::service::Interceptor for Bearer {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut().insert("authorization", self.0.clone());
        if let Some(ns) = &self.1 {
            req.metadata_mut()
                .insert("x-ekafleet-namespace", ns.clone());
        }
        Ok(req)
    }
}

type Client = FleetControlClient<tonic::service::interceptor::InterceptedService<Channel, Bearer>>;

async fn client(server: &Server, dir: &Path, token: &str) -> Client {
    namespaced_client(server, dir, token, None).await
}

async fn namespaced_client(
    server: &Server,
    dir: &Path,
    token: &str,
    namespace: Option<&str>,
) -> Client {
    let header = format!("Bearer {token}").parse().unwrap();
    let ns = namespace.map(|ns| ns.parse().unwrap());
    FleetControlClient::with_interceptor(channel(server, dir, None).await, Bearer(header, ns))
}

/// Write a flake whose `fleet` output runs `web` (with `command`) on one
/// machine, `web-1`.
fn write_fleet(flake: &Path, command: &str) {
    write_fleet_services(
        flake,
        serde_json::json!({
            "web": {
                "command": command,
                "resources": { "cpu": { "request": 100 }, "memory": { "request": 64 } },
                "scheduling": {
                    "replicas": 1,
                    "update": { "minHealthyTime": 0, "healthyDeadline": 30 }
                }
            }
        }),
    );
}

/// Write a flake whose `fleet` output runs `services` on `web-1`.
fn write_fleet_services(flake: &Path, services: serde_json::Value) {
    std::fs::create_dir_all(flake).unwrap();
    std::fs::write(
        flake.join("flake.nix"),
        "{ outputs = _: { fleet = builtins.fromJSON (builtins.readFile ./fleet.json); }; }\n",
    )
    .unwrap();
    let fleet = serde_json::json!({
        "name": "apply-test",
        "domain": "apply.test",
        "machines": {
            NODE: { "targetHost": "127.0.0.1", "capacity": { "cpu": 4000, "memory": 4096 } }
        },
        "services": services,
    });
    std::fs::write(flake.join("fleet.json"), fleet.to_string()).unwrap();
}

/// Commit the flake so the server locks it to a git revision.
fn commit(flake: &Path) {
    for args in [
        &["init", "-q"][..],
        &["add", "."],
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "fleet",
        ],
    ] {
        let status = Command::new("git")
            .args(args)
            .current_dir(flake)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }
}

/// A joined agent that reports every service it is told to run as healthy
/// and forwards the `web` command of each `DesiredState` it receives.
struct Agent {
    /// Each `web` spec received, with the `DesiredState`'s cache key.
    commands: mpsc::UnboundedReceiver<(ServiceSpec, String)>,
    /// Fleet key and secret updates, in the order received.
    secrets: mpsc::UnboundedReceiver<ServerPayload>,
}

async fn join_agent(server: &Server, dir: &Path, agent_dir: &Path) -> Identity {
    let token = client(server, dir, ADMIN_TOKEN)
        .await
        .create_join_token(CreateJoinTokenRequest {
            node_name: NODE.into(),
            ttl_secs: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;
    let mut identity = ekafleet::agent::NodeIdentity::new(agent_dir);
    ekafleet::agent::bootstrap::join(
        &server.grpc.to_string(),
        &ca_pem(dir),
        NODE,
        &token,
        &mut identity,
    )
    .await
    .unwrap();
    Identity::from_pem(
        identity.cert_pem.unwrap().as_bytes(),
        identity.key_pem.unwrap().as_bytes(),
    )
}

async fn connect_agent(server: &Server, dir: &Path, identity: Identity) -> Agent {
    let (tx, rx) = mpsc::channel(16);
    tx.send(AgentMessage {
        payload: Some(Payload::Heartbeat(Heartbeat {
            node_id: NODE.into(),
            ..Default::default()
        })),
    })
    .await
    .unwrap();
    let mut inbound = FleetControlClient::new(channel(server, dir, Some(identity)).await)
        .stream_control(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    let (commands_tx, commands) = mpsc::unbounded_channel();
    let (secrets_tx, secrets) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut services: Vec<String> = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                msg = inbound.message() => {
                    let Ok(Some(msg)) = msg else { return };
                    if let Some(p @ (ServerPayload::FleetKey(_) | ServerPayload::Secret(_))) = msg.payload {
                        let _ = secrets_tx.send(p);
                    } else if let Some(ServerPayload::DesiredState(ds)) = msg.payload {
                        services = ds.services.iter().map(|s| s.name.clone()).collect();
                        if let Some(web) = ds.services.iter().find(|s| s.name == "web") {
                            let _ = commands_tx.send((web.clone(), ds.cache_public_key.clone()));
                        }
                    }
                }
                _ = tick.tick() => {
                    let report = AgentMessage {
                        payload: Some(Payload::Health(HealthReport {
                            node_id: NODE.into(),
                            services: services
                                .iter()
                                .map(|name| ServiceHealth {
                                    service_name: name.clone(),
                                    instance_id: format!("{name}-0"),
                                    status: HealthStatus::Healthy as i32,
                                    readiness: HealthStatus::Healthy as i32,
                                    message: String::new(),
                                    checked_at: 0,
                                })
                                .collect(),
                        })),
                    };
                    let running = AgentMessage {
                        payload: Some(Payload::Status(StatusReport {
                            node_id: NODE.into(),
                            running_services: services
                                .iter()
                                .map(|name| ServiceInstance {
                                    service_name: name.clone(),
                                    instance_id: format!("{name}-0"),
                                    store_path: String::new(),
                                    state: ServiceState::ServiceRunning as i32,
                                })
                                .collect(),
                            current_system_path: String::new(),
                        })),
                    };
                    if tx.send(report).await.is_err() || tx.send(running).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Agent { commands, secrets }
}

impl Agent {
    /// The next secret update, with the last fleet key received before it
    /// (if any).
    async fn next_secret(&mut self) -> (ekafleet::proto::SecretUpdate, Option<Vec<u8>>) {
        let mut key = None;
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(30), self.secrets.recv())
                .await
                .expect("no secret update")
                .expect("agent stream closed");
            match msg {
                ServerPayload::FleetKey(k) => key = Some(k.encrypted_key),
                ServerPayload::Secret(update) => return (update, key),
                _ => unreachable!(),
            }
        }
    }

    /// The next secret value (skipping removals of unset secrets), with the
    /// last fleet key received before it.
    async fn next_secret_value(&mut self) -> (ekafleet::proto::SecretUpdate, Option<Vec<u8>>) {
        let mut last_key = None;
        loop {
            let (update, key) = self.next_secret().await;
            last_key = key.or(last_key);
            if !update.deleted {
                return (update, last_key);
            }
        }
    }

    /// The next `web` spec the server assigns whose command equals `want`,
    /// with the binary cache key.
    async fn expect_command(&mut self, want: &str) -> (ServiceSpec, String) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while let Some((spec, key)) = self.commands.recv().await {
                if spec.command == want {
                    return (spec, key);
                }
            }
            panic!("agent stream closed");
        })
        .await
        .unwrap_or_else(|_| panic!("agent never received {want}"))
    }
}

/// Run `Apply` to completion: (final status, final revision, messages).
async fn apply(client: &mut Client, flake: &Path) -> (ApplyStatus, u64, Vec<String>) {
    let mut stream = client
        .apply(ApplyRequest {
            flake_ref: flake.display().to_string(),
            follow: false,
        })
        .await
        .unwrap()
        .into_inner();
    let (mut status, mut revision, mut messages) = (ApplyStatus::ApplyPending, 0, Vec::new());
    while let Some(event) = tokio::time::timeout(Duration::from_secs(120), stream.message())
        .await
        .expect("apply stalled")
        .unwrap()
    {
        status = ApplyStatus::try_from(event.status).unwrap();
        revision = event.revision;
        messages.push(event.message);
    }
    (status, revision, messages)
}

fn nix_available() -> bool {
    let ok = Command::new("nix")
        .args(["flake", "--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping: nix with flakes is not available");
    }
    ok
}

#[tokio::test]
async fn apply_rollback_and_resume_after_a_crash() {
    if !nix_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let flake = dir.path().join("fleet");
    let server = start(dir.path()).await;
    let mut admin = client(&server, dir.path(), ADMIN_TOKEN).await;

    // Nothing applied yet.
    let err = admin
        .rollback(RollbackRequest { to_revision: 0 })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let agent_dir = dir.path().join("agent");
    let identity = join_agent(&server, dir.path(), &agent_dir).await;
    let mut agent = connect_agent(&server, dir.path(), identity.clone()).await;

    // Plan shows the create without recording anything.
    write_fleet(&flake, "/bin/v1");
    commit(&flake);
    let plan = admin
        .plan(PlanRequest {
            flake_ref: flake.display().to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(plan.has_changes);
    assert_eq!(plan.operations[0].service_name, "web");

    let (status, revision, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplySucceeded, "{messages:?}");
    assert_eq!(revision, 1);
    agent.expect_command("/bin/v1").await;

    write_fleet(&flake, "/bin/v2");
    let (status, revision, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplySucceeded, "{messages:?}");
    assert_eq!(revision, 2);
    agent.expect_command("/bin/v2").await;

    // A broken flake fails at evaluation and records nothing.
    std::fs::write(flake.join("fleet.json"), "{ not json").unwrap();
    let (status, _, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplyFailed, "{messages:?}");

    // Rollback re-applies revision 1 as revision 3.
    let rollback = admin
        .rollback(RollbackRequest { to_revision: 0 })
        .await
        .unwrap()
        .into_inner();
    assert!(rollback.success, "{}", rollback.message);
    assert_eq!(rollback.revision, 3);
    agent.expect_command("/bin/v1").await;

    let revisions = admin
        .list_config_revisions(ListConfigRevisionsRequest {})
        .await
        .unwrap()
        .into_inner()
        .revisions;
    let summary: Vec<_> = revisions
        .iter()
        .map(|r| (r.revision, r.rollback_of, r.current))
        .collect();
    assert_eq!(summary, [(1, 0, false), (2, 0, false), (3, 1, true)]);
    // The recorded reference is locked to the commit that was evaluated.
    assert!(
        revisions[0].flake_ref.starts_with("git+file://")
            && revisions[0].flake_ref.contains("rev=")
            && revisions[0].flake_ref.ends_with("#fleet"),
        "{}",
        revisions[0].flake_ref
    );
    assert_eq!(revisions[0].applied_by, revisions[2].applied_by);

    // After a crash the server picks the recorded revision back up and
    // reconciles the agent on its own.
    drop(agent);
    server.crash();
    let server = start(dir.path()).await;
    let mut agent = connect_agent(&server, dir.path(), identity).await;
    agent.expect_command("/bin/v1").await;
    let revisions = client(&server, dir.path(), ADMIN_TOKEN)
        .await
        .list_config_revisions(ListConfigRevisionsRequest {})
        .await
        .unwrap()
        .into_inner()
        .revisions;
    assert_eq!(revisions.len(), 3);
}

#[tokio::test]
async fn viewers_cannot_apply_or_roll_back() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let viewer = client(&server, dir.path(), ADMIN_TOKEN)
        .await
        .create_acl_token(CreateAclTokenRequest {
            role: "viewer".into(),
            description: "read-only".into(),
            namespace: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .token;
    let mut viewer = client(&server, dir.path(), &viewer).await;

    let err = viewer
        .apply(ApplyRequest {
            flake_ref: "/nonexistent".into(),
            follow: false,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let err = viewer
        .rollback(RollbackRequest { to_revision: 1 })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // Reading history is allowed.
    assert!(
        viewer
            .list_config_revisions(ListConfigRevisionsRequest {})
            .await
            .is_ok()
    );
}

/// A flake whose `web` service refers to a derivation and a source file, so
/// the server has a closure to build and serve.
fn write_closure_fleet(flake: &Path, nonce: &str) -> String {
    write_fleet(flake, "placeholder");
    let system = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    std::fs::write(
        flake.join("flake.nix"),
        format!(
            r#"{{ outputs = _: let
  fleet = builtins.fromJSON (builtins.readFile ./fleet.json);
  web = derivation {{ name = "cache-test-web"; system = "{system}"; builder = "/bin/sh"; args = [ "-c" "echo {nonce} > $out" ]; }};
  page = builtins.toFile "page.html" "{nonce}";
in {{ fleet = fleet // {{ services.web = fleet.services.web // {{ command = "${{web}}"; environment.PAGE = "${{page}}"; }}; }}; }}; }}
"#
        ),
    )
    .unwrap();
    commit(flake);
    nonce.to_string()
}

fn narinfo_field<'a>(narinfo: &'a str, field: &str) -> &'a str {
    narinfo
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{field}: ")))
        .unwrap_or_else(|| panic!("narinfo has no {field}:\n{narinfo}"))
}

#[tokio::test]
async fn apply_builds_closures_and_serves_them_to_the_assigned_agent() {
    if !nix_available() {
        return;
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let dir = tempfile::tempdir().unwrap();
    let flake = dir.path().join("fleet");
    let server = start(dir.path()).await;
    let mut admin = client(&server, dir.path(), ADMIN_TOKEN).await;
    let identity = join_agent(&server, dir.path(), &dir.path().join("agent")).await;
    let mut agent = connect_agent(&server, dir.path(), identity.clone()).await;

    let nonce = uuid::Uuid::new_v4().to_string();
    write_closure_fleet(&flake, &nonce);
    let (status, _, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplySucceeded, "{messages:?}");
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("Building 2 store paths")),
        "{messages:?}"
    );

    // The agent is told which store paths `web` needs and how to verify them.
    let (spec, key) = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let (spec, key) = agent.commands.recv().await.expect("agent stream closed");
            if !spec.store_paths.is_empty() {
                return (spec, key);
            }
        }
    })
    .await
    .expect("no store paths assigned");
    assert_eq!(spec.store_paths.len(), 2, "{:?}", spec.store_paths);
    let web = spec
        .store_paths
        .iter()
        .find(|p| p.ends_with("-cache-test-web"))
        .expect("derivation output")
        .clone();
    assert!(spec.store_paths.iter().any(|p| p.ends_with("-page.html")));
    assert_eq!(spec.command, web);
    let (key_name, public) = key.split_once(':').expect("name:key");
    assert!(key_name.starts_with("ekafleet-"), "{key}");

    // The server keeps the built closures rooted.
    let roots: Vec<_> = std::fs::read_dir(dir.path().join("data/gcroots"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(roots.len(), 1, "{roots:?}");
    assert_eq!(std::fs::read_dir(&roots[0]).unwrap().count(), 2);

    // The agent fetches the narinfo and NAR over its mTLS identity.
    let mut as_agent = FleetControlClient::new(channel(&server, dir.path(), Some(identity)).await);
    let hash = web.strip_prefix("/nix/store/").unwrap()[..32].to_string();
    let info = as_agent
        .cache_nar_info(CacheNarInfoRequest {
            hash_part: hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(info.found);
    let narinfo = info.narinfo;
    assert_eq!(narinfo_field(&narinfo, "StorePath"), web);
    assert_eq!(narinfo_field(&narinfo, "URL"), format!("nar/{hash}.nar"));
    let nar_hash = narinfo_field(&narinfo, "NarHash").to_string();
    let nar_size: u64 = narinfo_field(&narinfo, "NarSize").parse().unwrap();
    let refs: Vec<String> = narinfo_field(&narinfo, "References")
        .split_whitespace()
        .map(|r| format!("/nix/store/{r}"))
        .collect();
    let sig = narinfo_field(&narinfo, "Sig")
        .strip_prefix(&format!("{key_name}:"))
        .expect("signed with the advertised key");
    let fingerprint = format!("1;{web};{nar_hash};{nar_size};{}", refs.join(","));
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, b64.decode(public).unwrap())
        .verify(fingerprint.as_bytes(), &b64.decode(sig).unwrap())
        .expect("narinfo signature verifies");

    let mut stream = as_agent
        .cache_nar(CacheNarRequest {
            hash_part: hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut nar = Vec::new();
    while let Some(chunk) = stream.message().await.unwrap() {
        nar.extend(chunk.data);
    }
    assert_eq!(nar.len() as u64, nar_size);
    let digest = ring::digest::digest(&ring::digest::SHA256, &nar);
    assert_eq!(
        format!("sha256:{}", ekafleet::server::cache::nix32(digest.as_ref())),
        nar_hash
    );

    // Paths outside the assigned closures are refused, e.g. the derivation.
    let deriver = narinfo_field(&narinfo, "Deriver");
    let drv_hash = deriver[..32].to_string();
    let info = as_agent
        .cache_nar_info(CacheNarInfoRequest {
            hash_part: drv_hash.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!info.found);
    let err = as_agent
        .cache_nar(CacheNarRequest {
            hash_part: drv_hash,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // Viewers cannot use the cache at all.
    let viewer = admin
        .create_acl_token(CreateAclTokenRequest {
            role: "viewer".into(),
            description: "read-only".into(),
            namespace: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .token;
    let err = client(&server, dir.path(), &viewer)
        .await
        .cache_nar_info(CacheNarInfoRequest { hash_part: hash })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // Rolling back to a configuration without closures keeps the rooted
    // closures of the retained revision.
    write_fleet(&flake, "/bin/plain");
    commit_again(&flake);
    let (status, _, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplySucceeded, "{messages:?}");
    assert_eq!(
        std::fs::read_dir(dir.path().join("data/gcroots"))
            .unwrap()
            .count(),
        1
    );

    // A server whose store lacks a revision's paths (a new leader, or one
    // that collected them) rebuilds them from the locked flake reference:
    // here the paths are deleted and the flake has moved on.
    for root in std::fs::read_dir(dir.path().join("data/gcroots")).unwrap() {
        std::fs::remove_dir_all(root.unwrap().path()).unwrap();
    }
    let deleted = Command::new("nix")
        .args(["store", "delete"])
        .args(&spec.store_paths)
        .output()
        .unwrap();
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(spec.store_paths.iter().all(|p| !Path::new(p).exists()));

    let rollback = admin
        .rollback(RollbackRequest { to_revision: 1 })
        .await
        .unwrap()
        .into_inner();
    assert!(rollback.success, "{}", rollback.message);
    let (rolled_back, _) = agent.expect_command(&web).await;
    assert_eq!(rolled_back.store_paths, spec.store_paths);
    assert!(
        spec.store_paths.iter().all(|p| Path::new(p).exists()),
        "the recorded paths were rebuilt"
    );
    assert_eq!(
        std::fs::read_dir(dir.path().join("data/gcroots"))
            .unwrap()
            .count(),
        1,
        "and rooted again"
    );
}

/// Commit changes to an existing flake repository.
fn commit_again(flake: &Path) {
    for args in [
        &["add", "."][..],
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "update",
        ],
    ] {
        let status = Command::new("git")
            .args(args)
            .current_dir(flake)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }
}

#[tokio::test]
async fn namespace_tokens_reach_only_their_own_services() {
    if !nix_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let flake = dir.path().join("fleet");
    let server = start(dir.path()).await;
    let mut admin = client(&server, dir.path(), ADMIN_TOKEN).await;
    let identity = join_agent(&server, dir.path(), &dir.path().join("agent")).await;
    let mut agent = connect_agent(&server, dir.path(), identity).await;

    let service = |command: &str, namespace: &str| {
        serde_json::json!({
            "command": command,
            "namespace": namespace,
            "resources": { "cpu": { "request": 100 }, "memory": { "request": 64 } },
            "scheduling": {
                "replicas": 1,
                "update": { "minHealthyTime": 0, "healthyDeadline": 30 }
            }
        })
    };
    write_fleet_services(
        &flake,
        serde_json::json!({
            "web": service("/bin/web", "team-a"),
            "db": service("/bin/db", "team-b"),
        }),
    );
    commit(&flake);
    let (status, _, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplySucceeded, "{messages:?}");
    agent.expect_command("/bin/web").await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = admin.status(StatusRequest {}).await.unwrap().into_inner();
            if status.services.len() == 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("both services reported");

    let token = admin
        .create_acl_token(CreateAclTokenRequest {
            role: "operator".into(),
            description: "team a".into(),
            namespace: "team-a".into(),
        })
        .await
        .unwrap()
        .into_inner()
        .token;
    let denied = |r: Result<_, tonic::Status>| match r {
        Err(e) => assert_eq!(e.code(), tonic::Code::PermissionDenied, "{e}"),
        Ok(_) => panic!("namespace token was allowed"),
    };

    // The token only works for requests made in its namespace.
    let mut elsewhere = namespaced_client(&server, dir.path(), &token, Some("team-b")).await;
    denied(elsewhere.status(StatusRequest {}).await.map(drop));
    let mut team = namespaced_client(&server, dir.path(), &token, Some("team-a")).await;

    // Its own services, without the nodes they run on.
    let status = team.status(StatusRequest {}).await.unwrap().into_inner();
    let names: Vec<_> = status.services.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["web"]);
    assert!(status.nodes.is_empty() && status.pools.is_empty());
    let deployments = team
        .list_deployments(ListDeploymentsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .deployments;
    assert!(deployments.iter().all(|d| d.service_name == "web"));
    let events = team
        .events(EventsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .events;
    assert!(events.iter().all(|e| e.service == "web"), "{events:?}");

    // Service operations reach its services only.
    let scaled = team
        .scale(ScaleRequest {
            service_name: "web".into(),
            desired_count: 1,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(scaled.success);
    for name in ["db", "no-such-service"] {
        denied(
            team.scale(ScaleRequest {
                service_name: name.into(),
                desired_count: 3,
            })
            .await
            .map(drop),
        );
        denied(
            team.logs(LogsRequest {
                service_name: name.into(),
                ..Default::default()
            })
            .await
            .map(drop),
        );
    }

    // Fleet-wide operations are refused regardless of role.
    denied(team.list_nodes(ListNodesRequest {}).await.map(drop));
    denied(team.snapshot(SnapshotRequest {}).await.map(drop));
    denied(
        team.drain(DrainRequest {
            machine: NODE.into(),
            deadline_seconds: 0,
        })
        .await
        .map(drop),
    );
    denied(
        team.list_config_revisions(ListConfigRevisionsRequest {})
            .await
            .map(drop),
    );
    denied(
        team.plan(PlanRequest {
            flake_ref: flake.display().to_string(),
        })
        .await
        .map(drop),
    );
    denied(
        team.apply(ApplyRequest {
            flake_ref: flake.display().to_string(),
            follow: false,
        })
        .await
        .map(drop),
    );
    denied(
        team.create_join_token(CreateJoinTokenRequest {
            node_name: "rogue".into(),
            ttl_secs: 0,
        })
        .await
        .map(drop),
    );
}

#[tokio::test]
async fn static_secrets_are_set_scoped_and_pushed_to_the_assigned_agent() {
    use ekafleet::proto::{DeleteSecretRequest, ListSecretsRequest, SetSecretRequest};
    if !nix_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let flake = dir.path().join("fleet");
    let server = start(dir.path()).await;
    let mut admin = client(&server, dir.path(), ADMIN_TOKEN).await;
    let identity = join_agent(&server, dir.path(), &dir.path().join("agent")).await;
    let mut agent = connect_agent(&server, dir.path(), identity).await;

    let service = |command: &str, namespace: &str, secret: &str| {
        serde_json::json!({
            "command": command,
            "namespace": namespace,
            "secrets": { secret: {} },
            "resources": { "cpu": { "request": 100 }, "memory": { "request": 64 } },
            "scheduling": {
                "replicas": 1,
                "update": { "minHealthyTime": 0, "healthyDeadline": 30 }
            }
        })
    };
    write_fleet_services(
        &flake,
        serde_json::json!({
            "web": service("/bin/web", "team-a", "api-key"),
            "db": service("/bin/db", "team-b", "password"),
        }),
    );
    commit(&flake);

    // Plan and apply warn about declared secrets without a value.
    let plan = admin
        .plan(PlanRequest {
            flake_ref: flake.display().to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(plan.warnings.len(), 2, "{:?}", plan.warnings);
    assert!(plan.warnings[1].contains("service 'web' declares secret 'api-key'"));
    let (status, _, messages) = apply(&mut admin, &flake).await;
    assert_eq!(status, ApplyStatus::ApplySucceeded, "{messages:?}");
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("Warning: service 'db'")),
        "{messages:?}"
    );
    let (spec, _) = agent.expect_command("/bin/web").await;
    assert_eq!(spec.secrets, ["api-key"]);

    let token = |role: &str, namespace: &str| {
        let mut admin = admin.clone();
        let (role, namespace) = (role.to_string(), namespace.to_string());
        async move {
            admin
                .create_acl_token(CreateAclTokenRequest {
                    role,
                    description: String::new(),
                    namespace,
                })
                .await
                .unwrap()
                .into_inner()
                .token
        }
    };
    let set = |service: &str, value: &[u8]| SetSecretRequest {
        service_name: service.into(),
        secret_name: if service == "web" {
            "api-key"
        } else {
            "password"
        }
        .into(),
        value: value.to_vec(),
    };
    let denied = |r: Result<_, tonic::Status>| match r {
        Err(e) => assert_eq!(e.code(), tonic::Code::PermissionDenied, "{e}"),
        Ok(_) => panic!("request was allowed"),
    };

    // Viewers cannot set secrets; namespace tokens only for their services.
    let mut viewer = client(&server, dir.path(), &token("viewer", "").await).await;
    denied(viewer.set_secret(set("web", b"x")).await.map(drop));
    let mut team = namespaced_client(
        &server,
        dir.path(),
        &token("operator", "team-a").await,
        Some("team-a"),
    )
    .await;
    denied(team.set_secret(set("db", b"x")).await.map(drop));
    let invalid = team
        .set_secret(SetSecretRequest {
            secret_name: "../escape".into(),
            ..set("web", b"x")
        })
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
    let version = team
        .set_secret(set("web", b"s3cret"))
        .await
        .unwrap()
        .into_inner()
        .version;
    assert_eq!(version, 1);

    // The agent gets its derived key, then the value sealed for it alone.
    let (update, key) = agent.next_secret_value().await;
    let key = key.expect("the fleet key comes before any secret");
    assert_eq!(
        (update.service_name.as_str(), update.secret_name.as_str()),
        ("web", "api-key")
    );
    let secrets_dir = dir.path().join("agent-secrets");
    let mut injector = ekafleet::secrets::injector::SecretInjector::new(&secrets_dir);
    injector.update_key(&key.as_slice().try_into().unwrap());
    assert!(
        injector
            .inject("web", "api-key", &update.encrypted_value)
            .await
            .unwrap()
    );
    assert_eq!(
        std::fs::read(secrets_dir.join("web/api-key")).unwrap(),
        b"s3cret"
    );

    // Listing shows names and versions, scoped like everything else.
    let listed = team
        .list_secrets(ListSecretsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .secrets;
    let listed: Vec<_> = listed
        .iter()
        .map(|s| {
            (
                s.service_name.as_str(),
                s.secret_name.as_str(),
                s.version,
                s.declared,
            )
        })
        .collect();
    assert_eq!(listed, [("web", "api-key", 1, true)]);
    denied(
        team.list_secrets(ListSecretsRequest {
            service_name: "db".into(),
        })
        .await
        .map(drop),
    );

    // Values survive a server restart.
    server.crash();
    let server = start(dir.path()).await;
    let mut admin = client(&server, dir.path(), ADMIN_TOKEN).await;
    let listed = admin
        .list_secrets(ListSecretsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .secrets;
    let listed: Vec<_> = listed
        .iter()
        .map(|s| (s.service_name.as_str(), s.version))
        .collect();
    assert_eq!(listed, [("db", 0), ("web", 1)]);

    // Deleting tells the (reconnected) agent to remove the file.
    let identity = join_agent(&server, dir.path(), &dir.path().join("agent2")).await;
    let mut agent = connect_agent(&server, dir.path(), identity).await;
    agent.expect_command("/bin/web").await;
    let (update, key) = agent.next_secret_value().await;
    assert!(key.is_some());
    assert_eq!((update.version, update.deleted), (1, false));
    assert!(
        admin
            .delete_secret(DeleteSecretRequest {
                service_name: "web".into(),
                secret_name: "api-key".into(),
            })
            .await
            .unwrap()
            .into_inner()
            .deleted
    );
    loop {
        let (update, _) = agent.next_secret().await;
        if update.service_name == "web" {
            assert!(update.deleted);
            break;
        }
    }
}
