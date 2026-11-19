//! Fleet state durability against the real `ekafleet server` binary:
//! acknowledged writes survive a crash (SIGKILL) and a fleet-key rotation,
//! unreadable state stops the server instead of starting it empty, and the
//! REST API enforces write permissions.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ekafleet::proto::fleet_control_client::FleetControlClient;
use ekafleet::proto::{CreateAclTokenRequest, RotateFleetKeyRequest};

const ADMIN_TOKEN: &str = "state-admin-token";

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Server {
    child: Child,
    grpc: SocketAddr,
    http: SocketAddr,
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.http)
    }

    /// Simulate a crash: no graceful shutdown, no final snapshot.
    fn crash(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn server_command(dir: &Path, grpc: SocketAddr, http: SocketAddr) -> Command {
    let token_file = dir.join("admin-token");
    std::fs::write(&token_file, ADMIN_TOKEN).unwrap();
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("ekafleet"));
    cmd.args(["server", "--data-dir"])
        .arg(dir.join("data"))
        .args(["--listen", &grpc.to_string()])
        .args(["--http-listen", &http.to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .env_remove("EKAFLEET_TOKEN")
        .env_remove("EKAFLEET_SEAL_PASSPHRASE")
        .env_remove("EKAFLEET_SEAL_PASSPHRASE_FILE")
        .stdin(Stdio::null());
    cmd
}

async fn start(dir: &Path) -> Server {
    let (grpc, http) = (free_addr(), free_addr());
    let child = server_command(dir, grpc, http)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { child, grpc, http };
    let client = reqwest::Client::new();
    for _ in 0..300 {
        if let Ok(resp) = client.get(server.url("/health")).send().await
            && resp.status().is_success()
            && tokio::net::TcpStream::connect(grpc).await.is_ok()
        {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start");
}

async fn kv_put(server: &Server, token: &str, key: &str, value: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .put(server.url(&format!("/v1/kv/{key}")))
        .bearer_auth(token)
        .body(value.to_string())
        .send()
        .await
        .unwrap()
        .status()
}

async fn kv_get(server: &Server, key: &str) -> Option<String> {
    let resp = reqwest::Client::new()
        .get(server.url(&format!("/v1/kv/{key}")))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    body[0]["Value"].as_str().map(str::to_string)
}

async fn admin(
    server: &Server,
    dir: &Path,
) -> FleetControlClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        impl tonic::service::Interceptor + use<>,
    >,
> {
    let ca_pem = std::fs::read_to_string(dir.join("data/ca-cert.pem")).unwrap();
    let channel = tonic::transport::Endpoint::from_shared(format!("https://{}", server.grpc))
        .unwrap()
        .tls_config(ekafleet::agent::bootstrap::tls_config(
            &server.grpc.to_string(),
            &ca_pem,
        ))
        .unwrap()
        .connect()
        .await
        .unwrap();
    #[allow(clippy::result_large_err)]
    FleetControlClient::with_interceptor(channel, |mut req: tonic::Request<()>| {
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {ADMIN_TOKEN}").parse().unwrap(),
        );
        Ok(req)
    })
}

#[tokio::test]
async fn kv_writes_survive_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    assert!(
        kv_put(&server, ADMIN_TOKEN, "app/config", "v1")
            .await
            .is_success()
    );
    assert!(
        kv_put(&server, ADMIN_TOKEN, "app/other", "v2")
            .await
            .is_success()
    );
    server.crash();

    let server = start(dir.path()).await;
    assert_eq!(kv_get(&server, "app/config").await.as_deref(), Some("v1"));

    // Only user keys are listed, never internal state.
    let body = reqwest::Client::new()
        .get(server.url("/v1/kv?prefix=app/"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let keys: Vec<String> = serde_json::from_str(&body).unwrap();
    assert_eq!(keys, ["app/config", "app/other"]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for key in ["fleet-key", "raft-key"] {
            let mode = std::fs::metadata(dir.path().join("data").join(key))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{key}");
        }
    }
}

#[tokio::test]
async fn state_survives_fleet_key_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    assert!(
        kv_put(&server, ADMIN_TOKEN, "k", "before")
            .await
            .is_success()
    );
    let rotated = admin(&server, dir.path())
        .await
        .rotate_fleet_key(RotateFleetKeyRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(rotated.success);
    server.crash();

    let server = start(dir.path()).await;
    assert_eq!(kv_get(&server, "k").await.as_deref(), Some("before"));
}

#[tokio::test]
async fn viewers_cannot_write() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let viewer = admin(&server, dir.path())
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

    assert_eq!(
        kv_put(&server, &viewer, "k", "v").await,
        reqwest::StatusCode::FORBIDDEN
    );
    let status = reqwest::Client::new()
        .post(server.url("/v1/alerts/silences"))
        .bearer_auth(&viewer)
        .header("content-type", "application/json")
        .body(r#"{"matchers": {}, "duration_secs": 60}"#)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    // Viewers still read.
    let status = reqwest::Client::new()
        .get(server.url("/v1/kv?prefix="))
        .bearer_auth(&viewer)
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success());
    assert_eq!(kv_get(&server, "k").await, None);
}

#[tokio::test]
async fn unreadable_state_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    assert!(kv_put(&server, ADMIN_TOKEN, "k", "v").await.is_success());
    server.crash();

    // The last consensus log entry: the write just acknowledged.
    let log_dir = dir.path().join("data/raft/entries");
    let entry = std::fs::read_dir(&log_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "entry"))
        .max()
        .expect("a log entry");
    let mut bytes = std::fs::read(&entry).unwrap();
    *bytes.last_mut().unwrap() ^= 0xff;
    std::fs::write(&entry, bytes).unwrap();

    let output = server_command(dir.path(), free_addr(), free_addr())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Refusing to start"), "{stderr}");
}
