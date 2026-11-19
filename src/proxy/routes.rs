//! The ingress routes file, the hand-off between agent and proxy.
//!
//! The agent writes the routes the server assigned this node (from the
//! fleet configuration's `ingress`) to [`ROUTES_FILE`]; the unprivileged
//! proxy polls it and swaps its routing table and upstream pools when it
//! changes. Routes carry no secrets, so the file is world-readable.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::ingress::{Ingress, pool_name};
use super::router::PortRoute;

/// Where the agent writes, and the proxy reads, the ingress routes.
pub const ROUTES_FILE: &str = "/run/ekafleet/ingress-routes.json";

/// How often the proxy checks the routes file.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum RoutesError {
    #[error("routes file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("routes file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RoutesFile {
    pub routes: Vec<Route>,
    /// PEM of the fleet root CA, for routes with allowed callers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_ca: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Route {
    pub name: String,
    /// Host header to match, or `*`.
    pub host: String,
    pub path_prefix: String,
    pub backends: Vec<SocketAddr>,
    /// Other services taking a share of the traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split: Vec<SplitBackends>,
    /// Forward TCP connections on this port instead of routing HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_ip_affinity: bool,
    /// Served over HTTPS with the certificate in the TLS directory (see
    /// [`super::tls`]); the value is a digest of it, so the file changes
    /// when the certificate does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// SPIFFE IDs a client certificate must carry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_callers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SplitBackends {
    pub service: String,
    /// Percent of the route's traffic.
    pub weight: u32,
    pub backends: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RateLimit {
    pub requests_per_second: f64,
    pub burst: u32,
}

impl Route {
    /// Whether `other` has the same options (all but backends and TLS).
    pub fn same_options(&self, other: &Route) -> bool {
        let shares = |r: &Route| -> Vec<(String, u32)> {
            r.split
                .iter()
                .map(|s| (s.service.clone(), s.weight))
                .collect()
        };
        shares(self) == shares(other)
            && self.tcp_port == other.tcp_port
            && self.rate_limit == other.rate_limit
            && self.client_ip_affinity == other.client_ip_affinity
            && self.allowed_callers == other.allowed_callers
            && self.tls.is_some() == other.tls.is_some()
    }
}

/// `ip:port` strings → addresses, dropping (and logging) others.
fn parse_backends(route: &str, backends: &[String]) -> Vec<SocketAddr> {
    backends
        .iter()
        .filter_map(|b| match b.parse() {
            Ok(addr) => Some(addr),
            Err(_) => {
                tracing::warn!(route = %route, backend = %b, "Ignoring invalid ingress backend");
                None
            }
        })
        .collect()
}

impl RoutesFile {
    /// From the server's update. Backends that are not `ip:port` are
    /// dropped. TLS routes are served over HTTPS only when `tls` (route →
    /// certificate digest) has their certificate.
    pub fn from_update(
        update: &crate::proto::IngressUpdate,
        tls: &HashMap<String, String>,
    ) -> Self {
        let mut routes: Vec<Route> = update
            .routes
            .iter()
            .map(|r| Route {
                name: r.name.clone(),
                host: r.host.clone(),
                path_prefix: r.path_prefix.clone(),
                backends: parse_backends(&r.name, &r.backends),
                split: r
                    .split
                    .iter()
                    .map(|s| SplitBackends {
                        service: s.service.clone(),
                        weight: s.weight,
                        backends: parse_backends(&r.name, &s.backends),
                    })
                    .collect(),
                tcp_port: u16::try_from(r.tcp_port).ok().filter(|p| *p != 0),
                rate_limit: r.rate_limit.as_ref().map(|l| RateLimit {
                    requests_per_second: l.requests_per_second,
                    burst: l.burst,
                }),
                client_ip_affinity: r.client_ip_affinity,
                tls: tls.get(&r.name).cloned(),
                allowed_callers: r.allowed_callers.clone(),
            })
            .collect();
        routes.sort_by(|a, b| a.name.cmp(&b.name));
        let client_ca = if routes.iter().any(|r| !r.allowed_callers.is_empty()) {
            update.client_ca.clone()
        } else {
            String::new()
        };
        Self { routes, client_ca }
    }

    /// Write to `path` unless it already holds exactly these routes.
    /// Returns whether the file changed.
    pub async fn write(&self, path: &Path) -> Result<bool, RoutesError> {
        let mut json = serde_json::to_vec_pretty(self).map_err(|source| RoutesError::Parse {
            path: path.into(),
            source,
        })?;
        json.push(b'\n');
        if tokio::fs::read(path)
            .await
            .is_ok_and(|current| current == json)
        {
            return Ok(false);
        }
        let io = |source| RoutesError::Io {
            path: path.into(),
            source,
        };
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await.map_err(io)?;
        }
        crate::fsutil::write_atomic(path, &json, 0o644)
            .await
            .map_err(io)?;
        Ok(true)
    }

    /// Read `path`; a missing file means no routes.
    pub async fn read(path: &Path) -> Result<Self, RoutesError> {
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| RoutesError::Parse {
                path: path.into(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(RoutesError::Io {
                path: path.into(),
                source,
            }),
        }
    }

    /// Make `ingress` serve exactly these routes, replacing `previous`.
    pub async fn apply(&self, previous: Option<&RoutesFile>, ingress: &Ingress) {
        let table: HashMap<String, Vec<PortRoute>> = self
            .routes
            .iter()
            .filter(|r| r.tcp_port.is_none())
            .map(|r| {
                (
                    r.name.clone(),
                    vec![PortRoute {
                        hostname: r.host.clone(),
                        path_prefix: r.path_prefix.clone(),
                        port: 0,
                        weight: 100,
                    }],
                )
            })
            .collect();
        let mut pools = HashMap::new();
        for r in &self.routes {
            pools.insert(pool_name(&r.name, None), r.backends.clone());
            for s in &r.split {
                pools.insert(pool_name(&r.name, Some(&s.service)), s.backends.clone());
            }
        }
        // Pools and options first, so no route resolves to a missing pool.
        ingress.upstream.replace_all(pools).await;
        ingress
            .routes
            .replace(&self.routes, previous.map_or(&[][..], |p| &p.routes))
            .await;
        ingress.router.update_routes(&table).await;
        if let Some(tls) = &ingress.tls {
            tls.load(self).await;
        }
    }
}

/// Apply `path` to `ingress` now and whenever it changes, until
/// `shutdown`. An unreadable or invalid file keeps the last routes.
pub fn watch(
    path: PathBuf,
    ingress: Ingress,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current: Option<RoutesFile> = None;
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        let mut ticks: u64 = 0;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            match RoutesFile::read(&path).await {
                Ok(routes) if current.as_ref() != Some(&routes) => {
                    routes.apply(current.as_ref(), &ingress).await;
                    tracing::info!(routes = routes.routes.len(), "Ingress routes loaded");
                    current = Some(routes);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Keeping previous ingress routes"),
            }
            // Retried every tick: a port may have been busy.
            if let (Some(tcp), Some(routes)) = (&ingress.tcp, &current) {
                tcp.sync(routes, &ingress).await;
            }
            ticks += 1;
            if ticks.is_multiple_of(30) {
                ingress.routes.prune().await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{IngressRoute, IngressUpdate};
    use crate::proxy::l4::TcpRoutes;
    use crate::proxy::listener::ProxyListener;
    use crate::proxy::mtls::SpiffeAuthorizer;
    use crate::proxy::tls::{CertDir, IngressTls};

    fn update(backends: &[&str]) -> IngressUpdate {
        IngressUpdate {
            routes: vec![IngressRoute {
                name: "site".into(),
                host: "www.example.com".into(),
                path_prefix: "/".into(),
                backends: backends.iter().map(|b| b.to_string()).collect(),
                tcp_port: 0,
                ..Default::default()
            }],
            client_ca: "CA".into(),
        }
    }

    #[tokio::test]
    async fn written_only_when_changed_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/ingress-routes.json");
        assert_eq!(
            RoutesFile::read(&path).await.unwrap(),
            RoutesFile::default()
        );

        let routes =
            RoutesFile::from_update(&update(&["10.100.0.2:8080", "bogus"]), &HashMap::new());
        assert_eq!(routes.routes[0].backends.len(), 1);
        assert_eq!(routes.routes[0].tcp_port, None);
        // No route needs the client CA.
        assert!(routes.client_ca.is_empty());
        assert!(routes.write(&path).await.unwrap());
        assert!(!routes.write(&path).await.unwrap());
        assert_eq!(RoutesFile::read(&path).await.unwrap(), routes);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);

        // A TLS route is marked only once its certificate is installed.
        let mut tls_update = update(&[]);
        tls_update.routes[0].tls_cert_secret = "crt".into();
        tls_update.routes[0].allowed_callers = vec!["spiffe://t/service/web".into()];
        let pending = RoutesFile::from_update(&tls_update, &HashMap::new());
        assert_eq!(pending.routes[0].tls, None);
        assert_eq!(pending.client_ca, "CA");
        let ready = RoutesFile::from_update(
            &tls_update,
            &HashMap::from([("site".to_string(), "d1".to_string())]),
        );
        assert_eq!(ready.routes[0].tls.as_deref(), Some("d1"));

        tokio::fs::write(&path, "{").await.unwrap();
        assert!(matches!(
            RoutesFile::read(&path).await,
            Err(RoutesError::Parse { .. })
        ));
    }

    /// A backend that answers with its name and the Host it saw.
    async fn backend(name: &'static str) -> SocketAddr {
        let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| async move {
            let host = headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();
            format!("{name} {host}")
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        addr
    }

    fn http_route(name: &str, host: &str, prefix: &str, backends: Vec<SocketAddr>) -> Route {
        Route {
            name: name.into(),
            host: host.into(),
            path_prefix: prefix.into(),
            backends,
            ..Default::default()
        }
    }

    /// Wait until `check` holds, polling while the watcher catches up.
    async fn eventually<F, Fut>(mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for _ in 0..100 {
            if check().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("condition never held");
    }

    #[tokio::test]
    async fn the_proxy_serves_the_routes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingress-routes.json");
        let site = backend("site").await;
        let api = backend("api").await;
        let canary = backend("canary").await;
        let mut limited = http_route("limited", "limited.test", "/", vec![site]);
        limited.rate_limit = Some(RateLimit {
            requests_per_second: 0.001,
            burst: 2,
        });
        let mut split = http_route("split", "split.test", "/", vec![site]);
        split.split = vec![SplitBackends {
            service: "canary".into(),
            weight: 50,
            backends: vec![canary],
        }];
        RoutesFile {
            routes: vec![
                http_route("site", "www.example.com", "/", vec![site]),
                http_route("api", "www.example.com", "/api", vec![api]),
                limited,
                split,
            ],
            client_ca: String::new(),
        }
        .write(&path)
        .await
        .unwrap();

        let ingress = Ingress::default();
        let shutdown = CancellationToken::new();
        watch(path.clone(), ingress.clone(), shutdown.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let authorizer = SpiffeAuthorizer::new("fleet.test");
        tokio::spawn(ProxyListener::for_ingress(&ingress, authorizer).serve(listener));

        let client = reqwest::Client::new();
        let get = |host: &'static str, path: &'static str| {
            let client = client.clone();
            async move {
                let resp = client
                    .get(format!("http://{proxy}{path}"))
                    .header("host", host)
                    .send()
                    .await
                    .unwrap();
                (resp.status().as_u16(), resp.text().await.unwrap())
            }
        };
        // The watcher applies the file on its first tick.
        eventually(|| async { get("www.example.com:80", "/").await.0 == 200 }).await;
        assert_eq!(
            get("www.example.com:80", "/").await,
            (200, "site www.example.com:80".into())
        );
        assert_eq!(
            get("www.example.com", "/api/x").await,
            (200, "api www.example.com".into())
        );
        assert_eq!(get("other.test", "/").await.0, 404);

        // Two requests, then the client is over its limit.
        assert_eq!(get("limited.test", "/").await.0, 200);
        assert_eq!(get("limited.test", "/").await.0, 200);
        assert_eq!(get("limited.test", "/").await.0, 429);

        // Half the traffic goes to the canary.
        let mut canaries = 0;
        for _ in 0..40 {
            if get("split.test", "/").await.1.starts_with("canary") {
                canaries += 1;
            }
        }
        assert!((8..=32).contains(&canaries), "{canaries} of 40");

        // Removing the routes stops serving them.
        RoutesFile::default().write(&path).await.unwrap();
        eventually(|| async { get("www.example.com", "/").await.0 == 404 }).await;
        shutdown.cancel();
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn tcp_routes_forward_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingress-routes.json");
        // An echo server.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = conn.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let port = free_port();
        let route = Route {
            tcp_port: Some(port),
            ..http_route("db", "*", "/", vec![echo_addr])
        };
        RoutesFile {
            routes: vec![route],
            client_ca: String::new(),
        }
        .write(&path)
        .await
        .unwrap();
        let tcp = TcpRoutes::new("127.0.0.1".parse().unwrap());
        let ingress = Ingress {
            tcp: Some(tcp.clone()),
            ..Default::default()
        };
        let shutdown = CancellationToken::new();
        watch(path.clone(), ingress, shutdown.clone());
        eventually(|| async { tcp.listening().await.contains_key(&port) }).await;

        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Dropping the route closes its port.
        RoutesFile::default().write(&path).await.unwrap();
        eventually(|| async { tcp.listening().await.is_empty() }).await;
        eventually(|| async {
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        })
        .await;
        shutdown.cancel();
    }

    #[tokio::test]
    async fn tls_routes_are_served_by_sni_and_check_callers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingress-routes.json");
        let tls_dir = dir.path().join("tls");
        let site = backend("site").await;

        // The route's certificate, from a public CA.
        let public_key = rcgen::KeyPair::generate().unwrap();
        let public_ca = {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.self_signed(&public_key).unwrap()
        };
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["secure.test".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &public_ca, &public_key)
            .unwrap();
        let certs = CertDir::new(&tls_dir, None);
        let mut digest = String::new();
        for route in ["open", "guarded"] {
            digest = certs
                .write(
                    route,
                    leaf.pem().as_bytes(),
                    zeroize::Zeroizing::new(leaf_key.serialize_pem().into_bytes()),
                )
                .await
                .unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tls_dir.join("open.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // A key that does not match is refused.
        let other_key = rcgen::KeyPair::generate().unwrap();
        assert!(
            certs
                .write(
                    "bad",
                    leaf.pem().as_bytes(),
                    zeroize::Zeroizing::new(other_key.serialize_pem().into_bytes()),
                )
                .await
                .is_err()
        );

        // Fleet SVIDs of an allowed and another service.
        let fleet_ca = crate::ca::root::RootCa::new("fleet.test");
        fleet_ca.initialize(None, None).await.unwrap();
        let svid = |service: &'static str| {
            let fleet_ca = &fleet_ca;
            async move {
                let (leaf, chain, _) = fleet_ca
                    .issue_certificate(service, &[], None)
                    .await
                    .unwrap();
                let mut pem = leaf;
                pem.push(b'\n');
                pem.extend_from_slice(&chain);
                reqwest::Identity::from_pem(&pem).unwrap()
            }
        };
        let web = svid("web").await;
        let api = svid("api").await;

        let open = Route {
            tls: Some(digest.clone()),
            ..http_route("open", "secure.test", "/", vec![site])
        };
        let guarded = Route {
            tls: Some(digest),
            allowed_callers: vec!["spiffe://fleet.test/service/web".into()],
            ..http_route("guarded", "secure.test", "/internal", vec![site])
        };
        RoutesFile {
            routes: vec![open, guarded],
            client_ca: fleet_ca.root_certificate_pem().await.unwrap(),
        }
        .write(&path)
        .await
        .unwrap();

        let tls = IngressTls::new(&tls_dir);
        let ingress = Ingress {
            tls: Some(tls.clone()),
            ..Default::default()
        };
        let shutdown = CancellationToken::new();
        watch(path.clone(), ingress.clone(), shutdown.clone());
        let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain.local_addr().unwrap();
        let secure = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secure_addr = secure.local_addr().unwrap();
        let proxy = ProxyListener::for_ingress(&ingress, SpiffeAuthorizer::new("fleet.test"))
            .with_https_port(secure_addr.port());
        tokio::spawn(proxy.clone().serve(plain));
        tokio::spawn(proxy.serve_tls(secure, tls));

        let client = |identity: Option<reqwest::Identity>| {
            let mut builder = reqwest::Client::builder()
                .use_rustls_tls()
                .add_root_certificate(
                    reqwest::Certificate::from_pem(public_ca.pem().as_bytes()).unwrap(),
                )
                .resolve("secure.test", secure_addr)
                .redirect(reqwest::redirect::Policy::none());
            if let Some(identity) = identity {
                builder = builder.identity(identity);
            }
            builder.build().unwrap()
        };
        let anonymous = client(None);
        let url = |path: &str| format!("https://secure.test:{}{path}", secure_addr.port());
        let status = |client: reqwest::Client, url: String| async move {
            client.get(url).send().await.map(|r| r.status().as_u16())
        };

        // Served over HTTPS with the route's certificate (verified by SNI
        // name against the public CA).
        eventually(|| async { status(anonymous.clone(), url("/")).await.ok() == Some(200) }).await;
        // Only the allowed caller reaches the guarded path.
        assert_eq!(
            status(anonymous.clone(), url("/internal")).await.unwrap(),
            403
        );
        assert_eq!(
            status(client(Some(api)), url("/internal")).await.unwrap(),
            403
        );
        assert_eq!(
            status(client(Some(web)), url("/internal")).await.unwrap(),
            200
        );

        // Plain HTTP is redirected to HTTPS.
        let resp = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(format!("http://{plain_addr}/a?b=c"))
            .header("host", "secure.test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 308);
        assert_eq!(
            resp.headers()["location"],
            format!("https://secure.test:{}/a?b=c", secure_addr.port()).as_str()
        );
        shutdown.cancel();
    }
}
