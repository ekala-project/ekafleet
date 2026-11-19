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

use super::router::{PortRoute, ProxyRouter};
use super::upstream::UpstreamPool;

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesFile {
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Route {
    pub name: String,
    /// Host header to match, or `*`.
    pub host: String,
    pub path_prefix: String,
    pub backends: Vec<SocketAddr>,
}

impl RoutesFile {
    /// From the server's update. Backends that are not `ip:port` are
    /// dropped.
    pub fn from_update(update: &crate::proto::IngressUpdate) -> Self {
        let mut routes: Vec<Route> = update
            .routes
            .iter()
            .map(|r| Route {
                name: r.name.clone(),
                host: r.host.clone(),
                path_prefix: r.path_prefix.clone(),
                backends: r
                    .backends
                    .iter()
                    .filter_map(|b| match b.parse() {
                        Ok(addr) => Some(addr),
                        Err(_) => {
                            tracing::warn!(route = %r.name, backend = %b, "Ignoring invalid ingress backend");
                            None
                        }
                    })
                    .collect(),
            })
            .collect();
        routes.sort_by(|a, b| a.name.cmp(&b.name));
        Self { routes }
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

    /// Make `router` and `upstream` serve exactly these routes. Each route
    /// has its own upstream pool, named after it.
    pub async fn apply(&self, router: &ProxyRouter, upstream: &UpstreamPool) {
        let table: HashMap<String, Vec<PortRoute>> = self
            .routes
            .iter()
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
        let pools = self
            .routes
            .iter()
            .map(|r| (r.name.clone(), r.backends.clone()))
            .collect();
        // Pools first, so no route resolves to a missing pool.
        upstream.replace_all(pools).await;
        router.update_routes(&table).await;
    }
}

/// Apply `path` to `router` and `upstream` now and whenever it changes,
/// until `shutdown`. An unreadable or invalid file keeps the last routes.
pub fn watch(
    path: PathBuf,
    router: ProxyRouter,
    upstream: UpstreamPool,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current: Option<RoutesFile> = None;
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            match RoutesFile::read(&path).await {
                Ok(routes) if current.as_ref() != Some(&routes) => {
                    routes.apply(&router, &upstream).await;
                    tracing::info!(routes = routes.routes.len(), "Ingress routes loaded");
                    current = Some(routes);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Keeping previous ingress routes"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{IngressRoute, IngressUpdate};

    fn update(backends: &[&str]) -> IngressUpdate {
        IngressUpdate {
            routes: vec![IngressRoute {
                name: "site".into(),
                host: "www.example.com".into(),
                path_prefix: "/".into(),
                backends: backends.iter().map(|b| b.to_string()).collect(),
            }],
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

        let routes = RoutesFile::from_update(&update(&["10.100.0.2:8080", "bogus"]));
        assert_eq!(routes.routes[0].backends.len(), 1);
        assert!(routes.write(&path).await.unwrap());
        assert!(!routes.write(&path).await.unwrap());
        assert_eq!(RoutesFile::read(&path).await.unwrap(), routes);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);

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

    #[tokio::test]
    async fn the_proxy_serves_the_routes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingress-routes.json");
        let site = backend("site").await;
        let api = backend("api").await;
        RoutesFile {
            routes: vec![
                Route {
                    name: "site".into(),
                    host: "www.example.com".into(),
                    path_prefix: "/".into(),
                    backends: vec![site],
                },
                Route {
                    name: "api".into(),
                    host: "www.example.com".into(),
                    path_prefix: "/api".into(),
                    backends: vec![api],
                },
            ],
        }
        .write(&path)
        .await
        .unwrap();

        let router = ProxyRouter::new();
        let upstream = UpstreamPool::new();
        let shutdown = CancellationToken::new();
        watch(
            path.clone(),
            router.clone(),
            upstream.clone(),
            shutdown.clone(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let authorizer = crate::proxy::mtls::SpiffeAuthorizer::new("fleet.test");
        tokio::spawn(
            crate::proxy::listener::ProxyListener::new(router, upstream, authorizer)
                .serve(listener),
        );

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
        let mut first = (0, String::new());
        for _ in 0..50 {
            first = get("www.example.com:80", "/").await;
            if first.0 == 200 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(first, (200, "site www.example.com:80".into()));
        assert_eq!(
            get("www.example.com", "/api/x").await,
            (200, "api www.example.com".into())
        );
        assert_eq!(get("other.test", "/").await.0, 404);

        // Removing the routes stops serving them.
        RoutesFile::default().write(&path).await.unwrap();
        let mut status = 200;
        for _ in 0..80 {
            status = get("www.example.com", "/").await.0;
            if status == 404 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(status, 404);
        shutdown.cancel();
    }
}
