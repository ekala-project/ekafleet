use super::*;
use crate::ca::CaSigner;
use crate::ca::signer::DirectCaSigner;
use crate::proto::{PortSpec, ServiceSpec};

struct Cluster {
    domain: String,
    ca: Arc<dyn CaSigner>,
    root_pem: String,
    identity: ServerIdentity,
    _dir: tempfile::TempDir,
}

async fn cluster(domain: &str) -> Cluster {
    let dir = tempfile::tempdir().unwrap();
    let root = crate::ca::persist::open_ca(dir.path(), domain)
        .await
        .unwrap();
    let root_pem = root.root_certificate_pem().await.unwrap();
    let jwt = crate::ca::persist::open_jwt_signer(dir.path())
        .await
        .unwrap();
    let ca: Arc<dyn CaSigner> = Arc::new(DirectCaSigner::new(root, jwt));
    let identity = ServerIdentity::issue(ca.as_ref(), "s1").await.unwrap();
    Cluster {
        domain: domain.into(),
        ca,
        root_pem,
        identity,
        _dir: dir,
    }
}

fn peer_of(cluster: &Cluster, endpoint: &str) -> FederationPeer {
    FederationPeer {
        endpoint: endpoint.into(),
        trust_domain: cluster.domain.clone(),
        ca_cert: cluster.root_pem.clone(),
    }
}

fn federation(peers: &[(&str, FederationPeer)]) -> FederationConfig {
    FederationConfig {
        export_services: Vec::new(),
        peers: peers
            .iter()
            .map(|(name, peer)| (name.to_string(), peer.clone()))
            .collect(),
    }
}

/// Start `cluster`'s federation listener, trusting `peers`, exporting
/// `web`. Returns its endpoint.
async fn listen(cluster: &Cluster, peers: &[(&str, FederationPeer)]) -> String {
    let raft = FleetStateMachine::new();
    let config = serde_json::json!({
        "name": "t",
        "domain": cluster.domain,
        "services": {"web": {"command": "/bin/web"}},
        "federation": {"exportServices": ["web"]},
    });
    raft.apply_config(crate::raft::state::Command::ApplyConfig {
        flake_ref: ".".into(),
        config_json: config.to_string(),
        applied_at: 1,
        applied_by: "test".into(),
        rollback_of: None,
        closures: Default::default(),
        images: Default::default(),
    })
    .await
    .unwrap();
    let trusted = TrustedPeers::default();
    trusted.set(&federation(peers));
    let exporter = Exporter {
        domain: cluster.domain.clone(),
        bundle_pem: cluster.root_pem.clone(),
        jwks: r#"{"keys":[]}"#.into(),
        state: FleetState::new(),
        mesh: MeshRegistry::new(raft.clone(), &cluster.domain),
        raft_state: raft,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    tokio::spawn(serve(
        listener,
        cluster.identity.clone(),
        trusted,
        exporter,
        CancellationToken::new(),
    ));
    endpoint
}

#[test]
fn spiffe_ids_split_into_domain_and_path() {
    assert_eq!(
        split_spiffe_id("spiffe://a.test/server/s1"),
        Some(("a.test", "/server/s1"))
    );
    assert_eq!(split_spiffe_id("spiffe://a.test"), None);
    assert_eq!(split_spiffe_id("spiffe:///server/x"), None);
    assert_eq!(split_spiffe_id("https://a.test/server/x"), None);
}

#[tokio::test]
async fn peers_exchange_documents_over_mutual_tls() {
    let a = cluster("a.test").await;
    let b = cluster("b.test").await;
    // b trusts a; a fetches b.
    let endpoint = listen(&b, &[("a", peer_of(&a, "unused:1"))]).await;
    let document = fetch(&peer_of(&b, &endpoint), &a.identity).await.unwrap();
    assert_eq!(document.trust_domain, "b.test");
    assert_eq!(document.x509_bundle, b.root_pem);
    assert_eq!(document.jwt_bundle, r#"{"keys":[]}"#);
    assert_eq!(
        document.services,
        vec![ExportedService {
            name: "web".into(),
            addresses: vec![],
            ports: vec![],
        }]
    );
}

#[tokio::test]
async fn a_server_not_configured_as_a_peer_is_refused() {
    let a = cluster("a.test").await;
    let b = cluster("b.test").await;
    let c = cluster("c.test").await;
    let endpoint = listen(&b, &[("a", peer_of(&a, "unused:1"))]).await;
    let err = fetch(&peer_of(&b, &endpoint), &c.identity)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FederationError::Tls(_) | FederationError::Http(_)),
        "{err}"
    );
}

#[tokio::test]
async fn an_impostor_ca_cannot_pose_as_a_peer() {
    let a = cluster("a.test").await;
    let b = cluster("b.test").await;
    // Same trust domain as a, different CA.
    let impostor = cluster("a.test").await;
    let endpoint = listen(&b, &[("a", peer_of(&a, "unused:1"))]).await;
    assert!(
        fetch(&peer_of(&b, &endpoint), &impostor.identity)
            .await
            .is_err()
    );
    // And a's real identity still works.
    assert!(fetch(&peer_of(&b, &endpoint), &a.identity).await.is_ok());
}

#[tokio::test]
async fn the_peer_server_must_chain_to_its_configured_ca() {
    let a = cluster("a.test").await;
    let b = cluster("b.test").await;
    let other = cluster("b.test").await;
    let endpoint = listen(&b, &[("a", peer_of(&a, "unused:1"))]).await;
    // a expects b's server to chain to another CA of the same domain.
    let wrong_ca = FederationPeer {
        ca_cert: other.root_pem.clone(),
        ..peer_of(&b, &endpoint)
    };
    let err = fetch(&wrong_ca, &a.identity).await.unwrap_err();
    assert!(matches!(err, FederationError::Tls(_)), "{err}");
    // Or a different trust domain.
    let wrong_domain = FederationPeer {
        trust_domain: "x.test".into(),
        ..peer_of(&b, &endpoint)
    };
    assert!(fetch(&wrong_domain, &a.identity).await.is_err());
}

#[tokio::test]
async fn non_server_svids_are_not_peers() {
    let a = cluster("a.test").await;
    let trusted = TrustedPeers::default();
    trusted.set(&federation(&[("a", peer_of(&a, "unused:1"))]));
    let server = a.identity.certified_key().cert[0].clone();
    assert_eq!(trusted.peer_name(&server).as_deref(), Some("a"));
    assert!(is_server_of(&server, "a.test"));
    assert!(!is_server_of(&server, "b.test"));

    let csr = crate::ca::csr::generate_node_csr(Some("a.test"), "n1").unwrap();
    let (agent_pem, _, _) =
        a.ca.sign_csr(
            &csr.csr_der,
            &crate::ca::SvidSubject::Agent("n1".into()),
            None,
        )
        .await
        .unwrap();
    let agent = crate::ca::pki::pem_certs(&mut agent_pem.as_slice())
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(trusted.peer_name(&agent), None);
    assert!(!is_server_of(&agent, "a.test"));
}

#[test]
fn documents_are_checked_against_the_peer() {
    let peer = FederationPeer {
        endpoint: "b:7404".into(),
        trust_domain: "b.test".into(),
        ca_cert: String::new(),
    };
    let pem = rcgen::generate_simple_self_signed(vec!["x".into()])
        .unwrap()
        .cert
        .pem();
    let ok = Document {
        trust_domain: "b.test".into(),
        x509_bundle: pem,
        jwt_bundle: r#"{"keys":[]}"#.into(),
        services: vec![ExportedService {
            name: "web".into(),
            addresses: vec![Ipv4Addr::new(203, 0, 113, 5)],
            ports: vec![ExportedPort {
                name: "http".into(),
                port: 8080,
            }],
        }],
    };
    assert_eq!(validate_document(&ok, &peer), Ok(()));

    let bad = |f: &dyn Fn(&mut Document)| {
        let mut d = ok.clone();
        f(&mut d);
        validate_document(&d, &peer).unwrap_err()
    };
    assert!(bad(&|d| d.trust_domain = "a.test".into()).contains("trust domain"));
    assert!(bad(&|d| d.x509_bundle = "junk".into()).contains("x509Bundle"));
    assert!(bad(&|d| d.jwt_bundle = "{}".into()).contains("JWKS"));
    assert!(bad(&|d| d.services[0].name = "Web.x".into()).contains("DNS label"));
    assert!(bad(&|d| d.services.push(d.services[0].clone())).contains("twice"));
    assert!(bad(&|d| d.services[0].ports[0].port = 0).contains("port 0"));
}

fn spec(name: &str, namespace: &str, port: u32) -> ServiceSpec {
    ServiceSpec {
        name: name.into(),
        namespace: namespace.into(),
        ports: vec![PortSpec {
            name: "http".into(),
            port,
            protocol: "tcp".into(),
            hostname: String::new(),
        }],
        ..Default::default()
    }
}

#[test]
fn only_exported_serving_replicas_are_published() {
    // c is not serving; d is namespaced; b has no underlay address.
    let inputs = DnsInputs {
        assignments: BTreeMap::from([
            (
                "a".into(),
                vec![spec("web", "", 8080), spec("db", "", 5432)],
            ),
            ("b".into(), vec![spec("web", "default", 8080)]),
            ("c".into(), vec![spec("web", "", 8080)]),
            ("d".into(), vec![spec("web", "shop", 8080)]),
        ]),
        serving: [("a", "web"), ("a", "db"), ("b", "web"), ("d", "web")]
            .into_iter()
            .map(|(n, s)| (n.to_string(), s.to_string()))
            .collect(),
        ..Default::default()
    };
    let underlay = BTreeMap::from([
        ("a".into(), Ipv4Addr::new(203, 0, 113, 1)),
        ("c".into(), Ipv4Addr::new(203, 0, 113, 3)),
        ("d".into(), Ipv4Addr::new(203, 0, 113, 4)),
    ]);
    let services = exported_services(&["web".into()], &inputs, &underlay);
    assert_eq!(
        services,
        vec![ExportedService {
            name: "web".into(),
            addresses: vec![Ipv4Addr::new(203, 0, 113, 1)],
            ports: vec![ExportedPort {
                name: "http".into(),
                port: 8080
            }],
        }]
    );
}

#[tokio::test]
async fn stale_peers_keep_bundles_but_lose_services() {
    let view = FederationView::new();
    let document = Document {
        trust_domain: "b.test".into(),
        x509_bundle: "PEM".into(),
        jwt_bundle: String::new(),
        services: vec![ExportedService {
            name: "web".into(),
            addresses: vec![Ipv4Addr::new(203, 0, 113, 1)],
            ports: vec![],
        }],
    };
    view.update(
        "b",
        PeerView {
            document,
            synced_at: 1000,
        },
    )
    .await;
    assert_eq!(view.services(1000 + SERVICES_STALE_AFTER).await.len(), 1);
    assert!(view.services(1001 + SERVICES_STALE_AFTER).await.is_empty());
    assert_eq!(view.bundles().await[0].trust_domain, "b.test");
    view.retain(&BTreeSet::new()).await;
    assert!(view.bundles().await.is_empty());
}
