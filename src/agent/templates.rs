//! Config templates: rendered by the agent, visible only to their service.
//!
//! Each template is rendered to `<base>/<service>/<hash of destPath>` on the
//! agent's tmpfs runtime directory and bind-mounted read-only at `destPath`
//! inside the service's unit (see the supervisor). The host's own files are
//! never written, and rendered secrets never reach a persistent disk.
//!
//! Templates are re-rendered whenever their inputs may change: a new desired
//! state, a DNS snapshot (service addresses), or a secret update. A service
//! whose rendered files changed is sent the templates' `changeSignal`, or
//! restarted when a changed template has none.
//!
//! Files are rewritten in place (never renamed over), so an existing bind
//! mount sees the new content.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use tokio::sync::Mutex;

use super::template::{TemplateContext, render};
use crate::dns::resolver::DnsResolver;
use crate::proto::{ServiceSpec, TemplateSpec};

/// Where rendered templates live on agents.
pub const TEMPLATES_DIR: &str = "/run/ekafleet/templates";

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("invalid template destination '{0}': {1}")]
    InvalidDest(String, &'static str),
    #[error("invalid signal '{0}'")]
    InvalidSignal(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Reject destinations that are not plain absolute paths, or that would
/// need escaping in a unit file (`:` separates bind source and target, `%`
/// starts a specifier).
pub fn validate_dest(dest: &str) -> Result<(), TemplateError> {
    let invalid = |why| Err(TemplateError::InvalidDest(dest.to_string(), why));
    let path = Path::new(dest);
    if !path.is_absolute() {
        return invalid("must be absolute");
    }
    // `Path::components` hides `.` and repeated separators: check the
    // segments themselves.
    if dest[1..]
        .split('/')
        .any(|segment| matches!(segment, "" | "." | ".."))
    {
        return invalid("must be a normalized file path");
    }
    if dest
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | '%' | '\\' | '"' | '\''))
    {
        return invalid("contains a character not allowed in unit files");
    }
    Ok(())
}

/// A signal name as accepted by `systemctl kill --signal`.
pub fn validate_signal(signal: &str) -> Result<(), TemplateError> {
    let name = signal.strip_prefix("SIG").unwrap_or(signal);
    if !name.is_empty()
        && name.len() <= 12
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '+')
    {
        Ok(())
    } else {
        Err(TemplateError::InvalidSignal(signal.to_string()))
    }
}

/// Where the rendered file for `dest` of `service` lives under `base`.
pub fn rendered_path(base: &Path, service: &str, dest: &str) -> PathBuf {
    let digest = ring::digest::digest(&ring::digest::SHA256, dest.as_bytes());
    let name: String = digest.as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    base.join(service).join(name)
}

/// What a service needs after its rendered files changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateChange {
    /// Send these signals (every changed template declares one).
    Signal(BTreeSet<String>),
    /// A changed template declares no signal.
    Restart,
}

#[derive(Debug, Clone)]
struct ServiceTemplates {
    namespace: String,
    environment: HashMap<String, String>,
    templates: Vec<TemplateSpec>,
}

pub struct TemplateManager {
    base: PathBuf,
    secrets_dir: PathBuf,
    node_name: String,
    services: Mutex<HashMap<String, ServiceTemplates>>,
}

impl TemplateManager {
    /// `secrets_dir` holds the agent's decrypted secrets, one directory per
    /// service (see `SecretInjector`).
    pub fn new(base: PathBuf, secrets_dir: PathBuf, node_name: &str) -> Self {
        Self {
            base,
            secrets_dir,
            node_name: node_name.to_string(),
            services: Mutex::default(),
        }
    }

    /// Track the templates of this node's services (the full desired set),
    /// dropping the rendered files of services that are gone.
    pub async fn set_services<'a>(&self, specs: impl IntoIterator<Item = &'a ServiceSpec>) {
        let mut services = self.services.lock().await;
        let next: HashMap<String, ServiceTemplates> = specs
            .into_iter()
            .filter(|spec| !spec.templates.is_empty())
            .filter(|spec| crate::ca::validate_identity_name(&spec.name).is_ok())
            .map(|spec| {
                let templates = spec
                    .templates
                    .iter()
                    .filter(|t| {
                        let valid = validate_dest(&t.dest_path).and_then(|()| {
                            if t.change_signal.is_empty() {
                                Ok(())
                            } else {
                                validate_signal(&t.change_signal)
                            }
                        });
                        if let Err(e) = &valid {
                            tracing::warn!(service = %spec.name, error = %e, "Skipping template");
                        }
                        valid.is_ok()
                    })
                    .cloned()
                    .collect();
                (
                    spec.name.clone(),
                    ServiceTemplates {
                        namespace: spec.namespace.clone(),
                        environment: spec.environment.clone(),
                        templates,
                    },
                )
            })
            .collect();
        for (name, old) in services.iter() {
            let keep: Vec<PathBuf> = next
                .get(name)
                .map(|s| {
                    s.templates
                        .iter()
                        .map(|t| rendered_path(&self.base, name, &t.dest_path))
                        .collect()
                })
                .unwrap_or_default();
            for t in &old.templates {
                let path = rendered_path(&self.base, name, &t.dest_path);
                if !keep.contains(&path) {
                    let _ = tokio::fs::remove_file(&path).await;
                }
            }
            if !next.contains_key(name) {
                let _ = tokio::fs::remove_dir(self.base.join(name)).await;
            }
        }
        *services = next;
    }

    /// Render every tracked template; returns the services whose files
    /// changed and what they need.
    pub async fn render_all(&self, resolver: &DnsResolver) -> HashMap<String, TemplateChange> {
        let names: Vec<String> = self.services.lock().await.keys().cloned().collect();
        let mut changes = HashMap::new();
        for name in names {
            if let Some(change) = self.render_service(&name, resolver).await {
                changes.insert(name, change);
            }
        }
        changes
    }

    /// Render the templates of `service`, if it has any.
    pub async fn render_service(
        &self,
        service: &str,
        resolver: &DnsResolver,
    ) -> Option<TemplateChange> {
        let entry = self.services.lock().await.get(service).cloned()?;
        let ctx = self.context(service, &entry, resolver).await;
        let mut restart = false;
        let mut signals = BTreeSet::new();
        for template in &entry.templates {
            let path = rendered_path(&self.base, service, &template.dest_path);
            let mode = if template.mode == 0 {
                0o644
            } else {
                template.mode & 0o777
            };
            match write_rendered(&path, &render(&template.source, &ctx), mode).await {
                Ok(false) => {}
                Ok(true) => {
                    tracing::info!(service, dest = %template.dest_path, "Template rendered");
                    if template.change_signal.is_empty() {
                        restart = true;
                    } else {
                        signals.insert(template.change_signal.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(service, dest = %template.dest_path, error = %e, "Cannot write template");
                }
            }
        }
        if restart {
            Some(TemplateChange::Restart)
        } else if !signals.is_empty() {
            Some(TemplateChange::Signal(signals))
        } else {
            None
        }
    }

    async fn context(
        &self,
        service: &str,
        entry: &ServiceTemplates,
        resolver: &DnsResolver,
    ) -> TemplateContext {
        let namespace = (!crate::agent::netns::is_default_namespace(&entry.namespace))
            .then_some(entry.namespace.as_str());
        let mut secrets = HashMap::new();
        if let Ok(mut dir) = tokio::fs::read_dir(self.secrets_dir.join(service)).await {
            while let Ok(Some(file)) = dir.next_entry().await {
                if let (Some(name), Ok(value)) = (
                    file.file_name().to_str().map(str::to_string),
                    tokio::fs::read_to_string(file.path()).await,
                ) {
                    secrets.insert(name, value);
                }
            }
        }
        let meta = HashMap::from([
            ("node".to_string(), self.node_name.clone()),
            ("service".to_string(), service.to_string()),
            (
                "namespace".to_string(),
                namespace.unwrap_or("default").to_string(),
            ),
            ("domain".to_string(), resolver.domain().await),
        ]);
        TemplateContext {
            services: resolver.service_addresses(namespace).await,
            secrets,
            meta,
            env: entry.environment.clone(),
        }
    }
}

/// Write `content` to `path` in place unless it is already there. Returns
/// whether the file changed.
async fn write_rendered(path: &Path, content: &str, mode: u32) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(existing) = tokio::fs::read(path).await
        && existing == content.as_bytes()
    {
        let current = tokio::fs::metadata(path).await?.permissions().mode() & 0o777;
        if current != mode {
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
        }
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(mode);
    let mut file = options.open(path).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, content.as_bytes()).await?;
    file.sync_all().await?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    Ok(true)
}

/// Tell `service` its templates changed: signal it, or restart it if it is
/// running.
pub async fn notify(service: &str, change: &TemplateChange) {
    let unit = format!("ekafleet-{service}.service");
    let commands: Vec<Vec<String>> = match change {
        TemplateChange::Restart => vec![vec!["try-restart".into(), unit.clone()]],
        TemplateChange::Signal(signals) => signals
            .iter()
            .map(|s| vec!["kill".into(), "--signal".into(), s.clone(), unit.clone()])
            .collect(),
    };
    for args in commands {
        match tokio::process::Command::new("systemctl")
            .args(&args)
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                tracing::info!(service, action = %args.join(" "), "Service notified of template change");
            }
            Ok(out) => tracing::warn!(
                service,
                action = %args.join(" "),
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "Cannot notify service of template change"
            ),
            Err(e) => tracing::warn!(service, error = %e, "Cannot run systemctl"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{DnsRecord, DnsRecordType};
    use std::os::unix::fs::PermissionsExt;

    fn spec(name: &str, namespace: &str, templates: Vec<TemplateSpec>) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            namespace: namespace.into(),
            environment: HashMap::from([("MODE".to_string(), "prod".to_string())]),
            templates,
            ..Default::default()
        }
    }

    fn template(dest: &str, source: &str, signal: &str) -> TemplateSpec {
        TemplateSpec {
            dest_path: dest.into(),
            source: source.into(),
            mode: 0o640,
            change_signal: signal.into(),
        }
    }

    fn record(name: &str, kind: DnsRecordType, values: &[&str], ns: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type: kind as i32,
            values: values.iter().map(|v| v.to_string()).collect(),
            ttl: 10,
            namespace: ns.into(),
        }
    }

    #[test]
    fn destinations_must_be_plain_absolute_files() {
        for ok in ["/etc/web.conf", "/run/app/config.toml", "/srv/a-b_c.d/x"] {
            assert!(validate_dest(ok).is_ok(), "{ok}");
        }
        for bad in [
            "etc/web.conf",
            "/",
            "/etc/",
            "/etc/../shadow",
            "/etc/./x",
            "/a b",
            "/a:b",
            "/a%n",
            "/a\nExecStart=/bin/sh",
        ] {
            assert!(validate_dest(bad).is_err(), "{bad:?}");
        }
        assert!(validate_signal("SIGHUP").is_ok());
        assert!(validate_signal("USR1").is_ok());
        assert!(validate_signal("SIGRTMIN+3").is_ok());
        assert!(validate_signal("HUP; reboot").is_err());
        assert!(validate_signal("").is_err());
    }

    #[tokio::test]
    async fn renders_discovery_secrets_and_meta_and_reports_changes() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("templates");
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(secrets.join("api")).unwrap();
        std::fs::write(secrets.join("api/db-password"), "hunter2").unwrap();

        let resolver = DnsResolver::new("fleet.test", vec![]);
        resolver
            .replace(&[
                record("a.node", DnsRecordType::A, &["10.100.0.1"], ""),
                record("b.node", DnsRecordType::A, &["10.100.0.2"], ""),
                record(
                    "db.service",
                    DnsRecordType::A,
                    &["10.100.0.1", "10.100.0.2"],
                    "",
                ),
                record(
                    "db.service",
                    DnsRecordType::Srv,
                    &["5432 a.node", "5432 b.node"],
                    "",
                ),
            ])
            .await;

        let manager = TemplateManager::new(base.clone(), secrets.clone(), "a");
        manager
            .set_services(&[
                spec(
                    "api",
                    "",
                    vec![
                        template(
                            "/etc/api/db.conf",
                            "host={{ service \"db\" }} all={{ services \"db\" }} pw={{ secret \"db-password\" }}",
                            "",
                        ),
                        template(
                            "/etc/api/meta",
                            "{{ meta.node }}/{{ meta.service }}/{{ meta.namespace }}/{{ meta.domain }}/{{ env.MODE }}",
                            "SIGHUP",
                        ),
                    ],
                ),
                spec("plain", "", vec![]),
            ])
            .await;

        let changes = manager.render_all(&resolver).await;
        assert_eq!(
            changes,
            HashMap::from([("api".to_string(), TemplateChange::Restart)])
        );
        let conf = rendered_path(&base, "api", "/etc/api/db.conf");
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "host=10.100.0.1:5432 all=10.100.0.1:5432,10.100.0.2:5432 pw=hunter2"
        );
        assert_eq!(
            std::fs::metadata(&conf).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::read_to_string(rendered_path(&base, "api", "/etc/api/meta")).unwrap(),
            "a/api/default/fleet.test/prod"
        );

        // Nothing changed: nothing to do.
        assert!(manager.render_all(&resolver).await.is_empty());

        // A replica moves: only the discovery template changes, and it has no
        // signal, so the service restarts.
        resolver
            .replace(&[
                record("a.node", DnsRecordType::A, &["10.100.0.1"], ""),
                record("db.service", DnsRecordType::Srv, &["5432 a.node"], ""),
            ])
            .await;
        let inode = std::fs::metadata(&conf).unwrap();
        assert_eq!(
            manager.render_all(&resolver).await.get("api"),
            Some(&TemplateChange::Restart)
        );
        // Rewritten in place, so a bind mount of the file sees the update.
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&conf).unwrap().ino(), inode.ino());

        // A service that is gone loses its files.
        manager.set_services(&[]).await;
        assert!(!conf.exists());
        assert!(!base.join("api").exists());
    }

    #[tokio::test]
    async fn signalled_templates_signal_and_namespaces_see_their_own_services() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("templates");
        let resolver = DnsResolver::new("fleet.test", vec![]);
        resolver
            .replace(&[
                record("db.service", DnsRecordType::A, &["10.200.1.2"], "acme"),
                record(
                    "db.service",
                    DnsRecordType::Srv,
                    &["5432 db.service"],
                    "acme",
                ),
            ])
            .await;
        let manager = TemplateManager::new(base.clone(), dir.path().join("secrets"), "a");
        let specs = |source: &str| {
            vec![
                spec(
                    "api",
                    "acme",
                    vec![template("/etc/api.conf", source, "SIGUSR1")],
                ),
                spec(
                    "other",
                    "",
                    vec![template("/etc/other.conf", "db={{ service \"db\" }}", "")],
                ),
            ]
        };
        manager
            .set_services(&specs("db={{ service \"db\" }}"))
            .await;
        let changes = manager.render_all(&resolver).await;
        assert_eq!(
            changes.get("api"),
            Some(&TemplateChange::Signal(BTreeSet::from([
                "SIGUSR1".to_string()
            ])))
        );
        assert_eq!(
            std::fs::read_to_string(rendered_path(&base, "api", "/etc/api.conf")).unwrap(),
            "db=10.200.1.2:5432"
        );
        // Outside the namespace, its services do not exist.
        assert_eq!(
            std::fs::read_to_string(rendered_path(&base, "other", "/etc/other.conf")).unwrap(),
            "db="
        );

        // A changed template source re-renders on the next desired state.
        manager
            .set_services(&specs("db=[{{ service \"db\" }}]"))
            .await;
        assert!(manager.render_all(&resolver).await.contains_key("api"));
    }

    #[tokio::test]
    async fn invalid_templates_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("templates");
        let manager = TemplateManager::new(base.clone(), dir.path().join("secrets"), "a");
        manager
            .set_services(&[
                spec(
                    "api",
                    "",
                    vec![
                        template("/etc/../etc/shadow", "x", ""),
                        template("/etc/ok", "x", "HUP;x"),
                    ],
                ),
                spec("../evil", "", vec![template("/etc/x", "x", "")]),
            ])
            .await;
        assert!(
            manager
                .render_all(&DnsResolver::new("fleet.test", vec![]))
                .await
                .is_empty()
        );
        assert!(!base.exists());
    }
}
