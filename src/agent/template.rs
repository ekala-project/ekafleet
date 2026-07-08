#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

/// Template rendering context containing fleet metadata, service discovery
/// data, and secrets available for interpolation.
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    /// Service discovery: service_name → list of addresses (ip:port).
    pub services: HashMap<String, Vec<String>>,
    /// Secrets: secret_name → secret_value.
    pub secrets: HashMap<String, String>,
    /// Fleet metadata.
    pub meta: HashMap<String, String>,
    /// Environment variables.
    pub env: HashMap<String, String>,
}

/// Render a template string by substituting `{{ key }}` placeholders.
///
/// Supported template syntax:
/// - `{{ meta.fleet_name }}` — fleet metadata
/// - `{{ env.MY_VAR }}` — environment variable
/// - `{{ service "my-service" }}` — first address of a service
/// - `{{ services "my-service" }}` — comma-separated list of all addresses
/// - `{{ secret "my-secret" }}` — secret value
/// - `{{ key }}` — looks up in meta, then env
pub fn render(template: &str, ctx: &TemplateContext) -> String {
    let mut result = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find("{{") {
        result.push_str(&remaining[..start]);
        let after_open = &remaining[start + 2..];

        if let Some(end) = after_open.find("}}") {
            let expr = after_open[..end].trim();
            let value = evaluate_expr(expr, ctx);
            result.push_str(&value);
            remaining = &after_open[end + 2..];
        } else {
            // No closing }}, output literally
            result.push_str("{{");
            remaining = after_open;
        }
    }
    result.push_str(remaining);
    result
}

fn evaluate_expr(expr: &str, ctx: &TemplateContext) -> String {
    // service "name" — first address
    if let Some(name) = strip_func(expr, "service") {
        return ctx
            .services
            .get(name)
            .and_then(|addrs| addrs.first())
            .cloned()
            .unwrap_or_default();
    }

    // services "name" — comma-separated list
    if let Some(name) = strip_func(expr, "services") {
        return ctx
            .services
            .get(name)
            .map(|addrs| addrs.join(","))
            .unwrap_or_default();
    }

    // secret "name"
    if let Some(name) = strip_func(expr, "secret") {
        return ctx.secrets.get(name).cloned().unwrap_or_default();
    }

    // meta.key
    if let Some(key) = expr.strip_prefix("meta.") {
        return ctx.meta.get(key).cloned().unwrap_or_default();
    }

    // env.KEY
    if let Some(key) = expr.strip_prefix("env.") {
        return ctx.env.get(key).cloned().unwrap_or_default();
    }

    // Bare key: look up in meta, then env
    ctx.meta
        .get(expr)
        .or_else(|| ctx.env.get(expr))
        .cloned()
        .unwrap_or_default()
}

/// Extract the argument from a function-style expression like `service "my-svc"`.
fn strip_func<'a>(expr: &'a str, func_name: &str) -> Option<&'a str> {
    let rest = expr.strip_prefix(func_name)?.trim_start();
    // Remove surrounding quotes
    let rest = rest.trim_matches('"').trim_matches('\'');
    if rest.is_empty() { None } else { Some(rest) }
}

/// Render a template and write it to the destination path.
pub async fn render_to_file(
    template: &str,
    ctx: &TemplateContext,
    dest_path: &Path,
    perms: u32,
) -> Result<bool, std::io::Error> {
    let rendered = render(template, ctx);

    // Check if the file already has the same content (avoid unnecessary writes)
    if let Ok(existing) = tokio::fs::read_to_string(dest_path).await {
        if existing == rendered {
            return Ok(false); // no change
        }
    }

    // Create parent directories if needed
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(dest_path, &rendered).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(perms);
        tokio::fs::set_permissions(dest_path, permissions).await?;
    }

    tracing::info!(
        dest = %dest_path.display(),
        size = rendered.len(),
        "Template rendered"
    );

    Ok(true) // changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_meta() {
        let mut ctx = TemplateContext::default();
        ctx.meta.insert("fleet_name".into(), "production".into());
        ctx.meta.insert("domain".into(), "fleet.internal".into());

        let tpl = "cluster={{ meta.fleet_name }} domain={{ meta.domain }}";
        assert_eq!(
            render(tpl, &ctx),
            "cluster=production domain=fleet.internal"
        );
    }

    #[test]
    fn render_env() {
        let mut ctx = TemplateContext::default();
        ctx.env.insert("PORT".into(), "8080".into());

        assert_eq!(render("port={{ env.PORT }}", &ctx), "port=8080");
    }

    #[test]
    fn render_service() {
        let mut ctx = TemplateContext::default();
        ctx.services.insert(
            "postgres".into(),
            vec!["10.100.1.1:5432".into(), "10.100.2.1:5432".into()],
        );

        assert_eq!(
            render("db={{ service \"postgres\" }}", &ctx),
            "db=10.100.1.1:5432"
        );
        assert_eq!(
            render("dbs={{ services \"postgres\" }}", &ctx),
            "dbs=10.100.1.1:5432,10.100.2.1:5432"
        );
    }

    #[test]
    fn render_secret() {
        let mut ctx = TemplateContext::default();
        ctx.secrets.insert("db_password".into(), "s3cret".into());

        assert_eq!(
            render("password={{ secret \"db_password\" }}", &ctx),
            "password=s3cret"
        );
    }

    #[test]
    fn render_missing_key() {
        let ctx = TemplateContext::default();
        assert_eq!(render("val={{ missing }}", &ctx), "val=");
    }

    #[test]
    fn render_no_templates() {
        let ctx = TemplateContext::default();
        assert_eq!(render("plain text", &ctx), "plain text");
    }

    #[test]
    fn render_unclosed_brace() {
        let ctx = TemplateContext::default();
        assert_eq!(render("val={{ open", &ctx), "val={{ open");
    }
}
