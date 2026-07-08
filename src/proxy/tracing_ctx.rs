#![allow(dead_code)]

/// Trace context propagation through the reverse proxy.
/// Supports W3C Trace Context (traceparent/tracestate headers)
/// for integration with OpenTelemetry and Jaeger.

/// W3C Trace Context header names.
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const TRACESTATE_HEADER: &str = "tracestate";

/// Parsed W3C traceparent header.
#[derive(Debug, Clone)]
pub struct TraceContext {
    pub version: u8,
    pub trace_id: String,
    pub parent_id: String,
    pub flags: u8,
}

impl TraceContext {
    /// Parse a W3C traceparent header value.
    /// Format: `{version}-{trace-id}-{parent-id}-{flags}`
    pub fn parse(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = u8::from_str_radix(parts[0], 16).ok()?;
        if parts[1].len() != 32 || parts[2].len() != 16 {
            return None;
        }
        let flags = u8::from_str_radix(parts[3], 16).ok()?;

        Some(Self {
            version,
            trace_id: parts[1].to_string(),
            parent_id: parts[2].to_string(),
            flags,
        })
    }

    /// Generate a new span ID and create a child traceparent.
    pub fn child_traceparent(&self) -> String {
        let new_span_id = generate_span_id();
        format!(
            "{:02x}-{}-{}-{:02x}",
            self.version, self.trace_id, new_span_id, self.flags
        )
    }

    /// Format as a traceparent header value.
    pub fn to_header(&self) -> String {
        format!(
            "{:02x}-{}-{}-{:02x}",
            self.version, self.trace_id, self.parent_id, self.flags
        )
    }
}

/// Generate a random 16-character hex span ID.
fn generate_span_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes).expect("RNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract trace context from request headers, propagate through proxy,
/// and inject into the upstream request.
pub fn propagate_trace_context(incoming_headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut outgoing = Vec::new();

    for (name, value) in incoming_headers {
        let lower = name.to_lowercase();
        if lower == TRACEPARENT_HEADER {
            // Parse and create child span
            if let Some(ctx) = TraceContext::parse(value) {
                outgoing.push((TRACEPARENT_HEADER.to_string(), ctx.child_traceparent()));
            } else {
                outgoing.push((name.clone(), value.clone()));
            }
        } else if lower == TRACESTATE_HEADER {
            // Pass through tracestate as-is
            outgoing.push((name.clone(), value.clone()));
        }
    }

    // If no incoming trace context, generate a new one
    if !incoming_headers
        .iter()
        .any(|(n, _)| n.to_lowercase() == TRACEPARENT_HEADER)
    {
        let trace_id: String = {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut bytes = [0u8; 16];
            rng.fill(&mut bytes).expect("RNG failure");
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        };
        let span_id = generate_span_id();
        outgoing.push((
            TRACEPARENT_HEADER.to_string(),
            format!("00-{trace_id}-{span_id}-01"),
        ));
    }

    outgoing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_traceparent() {
        let ctx =
            TraceContext::parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").unwrap();
        assert_eq!(ctx.version, 0);
        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.parent_id, "b7ad6b7169203331");
        assert_eq!(ctx.flags, 1);
    }

    #[test]
    fn child_preserves_trace_id() {
        let ctx =
            TraceContext::parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").unwrap();
        let child = ctx.child_traceparent();
        assert!(child.contains("0af7651916cd43dd8448eb211c80319c"));
        assert!(!child.contains("b7ad6b7169203331")); // parent_id should change
    }

    #[test]
    fn invalid_traceparent() {
        assert!(TraceContext::parse("invalid").is_none());
        assert!(TraceContext::parse("00-short-id-01").is_none());
    }
}
