//! Scraping Prometheus endpoints of local services.
//!
//! The agent scrapes each service it runs on the service's own loopback:
//! the host's for default-namespace services, the namespace's network
//! namespace otherwise. Entering a network namespace changes the calling
//! thread, so every scrape runs on a fresh thread that exits afterwards and
//! never returns to a pool.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Largest response body accepted.
pub const MAX_BODY: usize = 4 << 20;
/// Largest response header block accepted.
const MAX_HEADERS: usize = 64 << 10;
/// Most distinct metric names kept per service.
pub const MAX_METRICS: usize = 1000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ScrapeError {
    #[error("invalid network namespace '{0}'")]
    InvalidNamespace(String),
    #[error("cannot enter network namespace {0}: {1}")]
    Netns(String, std::io::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("timed out after {DEADLINE:?}")]
    Timeout,
    #[error("response is larger than {MAX_BODY} bytes")]
    TooLarge,
    #[error("malformed HTTP response: {0}")]
    Http(String),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("scrape thread failed")]
    Thread,
}

/// One scrape target: a service endpoint on loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub service: String,
    pub port: u16,
    pub path: String,
    /// Fleet namespace whose network namespace the service runs in, or
    /// `None` for host networking.
    pub namespace: Option<String>,
}

/// Scrape `target` and sum its samples by metric name.
pub async fn scrape(target: Target) -> Result<BTreeMap<String, f64>, ScrapeError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ekafleet-scrape".into())
        .spawn(move || {
            let _ = tx.send(scrape_blocking(&target));
        })?;
    let body = rx.await.map_err(|_| ScrapeError::Thread)??;
    Ok(sum_by_name(&parse_prometheus(&body)))
}

fn scrape_blocking(target: &Target) -> Result<String, ScrapeError> {
    if let Some(namespace) = &target.namespace {
        enter_netns(namespace)?;
    }
    http_get(target.port, &target.path)
}

/// Move the calling thread into the network namespace of fleet namespace
/// `namespace`.
fn enter_netns(namespace: &str) -> Result<(), ScrapeError> {
    use std::os::fd::AsRawFd;
    if namespace.is_empty()
        || !namespace
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ScrapeError::InvalidNamespace(namespace.to_string()));
    }
    let path = format!("/run/netns/ekafleet-{namespace}");
    let file = std::fs::File::open(&path).map_err(|e| ScrapeError::Netns(path.clone(), e))?;
    // SAFETY: `file` is an open namespace file for the duration of the
    // call; setns only changes the network namespace of this thread.
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(ScrapeError::Netns(path, std::io::Error::last_os_error()));
    }
    Ok(())
}

/// GET `path` from 127.0.0.1:`port` with HTTP/1.0 and return the body.
fn http_get(port: u16, path: &str) -> Result<String, ScrapeError> {
    let start = Instant::now();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(DEADLINE))?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\
         Accept: text/plain;version=0.0.4\r\nUser-Agent: ekafleet-agent\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let mut buf = [0u8; 16 << 10];
    loop {
        if start.elapsed() > DEADLINE {
            return Err(ScrapeError::Timeout);
        }
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ScrapeError::Timeout);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.len() > MAX_BODY + MAX_HEADERS {
            return Err(ScrapeError::TooLarge);
        }
    }
    parse_response(&response)
}

/// The body of a complete HTTP/1.x response, if its status is 200.
fn parse_response(response: &[u8]) -> Result<String, ScrapeError> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ScrapeError::Http("no end of headers".into()))?;
    if split > MAX_HEADERS {
        return Err(ScrapeError::Http("headers too large".into()));
    }
    let head = std::str::from_utf8(&response[..split])
        .map_err(|_| ScrapeError::Http("headers are not UTF-8".into()))?;
    let body = &response[split + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(ScrapeError::Http(format!(
            "unexpected status line '{status_line}'"
        )));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ScrapeError::Http(format!("unexpected status line '{status_line}'")))?;
    if status != 200 {
        return Err(ScrapeError::Status(status));
    }

    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_ascii_lowercase();
        match name.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => chunked = value.contains("chunked"),
            "content-encoding" if value != "identity" => {
                return Err(ScrapeError::Http(format!("unsupported encoding '{value}'")));
            }
            _ => {}
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_BODY {
        return Err(ScrapeError::TooLarge);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, ScrapeError> {
    let bad = || ScrapeError::Http("malformed chunked body".into());
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        let size_line = std::str::from_utf8(&data[..line_end]).map_err(|_| bad())?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| bad())?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_BODY || data.len() < size + 2 || &data[size..size + 2] != b"\r\n" {
            return Err(bad());
        }
        out.extend_from_slice(&data[..size]);
        if out.len() > MAX_BODY {
            return Err(ScrapeError::TooLarge);
        }
        data = &data[size + 2..];
    }
}

/// One sample of the text exposition format.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// Parse the Prometheus text exposition format. Lines that do not parse,
/// and non-finite values, are skipped.
pub fn parse_prometheus(body: &str) -> Vec<MetricSample> {
    body.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MetricSample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let name_end = line
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .unwrap_or(line.len());
    let name = &line[..name_end];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut rest = &line[name_end..];
    let mut labels = BTreeMap::new();
    if let Some(after) = rest.strip_prefix('{') {
        let (parsed, remaining) = parse_labels(after)?;
        labels = parsed;
        rest = remaining;
    }
    // A value, then an optional timestamp.
    let value: f64 = rest.split_whitespace().next()?.parse().ok()?;
    value.is_finite().then(|| MetricSample {
        name: name.to_string(),
        labels,
        value,
    })
}

/// Parse `key="value",...}` and return the labels and what follows `}`.
fn parse_labels(mut s: &str) -> Option<(BTreeMap<String, String>, &str)> {
    let mut labels = BTreeMap::new();
    loop {
        s = s.trim_start();
        if let Some(rest) = s.strip_prefix('}') {
            return Some((labels, rest));
        }
        let eq = s.find('=')?;
        let key = s[..eq].trim().to_string();
        s = s[eq + 1..].trim_start().strip_prefix('"')?;
        let mut value = String::new();
        let mut chars = s.char_indices();
        let end = loop {
            let (i, c) = chars.next()?;
            match c {
                '\\' => match chars.next()?.1 {
                    'n' => value.push('\n'),
                    other => value.push(other),
                },
                '"' => break i,
                c => value.push(c),
            }
        };
        labels.insert(key, value);
        s = s[end + 1..].trim_start();
        s = s.strip_prefix(',').unwrap_or(s);
    }
}

/// Sum samples by metric name, keeping at most [`MAX_METRICS`] names.
pub fn sum_by_name(samples: &[MetricSample]) -> BTreeMap<String, f64> {
    let mut sums: BTreeMap<String, f64> = BTreeMap::new();
    for sample in samples {
        if let Some(sum) = sums.get_mut(&sample.name) {
            *sum += sample.value;
        } else if sums.len() < MAX_METRICS {
            sums.insert(sample.name.clone(), sample.value);
        }
    }
    sums
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_exposition_format() {
        let body = r#"
# HELP http_requests_total Requests.
# TYPE http_requests_total counter
http_requests_total{method="get",path="/a,b\"c"} 10 1700000000000
http_requests_total{method="post"} 5
queue_depth 3.5
up +Inf
broken{label="x" 1
temperature NaN
"#;
        let samples = parse_prometheus(body);
        assert_eq!(samples.len(), 3, "{samples:?}");
        assert_eq!(samples[0].labels["path"], "/a,b\"c");
        assert_eq!(samples[0].value, 10.0);
        let sums = sum_by_name(&samples);
        assert_eq!(sums["http_requests_total"], 15.0);
        assert_eq!(sums["queue_depth"], 3.5);
        assert!(!sums.contains_key("up"));
    }

    #[test]
    fn responses_need_status_200_and_may_be_chunked() {
        let plain = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nup 1\n";
        assert_eq!(parse_response(plain).unwrap(), "up 1\n");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nup \r\n2\r\n1\n\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), "up 1\n");
        let missing = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert!(matches!(
            parse_response(missing),
            Err(ScrapeError::Status(404))
        ));
        let gzip = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nxx";
        assert!(parse_response(gzip).is_err());
    }

    #[test]
    fn namespaces_cannot_escape_the_netns_directory() {
        assert!(matches!(
            enter_netns("../../proc/1/ns/net"),
            Err(ScrapeError::InvalidNamespace(_))
        ));
    }

    #[tokio::test]
    async fn scrapes_a_loopback_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = conn.read(&mut buf).unwrap();
            assert!(buf[..n].starts_with(b"GET /stats HTTP/1.0\r\n"));
            conn.write_all(b"HTTP/1.0 200 OK\r\n\r\njobs{q=\"a\"} 2\njobs{q=\"b\"} 3\n")
                .unwrap();
        });
        let sums = scrape(Target {
            service: "web".into(),
            port,
            path: "/stats".into(),
            namespace: None,
        })
        .await
        .unwrap();
        assert_eq!(sums["jobs"], 5.0);
    }
}
