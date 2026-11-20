//! UDP DNS server for the agent: answers fleet names from the
//! [`DnsResolver`] snapshot and forwards everything else upstream.
//!
//! One listener serves the host (`127.0.0.1:53` by default); one more runs
//! inside each namespace's network namespace on its bridge gateway, scoped
//! to that namespace's records.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::dns::resolver::{DnsResolver, Lookup, Records};

/// Largest datagram accepted or forwarded (EDNS clients may send more than
/// 512 bytes; our own answers stay within 512).
const MAX_PACKET: usize = 4096;
/// Answers we build are truncated (TC) beyond this.
const MAX_ANSWER: usize = 512;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// Queries in flight per listener.
const MAX_IN_FLIGHT: usize = 256;

const QTYPE_A: u16 = 1;
const QTYPE_SRV: u16 = 33;
const QTYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

/// Bind a UDP socket to `addr` inside the network namespace at
/// `netns_path` (e.g. `/run/netns/ekafleet-acme`). The socket stays in that
/// namespace; the calling process does not move.
pub async fn bind_in_netns(netns_path: &Path, addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = crate::agent::netns::run_in_netns(netns_path, move || {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    })
    .await?;
    UdpSocket::from_std(socket)
}

/// Answer queries on `socket` until `shutdown`. `namespace` scopes fleet
/// lookups (`None` for the host).
pub async fn serve(
    socket: UdpSocket,
    resolver: DnsResolver,
    namespace: Option<String>,
    shutdown: CancellationToken,
) {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    let namespace: Option<Arc<str>> = namespace.map(Into::into);
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let (len, src) = tokio::select! {
            _ = shutdown.cancelled() => return,
            received = socket.recv_from(&mut buf) => match received {
                Ok(received) => received,
                Err(e) => {
                    tracing::warn!(error = %e, "DNS receive failed");
                    continue;
                }
            },
        };
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            continue; // overloaded: drop, the client retries
        };
        let query = buf[..len].to_vec();
        let (socket, resolver, namespace) = (socket.clone(), resolver.clone(), namespace.clone());
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(response) = handle_query(&query, &resolver, namespace.as_deref()).await
                && let Err(e) = socket.send_to(&response, src).await
            {
                tracing::debug!(error = %e, %src, "Failed to send DNS response");
            }
        });
    }
}

/// The response to `query`, or `None` to drop it.
pub async fn handle_query(
    query: &[u8],
    resolver: &DnsResolver,
    namespace: Option<&str>,
) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & FLAG_QR != 0 {
        return None; // a response, not a query
    }
    let rd = flags & FLAG_RD;
    if (flags >> 11) & 0xF != 0 {
        return Some(header_only(id, rd, RCODE_NOTIMP));
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return Some(header_only(id, rd, RCODE_FORMERR));
    }
    let Some((qname, qtype_at)) = parse_qname(query, 12) else {
        return Some(header_only(id, rd, RCODE_FORMERR));
    };
    let Some(question) = query.get(qtype_at..qtype_at + 4) else {
        return Some(header_only(id, rd, RCODE_FORMERR));
    };
    let qtype = u16::from_be_bytes([question[0], question[1]]);
    let qclass = u16::from_be_bytes([question[2], question[3]]);
    let question = &query[12..qtype_at + 4];

    match resolver.lookup(&qname, namespace).await {
        Lookup::Forward => Some(
            forward(query, &resolver.upstream_servers().await)
                .await
                .unwrap_or_else(|| header_only(id, rd, RCODE_SERVFAIL)),
        ),
        Lookup::NxDomain => Some(answer(id, rd, RCODE_NXDOMAIN, question, &[])),
        Lookup::Found(records) => {
            let domain = resolver.domain().await;
            let answers = if qclass == CLASS_IN {
                encode_answers(&records, qtype, &domain)
            } else {
                Vec::new()
            };
            Some(answer(id, rd, 0, question, &answers))
        }
    }
}

/// Resource records answering `qtype` from `records`, each with a pointer
/// to the question name.
fn encode_answers(records: &Records, qtype: u16, domain: &str) -> Vec<Vec<u8>> {
    let mut answers = Vec::new();
    let rr = |rtype: u16, rdata: &[u8]| {
        let mut rr = vec![0xC0, 0x0C];
        rr.extend_from_slice(&rtype.to_be_bytes());
        rr.extend_from_slice(&CLASS_IN.to_be_bytes());
        rr.extend_from_slice(&records.ttl.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(rdata);
        rr
    };
    if matches!(qtype, QTYPE_A | QTYPE_ANY) {
        for ip in &records.a {
            answers.push(rr(QTYPE_A, &ip.octets()));
        }
    }
    if matches!(qtype, QTYPE_SRV | QTYPE_ANY) {
        for (port, target) in &records.srv {
            let Some(target) = encode_name(&format!("{target}.{domain}")) else {
                continue;
            };
            // Priority 0, weight 1: clients spread over every target.
            let mut rdata = vec![0, 0, 0, 1];
            rdata.extend_from_slice(&port.to_be_bytes());
            rdata.extend_from_slice(&target);
            answers.push(rr(QTYPE_SRV, &rdata));
        }
    }
    answers
}

/// A response with the question and as many answers as fit in
/// [`MAX_ANSWER`] bytes (TC set if some did not).
fn answer(id: u16, rd: u16, rcode: u16, question: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
    let mut body = question.to_vec();
    let mut count: u16 = 0;
    let mut truncated = false;
    for rr in answers {
        if 12 + body.len() + rr.len() > MAX_ANSWER {
            truncated = true;
            break;
        }
        body.extend_from_slice(rr);
        count += 1;
    }
    let mut flags = FLAG_QR | FLAG_AA | FLAG_RA | rd | rcode;
    if truncated {
        flags |= FLAG_TC;
    }
    let mut resp = Vec::with_capacity(12 + body.len());
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&count.to_be_bytes());
    resp.extend_from_slice(&[0, 0, 0, 0]);
    resp.extend_from_slice(&body);
    resp
}

/// A response with no question section.
fn header_only(id: u16, rd: u16, rcode: u16) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&(FLAG_QR | FLAG_RA | rd | rcode).to_be_bytes());
    resp.extend_from_slice(&[0; 8]);
    resp
}

/// Relay `query` to the first upstream that answers it. Only a reply from
/// that upstream (connected socket) with the query's ID is accepted.
async fn forward(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; MAX_PACKET];
    for upstream in upstreams {
        let local: SocketAddr = if upstream.is_ipv4() {
            "0.0.0.0:0".parse().ok()?
        } else {
            "[::]:0".parse().ok()?
        };
        let Ok(socket) = UdpSocket::bind(local).await else {
            continue;
        };
        if socket.connect(upstream).await.is_err() || socket.send(query).await.is_err() {
            continue;
        }
        let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
        while let Ok(Ok(len)) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            if len >= 12 && buf[..2] == query[..2] {
                return Some(buf[..len].to_vec());
            }
        }
    }
    None
}

/// Parse an uncompressed name at `offset`: (lower-case dotted name, offset
/// after it). Questions never need compression; pointers are refused.
fn parse_qname(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = packet.get(offset..offset + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        offset += len;
        if name.len() > 253 {
            return None;
        }
    }
    Some((name.to_ascii_lowercase(), offset))
}

/// Encode a dotted name in wire format.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut encoded = Vec::with_capacity(name.len() + 2);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return None;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    (encoded.len() <= 255).then_some(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{DnsRecord, DnsRecordType};

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        pkt.extend_from_slice(&encode_name(name).unwrap());
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&CLASS_IN.to_be_bytes());
        pkt
    }

    fn rcode(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[2], resp[3]]) & 0xF
    }

    fn ancount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }

    async fn resolver() -> DnsResolver {
        let resolver = DnsResolver::new("fleet.test", vec![]);
        let record = |name: &str, kind: DnsRecordType, values: &[&str], ns: &str| DnsRecord {
            name: name.into(),
            record_type: kind as i32,
            values: values.iter().map(|v| v.to_string()).collect(),
            ttl: 10,
            namespace: ns.into(),
        };
        resolver
            .replace(&[
                record(
                    "web.service",
                    DnsRecordType::A,
                    &["10.100.0.1", "10.100.0.2"],
                    "",
                ),
                record("web.service", DnsRecordType::Srv, &["8080 a.node"], ""),
                record("db.service", DnsRecordType::A, &["10.200.1.2"], "acme"),
            ])
            .await;
        resolver
    }

    #[tokio::test]
    async fn answers_a_and_srv_for_fleet_names() {
        let resolver = resolver().await;
        let resp = handle_query(&query("Web.Service.fleet.test", QTYPE_A), &resolver, None)
            .await
            .unwrap();
        assert_eq!(&resp[..2], &[0x12, 0x34]);
        assert_eq!(rcode(&resp), 0);
        assert_eq!(ancount(&resp), 2);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & FLAG_AA, 0);
        assert_ne!(flags & FLAG_RD, 0, "RD is copied from the query");
        // Last answer's RDATA is the second address.
        assert_eq!(&resp[resp.len() - 4..], &[10, 100, 0, 2]);

        let resp = handle_query(&query("web.service.fleet.test", QTYPE_SRV), &resolver, None)
            .await
            .unwrap();
        assert_eq!(ancount(&resp), 1);
        let target = encode_name("a.node.fleet.test").unwrap();
        assert!(resp.ends_with(&target));
        let port_at = resp.len() - target.len() - 2;
        assert_eq!(&resp[port_at..port_at + 2], &8080u16.to_be_bytes());

        // AAAA: the name exists but has no such records.
        let resp = handle_query(&query("web.service.fleet.test", 28), &resolver, None)
            .await
            .unwrap();
        assert_eq!((rcode(&resp), ancount(&resp)), (0, 0));
    }

    #[tokio::test]
    async fn namespace_records_answer_only_inside_their_namespace() {
        let resolver = resolver().await;
        let q = query("db.service.fleet.test", QTYPE_A);
        let host = handle_query(&q, &resolver, None).await.unwrap();
        assert_eq!(rcode(&host), RCODE_NXDOMAIN);
        let other = handle_query(&q, &resolver, Some("globex")).await.unwrap();
        assert_eq!(rcode(&other), RCODE_NXDOMAIN);
        let acme = handle_query(&q, &resolver, Some("acme")).await.unwrap();
        assert_eq!((rcode(&acme), ancount(&acme)), (0, 1));
    }

    #[tokio::test]
    async fn rejects_malformed_and_unsupported_queries() {
        let resolver = resolver().await;
        assert!(handle_query(&[0; 5], &resolver, None).await.is_none());
        let mut response = query("web.service.fleet.test", QTYPE_A);
        response[2] |= 0x80;
        assert!(handle_query(&response, &resolver, None).await.is_none());
        let mut notify = query("web.service.fleet.test", QTYPE_A);
        notify[2] |= 4 << 3;
        assert_eq!(
            rcode(&handle_query(&notify, &resolver, None).await.unwrap()),
            RCODE_NOTIMP
        );
        let mut pointer = query("x", QTYPE_A);
        pointer[12] = 0xC0;
        assert_eq!(
            rcode(&handle_query(&pointer, &resolver, None).await.unwrap()),
            RCODE_FORMERR
        );
        // No upstreams: external names fail rather than hang.
        let resp = handle_query(&query("example.com", QTYPE_A), &resolver, None)
            .await
            .unwrap();
        assert_eq!(rcode(&resp), RCODE_SERVFAIL);
    }

    #[tokio::test]
    async fn large_answers_are_truncated() {
        let resolver = DnsResolver::new("fleet.test", vec![]);
        let ips: Vec<String> = (0..100).map(|i| format!("10.100.0.{i}")).collect();
        resolver
            .replace(&[DnsRecord {
                name: "big.service".into(),
                record_type: DnsRecordType::A as i32,
                values: ips,
                ttl: 10,
                namespace: String::new(),
            }])
            .await;
        let resp = handle_query(&query("big.service.fleet.test", QTYPE_A), &resolver, None)
            .await
            .unwrap();
        assert!(resp.len() <= MAX_ANSWER);
        assert_ne!(u16::from_be_bytes([resp[2], resp[3]]) & FLAG_TC, 0);
        assert!(ancount(&resp) > 0);
    }

    #[tokio::test]
    async fn forwards_external_names_to_an_upstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, src) = upstream.recv_from(&mut buf).await.unwrap();
            let mut reply = buf[..len].to_vec();
            reply[2] |= 0x80;
            reply.push(0xAB); // marker
            upstream.send_to(&reply, src).await.unwrap();
        });
        let resolver = DnsResolver::new("fleet.test", vec![addr]);
        let resp = handle_query(&query("example.com", QTYPE_A), &resolver, None)
            .await
            .unwrap();
        assert_eq!(resp.last(), Some(&0xAB));
    }
}
