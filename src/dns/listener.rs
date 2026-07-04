#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::dns::resolver::{DnsResolver, ResolveResult};

/// Minimal DNS UDP listener that resolves fleet.internal queries
/// using the DnsResolver's cache.
pub struct DnsListener {
    resolver: DnsResolver,
}

impl DnsListener {
    pub fn new(resolver: DnsResolver) -> Self {
        Self { resolver }
    }

    /// Start the DNS listener on the given bind address.
    pub async fn start(self, bind_addr: SocketAddr) -> Result<(), std::io::Error> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        tracing::info!(addr = %bind_addr, "DNS listener started");

        let resolver = self.resolver;
        let mut buf = [0u8; 512];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query = &buf[..len];

            let response = handle_query(query, &resolver).await;
            if let Err(e) = socket.send_to(&response, src).await {
                tracing::warn!(error = %e, src = %src, "Failed to send DNS response");
            }
        }
    }
}

/// Handle a DNS query and produce a response.
async fn handle_query(query: &[u8], resolver: &DnsResolver) -> Vec<u8> {
    // Parse the DNS header (minimum 12 bytes)
    if query.len() < 12 {
        return build_error_response(query, RCODE_FORMERR);
    }

    let id = u16::from_be_bytes([query[0], query[1]]);
    let _flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    if qdcount == 0 {
        return build_error_response(query, RCODE_FORMERR);
    }

    // Parse the first question
    let (qname, offset) = match parse_qname(query, 12) {
        Some(v) => v,
        None => return build_error_response(query, RCODE_FORMERR),
    };

    if offset + 4 > query.len() {
        return build_error_response(query, RCODE_FORMERR);
    }

    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let _qclass = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);

    // Resolve via DnsResolver
    match resolver.resolve(&qname).await {
        ResolveResult::Cached(ips) => {
            if qtype == QTYPE_A || qtype == QTYPE_ANY {
                build_a_response(id, query, 12, offset + 4, &ips)
            } else if qtype == QTYPE_SRV {
                // SRV not supported for cached entries, return empty
                build_empty_response(id, query, 12, offset + 4)
            } else {
                build_empty_response(id, query, 12, offset + 4)
            }
        }
        ResolveResult::CacheMiss(_) => {
            // No data in cache — return NXDOMAIN
            build_nxdomain_response(id, query, 12, offset + 4)
        }
        ResolveResult::Forward => {
            // Not a fleet domain — return REFUSED
            build_refused_response(id, query)
        }
    }
}

// DNS constants
const QTYPE_A: u16 = 1;
const QTYPE_SRV: u16 = 33;
const QTYPE_ANY: u16 = 255;
const RCODE_FORMERR: u8 = 1;

/// Parse a DNS QNAME from the packet starting at `offset`.
/// Returns (domain_name_string, offset_after_qname).
fn parse_qname(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();

    loop {
        if offset >= packet.len() {
            return None;
        }
        let len = packet[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        // Check for compression pointer (0xC0 prefix)
        if len & 0xC0 == 0xC0 {
            // Compression not fully supported — skip
            offset += 2;
            break;
        }
        offset += 1;
        if offset + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    Some((labels.join("."), offset))
}

/// Encode a domain name into DNS wire format (length-prefixed labels).
fn encode_qname(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0); // terminator
    encoded
}

/// Build a DNS response with A records.
fn build_a_response(
    id: u16,
    query: &[u8],
    question_start: usize,
    question_end: usize,
    ips: &[std::net::Ipv4Addr],
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(512);

    // Header
    resp.extend_from_slice(&id.to_be_bytes());
    // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, RCODE=0
    resp.extend_from_slice(&0x8580u16.to_be_bytes());
    // QDCOUNT = 1
    resp.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT = number of IPs
    resp.extend_from_slice(&(ips.len() as u16).to_be_bytes());
    // NSCOUNT, ARCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    // Question section (copy from query)
    resp.extend_from_slice(&query[question_start..question_end]);

    // Answer section — pointer to name in question section (0xC00C)
    for ip in ips {
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        resp.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&ip.octets()); // RDATA
    }

    resp
}

/// Build an empty (no answer) response.
fn build_empty_response(
    id: u16,
    query: &[u8],
    question_start: usize,
    question_end: usize,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8580u16.to_be_bytes()); // QR=1, AA=1, RD=1, RA=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(&query[question_start..question_end]);
    resp
}

/// Build an NXDOMAIN response.
fn build_nxdomain_response(
    id: u16,
    query: &[u8],
    question_start: usize,
    question_end: usize,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&id.to_be_bytes());
    // QR=1, AA=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    resp.extend_from_slice(&0x8583u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(&query[question_start..question_end]);
    resp
}

/// Build a REFUSED response.
fn build_refused_response(id: u16, query: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&id.to_be_bytes());
    // QR=1, RD=1, RA=1, RCODE=5 (REFUSED)
    resp.extend_from_slice(&0x8185u16.to_be_bytes());
    // Copy question counts from original query
    if query.len() >= 12 {
        resp.extend_from_slice(&query[4..12]); // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        // Copy question section
        resp.extend_from_slice(&query[12..]);
    } else {
        resp.extend_from_slice(&[0; 8]);
    }
    resp
}

/// Build a generic error response.
fn build_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };

    let mut resp = Vec::with_capacity(12);
    resp.extend_from_slice(&id.to_be_bytes());
    let flags = 0x8100u16 | rcode as u16;
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&[0; 8]); // all counts zero
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question
        pkt.extend_from_slice(&encode_qname(domain));
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        pkt
    }

    #[tokio::test]
    async fn resolves_cached_fleet_query() {
        let resolver = DnsResolver::new("fleet.internal", vec![]);
        resolver
            .update_cache(
                "myapp",
                vec![Ipv4Addr::new(10, 0, 0, 1)],
                Duration::from_secs(60),
            )
            .await;

        let query = build_query("myapp.service.fleet.internal", QTYPE_A);
        let response = handle_query(&query, &resolver).await;

        // Check response has answer
        assert!(response.len() > 12);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);
    }

    #[tokio::test]
    async fn returns_nxdomain_for_cache_miss() {
        let resolver = DnsResolver::new("fleet.internal", vec![]);

        let query = build_query("unknown.service.fleet.internal", QTYPE_A);
        let response = handle_query(&query, &resolver).await;

        // RCODE should be 3 (NXDOMAIN)
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, 3);
    }

    #[tokio::test]
    async fn returns_refused_for_external() {
        let resolver = DnsResolver::new("fleet.internal", vec![]);

        let query = build_query("google.com", QTYPE_A);
        let response = handle_query(&query, &resolver).await;

        // RCODE should be 5 (REFUSED)
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, 5);
    }

    #[test]
    fn parse_qname_basic() {
        let mut pkt = vec![0u8; 12]; // dummy header
        pkt.push(3);
        pkt.extend_from_slice(b"foo");
        pkt.push(3);
        pkt.extend_from_slice(b"bar");
        pkt.push(0);

        let (name, offset) = parse_qname(&pkt, 12).unwrap();
        assert_eq!(name, "foo.bar");
        assert_eq!(offset, 12 + 1 + 3 + 1 + 3 + 1);
    }

    #[test]
    fn encode_qname_roundtrip() {
        let encoded = encode_qname("myapp.service.fleet.internal");
        // Should be: 5 myapp 7 service 5 fleet 8 internal 0
        assert_eq!(encoded[0], 5);
        assert_eq!(&encoded[1..6], b"myapp");
        assert_eq!(encoded[6], 7);
        assert_eq!(*encoded.last().unwrap(), 0);
    }
}
