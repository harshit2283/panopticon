#![allow(dead_code)]

//! DNS protocol parser (RFC 1035).
//!
//! DNS uses UDP (port 53) — each packet is a complete message, no reassembly.
//! Parses queries (egress) and responses (ingress), extracting domain names,
//! record types (A, AAAA, CNAME, SRV), and response codes.
//!
//! DNS cache integration uses Option A: resolved records are returned in
//! `L7Message.headers` as `("dns_a_record", "domain|ip_u32|ttl_secs")` tuples.
//! The event loop extracts these and feeds `DnsCache::insert_observed()`.

use std::collections::HashMap;

use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Constants ────────────────────────────────────────────────────────────

/// Maximum pending queries before evicting the oldest.
const MAX_PENDING_QUERIES: usize = 1024;

/// Maximum recursion depth for DNS name pointer decompression.
const MAX_NAME_RECURSION: usize = 10;

// DNS record types
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;

// DNS RCODE values
const RCODE_NOERROR: u16 = 0;

// ── Parser State ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Ready to process the next DNS packet.
    Idle,
}

/// DNS protocol parser.
pub struct DnsParser {
    state: State,
    /// Maps transaction ID → (qname, request_timestamp_ns).
    pending_queries: HashMap<u16, (String, u64)>,
}

impl DnsParser {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            pending_queries: HashMap::new(),
        }
    }

    /// Parse a DNS query (egress).
    fn parse_query(&mut self, data: &[u8], timestamp_ns: u64) -> ParseResult {
        if data.len() < 12 {
            return ParseResult::Error("DNS packet too short for header".into());
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);

        if qdcount == 0 {
            return ParseResult::NeedMoreData;
        }

        // Parse the first question
        let (qname, offset) = match parse_dns_name(data, 12) {
            Some(r) => r,
            None => return ParseResult::Error("DNS: failed to parse QNAME".into()),
        };

        if offset + 4 > data.len() {
            return ParseResult::Error("DNS: truncated question section".into());
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);

        // Evict oldest if at capacity
        if self.pending_queries.len() >= MAX_PENDING_QUERIES
            && let Some(&oldest_id) = self
                .pending_queries
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(id, _)| id)
        {
            self.pending_queries.remove(&oldest_id);
        }

        self.pending_queries
            .insert(id, (qname.clone(), timestamp_ns));

        let mut msg = L7Message::new(Protocol::Dns, Direction::Egress, timestamp_ns);
        msg.method = Some("QUERY".into());
        msg.path = Some(qname);
        msg.headers
            .push(("qtype".into(), qtype_to_string(qtype).into()));
        msg.request_size_bytes = data.len() as u64;

        ParseResult::Messages(vec![msg])
    }

    /// Parse a DNS response (ingress).
    fn parse_response(&mut self, data: &[u8], timestamp_ns: u64) -> ParseResult {
        if data.len() < 12 {
            return ParseResult::Error("DNS packet too short for header".into());
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let rcode = flags & 0x000F;
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        // Skip question section
        let mut offset = 12;
        for _ in 0..qdcount {
            let (_, new_offset) = match parse_dns_name(data, offset) {
                Some(r) => r,
                None => return ParseResult::Error("DNS: failed to parse question name".into()),
            };
            offset = new_offset + 4; // skip QTYPE + QCLASS
            if offset > data.len() {
                return ParseResult::Error("DNS: truncated question section".into());
            }
        }

        // Parse answer section
        let mut resolved_ips = Vec::new();
        let mut cname_targets = Vec::new();
        let mut srv_targets = Vec::new();
        let mut headers = Vec::new();

        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }

            let (_, name_end) = match parse_dns_name(data, offset) {
                Some(r) => r,
                None => break,
            };
            offset = name_end;

            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            // rclass at offset+2..offset+4 (unused)
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let rdata = &data[offset..offset + rdlength];

            match rtype {
                TYPE_A if rdlength == 4 => {
                    let ip = u32::from_be_bytes([rdata[0], rdata[1], rdata[2], rdata[3]]);
                    let ip_str = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                    resolved_ips.push(ip_str);

                    // Look up the original qname for this response
                    let domain = self
                        .pending_queries
                        .get(&id)
                        .map(|(q, _)| q.clone())
                        .unwrap_or_default();

                    if !domain.is_empty() {
                        headers.push(("dns_a_record".into(), format!("{}|{}|{}", domain, ip, ttl)));
                    }
                }
                TYPE_AAAA if rdlength == 16 => {
                    // Format as IPv6
                    let mut parts = Vec::with_capacity(8);
                    for i in 0..8 {
                        let word = u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]]);
                        parts.push(format!("{:x}", word));
                    }
                    resolved_ips.push(parts.join(":"));
                }
                TYPE_CNAME => {
                    if let Some((cname, _)) = parse_dns_name(data, offset) {
                        cname_targets.push(cname);
                    }
                }
                TYPE_SRV if rdlength >= 6 => {
                    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                    let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                    let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    if let Some((target, _)) = parse_dns_name(data, offset + 6) {
                        srv_targets.push(format!(
                            "{}:{} (pri={}, w={})",
                            target, port, priority, weight
                        ));
                    }
                }
                _ => {
                    // Unknown record type, skip
                }
            }

            offset += rdlength;
        }

        // Build L7Message
        let mut msg = L7Message::new(Protocol::Dns, Direction::Ingress, timestamp_ns);
        msg.method = Some("RESPONSE".into());
        msg.status = Some(rcode as u32);
        msg.response_size_bytes = data.len() as u64;
        msg.headers = headers;

        // Match pending query for qname + latency
        if let Some((qname, req_ts)) = self.pending_queries.remove(&id) {
            msg.path = Some(qname);
            msg.latency_ns = Some(timestamp_ns.saturating_sub(req_ts));
        }

        // Build payload_text from resolved records
        let mut parts = Vec::new();
        parts.extend(resolved_ips);
        parts.extend(cname_targets);
        parts.extend(srv_targets);
        if !parts.is_empty() {
            msg.payload_text = Some(parts.join(", "));
        }

        ParseResult::Messages(vec![msg])
    }
}

impl ProtocolParser for DnsParser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        if data.len() < 12 {
            return ParseResult::Error("DNS packet too short".into());
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags >> 15) & 1 == 1;

        match direction {
            Direction::Egress => self.parse_query(data, timestamp_ns),
            Direction::Ingress => {
                if is_response {
                    self.parse_response(data, timestamp_ns)
                } else {
                    // Ingress query (e.g. from a DNS server perspective) — treat as query
                    self.parse_query(data, timestamp_ns)
                }
            }
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Dns
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            State::Idle => "idle",
        }
    }
}

// ── DNS Name Parsing ─────────────────────────────────────────────────────

/// Parse a DNS name from `data` starting at `offset`.
/// Returns (name, offset_after_name) or None on error.
/// Handles label compression pointers (0xC0 prefix).
fn parse_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut end_offset = 0; // The position after the name in the original data
    let mut recursion = 0;

    loop {
        if offset >= data.len() {
            return None;
        }

        let len_byte = data[offset];

        if len_byte == 0 {
            // End of name
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }

        if (len_byte & 0xC0) == 0xC0 {
            // Compression pointer
            if offset + 1 >= data.len() {
                return None;
            }
            if !jumped {
                end_offset = offset + 2;
            }
            let pointer = ((len_byte as usize & 0x3F) << 8) | (data[offset + 1] as usize);
            if pointer >= data.len() {
                return None;
            }
            offset = pointer;
            jumped = true;
            recursion += 1;
            if recursion > MAX_NAME_RECURSION {
                return None;
            }
            continue;
        }

        // Regular label
        let label_len = len_byte as usize;
        offset += 1;
        if offset + label_len > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[offset..offset + label_len]).into_owned();
        labels.push(label);
        offset += label_len;
    }

    if !jumped {
        // end_offset was set in the termination case
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Some((name, end_offset))
}

/// Convert a DNS query type to a human-readable string.
fn qtype_to_string(qtype: u16) -> &'static str {
    match qtype {
        TYPE_A => "A",
        TYPE_CNAME => "CNAME",
        TYPE_AAAA => "AAAA",
        TYPE_SRV => "SRV",
        15 => "MX",
        2 => "NS",
        6 => "SOA",
        16 => "TXT",
        12 => "PTR",
        255 => "ANY",
        _ => "OTHER",
    }
}

// ── Helper: Build DNS Packets for Tests ──────────────────────────────────

#[cfg(test)]
mod test_helpers {
    /// Encode a DNS name as a sequence of length-prefixed labels.
    pub fn encode_dns_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // terminator
        buf
    }

    /// Build a minimal DNS query packet.
    pub fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&id.to_be_bytes()); // ID
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Flags: standard query
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question
        pkt.extend_from_slice(&encode_dns_name(qname));
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        pkt
    }

    /// Build a DNS response with answer records.
    /// Each answer is (name_bytes, rtype, ttl, rdata).
    pub fn build_dns_response(
        id: u16,
        rcode: u16,
        qname: &str,
        qtype: u16,
        answers: &[(&[u8], u16, u32, &[u8])],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&id.to_be_bytes());
        let flags: u16 = 0x8000 | rcode; // QR=1 (response) + RCODE
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question section
        pkt.extend_from_slice(&encode_dns_name(qname));
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        // Answer section
        for (name_bytes, rtype, ttl, rdata) in answers {
            pkt.extend_from_slice(name_bytes);
            pkt.extend_from_slice(&rtype.to_be_bytes());
            pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
            pkt.extend_from_slice(&ttl.to_be_bytes());
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            pkt.extend_from_slice(rdata);
        }
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_parse_a_record_response() {
        let mut parser = DnsParser::new();

        // Send query
        let query = build_dns_query(0x1234, "nginx.default.svc.cluster.local", TYPE_A);
        parser.feed(&query, Direction::Egress, 1000);

        // Build response with A record: 10.0.0.1
        let name = encode_dns_name("nginx.default.svc.cluster.local");
        let rdata = [10u8, 0, 0, 1];
        let resp = build_dns_response(
            0x1234,
            RCODE_NOERROR,
            "nginx.default.svc.cluster.local",
            TYPE_A,
            &[(&name, TYPE_A, 300, &rdata)],
        );

        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("RESPONSE"));
                assert_eq!(
                    msgs[0].path.as_deref(),
                    Some("nginx.default.svc.cluster.local")
                );
                assert_eq!(msgs[0].status, Some(0));
                assert_eq!(msgs[0].latency_ns, Some(1000));
                assert!(msgs[0].payload_text.as_ref().unwrap().contains("10.0.0.1"));
                // Check dns_a_record header
                let a_records: Vec<_> = msgs[0]
                    .headers
                    .iter()
                    .filter(|(k, _)| k == "dns_a_record")
                    .collect();
                assert_eq!(a_records.len(), 1);
                assert!(a_records[0].1.contains("nginx.default.svc.cluster.local"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_aaaa_response() {
        let mut parser = DnsParser::new();

        let query = build_dns_query(0x2222, "ipv6.example.com", TYPE_AAAA);
        parser.feed(&query, Direction::Egress, 1000);

        // AAAA record: ::1 (all zeros except last byte)
        let name = encode_dns_name("ipv6.example.com");
        let mut rdata = [0u8; 16];
        rdata[15] = 1; // ::1
        let resp = build_dns_response(
            0x2222,
            RCODE_NOERROR,
            "ipv6.example.com",
            TYPE_AAAA,
            &[(&name, TYPE_AAAA, 600, &rdata)],
        );

        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].status, Some(0));
                // Should contain IPv6 address
                assert!(msgs[0].payload_text.is_some());
                // No dns_a_record header for AAAA
                let a_records: Vec<_> = msgs[0]
                    .headers
                    .iter()
                    .filter(|(k, _)| k == "dns_a_record")
                    .collect();
                assert!(a_records.is_empty());
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_cname_chain() {
        let mut parser = DnsParser::new();

        let query = build_dns_query(0x3333, "www.example.com", TYPE_A);
        parser.feed(&query, Direction::Egress, 1000);

        // Response with CNAME → A
        let name1 = encode_dns_name("www.example.com");
        let cname_rdata = encode_dns_name("cdn.example.com");
        let name2 = encode_dns_name("cdn.example.com");
        let a_rdata = [93u8, 184, 216, 34]; // 93.184.216.34

        let resp = build_dns_response(
            0x3333,
            RCODE_NOERROR,
            "www.example.com",
            TYPE_A,
            &[
                (&name1, TYPE_CNAME, 3600, &cname_rdata),
                (&name2, TYPE_A, 300, &a_rdata),
            ],
        );

        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                let text = msgs[0].payload_text.as_ref().unwrap();
                assert!(text.contains("93.184.216.34"));
                assert!(text.contains("cdn.example.com"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_nxdomain() {
        let mut parser = DnsParser::new();

        let query = build_dns_query(0x4444, "nonexistent.example.com", TYPE_A);
        parser.feed(&query, Direction::Egress, 1000);

        // NXDOMAIN response (RCODE=3), no answers
        let resp = build_dns_response(
            0x4444,
            3, // NXDOMAIN
            "nonexistent.example.com",
            TYPE_A,
            &[],
        );

        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].status, Some(3)); // NXDOMAIN
                assert!(msgs[0].payload_text.is_none());
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_compressed_name_pointer() {
        // Build a packet where the answer uses a compression pointer to the question name
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&0x5555u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x8000u16.to_be_bytes()); // Flags: response
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question: "example.com" at offset 12
        let qname = encode_dns_name("example.com");
        pkt.extend_from_slice(&qname);
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

        // Answer: pointer to offset 12 (the question name)
        pkt.push(0xC0); // compression pointer
        pkt.push(12); // offset = 12
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        pkt.extend_from_slice(&60u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        pkt.extend_from_slice(&[1u8, 2, 3, 4]); // RDATA: 1.2.3.4

        let mut parser = DnsParser::new();
        // First send a query to set up pending
        let query = build_dns_query(0x5555, "example.com", TYPE_A);
        parser.feed(&query, Direction::Egress, 1000);

        let result = parser.feed(&pkt, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert!(msgs[0].payload_text.as_ref().unwrap().contains("1.2.3.4"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_multi_answer_response() {
        let mut parser = DnsParser::new();

        let query = build_dns_query(0x6666, "multi.example.com", TYPE_A);
        parser.feed(&query, Direction::Egress, 1000);

        let name = encode_dns_name("multi.example.com");
        let resp = build_dns_response(
            0x6666,
            RCODE_NOERROR,
            "multi.example.com",
            TYPE_A,
            &[
                (&name, TYPE_A, 300, &[10u8, 0, 0, 1]),
                (&name, TYPE_A, 300, &[10u8, 0, 0, 2]),
                (&name, TYPE_A, 300, &[10u8, 0, 0, 3]),
            ],
        );

        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                let text = msgs[0].payload_text.as_ref().unwrap();
                assert!(text.contains("10.0.0.1"));
                assert!(text.contains("10.0.0.2"));
                assert!(text.contains("10.0.0.3"));
                // Should have 3 dns_a_record headers
                let a_records: Vec<_> = msgs[0]
                    .headers
                    .iter()
                    .filter(|(k, _)| k == "dns_a_record")
                    .collect();
                assert_eq!(a_records.len(), 3);
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_query_response_latency_matching() {
        let mut parser = DnsParser::new();

        let query = build_dns_query(0x7777, "latency.test", TYPE_A);
        parser.feed(&query, Direction::Egress, 1_000_000);

        let name = encode_dns_name("latency.test");
        let resp = build_dns_response(
            0x7777,
            RCODE_NOERROR,
            "latency.test",
            TYPE_A,
            &[(&name, TYPE_A, 60, &[127u8, 0, 0, 1])],
        );

        let result = parser.feed(&resp, Direction::Ingress, 1_500_000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].latency_ns, Some(500_000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_packet_error() {
        let mut parser = DnsParser::new();

        // Only 8 bytes — too short for DNS header (12 bytes)
        let data = [0u8; 8];
        let result = parser.feed(&data, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::Error(_)));
    }

    #[test]
    fn test_unknown_query_type_ignored() {
        let mut parser = DnsParser::new();

        let query = build_dns_query(0x8888, "mx.example.com", 15); // MX = 15
        let result = parser.feed(&query, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("QUERY"));
                assert_eq!(msgs[0].path.as_deref(), Some("mx.example.com"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_parser_protocol() {
        let parser = DnsParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Dns);
        assert_eq!(parser.state_name(), "idle");
    }
}
