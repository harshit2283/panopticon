#![allow(dead_code)]

//! MySQL wire protocol parser.
//!
//! Wire format: 3-byte length (LE) + 1-byte seq_id + payload.
//! Detects server version at handshake (MySQL 5.7 vs 8.0+ via auth plugin).

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

const COM_QUERY: u8 = 0x03;
const COM_STMT_PREPARE: u8 = 0x16;
const ERR_MARKER: u8 = 0xFF;
const OK_MARKER: u8 = 0x00;
const EOF_MARKER: u8 = 0xFE;

#[derive(Debug, Clone, PartialEq)]
enum State {
    WaitingForHandshake,
    InAuth,
    Ready,
    InQuery,
    InResponse {
        cols_expected: usize,
        cols_received: usize,
        past_col_eof: bool,
    },
}

pub struct MysqlParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    server_version: Option<String>,
    auth_plugin: Option<String>,
    query_ts: Option<u64>,
    query_text: Option<String>,
}

impl MysqlParser {
    pub fn new() -> Self {
        Self {
            state: State::WaitingForHandshake,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            server_version: None,
            auth_plugin: None,
            query_ts: None,
            query_text: None,
        }
    }

    fn try_read_packet(buf: &StreamBuffer) -> Option<(Vec<u8>, usize)> {
        let data = buf.data();
        if data.len() < 4 {
            return None;
        }
        let payload_len = data[0] as usize | (data[1] as usize) << 8 | (data[2] as usize) << 16;
        let total = 4 + payload_len;
        if data.len() < total {
            return None;
        }
        Some((data[4..total].to_vec(), total))
    }

    fn process(&mut self, ts: u64) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            match self.state.clone() {
                State::WaitingForHandshake => {
                    if !self.parse_handshake() {
                        break;
                    }
                }
                State::InAuth => {
                    if !self.complete_auth() {
                        break;
                    }
                }
                State::Ready => {
                    if !self.parse_command(ts) {
                        break;
                    }
                }
                State::InQuery => match self.parse_response(ts) {
                    Some(msg) => {
                        messages.push(msg);
                        self.state = State::Ready;
                    }
                    None => break,
                },
                State::InResponse {
                    cols_expected,
                    cols_received,
                    past_col_eof,
                } => match self.read_result_set(ts, cols_expected, cols_received, past_col_eof) {
                    RsResult::Done(msg) => {
                        messages.push(msg);
                        self.state = State::Ready;
                    }
                    RsResult::Progress(a, b, c) => {
                        self.state = State::InResponse {
                            cols_expected: a,
                            cols_received: b,
                            past_col_eof: c,
                        };
                        break;
                    }
                    RsResult::Need => break,
                },
            }
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn parse_handshake(&mut self) -> bool {
        let (payload, consumed) = match Self::try_read_packet(&self.server_buf) {
            Some(p) => p,
            None => {
                // If the agent attaches after the server greeting was already exchanged,
                // the first packet we observe can be a client auth packet or command.
                if let Some((client_payload, _)) = Self::try_read_packet(&self.client_buf) {
                    self.state = if !client_payload.is_empty()
                        && matches!(client_payload[0], COM_QUERY | COM_STMT_PREPARE)
                    {
                        State::Ready
                    } else {
                        State::InAuth
                    };
                    return true;
                }
                return false;
            }
        };
        self.server_buf.consume(consumed);
        if payload.is_empty() || payload[0] != 0x0a {
            self.state = State::Ready;
            return true;
        }
        if let Some(null_pos) = payload[1..].iter().position(|&b| b == 0) {
            self.server_version =
                Some(String::from_utf8_lossy(&payload[1..1 + null_pos]).into_owned());
        }
        let payload_str = String::from_utf8_lossy(&payload);
        if payload_str.contains("caching_sha2_password") {
            self.auth_plugin = Some("caching_sha2_password".into());
        } else if payload_str.contains("mysql_native_password") {
            self.auth_plugin = Some("mysql_native_password".into());
        }
        self.state = State::InAuth;
        true
    }

    fn complete_auth(&mut self) -> bool {
        if let Some((payload, c)) = Self::try_read_packet(&self.client_buf) {
            // Late attach recovery: if we already see a command packet, auth is done.
            // Drain a single pending auth ACK from server to avoid response misalignment.
            if !payload.is_empty() && matches!(payload[0], COM_QUERY | COM_STMT_PREPARE) {
                if let Some((server_payload, server_consumed)) =
                    Self::try_read_packet(&self.server_buf)
                    && !server_payload.is_empty()
                    && (server_payload[0] == OK_MARKER || server_payload[0] == ERR_MARKER)
                {
                    self.server_buf.consume(server_consumed);
                }
                self.state = State::Ready;
                return true;
            }
            self.client_buf.consume(c);
        }
        let (payload, consumed) = match Self::try_read_packet(&self.server_buf) {
            Some(p) => p,
            None => return false,
        };
        self.server_buf.consume(consumed);
        if !payload.is_empty() && (payload[0] == OK_MARKER || payload[0] == ERR_MARKER) {
            self.state = State::Ready;
            return true;
        }
        // Recovery: if auth response shape is unexpected, avoid getting stuck in InAuth.
        self.state = State::Ready;
        true
    }

    fn parse_command(&mut self, ts: u64) -> bool {
        let (payload, consumed) = match Self::try_read_packet(&self.client_buf) {
            Some(p) => p,
            None => return false,
        };
        self.client_buf.consume(consumed);
        if payload.is_empty() {
            return false;
        }
        match payload[0] {
            COM_QUERY | COM_STMT_PREPARE => {
                self.query_text = Some(String::from_utf8_lossy(&payload[1..]).into_owned());
                self.query_ts = Some(ts);
                self.state = State::InQuery;
                true
            }
            _ => true,
        }
    }

    fn parse_response(&mut self, ts: u64) -> Option<L7Message> {
        let (payload, consumed) = Self::try_read_packet(&self.server_buf)?;
        if payload.is_empty() {
            self.server_buf.consume(consumed);
            return None;
        }
        match payload[0] {
            OK_MARKER => {
                self.server_buf.consume(consumed);
                let mut m = self.build_msg(ts);
                m.status = Some(0);
                Some(m)
            }
            ERR_MARKER => {
                self.server_buf.consume(consumed);
                let mut m = self.build_msg(ts);
                if payload.len() >= 3 {
                    m.status = Some(u16::from_le_bytes([payload[1], payload[2]]) as u32);
                }
                if payload.len() > 9 && payload[3] == b'#' {
                    m.payload_text = Some(String::from_utf8_lossy(&payload[9..]).into_owned());
                } else if payload.len() > 3 {
                    m.payload_text = Some(String::from_utf8_lossy(&payload[3..]).into_owned());
                }
                Some(m)
            }
            _ => {
                self.server_buf.consume(consumed);
                match decode_lenenc(&payload) {
                    Some(cols) => {
                        self.state = State::InResponse {
                            cols_expected: cols as usize,
                            cols_received: 0,
                            past_col_eof: false,
                        };
                    }
                    None => {
                        // Malformed packet — insufficient bytes for lenenc integer.
                        // Treat as no result set; stay Ready so the connection survives.
                        self.state = State::Ready;
                    }
                }
                None
            }
        }
    }

    fn read_result_set(&mut self, ts: u64, ce: usize, mut cr: usize, mut past: bool) -> RsResult {
        loop {
            let (payload, consumed) = match Self::try_read_packet(&self.server_buf) {
                Some(p) => p,
                None => return RsResult::Progress(ce, cr, past),
            };
            self.server_buf.consume(consumed);
            if payload.is_empty() {
                continue;
            }
            if !past {
                if cr < ce {
                    cr += 1;
                    continue;
                }
                // MySQL 5.7: EOF delimiter; MySQL 8 with CLIENT_DEPRECATE_EOF: OK delimiter.
                if (payload[0] == EOF_MARKER && payload.len() < 9) || payload[0] == OK_MARKER {
                    past = true;
                    continue;
                }
                // Attach/resync tolerance: treat packet as first row if delimiter was missed.
                past = true;
            }

            if (payload[0] == EOF_MARKER && payload.len() < 9)
                || payload[0] == OK_MARKER
                || payload[0] == ERR_MARKER
            {
                let mut m = self.build_msg(ts);
                if payload[0] == ERR_MARKER && payload.len() >= 3 {
                    m.status = Some(u16::from_le_bytes([payload[1], payload[2]]) as u32);
                } else {
                    m.status = Some(0);
                }
                return RsResult::Done(m);
            }
        }
    }

    fn build_msg(&mut self, ts: u64) -> L7Message {
        let mut msg = L7Message::new(Protocol::Mysql, Direction::Ingress, ts);
        msg.method = Some("QUERY".into());
        if let Some(q) = self.query_text.take() {
            if let Some(cmd) = q.split_whitespace().next() {
                msg.method = Some(cmd.to_uppercase());
            }
            let cap = q.len().min(4096);
            msg.payload_text = Some(q[..cap].to_string());
        }
        if let Some(t) = self.query_ts.take() {
            msg.latency_ns = Some(ts.saturating_sub(t));
        }
        msg
    }

    pub fn current_state(&self) -> &'static str {
        match self.state {
            State::WaitingForHandshake => "waiting_for_handshake",
            State::InAuth => "in_auth",
            State::Ready => "ready",
            State::InQuery => "in_query",
            State::InResponse { .. } => "in_response",
        }
    }
}

enum RsResult {
    Done(L7Message),
    Progress(usize, usize, bool),
    Need,
}

fn decode_lenenc(data: &[u8]) -> Option<u64> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0..=0xFB => Some(data[0] as u64),
        0xFC if data.len() >= 3 => Some(u16::from_le_bytes([data[1], data[2]]) as u64),
        0xFD if data.len() >= 4 => {
            Some(data[1] as u64 | (data[2] as u64) << 8 | (data[3] as u64) << 16)
        }
        0xFE if data.len() >= 9 => Some(u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ])),
        _ => None, // insufficient bytes for this length-encoded integer
    }
}

impl ProtocolParser for MysqlParser {
    fn feed(&mut self, data: &[u8], direction: Direction, ts: u64) -> ParseResult {
        match direction {
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("MySQL server buffer overflow".into());
                }
            }
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("MySQL client buffer overflow".into());
                }
            }
        }
        self.process(ts)
    }
    fn protocol(&self) -> Protocol {
        Protocol::Mysql
    }
    fn state_name(&self) -> &'static str {
        self.current_state()
    }
    fn protocol_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut p = vec![
            (len & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
            seq,
        ];
        p.extend_from_slice(payload);
        p
    }

    fn make_greeting(version: &str, plugin: &str) -> Vec<u8> {
        let mut payload = vec![0x0a];
        payload.extend_from_slice(version.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&[1, 0, 0, 0]);
        payload.extend_from_slice(&[0xAA; 8]);
        payload.push(0);
        payload.extend_from_slice(&[0xFF, 0xFF, 0x21, 0x02, 0x00, 0xFF, 0xFF, 21]);
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(&[0xBB; 13]);
        payload.extend_from_slice(plugin.as_bytes());
        payload.push(0);
        make_packet(0, &payload)
    }

    #[test]
    fn test_version_detect_80() {
        let mut p = MysqlParser::new();
        p.feed(
            &make_greeting("8.0.32", "caching_sha2_password"),
            Direction::Ingress,
            0,
        );
        assert_eq!(p.server_version.as_deref(), Some("8.0.32"));
        assert_eq!(p.auth_plugin.as_deref(), Some("caching_sha2_password"));
    }

    #[test]
    fn test_version_detect_57() {
        let mut p = MysqlParser::new();
        p.feed(
            &make_greeting("5.7.44", "mysql_native_password"),
            Direction::Ingress,
            0,
        );
        assert_eq!(p.server_version.as_deref(), Some("5.7.44"));
        assert_eq!(p.auth_plugin.as_deref(), Some("mysql_native_password"));
    }

    #[test]
    fn test_query_ok() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 1");
        p.feed(&make_packet(0, &cmd), Direction::Egress, 1000);
        let result = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            2000,
        );
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
                assert_eq!(m[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_query_error() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"BAD SQL");
        p.feed(&make_packet(0, &cmd), Direction::Egress, 1000);
        let mut err = vec![ERR_MARKER];
        err.extend_from_slice(&1064u16.to_le_bytes());
        err.push(b'#');
        err.extend_from_slice(b"42000");
        err.extend_from_slice(b"syntax error");
        let result = p.feed(&make_packet(1, &err), Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m[0].status, Some(1064));
                assert!(m[0].payload_text.as_ref().unwrap().contains("syntax error"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_metadata() {
        let p = MysqlParser::new();
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Mysql);
        assert_eq!(p.current_state(), "waiting_for_handshake");
    }

    #[test]
    fn test_attach_after_handshake_still_parses_query() {
        let mut p = MysqlParser::new();

        // First observed packet is a client COM_QUERY (server greeting was missed).
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 1");
        assert!(matches!(
            p.feed(&make_packet(0, &cmd), Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));

        // Server OK response should still produce a MySQL message.
        let result = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            2000,
        );
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].protocol, Protocol::Mysql);
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_attach_mid_auth_no_response_shift() {
        let mut p = MysqlParser::new();

        // First observed client packet is an auth response (not a command).
        let auth_response = make_packet(1, &[0x85, 0, 0, 0, 0]);
        assert!(matches!(
            p.feed(&auth_response, Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));

        // Auth OK from server.
        assert!(matches!(
            p.feed(
                &make_packet(2, &[OK_MARKER, 0, 0, 2, 0]),
                Direction::Ingress,
                1500
            ),
            ParseResult::NeedMoreData
        ));

        // Real query should still align to its own response.
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 42");
        assert!(matches!(
            p.feed(&make_packet(0, &cmd), Direction::Egress, 2000),
            ParseResult::NeedMoreData
        ));

        let result = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            3000,
        );
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
                assert_eq!(m[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_resultset_ok_terminator_mysql8() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;

        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 1");
        assert!(matches!(
            p.feed(&make_packet(0, &cmd), Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));

        // Column count (1)
        assert!(matches!(
            p.feed(&make_packet(1, &[0x01]), Direction::Ingress, 1500),
            ParseResult::NeedMoreData
        ));
        // One column definition packet
        assert!(matches!(
            p.feed(&make_packet(2, b"col"), Direction::Ingress, 1600),
            ParseResult::NeedMoreData
        ));
        // MySQL 8 style OK delimiter for end of column definitions
        assert!(matches!(
            p.feed(
                &make_packet(3, &[OK_MARKER, 0, 0, 2, 0]),
                Direction::Ingress,
                1700
            ),
            ParseResult::NeedMoreData
        ));
        // One row payload
        assert!(matches!(
            p.feed(&make_packet(4, b"\x01"), Direction::Ingress, 1800),
            ParseResult::NeedMoreData
        ));
        // Final OK terminator for end of rows
        let result = p.feed(
            &make_packet(5, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            2200,
        );
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_lenenc() {
        // Valid encodings
        assert_eq!(decode_lenenc(&[5]), Some(5));
        assert_eq!(decode_lenenc(&[0xFC, 1, 0]), Some(1));
        assert_eq!(decode_lenenc(&[0xFC, 0xFF, 0xFF]), Some(65535));
        assert_eq!(decode_lenenc(&[0xFD, 1, 0, 0]), Some(1));
        // Bounds check: insufficient data must return None, not panic
        assert_eq!(decode_lenenc(&[]), None);
        assert_eq!(decode_lenenc(&[0xFD]), None); // 0xFD needs 4 bytes
        assert_eq!(decode_lenenc(&[0xFD, 1, 2]), None); // 3 bytes, needs 4
        assert_eq!(decode_lenenc(&[0xFC, 1]), None); // 0xFC needs 3 bytes
        assert_eq!(decode_lenenc(&[0xFE, 1, 2, 3, 4, 5, 6, 7]), None); // 0xFE needs 9 bytes
    }
}
