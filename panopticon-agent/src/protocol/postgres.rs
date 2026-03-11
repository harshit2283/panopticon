#![allow(dead_code)]

//! PostgreSQL wire protocol parser.
//!
//! Wire format: 1-byte message type + 4-byte length + payload.
//! StartupMessage has no type byte (length + protocol version instead).

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

#[derive(Debug, Clone, PartialEq)]
enum State {
    WaitingForStartup,
    InAuth,
    Ready,
    InSimpleQuery,
    InExtendedQuery,
    InResponse,
}

pub struct PostgresParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    server_version: Option<String>,
    query_ts: Option<u64>,
    query_text: Option<String>,
    /// Error message accumulated from `E` (ErrorResponse) — emitted on `Z` (ReadyForQuery).
    pending_error: Option<String>,
    /// Non-zero status from `E`; overrides the default success status on emit.
    pending_status: Option<u32>,
}

impl PostgresParser {
    pub fn new() -> Self {
        Self {
            state: State::WaitingForStartup,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            server_version: None,
            query_ts: None,
            query_text: None,
            pending_error: None,
            pending_status: None,
        }
    }

    /// Read a standard backend message: type(1) + length(4) + payload
    fn try_read_backend_msg(buf: &StreamBuffer) -> Option<(u8, Vec<u8>, usize)> {
        let data = buf.data();
        if data.len() < 5 {
            return None;
        }
        let msg_type = data[0];
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if len < 4 {
            return None;
        }
        let total = 1 + len;
        if data.len() < total {
            return None;
        }
        let payload = data[5..total].to_vec();
        Some((msg_type, payload, total))
    }

    /// Read a frontend message: type(1) + length(4) + payload
    fn try_read_frontend_msg(buf: &StreamBuffer) -> Option<(u8, Vec<u8>, usize)> {
        Self::try_read_backend_msg(buf) // same format
    }

    /// Read a startup message (no type byte): length(4) + version(4) + params
    fn try_read_startup(buf: &StreamBuffer) -> Option<(Vec<u8>, usize)> {
        let data = buf.data();
        if data.len() < 8 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if !(8..=10000).contains(&len) {
            return None;
        }
        if data.len() < len {
            return None;
        }
        Some((data[4..len].to_vec(), len))
    }

    fn process(&mut self, ts: u64) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            match self.state.clone() {
                State::WaitingForStartup => {
                    if !self.handle_startup() {
                        break;
                    }
                }
                State::InAuth => {
                    if !self.handle_auth() {
                        break;
                    }
                }
                State::Ready => {
                    if !self.handle_ready(ts) {
                        break;
                    }
                }
                State::InSimpleQuery | State::InExtendedQuery | State::InResponse => {
                    match self.handle_response(ts) {
                        Some(msg) => {
                            messages.push(msg);
                            self.state = State::Ready;
                        }
                        None => break,
                    }
                }
            }
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn handle_startup(&mut self) -> bool {
        // Try reading startup from client
        if let Some((_payload, consumed)) = Self::try_read_startup(&self.client_buf) {
            self.client_buf.consume(consumed);
            self.state = State::InAuth;
            return true;
        }
        // Also check if server sends first (e.g., SSL response)
        if let Some((msg_type, _payload, consumed)) = Self::try_read_backend_msg(&self.server_buf) {
            self.server_buf.consume(consumed);
            if msg_type == b'N' || msg_type == b'S' {
                // N = SSL not supported, S = SSL supported, or ParameterStatus
                return true;
            }
        }
        false
    }

    fn handle_auth(&mut self) -> bool {
        // Consume client auth messages
        while let Some((_type, _payload, consumed)) = Self::try_read_frontend_msg(&self.client_buf)
        {
            self.client_buf.consume(consumed);
        }

        // Process server messages
        while let Some((msg_type, payload, consumed)) = Self::try_read_backend_msg(&self.server_buf)
        {
            self.server_buf.consume(consumed);
            match msg_type {
                b'R' => {
                    // Authentication messages
                    if payload.len() >= 4 {
                        let auth_type =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if auth_type == 0 {
                            // AuthenticationOk — but don't transition yet, wait for ReadyForQuery
                        }
                    }
                }
                b'S' => {
                    // ParameterStatus: name\0value\0
                    self.parse_parameter_status(&payload);
                }
                b'K' => {} // BackendKeyData — skip
                b'Z' => {
                    // ReadyForQuery — auth complete
                    self.state = State::Ready;
                    return true;
                }
                b'E' => {
                    // ErrorResponse during auth
                    self.state = State::Ready;
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    fn handle_ready(&mut self, ts: u64) -> bool {
        let (msg_type, payload, consumed) = match Self::try_read_frontend_msg(&self.client_buf) {
            Some(m) => m,
            None => return false,
        };
        self.client_buf.consume(consumed);

        match msg_type {
            b'Q' => {
                // Simple Query
                let query = extract_string(&payload);
                self.query_text = Some(query);
                self.query_ts = Some(ts);
                self.state = State::InSimpleQuery;
                true
            }
            b'P' => {
                // Parse (extended query): name\0 + query\0 + param types
                let query = extract_second_string(&payload);
                self.query_text = Some(query);
                self.query_ts = Some(ts);
                self.state = State::InExtendedQuery;
                true
            }
            b'B' | b'D' | b'E' | b'H' | b'S' => {
                // Bind, Describe, Execute, Flush, Sync — part of extended query
                if self.query_text.is_some() {
                    self.state = State::InExtendedQuery;
                }
                true
            }
            b'X' => false, // Terminate
            _ => true,
        }
    }

    fn handle_response(&mut self, ts: u64) -> Option<L7Message> {
        loop {
            let (msg_type, payload, consumed) = Self::try_read_backend_msg(&self.server_buf)?;
            self.server_buf.consume(consumed);

            match msg_type {
                b'T' => {} // RowDescription — skip
                b'D' => {} // DataRow — skip
                b'C' => {
                    // CommandComplete: tag\0
                    let _tag = extract_string(&payload);
                    // Don't emit yet — wait for ReadyForQuery
                }
                b'E' => {
                    // ErrorResponse — stash the error; emit on ReadyForQuery so query_text
                    // isn't consumed here (build_msg would clear it via take()).
                    self.pending_error = Some(parse_error_response(&payload));
                    self.pending_status = Some(1);
                }
                b'Z' => {
                    // ReadyForQuery — build message from accumulated query state + any error.
                    let mut msg = self.build_msg(ts);
                    msg.status = Some(self.pending_status.take().unwrap_or(0));
                    if let Some(err) = self.pending_error.take() {
                        // Error message takes precedence over query text in payload_text.
                        msg.payload_text = Some(err);
                    }
                    return Some(msg);
                }
                b'S' => {
                    // ParameterStatus (can arrive during query)
                    self.parse_parameter_status(&payload);
                }
                b'I' => {}                                    // EmptyQueryResponse
                b'1' | b'2' | b'3' | b'n' | b's' | b't' => {} // Extended query sub-responses
                _ => {}
            }
        }
    }

    fn parse_parameter_status(&mut self, payload: &[u8]) {
        // Format: name\0value\0
        if let Some(null_pos) = payload.iter().position(|&b| b == 0) {
            let name = String::from_utf8_lossy(&payload[..null_pos]);
            if name == "server_version" && null_pos + 1 < payload.len() {
                let rest = &payload[null_pos + 1..];
                if let Some(end) = rest.iter().position(|&b| b == 0) {
                    self.server_version = Some(String::from_utf8_lossy(&rest[..end]).into_owned());
                } else {
                    self.server_version = Some(String::from_utf8_lossy(rest).into_owned());
                }
            }
        }
    }

    fn build_msg(&mut self, ts: u64) -> L7Message {
        let mut msg = L7Message::new(Protocol::Postgres, Direction::Ingress, ts);
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

    fn current_state(&self) -> &'static str {
        match self.state {
            State::WaitingForStartup => "waiting_for_startup",
            State::InAuth => "in_auth",
            State::Ready => "ready",
            State::InSimpleQuery => "in_simple_query",
            State::InExtendedQuery => "in_extended_query",
            State::InResponse => "in_response",
        }
    }
}

fn extract_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn extract_second_string(data: &[u8]) -> String {
    // Skip first null-terminated string, return second
    if let Some(first_null) = data.iter().position(|&b| b == 0) {
        let rest = &data[first_null + 1..];
        extract_string(rest)
    } else {
        extract_string(data)
    }
}

fn parse_error_response(data: &[u8]) -> String {
    // ErrorResponse: series of type(1) + string\0, terminated by \0
    let mut message = String::new();
    let mut i = 0;
    while i < data.len() && data[i] != 0 {
        let field_type = data[i] as char;
        i += 1;
        let end = data[i..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - i);
        let value = String::from_utf8_lossy(&data[i..i + end]);
        if field_type == 'M' {
            message = value.into_owned();
        }
        i += end + 1;
    }
    message
}

impl ProtocolParser for PostgresParser {
    fn feed(&mut self, data: &[u8], direction: Direction, ts: u64) -> ParseResult {
        match direction {
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("PG server buffer overflow".into());
                }
            }
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("PG client buffer overflow".into());
                }
            }
        }
        self.process(ts)
    }
    fn protocol(&self) -> Protocol {
        Protocol::Postgres
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

    fn make_backend_msg(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let len = (4 + payload.len()) as u32;
        let mut pkt = vec![msg_type];
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    fn make_frontend_msg(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        make_backend_msg(msg_type, payload) // same format
    }

    fn make_startup_msg() -> Vec<u8> {
        // length(4) + version 3.0(4) + "user\0test\0\0"
        let params = b"user\0test\0\0";
        let len = (8 + params.len()) as u32;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&196608u32.to_be_bytes()); // v3.0
        pkt.extend_from_slice(params);
        pkt
    }

    fn setup_ready_parser() -> PostgresParser {
        let mut p = PostgresParser::new();
        // Feed startup
        p.feed(&make_startup_msg(), Direction::Egress, 0);
        // Feed auth ok
        p.feed(
            &make_backend_msg(b'R', &0u32.to_be_bytes()),
            Direction::Ingress,
            0,
        );
        // Feed ParameterStatus for server_version
        let mut param = b"server_version\0".to_vec();
        param.extend_from_slice(b"15.4\0");
        p.feed(&make_backend_msg(b'S', &param), Direction::Ingress, 0);
        // Feed ReadyForQuery
        p.feed(&make_backend_msg(b'Z', &[b'I']), Direction::Ingress, 0);
        p
    }

    #[test]
    fn test_startup_and_auth() {
        let p = setup_ready_parser();
        assert_eq!(p.state, State::Ready);
        assert_eq!(p.server_version.as_deref(), Some("15.4"));
    }

    #[test]
    fn test_simple_query() {
        let mut p = setup_ready_parser();

        // Send simple query
        let query = b"SELECT 1\0";
        p.feed(&make_frontend_msg(b'Q', query), Direction::Egress, 1000);

        // Server: RowDescription + DataRow + CommandComplete + ReadyForQuery
        let mut response = Vec::new();
        response.extend_from_slice(&make_backend_msg(
            b'T',
            &[
                0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
            ],
        ));
        response.extend_from_slice(&make_backend_msg(b'D', &[0, 1, 0, 0, 0, 1, b'1']));
        response.extend_from_slice(&make_backend_msg(b'C', b"SELECT 1\0"));
        response.extend_from_slice(&make_backend_msg(b'Z', &[b'I']));

        let result = p.feed(&response, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
                assert!(msgs[0].payload_text.as_ref().unwrap().contains("SELECT 1"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_extended_query() {
        let mut p = setup_ready_parser();

        // Parse message: name\0 + query\0 + num_params(2)
        let mut parse_payload = Vec::new();
        parse_payload.extend_from_slice(b"stmt\0");
        parse_payload.extend_from_slice(b"SELECT $1\0");
        parse_payload.extend_from_slice(&0u16.to_be_bytes());
        p.feed(
            &make_frontend_msg(b'P', &parse_payload),
            Direction::Egress,
            1000,
        );

        // Server responses for extended query
        let mut response = Vec::new();
        response.extend_from_slice(&make_backend_msg(b'1', &[])); // ParseComplete
        response.extend_from_slice(&make_backend_msg(b'2', &[])); // BindComplete
        response.extend_from_slice(&make_backend_msg(
            b'T',
            &[
                0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
            ],
        ));
        response.extend_from_slice(&make_backend_msg(b'D', &[0, 1, 0, 0, 0, 1, b'1']));
        response.extend_from_slice(&make_backend_msg(b'C', b"SELECT 1\0"));
        response.extend_from_slice(&make_backend_msg(b'Z', &[b'I']));

        let result = p.feed(&response, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_error_response() {
        let mut p = setup_ready_parser();

        p.feed(
            &make_frontend_msg(b'Q', b"BAD SQL\0"),
            Direction::Egress,
            1000,
        );

        let mut err_payload = Vec::new();
        err_payload.push(b'S');
        err_payload.extend_from_slice(b"ERROR\0");
        err_payload.push(b'M');
        err_payload.extend_from_slice(b"syntax error\0");
        err_payload.push(b'C');
        err_payload.extend_from_slice(b"42601\0");
        err_payload.push(0); // terminator

        let mut response = Vec::new();
        response.extend_from_slice(&make_backend_msg(b'E', &err_payload));
        response.extend_from_slice(&make_backend_msg(b'Z', &[b'I']));

        let result = p.feed(&response, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                // query was set
                assert!(msgs[0].payload_text.is_some());
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_version_detection() {
        let mut p = PostgresParser::new();
        p.feed(&make_startup_msg(), Direction::Egress, 0);

        // ParameterStatus with server_version
        let mut param = b"server_version\0".to_vec();
        param.extend_from_slice(b"16.1\0");
        p.feed(&make_backend_msg(b'S', &param), Direction::Ingress, 0);

        assert_eq!(ProtocolParser::protocol_version(&p), Some("16.1"));
    }

    #[test]
    fn test_metadata() {
        let p = PostgresParser::new();
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Postgres);
        assert_eq!(p.state_name(), "waiting_for_startup");
    }
}
