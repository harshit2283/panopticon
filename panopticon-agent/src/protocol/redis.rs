#![allow(dead_code)]

//! Redis RESP protocol parser.
//!
//! RESP (Redis Serialization Protocol) is line-delimited with type prefixes:
//! - `+` Simple String
//! - `-` Error
//! - `:` Integer
//! - `$` Bulk String (length-prefixed)
//! - `*` Array (element count)
//!
//! Hand-written recursive descent — no `nom` needed for this simple format.

use std::collections::VecDeque;

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Parser State ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Waiting for a command (client) or response (server).
    Idle,
    /// Parsing an in-progress value.
    Parsing,
}

/// Redis RESP protocol parser.
pub struct RedisParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    /// Queue of pending (command_parts, request_timestamp) entries.
    /// VecDeque enables correct pipelining: each response dequeues the oldest request.
    pending_queue: VecDeque<(Vec<String>, u64)>,
}

impl RedisParser {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            pending_queue: VecDeque::new(),
        }
    }

    /// Try to parse complete RESP values from the client buffer.
    fn try_parse_request(&mut self, timestamp_ns: u64) -> ParseResult {
        let messages: Vec<L7Message> = Vec::new();

        loop {
            let data = self.client_buf.data();
            if data.is_empty() {
                break;
            }

            match parse_resp_value(data) {
                RespParse::Complete(value, consumed) => {
                    self.client_buf.consume(consumed);

                    // Enqueue this command — VecDeque preserves order for pipelining.
                    let parts = flatten_to_strings(&value);
                    if !parts.is_empty() {
                        self.pending_queue.push_back((parts, timestamp_ns));
                    }
                    self.state = State::Idle;
                }
                RespParse::Incomplete => {
                    self.state = State::Parsing;
                    break;
                }
                RespParse::Error(e) => return ParseResult::Error(e),
            }
        }

        if !messages.is_empty() {
            ParseResult::Messages(messages)
        } else {
            ParseResult::NeedMoreData
        }
    }

    /// Try to parse complete RESP values from the server buffer and produce L7Messages.
    fn try_parse_response(&mut self, timestamp_ns: u64) -> ParseResult {
        let mut messages = Vec::new();

        loop {
            let data = self.server_buf.data();
            if data.is_empty() {
                break;
            }

            match parse_resp_value(data) {
                RespParse::Complete(value, consumed) => {
                    self.server_buf.consume(consumed);

                    // Dequeue the oldest pending command (FIFO — correct for pipelining).
                    let mut msg = L7Message::new(Protocol::Redis, Direction::Ingress, timestamp_ns);
                    if let Some((parts, req_ts)) = self.pending_queue.pop_front() {
                        msg.method = Some(parts[0].to_uppercase());
                        if parts.len() > 1 {
                            msg.path = Some(parts[1].clone());
                        }
                        msg.latency_ns = Some(timestamp_ns.saturating_sub(req_ts));
                    }

                    // Check for error response
                    if let RespValue::Error(e) = &value {
                        msg.status = Some(1); // non-zero = error
                        msg.payload_text = Some(e.clone());
                    } else {
                        msg.status = Some(0);
                        msg.payload_text = resp_value_to_text(&value);
                    }

                    messages.push(msg);
                    self.state = State::Idle;
                }
                RespParse::Incomplete => {
                    self.state = State::Parsing;
                    break;
                }
                RespParse::Error(e) => return ParseResult::Error(e),
            }
        }

        if !messages.is_empty() {
            ParseResult::Messages(messages)
        } else {
            ParseResult::NeedMoreData
        }
    }

    pub fn current_state(&self) -> &'static str {
        match self.state {
            State::Idle => "idle",
            State::Parsing => "parsing",
        }
    }

    pub fn reset_for_next_transaction(&mut self) {
        self.pending_queue.clear();
        self.client_buf.clear();
        self.server_buf.clear();
        self.state = State::Idle;
    }
}

impl ProtocolParser for RedisParser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        match direction {
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("Redis client buffer overflow".into());
                }
                self.try_parse_request(timestamp_ns)
            }
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("Redis server buffer overflow".into());
                }
                self.try_parse_response(timestamp_ns)
            }
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Redis
    }

    fn state_name(&self) -> &'static str {
        self.current_state()
    }
}

// ── RESP Value Types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),   // None = null bulk string
    Array(Option<Vec<RespValue>>), // None = null array
}

enum RespParse {
    Complete(RespValue, usize), // value + bytes consumed
    Incomplete,
    Error(String),
}

/// Parse a single RESP value from the beginning of `data`.
fn parse_resp_value(data: &[u8]) -> RespParse {
    if data.is_empty() {
        return RespParse::Incomplete;
    }

    match data[0] {
        b'+' => parse_simple_string(data),
        b'-' => parse_error(data),
        b':' => parse_integer(data),
        b'$' => parse_bulk_string(data),
        b'*' => parse_array(data),
        _ => RespParse::Error(format!("unknown RESP type byte: 0x{:02x}", data[0])),
    }
}

/// Find `\r\n` in data, returning the index of `\r`.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Parse `+<string>\r\n`
fn parse_simple_string(data: &[u8]) -> RespParse {
    match find_crlf(data) {
        Some(pos) => {
            let s = String::from_utf8_lossy(&data[1..pos]).into_owned();
            RespParse::Complete(RespValue::SimpleString(s), pos + 2)
        }
        None => RespParse::Incomplete,
    }
}

/// Parse `-<error>\r\n`
fn parse_error(data: &[u8]) -> RespParse {
    match find_crlf(data) {
        Some(pos) => {
            let s = String::from_utf8_lossy(&data[1..pos]).into_owned();
            RespParse::Complete(RespValue::Error(s), pos + 2)
        }
        None => RespParse::Incomplete,
    }
}

/// Parse `:<integer>\r\n`
fn parse_integer(data: &[u8]) -> RespParse {
    match find_crlf(data) {
        Some(pos) => {
            let s = std::str::from_utf8(&data[1..pos]).unwrap_or("0");
            match s.parse::<i64>() {
                Ok(n) => RespParse::Complete(RespValue::Integer(n), pos + 2),
                Err(_) => RespParse::Error(format!("invalid RESP integer: {s}")),
            }
        }
        None => RespParse::Incomplete,
    }
}

/// Parse `$<len>\r\n<data>\r\n` or `$-1\r\n` (null)
fn parse_bulk_string(data: &[u8]) -> RespParse {
    let crlf_pos = match find_crlf(data) {
        Some(pos) => pos,
        None => return RespParse::Incomplete,
    };

    let len_str = std::str::from_utf8(&data[1..crlf_pos]).unwrap_or("");
    let len: i64 = match len_str.parse() {
        Ok(n) => n,
        Err(_) => return RespParse::Error(format!("invalid bulk string length: {len_str}")),
    };

    if len < 0 {
        // Null bulk string
        return RespParse::Complete(RespValue::BulkString(None), crlf_pos + 2);
    }

    let len = len as usize;
    let data_start = crlf_pos + 2;
    let data_end = data_start + len;
    let total = data_end + 2; // +2 for trailing \r\n

    if data.len() < total {
        return RespParse::Incomplete;
    }

    let bytes = data[data_start..data_end].to_vec();
    RespParse::Complete(RespValue::BulkString(Some(bytes)), total)
}

/// Parse `*<count>\r\n<elements...>` or `*-1\r\n` (null)
fn parse_array(data: &[u8]) -> RespParse {
    let crlf_pos = match find_crlf(data) {
        Some(pos) => pos,
        None => return RespParse::Incomplete,
    };

    let count_str = std::str::from_utf8(&data[1..crlf_pos]).unwrap_or("");
    let count: i64 = match count_str.parse() {
        Ok(n) => n,
        Err(_) => return RespParse::Error(format!("invalid array count: {count_str}")),
    };

    if count < 0 {
        return RespParse::Complete(RespValue::Array(None), crlf_pos + 2);
    }

    let mut offset = crlf_pos + 2;
    let mut elements = Vec::with_capacity(count as usize);

    for _ in 0..count {
        if offset >= data.len() {
            return RespParse::Incomplete;
        }
        match parse_resp_value(&data[offset..]) {
            RespParse::Complete(value, consumed) => {
                elements.push(value);
                offset += consumed;
            }
            RespParse::Incomplete => return RespParse::Incomplete,
            RespParse::Error(e) => return RespParse::Error(e),
        }
    }

    RespParse::Complete(RespValue::Array(Some(elements)), offset)
}

/// Extract string values from a RESP value (for command parsing).
fn flatten_to_strings(value: &RespValue) -> Vec<String> {
    match value {
        RespValue::Array(Some(elements)) => {
            elements.iter().filter_map(resp_element_to_string).collect()
        }
        _ => {
            if let Some(s) = resp_element_to_string(value) {
                vec![s]
            } else {
                vec![]
            }
        }
    }
}

fn resp_element_to_string(value: &RespValue) -> Option<String> {
    match value {
        RespValue::SimpleString(s) => Some(s.clone()),
        RespValue::BulkString(Some(bytes)) => Some(String::from_utf8_lossy(bytes).into_owned()),
        RespValue::Integer(n) => Some(n.to_string()),
        _ => None,
    }
}

fn resp_value_to_text(value: &RespValue) -> Option<String> {
    match value {
        RespValue::SimpleString(s) => Some(s.clone()),
        RespValue::BulkString(Some(bytes)) => Some(String::from_utf8_lossy(bytes).into_owned()),
        RespValue::BulkString(None) => Some("(nil)".into()),
        RespValue::Integer(n) => Some(format!("(integer) {n}")),
        RespValue::Error(e) => Some(format!("(error) {e}")),
        RespValue::Array(None) => Some("(nil)".into()),
        RespValue::Array(Some(elements)) => {
            let parts: Vec<String> = elements.iter().filter_map(resp_value_to_text).collect();
            Some(parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_set_command() {
        let mut parser = RedisParser::new();

        // Client sends: *3\r\n$3\r\nSET\r\n$8\r\nuser:123\r\n$5\r\nhello\r\n
        // Note: "user:123" is 8 bytes, so the correct RESP length prefix is $8.
        let cmd = b"*3\r\n$3\r\nSET\r\n$8\r\nuser:123\r\n$5\r\nhello\r\n";
        let result = parser.feed(cmd, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        // Server responds: +OK\r\n
        let resp = b"+OK\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SET"));
                assert_eq!(msgs[0].path.as_deref(), Some("user:123"));
                assert_eq!(msgs[0].status, Some(0));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_get_command() {
        let mut parser = RedisParser::new();

        let cmd = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b"$5\r\nhello\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("mykey"));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("hello"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_multi_packet_bulk_string() {
        let mut parser = RedisParser::new();

        // Send GET command
        let cmd = b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        // Server response split across three packets ("helloworld" = 10 bytes).
        // $10\r\n declares a 10-byte bulk string: "hell"(4) + "oworl"(5) + "d"(1) = "helloworld".
        let resp1 = b"$10\r\nhell";
        let result = parser.feed(resp1, Direction::Ingress, 2000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let resp2 = b"oworl";
        let result = parser.feed(resp2, Direction::Ingress, 2000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let resp3 = b"d\r\n";
        let result = parser.feed(resp3, Direction::Ingress, 3000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].payload_text.as_deref(), Some("helloworld"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_error_response() {
        let mut parser = RedisParser::new();

        let cmd = b"*1\r\n$4\r\nINFO\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b"-ERR unknown command 'INFO'\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].status, Some(1));
                assert!(msgs[0].payload_text.as_ref().unwrap().contains("ERR"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_pipeline() {
        let mut parser = RedisParser::new();

        // Client sends two commands back-to-back (pipeline) at the same timestamp
        let cmd =
            b"*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\n1\r\n*3\r\n$3\r\nSET\r\n$1\r\nb\r\n$1\r\n2\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        // Server responds with two +OK — must produce exactly 2 messages, in order
        let resp = b"+OK\r\n+OK\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(
                    msgs.len(),
                    2,
                    "pipelined requests must each produce a message"
                );
                assert_eq!(msgs[0].method.as_deref(), Some("SET"));
                assert_eq!(msgs[0].path.as_deref(), Some("a"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
                assert_eq!(msgs[1].method.as_deref(), Some("SET"));
                assert_eq!(msgs[1].path.as_deref(), Some("b"));
                assert_eq!(msgs[1].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_null_bulk_string() {
        let mut parser = RedisParser::new();

        let cmd = b"*2\r\n$3\r\nGET\r\n$11\r\nnonexistent\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b"$-1\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].payload_text.as_deref(), Some("(nil)"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_integer_response() {
        let mut parser = RedisParser::new();

        let cmd = b"*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b":42\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("INCR"));
                assert_eq!(msgs[0].path.as_deref(), Some("counter"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_parser_protocol() {
        let parser = RedisParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Redis);
        assert_eq!(parser.state_name(), "idle");
    }

    #[test]
    fn test_current_state() {
        let mut parser = RedisParser::new();
        assert_eq!(parser.current_state(), "idle");

        parser.state = State::Parsing;
        assert_eq!(parser.current_state(), "parsing");
    }

    #[test]
    fn test_reset_for_next_transaction() {
        let mut parser = RedisParser::new();

        parser.client_buf.extend(b"data").unwrap();
        parser.server_buf.extend(b"response").unwrap();
        parser.pending_queue.push_back((vec!["GET".into()], 1000));
        parser.state = State::Parsing;

        parser.reset_for_next_transaction();

        assert!(parser.client_buf.is_empty());
        assert!(parser.server_buf.is_empty());
        assert!(parser.pending_queue.is_empty());
        assert_eq!(parser.state, State::Idle);
    }
}
