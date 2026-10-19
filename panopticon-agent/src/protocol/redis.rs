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
                RespParse::Complete(RespValue::Push(_), consumed) => {
                    // Out-of-band push: answers no command, keep the queue.
                    self.server_buf.consume(consumed);
                }
                RespParse::Complete(value, consumed) => {
                    self.server_buf.consume(consumed);

                    // Dequeue the oldest pending command (FIFO — correct for pipelining).
                    let mut msg = L7Message::new(Protocol::Redis, Direction::Ingress, timestamp_ns);
                    if let Some((parts, req_ts)) = self.pending_queue.pop_front() {
                        msg.method = Some(parts[0].to_uppercase());
                        if parts.len() > 1 {
                            msg.path = Some(parts[1].clone());
                        }
                        // Arguments after the key (SET value, HSET field/value
                        // pairs, ...) carry the data written: scan it for PII.
                        if parts.len() > 2 {
                            msg.request_text = Some(parts[2..].join(" "));
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
    /// RESP3 out-of-band push (pub/sub, client-side caching invalidation):
    /// not a reply to any pending command.
    Push(Vec<RespValue>),
}

enum RespParse {
    Complete(RespValue, usize), // value + bytes consumed
    Incomplete,
    Error(String),
}

/// Parse a single RESP value from the beginning of `data`.
/// Max nesting of RESP arrays. Parsing recurses per level and agent workers
/// run on small (2MB) tokio stacks; real commands/replies nest 1–3 deep.
const MAX_RESP_DEPTH: usize = 32;
/// Upper bound on elements pre-allocated for an array. The count is
/// peer-controlled: `Vec::with_capacity(huge)` aborts the whole process.
const MAX_PREALLOC_ELEMENTS: usize = 1024;

fn parse_resp_value(data: &[u8]) -> RespParse {
    parse_resp_value_at(data, 0)
}

fn parse_resp_value_at(data: &[u8], depth: usize) -> RespParse {
    if data.is_empty() {
        return RespParse::Incomplete;
    }

    match data[0] {
        b'+' => parse_simple_string(data),
        b'-' => parse_error(data),
        b':' => parse_integer(data),
        b'$' => parse_bulk_string(data),
        b'*' | b'%' | b'~' | b'>' | b'|' if depth >= MAX_RESP_DEPTH => {
            RespParse::Error(format!("RESP nesting deeper than {MAX_RESP_DEPTH}"))
        }
        b'*' => parse_array(data, depth),
        // ── RESP3 (negotiated with HELLO 3; default in current clients) ──
        b'_' => match find_crlf(data) {
            Some(pos) => RespParse::Complete(RespValue::BulkString(None), pos + 2),
            None => RespParse::Incomplete,
        },
        b'#' | b',' | b'(' => match find_crlf(data) {
            // boolean / double / big number: keep the literal text
            Some(pos) => RespParse::Complete(
                RespValue::SimpleString(String::from_utf8_lossy(&data[1..pos]).into_owned()),
                pos + 2,
            ),
            None => RespParse::Incomplete,
        },
        b'!' => match parse_bulk_string(data) {
            RespParse::Complete(RespValue::BulkString(b), n) => RespParse::Complete(
                RespValue::Error(String::from_utf8_lossy(&b.unwrap_or_default()).into_owned()),
                n,
            ),
            other => other,
        },
        b'=' => match parse_bulk_string(data) {
            // verbatim string: "txt:" / "mkd:" format prefix
            RespParse::Complete(RespValue::BulkString(Some(b)), n) => RespParse::Complete(
                RespValue::BulkString(Some(b.get(4..).unwrap_or_default().to_vec())),
                n,
            ),
            other => other,
        },
        b'%' => parse_aggregate(data, depth, 2, |v| RespValue::Array(Some(v))),
        b'~' => parse_aggregate(data, depth, 1, |v| RespValue::Array(Some(v))),
        b'>' => parse_aggregate(data, depth, 1, RespValue::Push),
        b'|' => {
            // Attribute: metadata map that precedes the actual reply.
            match parse_aggregate(data, depth, 2, |v| RespValue::Array(Some(v))) {
                RespParse::Complete(_, attr_len) => {
                    match parse_resp_value_at(&data[attr_len..], depth + 1) {
                        RespParse::Complete(value, n) => RespParse::Complete(value, attr_len + n),
                        other => other,
                    }
                }
                other => other,
            }
        }
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

/// RESP3 aggregate: `<type><count>\r\n` followed by `count * per_entry`
/// values (2 per entry for maps and attributes, 1 for sets and pushes).
fn parse_aggregate(
    data: &[u8],
    depth: usize,
    per_entry: usize,
    wrap: impl FnOnce(Vec<RespValue>) -> RespValue,
) -> RespParse {
    let crlf_pos = match find_crlf(data) {
        Some(pos) => pos,
        None => return RespParse::Incomplete,
    };
    let count_str = std::str::from_utf8(&data[1..crlf_pos]).unwrap_or("");
    let count: usize = match count_str.parse() {
        Ok(n) => n,
        Err(_) => return RespParse::Error(format!("invalid RESP3 count: {count_str}")),
    };
    let total = count.saturating_mul(per_entry);
    let mut offset = crlf_pos + 2;
    let mut elements = Vec::with_capacity(total.min(MAX_PREALLOC_ELEMENTS));
    for _ in 0..total {
        if offset >= data.len() {
            return RespParse::Incomplete;
        }
        match parse_resp_value_at(&data[offset..], depth + 1) {
            RespParse::Complete(value, consumed) => {
                elements.push(value);
                offset += consumed;
            }
            other => return other,
        }
    }
    RespParse::Complete(wrap(elements), offset)
}

/// Parse `*<count>\r\n<elements...>` or `*-1\r\n` (null)
fn parse_array(data: &[u8], depth: usize) -> RespParse {
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
    // Grow as elements actually arrive; never trust the declared count.
    let mut elements = Vec::with_capacity((count as usize).min(MAX_PREALLOC_ELEMENTS));

    for _ in 0..count {
        if offset >= data.len() {
            return RespParse::Incomplete;
        }
        match parse_resp_value_at(&data[offset..], depth + 1) {
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
        RespValue::Array(Some(elements)) | RespValue::Push(elements) => {
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
    fn test_get_missing_key_returns_null_bulk() {
        let mut parser = RedisParser::new();
        parser.feed(
            b"*2\r\n$3\r\nGET\r\n$8\r\no:tok_5_\r\n",
            Direction::Egress,
            1000,
        );
        match parser.feed(b"$-1\r\n", Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("o:tok_5_"));
            }
            other => panic!("expected GET message for a null reply, got {other:?}"),
        }
    }

    #[test]
    fn test_resp3_replies() {
        // HELLO 3 map reply, RESP3 null, boolean, double, verbatim, blob error.
        let mut parser = RedisParser::new();
        let cmds = b"*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n\
            *2\r\n$3\r\nGET\r\n$4\r\nnone\r\n\
            *2\r\n$6\r\nEXISTS\r\n$1\r\nk\r\n\
            *2\r\n$5\r\nSCORE\r\n$1\r\nk\r\n\
            *2\r\n$4\r\nINFO\r\n$1\r\nk\r\n\
            *2\r\n$4\r\nFAIL\r\n$1\r\nk\r\n";
        parser.feed(cmds, Direction::Egress, 1000);
        let replies = b"%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n\
            _\r\n\
            >2\r\n$10\r\ninvalidate\r\n*1\r\n$1\r\nk\r\n\
            #t\r\n\
            ,3.14\r\n\
            |1\r\n$3\r\nttl\r\n:5\r\n=9\r\ntxt:hello\r\n\
            !10\r\nERR boom!!\r\n";
        match parser.feed(replies, Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                let got: Vec<_> = msgs
                    .iter()
                    .map(|m| {
                        (
                            m.method.clone().unwrap(),
                            m.status.unwrap(),
                            m.payload_text.clone(),
                        )
                    })
                    .collect();
                assert_eq!(got.len(), 6, "{got:?}"); // the push answers nothing
                assert_eq!(got[1], ("GET".into(), 0, Some("(nil)".into())));
                assert_eq!(got[2].2.as_deref(), Some("t"));
                assert_eq!(got[3].2.as_deref(), Some("3.14"));
                assert_eq!(got[4].2.as_deref(), Some("hello"));
                assert_eq!(got[5].1, 1);
            }
            other => panic!("expected RESP3 replies, got {other:?}"),
        }
    }

    #[test]
    fn test_set_value_is_request_text() {
        let mut parser = RedisParser::new();
        parser.feed(
            b"*3\r\n$3\r\nSET\r\n$4\r\nuser\r\n$17\r\nbob@example.com!!\r\n",
            Direction::Egress,
            1000,
        );
        match parser.feed(b"+OK\r\n", Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].request_text.as_deref(), Some("bob@example.com!!"));
            }
            other => panic!("expected SET message, got {other:?}"),
        }
    }

    #[test]
    fn test_huge_array_count_does_not_abort() {
        // Found by fuzzing: a peer-declared count was passed straight to
        // Vec::with_capacity, aborting the whole agent process.
        let mut parser = RedisParser::new();
        let _ = parser.feed(b"*99999999999999\r\n$3\r\nGET\r\n", Direction::Egress, 1000);
        let _ = parser.feed(b"*9223372036854775807\r\n", Direction::Ingress, 2000);
    }

    #[test]
    fn test_deep_nesting_is_rejected_without_stack_overflow() {
        // 100k nested arrays would recurse 100k frames; workers run on small
        // stacks, so run on a 256KB thread to prove the depth limit holds.
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let nested = b"*1\r\n".repeat(100_000);
                assert!(matches!(parse_resp_value(&nested), RespParse::Error(_)));
            })
            .unwrap();
        handle
            .join()
            .expect("deep RESP nesting must not overflow the stack");
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
