//! HTTP/1.1 protocol parser.
//!
//! Uses the `httparse` crate for zero-copy header parsing. Handles:
//! - Content-Length body accumulation
//! - Chunked transfer-encoding
//! - Keep-Alive: emit L7Message on complete response, reset for next transaction
//! - Latency calculation from request→response timestamps

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Parser State ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum State {
    /// Waiting for an HTTP request from the client.
    WaitingForRequest,
    /// Accumulating request body bytes.
    ReadingRequestBody { remaining: usize },
    /// Request complete, waiting for response from server.
    WaitingForResponse,
    /// Accumulating response body bytes.
    ReadingResponseBody { remaining: usize },
    /// Reading chunked response body.
    ReadingChunkedResponse,
}

/// Parsed request metadata, stored while we wait for the response.
#[derive(Debug, Clone)]
struct PendingRequest {
    method: String,
    path: String,
    timestamp_ns: u64,
    request_size: u64,
    headers: Vec<(String, String)>,
}

/// HTTP/1.1 parser with Keep-Alive support.
pub struct Http1Parser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    pending_request: Option<PendingRequest>,
    /// Accumulated response body (for payload_text).
    response_body: Vec<u8>,
    response_headers: Vec<(String, String)>,
    response_status: Option<u32>,
    response_content_type: Option<String>,
}

impl Http1Parser {
    pub fn new() -> Self {
        Self {
            state: State::WaitingForRequest,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            pending_request: None,
            response_body: Vec::new(),
            response_headers: Vec::new(),
            response_status: None,
            response_content_type: None,
        }
    }

    fn process(&mut self, timestamp_ns: u64) -> ParseResult {
        let mut messages = Vec::new();

        loop {
            match self.state.clone() {
                State::WaitingForRequest => {
                    if self.try_parse_request(timestamp_ns) {
                        continue;
                    }
                    if self.try_parse_response(timestamp_ns) {
                        if self.state == State::WaitingForRequest {
                            if let Some(msg) = self.emit_message(timestamp_ns) {
                                messages.push(msg);
                            }
                            self.reset_for_next_transaction();
                        }
                        continue;
                    }
                    break;
                }
                State::ReadingRequestBody { remaining } => {
                    let avail = self.client_buf.data().len();
                    if avail >= remaining {
                        self.client_buf.consume(remaining);
                        self.state = State::WaitingForResponse;
                    } else {
                        self.client_buf.consume(avail);
                        self.state = State::ReadingRequestBody {
                            remaining: remaining - avail,
                        };
                        break;
                    }
                }
                State::WaitingForResponse => {
                    if !self.try_parse_response(timestamp_ns) {
                        break;
                    }
                    // Bodyless responses (204, 304, Content-Length: 0) skip directly to
                    // WaitingForRequest without accumulating a body — emit the L7Message now.
                    if self.state == State::WaitingForRequest {
                        if let Some(msg) = self.emit_message(timestamp_ns) {
                            messages.push(msg);
                        }
                        self.reset_for_next_transaction();
                    }
                }
                State::ReadingResponseBody { remaining } => {
                    let data = self.server_buf.data();
                    let to_read = data.len().min(remaining);
                    self.response_body.extend_from_slice(&data[..to_read]);
                    self.server_buf.consume(to_read);

                    if to_read >= remaining {
                        // Response body complete — emit message
                        if let Some(msg) = self.emit_message(timestamp_ns) {
                            messages.push(msg);
                        }
                        self.reset_for_next_transaction();
                    } else {
                        self.state = State::ReadingResponseBody {
                            remaining: remaining - to_read,
                        };
                        break;
                    }
                }
                State::ReadingChunkedResponse => match self.read_chunked_body() {
                    ChunkResult::Complete => {
                        if let Some(msg) = self.emit_message(timestamp_ns) {
                            messages.push(msg);
                        }
                        self.reset_for_next_transaction();
                    }
                    ChunkResult::NeedMoreData => break,
                    ChunkResult::Error(e) => return ParseResult::Error(e),
                },
            }
        }

        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    /// Try to parse an HTTP request from the client buffer.
    /// Returns true if a request was successfully parsed (state advanced).
    fn try_parse_request(&mut self, timestamp_ns: u64) -> bool {
        let data = self.client_buf.data();
        if data.is_empty() {
            return false;
        }

        let mut headers_buf = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers_buf);

        match req.parse(data) {
            Ok(httparse::Status::Complete(header_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();

                let mut headers = Vec::new();
                let mut content_length: Option<usize> = None;

                for h in req.headers.iter() {
                    let name = h.name.to_lowercase();
                    let value = String::from_utf8_lossy(h.value).into_owned();
                    if name == "content-length" {
                        content_length = value.parse().ok();
                    }
                    headers.push((name, value));
                }

                self.pending_request = Some(PendingRequest {
                    method,
                    path,
                    timestamp_ns,
                    request_size: header_len as u64,
                    headers,
                });

                self.client_buf.consume(header_len);

                if let Some(body_len) = content_length {
                    if body_len > 0 {
                        self.state = State::ReadingRequestBody {
                            remaining: body_len,
                        };
                        if let Some(req) = &mut self.pending_request {
                            req.request_size += body_len as u64;
                        }
                    } else {
                        self.state = State::WaitingForResponse;
                    }
                } else {
                    self.state = State::WaitingForResponse;
                }
                true
            }
            Ok(httparse::Status::Partial) => false,
            Err(_) => false,
        }
    }

    /// Try to parse an HTTP response from the server buffer.
    /// Returns true if response headers were successfully parsed (state advanced).
    fn try_parse_response(&mut self, _timestamp_ns: u64) -> bool {
        let data = self.server_buf.data();
        if data.is_empty() {
            return false;
        }

        let mut headers_buf = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers_buf);

        match resp.parse(data) {
            Ok(httparse::Status::Complete(header_len)) => {
                self.response_status = resp.code.map(|c| c as u32);

                let mut content_length: Option<usize> = None;
                let mut is_chunked = false;

                self.response_headers.clear();
                for h in resp.headers.iter() {
                    let name = h.name.to_lowercase();
                    let value = String::from_utf8_lossy(h.value).into_owned();
                    if name == "content-length" {
                        content_length = value.parse().ok();
                    }
                    if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                        is_chunked = true;
                    }
                    if name == "content-type" {
                        self.response_content_type = Some(value.clone());
                    }
                    self.response_headers.push((name, value));
                }

                self.server_buf.consume(header_len);
                self.response_body.clear();

                if is_chunked {
                    self.state = State::ReadingChunkedResponse;
                } else if let Some(body_len) = content_length {
                    if body_len > 0 {
                        self.state = State::ReadingResponseBody {
                            remaining: body_len,
                        };
                    } else {
                        // No body — emit immediately
                        self.state = State::WaitingForRequest;
                        return true;
                    }
                } else {
                    // No content-length and not chunked — assume no body
                    // (for 204, 304, HEAD responses, etc.)
                    self.state = State::WaitingForRequest;
                    return true;
                }
                true
            }
            Ok(httparse::Status::Partial) => false,
            Err(_) => false,
        }
    }

    /// Read chunked transfer-encoding body.
    fn read_chunked_body(&mut self) -> ChunkResult {
        loop {
            let data = self.server_buf.data();
            if data.is_empty() {
                return ChunkResult::NeedMoreData;
            }

            // Find chunk size line (hex number followed by \r\n)
            let crlf_pos = match data.windows(2).position(|w| w == b"\r\n") {
                Some(pos) => pos,
                None => return ChunkResult::NeedMoreData,
            };

            let size_str = match std::str::from_utf8(&data[..crlf_pos]) {
                Ok(s) => s.trim(),
                Err(_) => return ChunkResult::Error("invalid chunk size encoding".into()),
            };

            let chunk_size = match usize::from_str_radix(size_str, 16) {
                Ok(n) => n,
                Err(_) => return ChunkResult::Error(format!("invalid chunk size: {size_str}")),
            };

            // Last chunk (size=0)
            if chunk_size == 0 {
                // Consume "0\r\n\r\n"
                let end = crlf_pos + 2 + 2; // chunk line + trailing CRLF
                if data.len() >= end {
                    self.server_buf.consume(end);
                    return ChunkResult::Complete;
                }
                return ChunkResult::NeedMoreData;
            }

            // Need: chunk_size_line + chunk_data + trailing \r\n
            let total = crlf_pos + 2 + chunk_size + 2;
            if data.len() < total {
                return ChunkResult::NeedMoreData;
            }

            let chunk_start = crlf_pos + 2;
            self.response_body
                .extend_from_slice(&data[chunk_start..chunk_start + chunk_size]);
            self.server_buf.consume(total);
        }
    }

    /// Build an L7Message from the pending request + accumulated response.
    fn emit_message(&self, timestamp_ns: u64) -> Option<L7Message> {
        let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, timestamp_ns);

        msg.status = self.response_status;
        msg.content_type = self.response_content_type.clone();
        msg.response_size_bytes = self.response_body.len() as u64;

        if let Some(req) = self.pending_request.as_ref() {
            msg.method = Some(req.method.clone());
            msg.path = Some(req.path.clone());
            msg.latency_ns = Some(timestamp_ns.saturating_sub(req.timestamp_ns));
            msg.request_size_bytes = req.request_size;
            msg.headers = req
                .headers
                .iter()
                .chain(self.response_headers.iter())
                .cloned()
                .collect();
        } else {
            msg.headers = self.response_headers.clone();
        }

        // Attempt UTF-8 decode for PII scanning
        if !self.response_body.is_empty()
            && let Ok(text) = std::str::from_utf8(&self.response_body)
        {
            // Cap at 64KB for PII scanning
            let cap = text.len().min(65536);
            msg.payload_text = Some(text[..cap].to_string());
        }

        Some(msg)
    }

    pub fn current_state(&self) -> &'static str {
        match self.state {
            State::WaitingForRequest => "waiting_for_request",
            State::ReadingRequestBody { .. } => "reading_request_body",
            State::WaitingForResponse => "waiting_for_response",
            State::ReadingResponseBody { .. } => "reading_response_body",
            State::ReadingChunkedResponse => "reading_chunked_response",
        }
    }

    /// Reset state for the next Keep-Alive transaction.
    fn reset_for_next_transaction(&mut self) {
        self.state = State::WaitingForRequest;
        self.pending_request = None;
        self.response_body.clear();
        self.response_headers.clear();
        self.response_status = None;
        self.response_content_type = None;
    }
}

enum ChunkResult {
    Complete,
    NeedMoreData,
    Error(String),
}

impl ProtocolParser for Http1Parser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        enum BufferTarget {
            Client,
            Server,
        }

        let target = if is_http1_response(data) {
            BufferTarget::Server
        } else if is_http1_request(data) {
            BufferTarget::Client
        } else {
            match direction {
                Direction::Egress => BufferTarget::Client,
                Direction::Ingress => BufferTarget::Server,
            }
        };

        match target {
            BufferTarget::Client => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("HTTP/1.1 client buffer overflow".into());
                }
            }
            BufferTarget::Server => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("HTTP/1.1 server buffer overflow".into());
                }
            }
        }
        self.process(timestamp_ns)
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http1
    }

    fn state_name(&self) -> &'static str {
        self.current_state()
    }

    fn protocol_version(&self) -> Option<&str> {
        Some("1.1")
    }
}

fn is_http1_request(payload: &[u8]) -> bool {
    payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"OPTIONS ")
        || payload.starts_with(b"PATCH ")
        || payload.starts_with(b"CONNECT ")
}

fn is_http1_response(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/1.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_get() {
        let mut parser = Http1Parser::new();

        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parser.feed(req, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("/index.html"));
                assert_eq!(msgs[0].status, Some(200));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("hello"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_post_with_body() {
        let mut parser = Http1Parser::new();

        let req = b"POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 13\r\n\r\n{\"name\":\"bob\"}";
        parser.feed(req, Direction::Egress, 1000);

        let resp = b"HTTP/1.1 201 Created\r\nContent-Length: 11\r\n\r\n{\"id\": 123}";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("POST"));
                assert_eq!(msgs[0].status, Some(201));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_chunked_response() {
        let mut parser = Http1Parser::new();

        let req = b"GET /stream HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parser.feed(req, Direction::Egress, 1000);

        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].payload_text.as_deref(), Some("hello world"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_keep_alive_two_requests() {
        let mut parser = Http1Parser::new();

        // First request/response
        let req1 = b"GET /page1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parser.feed(req1, Direction::Egress, 1000);
        let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npage";
        let result1 = parser.feed(resp1, Direction::Ingress, 2000);
        assert!(matches!(result1, ParseResult::Messages(_)));

        // Second request/response (Keep-Alive)
        let req2 = b"GET /page2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parser.feed(req2, Direction::Egress, 3000);
        let resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npage2";
        let result2 = parser.feed(resp2, Direction::Ingress, 4000);
        match result2 {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].path.as_deref(), Some("/page2"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_partial_header_split() {
        let mut parser = Http1Parser::new();

        // Send request in two pieces
        let req1 = b"GET /test HTTP/1.1\r\nHo";
        let result = parser.feed(req1, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let req2 = b"st: example.com\r\n\r\n";
        let result = parser.feed(req2, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        // Verify state advanced
        assert_eq!(parser.state_name(), "waiting_for_response");
    }

    #[test]
    fn test_parser_metadata() {
        let parser = Http1Parser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Http1);
        assert_eq!(parser.state_name(), "waiting_for_request");
        assert_eq!(ProtocolParser::protocol_version(&parser), Some("1.1"));
    }

    #[test]
    fn test_no_content_length_response() {
        let mut parser = Http1Parser::new();

        let req = b"GET /empty HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parser.feed(req, Direction::Egress, 1000);

        // 204 No Content — no body, must still emit an L7Message
        let resp = b"HTTP/1.1 204 No Content\r\n\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].status, Some(204));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages for 204, got {other:?}"),
        }
        assert_eq!(parser.state_name(), "waiting_for_request");
    }

    #[test]
    fn test_304_not_modified() {
        let mut parser = Http1Parser::new();

        let req = b"GET /cached HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: \"abc\"\r\n\r\n";
        parser.feed(req, Direction::Egress, 1000);

        // 304 Not Modified — bodyless, must emit L7Message
        let resp = b"HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\n\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].status, Some(304));
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages for 304, got {other:?}"),
        }
    }

    #[test]
    fn test_multi_packet_response_body() {
        let mut parser = Http1Parser::new();

        let req = b"GET /data HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parser.feed(req, Direction::Egress, 1000);

        // Response headers
        let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
        let result = parser.feed(resp1, Direction::Ingress, 2000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        // Rest of body
        let resp2 = b"world";
        let result = parser.feed(resp2, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].payload_text.as_deref(), Some("helloworld"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_server_side_tls_direction_routing() {
        let mut parser = Http1Parser::new();

        let req = b"GET /tls HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = parser.feed(req, Direction::Ingress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let result = parser.feed(resp, Direction::Egress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("/tls"));
                assert_eq!(msgs[0].status, Some(200));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("OK"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_response_only_message_from_server_write() {
        let mut parser = Http1Parser::new();

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let result = parser.feed(resp, Direction::Egress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method, None);
                assert_eq!(msgs[0].path, None);
                assert_eq!(msgs[0].status, Some(200));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("OK"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_current_state_transitions() {
        let mut parser = Http1Parser::new();
        assert_eq!(parser.current_state(), "waiting_for_request");

        let req = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        parser.feed(req, Direction::Egress, 1000);
        assert_eq!(parser.current_state(), "waiting_for_response");
    }

    #[test]
    fn test_reset_for_next_transaction() {
        let mut parser = Http1Parser::new();

        let req = b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest";
        parser.feed(req, Direction::Egress, 1000);
        assert_eq!(parser.current_state(), "waiting_for_response");

        parser.reset_for_next_transaction();
        assert_eq!(parser.current_state(), "waiting_for_request");
    }
}
