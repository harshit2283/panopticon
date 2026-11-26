//! HTTP/1.x protocol parser.
//!
//! Uses the `httparse` crate for header parsing. Requests are queued in
//! the order they are read and each response answers the oldest one
//! (pipelining included). Message framing follows RFC 9112 §6.3:
//! - a request body is `Transfer-Encoding: chunked` or `Content-Length`,
//!   otherwise empty;
//! - a response to `HEAD`, a `1xx`, `204` or `304` has no body; a `1xx`
//!   other than `101` is interim and does not answer its request;
//! - `101 Switching Protocols` and a `2xx` answer to `CONNECT` turn the
//!   connection into something else (a tunnel, WebSocket, h2c): it is
//!   exported once and nothing more is read from it;
//! - otherwise chunked, then `Content-Length`, and a response with
//!   neither is delimited by the connection's close: it is exported
//!   without its body and nothing more is read from the connection.
//!
//! Which capture direction carries requests is learned once, from the
//! first message start seen, never per segment: a body segment that starts
//! with `HTTP/1.` or `GET ` stays in its own direction.
//!
//! **Sync.** The parser reads message boundaries only from a stream it saw
//! from its first byte, with every byte accounted for. A connection joined
//! mid-stream ([`ProtocolParser::joined_late`]), bytes it cannot place, a
//! malformed message, ambiguous framing (conflicting `Content-Length`,
//! `Transfer-Encoding` with `Content-Length` in a request), or a response
//! with no request waiting all mean that a "message" found from there may
//! lie inside a body, or answer another request. The connection is then
//! `unsynced` for the rest of its life: messages are still exported, with
//! a known method and the sizes only (no path, header, content type, body,
//! status or latency).
//!
//! **TLS.** A TLS key is not latched (its start is unproven, not shown
//! missing), but its request paths hold no bare name ([`tls_path`]).

use std::collections::VecDeque;

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Constants ────────────────────────────────────────────────────────────

/// Request-line prefixes used to find a message start once sync is lost;
/// also the only methods ever exported from an unsynced connection.
const REQUEST_STARTS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];
const KNOWN_METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];
const RESPONSE_START: &[u8] = b"HTTP/1.";

/// Max body bytes retained for payload_text / request_text.
const MAX_CAPTURED_BODY: usize = 64 * 1024;

/// Requests waiting for a response. More means the parser lost track
/// (a pipelining client never waits this long).
const MAX_PENDING: usize = 64;

/// Longest chunk-size or trailer line accepted.
const MAX_CHUNK_LINE: usize = 4096;

// ── Bodies ───────────────────────────────────────────────────────────────

/// A message body as captured: its first `MAX_CAPTURED_BODY` bytes, its
/// full size, and whether bytes were kept after a gap inside it.
#[derive(Debug, Default, Clone)]
struct Body {
    bytes: Vec<u8>,
    size: u64,
    /// A gap inside the body; it becomes `gap` if more body bytes follow.
    gap_pending: bool,
    /// Body bytes were kept after bytes of the same body were lost: they
    /// may hold a credential's value without its name, so the body is not
    /// exported (its size is). A gap that only cuts a body's end (the
    /// capture cap on a large segment) keeps the captured prefix.
    gap: bool,
}

impl Body {
    fn append(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.gap |= self.gap_pending;
        self.size += bytes.len() as u64;
        let room = MAX_CAPTURED_BODY.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// `n` body bytes were never captured.
    fn lost(&mut self, n: usize) {
        self.size += n as u64;
        self.gap_pending = true;
    }

    fn text(&self) -> Option<String> {
        if self.gap {
            return None;
        }
        body_text(&self.bytes)
    }
}

/// Body as text for PII scanning: `None` if empty or not UTF-8. The capture
/// cap can split a multi-byte character at the end; keep the valid prefix then.
fn body_text(body: &[u8]) -> Option<String> {
    let text = match std::str::from_utf8(body) {
        Ok(t) => Some(t),
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&body[..e.valid_up_to()]).ok(),
        Err(_) => None,
    };
    text.filter(|t| !t.is_empty()).map(str::to_string)
}

// ── Chunked transfer coding ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Chunk {
    /// Expecting a chunk-size line (`hex[;ext]\r\n`).
    Size,
    /// Inside chunk data.
    Data(usize),
    /// Expecting the CRLF after chunk data.
    DataEnd,
    /// After the last chunk: trailer lines until an empty one.
    Trailer,
}

enum Step {
    Need,
    Done,
    /// Not chunked framing: the stream's boundaries are unknown.
    Bad,
}

/// Decode as much chunked framing from `buf` as is there, into `body`.
fn read_chunked(buf: &mut StreamBuffer, st: &mut Chunk, body: &mut Option<&mut Body>) -> Step {
    loop {
        let data = buf.data();
        match *st {
            Chunk::Size | Chunk::Trailer => {
                let Some(eol) = data.windows(2).position(|w| w == b"\r\n") else {
                    return if data.len() > MAX_CHUNK_LINE {
                        Step::Bad
                    } else {
                        Step::Need
                    };
                };
                if eol > MAX_CHUNK_LINE {
                    return Step::Bad;
                }
                if *st == Chunk::Trailer {
                    buf.consume(eol + 2);
                    if eol == 0 {
                        return Step::Done;
                    }
                    continue;
                }
                let line = &data[..eol];
                let digits = line
                    .iter()
                    .position(|&b| b == b';' || b == b' ' || b == b'\t')
                    .map_or(line, |i| &line[..i]);
                let Some(size) = std::str::from_utf8(digits)
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| usize::from_str_radix(s, 16).ok())
                else {
                    return Step::Bad;
                };
                buf.consume(eol + 2);
                *st = if size == 0 {
                    Chunk::Trailer
                } else {
                    Chunk::Data(size)
                };
            }
            Chunk::Data(remaining) => {
                if data.is_empty() {
                    return Step::Need;
                }
                let take = data.len().min(remaining);
                if let Some(b) = body.as_deref_mut() {
                    b.append(&data[..take]);
                }
                buf.consume(take);
                if take < remaining {
                    *st = Chunk::Data(remaining - take);
                    return Step::Need;
                }
                *st = Chunk::DataEnd;
            }
            Chunk::DataEnd => {
                if data.len() < 2 {
                    return Step::Need;
                }
                if &data[..2] != b"\r\n" {
                    return Step::Bad;
                }
                buf.consume(2);
                *st = Chunk::Size;
            }
        }
    }
}

// ── Framing ──────────────────────────────────────────────────────────────

/// How a message's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Framing {
    None,
    Length(usize),
    Chunked,
    /// Until the connection closes (responses only).
    Close,
}

/// What the framing headers of a message say. `None`: they contradict
/// each other or cannot be read (the peers may disagree on the boundary).
fn framing(headers: &[(String, String)], request: bool) -> Option<(Framing, bool)> {
    let mut length: Option<usize> = None;
    let mut te: Option<String> = None;
    for (name, value) in headers {
        match name.as_str() {
            "content-length" => {
                // `Content-Length: 5, 5` is allowed; different values not.
                for part in value.split(',') {
                    let n: usize = part.trim().parse().ok()?;
                    if length.is_some_and(|l| l != n) {
                        return None;
                    }
                    length = Some(n);
                }
            }
            "transfer-encoding" => {
                let v = te.get_or_insert_with(String::new);
                if !v.is_empty() {
                    v.push(',');
                }
                v.push_str(&value.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    if let Some(te) = te {
        let chunked_last = te.rsplit(',').next().map(str::trim) == Some("chunked");
        // A request whose transfer coding does not end in chunked cannot
        // be framed (RFC 9112 §6.3); a response then runs to the close.
        // A request with both headers is a smuggling shape: the server
        // may frame it either way.
        return match (chunked_last, request) {
            (true, true) => Some((Framing::Chunked, length.is_some())),
            (true, false) => Some((Framing::Chunked, false)),
            (false, true) => None,
            (false, false) => Some((Framing::Close, false)),
        };
    }
    Some(match length {
        Some(0) => (Framing::None, false),
        Some(n) => (Framing::Length(n), false),
        None if request => (Framing::None, false),
        None => (Framing::Close, false),
    })
}

// ── Parser state ─────────────────────────────────────────────────────────

/// A request read from the client, waiting for its response.
#[derive(Debug, Clone)]
struct PendingRequest {
    method: String,
    path: String,
    timestamp_ns: u64,
    header_size: u64,
    headers: Vec<(String, String)>,
    body: Body,
}

/// What the client side is reading.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ReqState {
    Line,
    /// Body of the newest pending request (`attached`: it is still
    /// queued; a response may answer a request before its body ends).
    Body {
        remaining: usize,
        attached: bool,
    },
    Chunked {
        st: Chunk,
        attached: bool,
    },
}

/// The response being read.
#[derive(Debug, Clone, Default)]
struct Response {
    status: Option<u32>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body: Body,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RespState {
    Line,
    Body { remaining: usize },
    Chunked(Chunk),
}

/// HTTP/1.x parser with Keep-Alive and pipelining support.
pub struct Http1Parser {
    /// The capture direction that carries requests, learned once.
    client_dir: Option<Direction>,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    req_state: ReqState,
    pending: VecDeque<PendingRequest>,
    resp_state: RespState,
    response: Response,
    /// Message boundaries (and which request a response answers) are no
    /// longer known for certain; see the module docs. For good.
    unsynced: bool,
    /// The connection stopped being HTTP/1 framed (a tunnel, an upgrade,
    /// a close-delimited body, or framing that cannot be followed): no
    /// more bytes are read from it.
    opaque: bool,
    /// The last call was [`ProtocolParser::skip`], which accounted for the
    /// gap itself. The connection manager follows every skip with
    /// [`ProtocolParser::joined_late`], which this flag lets through once.
    skip_accounted: bool,
    /// A TLS key whose start is unproven
    /// ([`ProtocolParser::tls_unproven_start`]): its request paths hold no
    /// bare name ([`tls_path`]).
    tls_unproven: bool,
}

impl Http1Parser {
    pub fn new() -> Self {
        Self {
            client_dir: None,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            req_state: ReqState::Line,
            pending: VecDeque::new(),
            resp_state: RespState::Line,
            response: Response::default(),
            unsynced: false,
            opaque: false,
            skip_accounted: false,
            tls_unproven: false,
        }
    }

    /// Sync is lost for the rest of the connection.
    fn lose_sync(&mut self) {
        self.unsynced = true;
    }

    /// Stop reading the connection: nothing after this point is HTTP/1
    /// framed (or its framing cannot be followed).
    fn go_opaque(&mut self) {
        self.opaque = true;
        self.client_buf.clear();
        self.server_buf.clear();
        self.pending.clear();
        self.response = Response::default();
    }

    fn process(&mut self, timestamp_ns: u64) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            if self.opaque {
                self.client_buf.clear();
                self.server_buf.clear();
                break;
            }
            let client = self.step_client(timestamp_ns);
            let server = !self.opaque && self.step_server(timestamp_ns, &mut messages);
            if !client && !server {
                break;
            }
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    /// Advance the client side by one unit. False: needs more data.
    fn step_client(&mut self, timestamp_ns: u64) -> bool {
        match self.req_state {
            ReqState::Line => self.parse_request(timestamp_ns),
            ReqState::Body {
                remaining,
                attached,
            } => {
                let data = self.client_buf.data();
                if data.is_empty() {
                    return false;
                }
                let take = data.len().min(remaining);
                if attached && let Some(req) = self.pending.back_mut() {
                    req.body.append(&data[..take]);
                }
                self.client_buf.consume(take);
                self.req_state = if take == remaining {
                    ReqState::Line
                } else {
                    ReqState::Body {
                        remaining: remaining - take,
                        attached,
                    }
                };
                true
            }
            ReqState::Chunked { mut st, attached } => {
                let before = self.client_buf.len();
                let mut body = if attached {
                    self.pending.back_mut().map(|r| &mut r.body)
                } else {
                    None
                };
                let step = read_chunked(&mut self.client_buf, &mut st, &mut body);
                let progressed = self.client_buf.len() != before;
                match step {
                    Step::Done => {
                        self.req_state = ReqState::Line;
                        true
                    }
                    Step::Need => {
                        self.req_state = ReqState::Chunked { st, attached };
                        progressed
                    }
                    Step::Bad => {
                        self.lose_sync();
                        self.go_opaque();
                        false
                    }
                }
            }
        }
    }

    /// Find where the next message starts in `buf`. On a synced connection
    /// it must be right there (empty lines before a request line are
    /// allowed); anything else loses sync, and from then on the next
    /// plausible start is searched for.
    fn locate(&mut self, request: bool) -> bool {
        let starts: &[&[u8]] = if request {
            &REQUEST_STARTS
        } else {
            &[RESPONSE_START]
        };
        let unsynced = self.unsynced;
        let buf = if request {
            &mut self.client_buf
        } else {
            &mut self.server_buf
        };
        if request && !unsynced {
            while buf.data().starts_with(b"\r\n") {
                buf.consume(2);
            }
            if buf.data() == b"\r" {
                return false;
            }
        }
        let data = buf.data();
        if data.is_empty() {
            return false;
        }
        if !unsynced {
            if request {
                // Any token method is a request line here (httparse checks).
                return true;
            }
            if data.starts_with(RESPONSE_START) || RESPONSE_START.starts_with(data) {
                return true;
            }
            self.lose_sync();
            return self.locate(request);
        }
        if starts
            .iter()
            .any(|s| data.starts_with(s) || s.starts_with(data))
        {
            return starts.iter().any(|s| data.starts_with(s));
        }
        let drop = (0..data.len())
            .find(|&i| starts.iter().any(|s| data[i..].starts_with(s)))
            .unwrap_or(data.len().saturating_sub(8));
        buf.consume(drop);
        let data = buf.data();
        starts.iter().any(|s| data.starts_with(s))
    }

    fn parse_request(&mut self, timestamp_ns: u64) -> bool {
        if !self.locate(true) {
            return false;
        }
        let mut headers_buf = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers_buf);
        let header_len = match req.parse(self.client_buf.data()) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) => return false,
            Err(_) => {
                // Not a request line where one must be: drop a byte and
                // look for the next plausible start, unsynced.
                self.lose_sync();
                self.client_buf.consume(1);
                return true;
            }
        };
        let method = req.method.unwrap_or("").to_string();
        let path = req.path.unwrap_or("").to_string();
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_ascii_lowercase(),
                    String::from_utf8_lossy(h.value).into_owned(),
                )
            })
            .collect();
        self.client_buf.consume(header_len);
        let framing = match framing(&headers, true) {
            Some((f, ambiguous)) => {
                if ambiguous {
                    self.lose_sync();
                }
                f
            }
            None => {
                // The server and the parser may disagree on where this
                // request ends: nothing after it can be framed.
                self.lose_sync();
                self.go_opaque();
                return false;
            }
        };
        if self.pending.len() >= MAX_PENDING {
            self.lose_sync();
            self.pending.pop_front();
        }
        self.pending.push_back(PendingRequest {
            method,
            path,
            timestamp_ns,
            header_size: header_len as u64,
            headers,
            body: Body::default(),
        });
        self.req_state = match framing {
            Framing::Length(n) => ReqState::Body {
                remaining: n,
                attached: true,
            },
            Framing::Chunked => ReqState::Chunked {
                st: Chunk::Size,
                attached: true,
            },
            Framing::None | Framing::Close => ReqState::Line,
        };
        true
    }

    /// Advance the server side by one unit. False: needs more data.
    fn step_server(&mut self, timestamp_ns: u64, out: &mut Vec<L7Message>) -> bool {
        match self.resp_state {
            RespState::Line => self.parse_response(timestamp_ns, out),
            RespState::Body { remaining } => {
                let data = self.server_buf.data();
                if data.is_empty() {
                    return false;
                }
                let take = data.len().min(remaining);
                self.response.body.append(&data[..take]);
                self.server_buf.consume(take);
                if take == remaining {
                    self.finish(timestamp_ns, out);
                } else {
                    self.resp_state = RespState::Body {
                        remaining: remaining - take,
                    };
                }
                true
            }
            RespState::Chunked(mut st) => {
                let before = self.server_buf.len();
                let step = read_chunked(
                    &mut self.server_buf,
                    &mut st,
                    &mut Some(&mut self.response.body),
                );
                let progressed = self.server_buf.len() != before;
                match step {
                    Step::Done => {
                        self.finish(timestamp_ns, out);
                        true
                    }
                    Step::Need => {
                        self.resp_state = RespState::Chunked(st);
                        progressed
                    }
                    Step::Bad => {
                        self.lose_sync();
                        self.go_opaque();
                        false
                    }
                }
            }
        }
    }

    fn parse_response(&mut self, timestamp_ns: u64, out: &mut Vec<L7Message>) -> bool {
        if !self.locate(false) {
            return false;
        }
        let mut headers_buf = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers_buf);
        let header_len = match resp.parse(self.server_buf.data()) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) => return false,
            Err(_) => {
                self.lose_sync();
                self.server_buf.consume(1);
                return true;
            }
        };
        let status = resp.code.unwrap_or(0) as u32;
        let headers: Vec<(String, String)> = resp
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_ascii_lowercase(),
                    String::from_utf8_lossy(h.value).into_owned(),
                )
            })
            .collect();
        self.server_buf.consume(header_len);

        // Interim response: the request is still waiting for its final one.
        if (100..200).contains(&status) && status != 101 {
            return true;
        }
        // An answer with no request waiting: it answers a request the
        // parser did not see, so the queue no longer lines up.
        if self.pending.is_empty() {
            self.lose_sync();
        }
        let method = self.pending.front().map(|r| r.method.as_str());
        let tunnel = status == 101 || (method == Some("CONNECT") && (200..300).contains(&status));
        let bodyless = method == Some("HEAD") || matches!(status, 204 | 304);
        let framing = if tunnel || bodyless {
            Framing::None
        } else {
            match framing(&headers, false) {
                Some((f, _)) => f,
                None => {
                    self.lose_sync();
                    Framing::Close
                }
            }
        };
        self.response = Response {
            status: Some(status),
            content_type: headers
                .iter()
                .find(|(n, _)| n == "content-type")
                .map(|(_, v)| v.clone()),
            headers,
            body: Body::default(),
        };
        match framing {
            Framing::None => {
                self.finish(timestamp_ns, out);
                if tunnel {
                    self.go_opaque();
                }
            }
            Framing::Length(n) => self.resp_state = RespState::Body { remaining: n },
            Framing::Chunked => self.resp_state = RespState::Chunked(Chunk::Size),
            Framing::Close => {
                // The body runs to the close, which the parser is not
                // told about: export the exchange now, without the body,
                // and read nothing more.
                self.finish(timestamp_ns, out);
                self.go_opaque();
            }
        }
        true
    }

    /// The response is complete: export it with the request it answers.
    fn finish(&mut self, timestamp_ns: u64, out: &mut Vec<L7Message>) {
        let req = self.pending.pop_front();
        if self.pending.is_empty() {
            // The request whose body is being read was just answered.
            match &mut self.req_state {
                ReqState::Body { attached, .. } | ReqState::Chunked { attached, .. } => {
                    *attached = false
                }
                ReqState::Line => {}
            }
        }
        let resp = std::mem::take(&mut self.response);
        self.resp_state = RespState::Line;
        out.push(self.message(req, resp, timestamp_ns));
    }

    fn message(&self, req: Option<PendingRequest>, resp: Response, timestamp_ns: u64) -> L7Message {
        let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, timestamp_ns);
        msg.response_size_bytes = resp.body.size;
        if self.unsynced {
            msg.method = req.as_ref().and_then(|r| {
                KNOWN_METHODS
                    .iter()
                    .find(|m| **m == r.method)
                    .map(|m| m.to_string())
            });
            msg.request_size_bytes = req.as_ref().map_or(0, |r| r.header_size + r.body.size);
            if let Some(mut r) = req {
                wipe_request(&mut r);
            }
            wipe_response(resp);
            return msg;
        }
        msg.status = resp.status;
        msg.content_type = resp.content_type;
        msg.payload_text = resp.body.text();
        match req {
            Some(r) => {
                msg.latency_ns = Some(timestamp_ns.saturating_sub(r.timestamp_ns));
                msg.request_size_bytes = r.header_size + r.body.size;
                msg.request_text = r.body.text();
                msg.method = Some(r.method);
                msg.path = Some(if self.tls_unproven {
                    tls_path(r.path)
                } else {
                    r.path
                });
                msg.headers = r.headers;
                msg.headers.extend(resp.headers);
            }
            None => msg.headers = resp.headers,
        }
        msg
    }

    pub fn current_state(&self) -> &'static str {
        if self.opaque {
            return "opaque";
        }
        match (self.req_state, self.resp_state) {
            (ReqState::Body { .. } | ReqState::Chunked { .. }, _) => "reading_request_body",
            (_, RespState::Body { .. }) => "reading_response_body",
            (_, RespState::Chunked(_)) => "reading_chunked_response",
            _ if !self.pending.is_empty() => "waiting_for_response",
            _ => "waiting_for_request",
        }
    }

    /// Forget every exchange in flight (the connection's sync state and
    /// orientation stay).
    pub fn reset_for_next_transaction(&mut self) {
        self.client_buf.clear();
        self.server_buf.clear();
        self.pending.clear();
        self.req_state = ReqState::Line;
        self.resp_state = RespState::Line;
        self.response = Response::default();
    }
}

fn wipe_request(r: &mut PendingRequest) {
    zeroize::Zeroize::zeroize(&mut r.path);
    zeroize::Zeroize::zeroize(&mut r.body.bytes);
    for (k, v) in r.headers.iter_mut() {
        zeroize::Zeroize::zeroize(k);
        zeroize::Zeroize::zeroize(v);
    }
}

fn wipe_response(mut r: Response) {
    zeroize::Zeroize::zeroize(&mut r.body.bytes);
    if let Some(ct) = r.content_type.as_mut() {
        zeroize::Zeroize::zeroize(ct);
    }
    for (k, v) in r.headers.iter_mut() {
        zeroize::Zeroize::zeroize(k);
        zeroize::Zeroize::zeroize(v);
    }
}

impl ProtocolParser for Http1Parser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        self.skip_accounted = false;
        if self.opaque {
            return ParseResult::NeedMoreData;
        }
        // Orientation, once: the manager normalises directions when it
        // knows the server; a parser used without one learns it from the
        // first message start.
        let client_dir = *self.client_dir.get_or_insert_with(|| {
            if data.starts_with(RESPONSE_START) {
                opposite(direction)
            } else if REQUEST_STARTS.iter().any(|s| data.starts_with(s)) {
                direction
            } else {
                Direction::Egress
            }
        });
        let buf = if direction == client_dir {
            &mut self.client_buf
        } else {
            &mut self.server_buf
        };
        if buf.extend(data).is_err() {
            return ParseResult::Error("HTTP/1.1 buffer overflow".into());
        }
        self.process(timestamp_ns)
    }

    /// `n` bytes were not captured. Inside a body of known length (or a
    /// chunk's data) they are counted and the body is marked; anywhere
    /// else the boundaries are lost and the parser is replaced.
    fn skip(&mut self, direction: Direction, n: usize, timestamp_ns: u64) -> Option<ParseResult> {
        if self.opaque {
            self.skip_accounted = true;
            return Some(ParseResult::NeedMoreData);
        }
        let from_client = Some(direction) == self.client_dir
            || (self.client_dir.is_none() && direction == Direction::Egress);
        let result = if from_client {
            if !self.client_buf.is_empty() {
                return None;
            }
            match self.req_state {
                ReqState::Body {
                    remaining,
                    attached,
                } if n <= remaining => {
                    if attached && let Some(r) = self.pending.back_mut() {
                        r.body.lost(n);
                    }
                    self.req_state = if n == remaining {
                        ReqState::Line
                    } else {
                        ReqState::Body {
                            remaining: remaining - n,
                            attached,
                        }
                    };
                    ParseResult::NeedMoreData
                }
                ReqState::Chunked {
                    st: Chunk::Data(remaining),
                    attached,
                } if n <= remaining => {
                    if attached && let Some(r) = self.pending.back_mut() {
                        r.body.lost(n);
                    }
                    let st = if n == remaining {
                        Chunk::DataEnd
                    } else {
                        Chunk::Data(remaining - n)
                    };
                    self.req_state = ReqState::Chunked { st, attached };
                    ParseResult::NeedMoreData
                }
                _ => return None,
            }
        } else {
            if !self.server_buf.is_empty() {
                return None;
            }
            match self.resp_state {
                RespState::Body { remaining } if n <= remaining => {
                    self.response.body.lost(n);
                    if n == remaining {
                        let mut out = Vec::new();
                        self.finish(timestamp_ns, &mut out);
                        ParseResult::Messages(out)
                    } else {
                        self.resp_state = RespState::Body {
                            remaining: remaining - n,
                        };
                        ParseResult::NeedMoreData
                    }
                }
                RespState::Chunked(Chunk::Data(remaining)) if n <= remaining => {
                    self.response.body.lost(n);
                    self.resp_state = RespState::Chunked(if n == remaining {
                        Chunk::DataEnd
                    } else {
                        Chunk::Data(remaining - n)
                    });
                    ParseResult::NeedMoreData
                }
                _ => return None,
            }
        };
        self.skip_accounted = true;
        Some(result)
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

    /// The stream was not seen from its first byte (or bytes were lost
    /// that `skip` could not place): a request or status line found from
    /// here may lie inside a body, and a response may answer a request
    /// sent before capture. The connection is unsynced for good (see the
    /// module docs). Not right after a `skip` that accounted for its gap
    /// (`skip_accounted`).
    fn joined_late(&mut self) {
        if std::mem::take(&mut self.skip_accounted) {
            return;
        }
        self.lose_sync();
    }

    /// The key may start inside a body, or a record may have been lost
    /// (no trace on a TLS key), so a request line read on it can be body
    /// bytes. Its path gets the strict credential rule ([`tls_path`]);
    /// pairing is not latched (USER-GUIDE §5.3, integrity limit).
    fn tls_unproven_start(&mut self) {
        self.tls_unproven = true;
    }
}

/// A request path read on a TLS key whose start is unproven: body bytes
/// read as a request line would otherwise get the bare-name exemption a
/// body never has (`/reset/x/token`). No bare name: a path part (before
/// any `?` or `#`) with any credential word is withheld whole
/// ([`FIELD_WITHHELD`](super::FIELD_WITHHELD)); otherwise the path goes to
/// the usual rules (keyed query parameters masked).
fn tls_path(mut path: String) -> String {
    let part = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    if super::mask_credentials_enabled() && super::has_credential_context(part) {
        super::count_builtin();
        zeroize::Zeroize::zeroize(&mut path);
        return super::FIELD_WITHHELD.to_string();
    }
    path
}

fn opposite(d: Direction) -> Direction {
    match d {
        Direction::Egress => Direction::Ingress,
        Direction::Ingress => Direction::Egress,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capture gap inside a body can remove a credential's name and keep
    /// its value: a body with a gap is withheld (sizes kept).
    #[test]
    fn test_body_with_a_gap_is_withheld() {
        let body = br#"{"password":"s7Kf2v9LmQ8z","n":1}"#;
        let mut p = Http1Parser::new();
        let head = format!(
            "POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        p.feed(head.as_bytes(), Direction::Egress, 1);
        assert!(crate::protocol::skip_as_manager(&mut p, Direction::Egress, 13, 2).is_some()); // {"password":"
        p.feed(&body[13..], Direction::Egress, 3);
        let tail = r#"{"token_hint":"s7Kf2v9LmQ8z"}"#;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", tail.len());
        p.feed(head.as_bytes(), Direction::Ingress, 4);
        assert!(crate::protocol::skip_as_manager(&mut p, Direction::Ingress, 2, 5).is_some());
        let ParseResult::Messages(m) = p.feed(&tail.as_bytes()[2..], Direction::Ingress, 6) else {
            panic!("expected the message");
        };
        assert_eq!(m[0].request_text, None, "{m:?}");
        assert_eq!(m[0].payload_text, None, "{m:?}");
        assert_eq!(m[0].status, Some(200));

        // The next exchange on the connection is exported normally.
        p.feed(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n", Direction::Egress, 7);
        let ParseResult::Messages(m) = p.feed(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            Direction::Ingress,
            8,
        ) else {
            panic!("expected the message");
        };
        assert_eq!(m[0].payload_text.as_deref(), Some("ok"));
    }

    /// A gap that only cuts the end of a body (the capture cap on a large
    /// segment) keeps the captured prefix: names come before values, and
    /// the export scans and trims a cut value.
    #[test]
    fn test_body_cut_at_its_end_keeps_its_prefix() {
        let mut p = Http1Parser::new();
        p.feed(
            b"POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nhead of the body",
            Direction::Egress,
            1,
        );
        assert!(crate::protocol::skip_as_manager(&mut p, Direction::Egress, 84, 2).is_some());
        p.feed(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\nfirst part",
            Direction::Ingress,
            3,
        );
        let Some(ParseResult::Messages(m)) =
            crate::protocol::skip_as_manager(&mut p, Direction::Ingress, 9990, 4)
        else {
            panic!("the gap finishes the response");
        };
        assert_eq!(m[0].request_text.as_deref(), Some("head of the body"));
        assert_eq!(m[0].payload_text.as_deref(), Some("first part"));
        assert_eq!(m[0].response_size_bytes, 10000);
    }

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

        let req = b"POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 14\r\n\r\n{\"name\":\"bob\"}";
        parser.feed(req, Direction::Egress, 1000);

        let resp = b"HTTP/1.1 201 Created\r\nContent-Length: 11\r\n\r\n{\"id\": 123}";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("POST"));
                assert_eq!(msgs[0].status, Some(201));
                assert_eq!(msgs[0].request_text.as_deref(), Some("{\"name\":\"bob\"}"));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("{\"id\": 123}"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_request_body_across_packets_is_kept() {
        let mut parser = Http1Parser::new();
        parser.feed(
            b"POST /signup HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 38\r\n\r\nemail=jane%40example.com",
            Direction::Egress,
            1000,
        );
        parser.feed(b"&ssn=123-45-", Direction::Egress, 1001);
        parser.feed(b"67", Direction::Egress, 1002);
        let result = parser.feed(b"HTTP/1.1 204 No Content\r\n\r\n", Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(
                    msgs[0].request_text.as_deref(),
                    Some("email=jane%40example.com&ssn=123-45-67")
                );
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
    fn test_chunked_size_overflow_does_not_panic() {
        let mut parser = Http1Parser::new();
        parser.feed(
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            Direction::Egress,
            1000,
        );
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\nabc\r\n";
        // Must not panic (previously integer overflow / out-of-bounds slice).
        let _ = parser.feed(resp, Direction::Ingress, 2000);
    }

    #[test]
    fn test_parse_errors_do_not_quote_input() {
        // Errors are logged: they must not carry captured bytes.
        let mut parser = Http1Parser::new();
        parser.feed(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Direction::Egress, 1);
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nssn=123-45-6789\r\nx\r\n";
        // Not chunked framing: nothing more is read from the connection.
        match parser.feed(resp, Direction::Ingress, 2) {
            ParseResult::Error(e) => assert!(!e.contains("123-45"), "{e}"),
            ParseResult::NeedMoreData => assert_eq!(parser.state_name(), "opaque"),
            other => panic!("expected nothing, got {other:?}"),
        }
    }

    #[test]
    fn test_large_body_capped_but_size_counted() {
        let mut parser = Http1Parser::new();
        parser.feed(
            b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n",
            Direction::Egress,
            1000,
        );
        let body_len = MAX_CAPTURED_BODY + 10_000;
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n");
        parser.feed(header.as_bytes(), Direction::Ingress, 2000);
        let body = vec![b'a'; body_len];
        let mut msgs = Vec::new();
        for chunk in body.chunks(4096) {
            if let ParseResult::Messages(m) = parser.feed(chunk, Direction::Ingress, 3000) {
                msgs.extend(m);
            }
        }
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].response_size_bytes, body_len as u64);
        assert_eq!(
            msgs[0].payload_text.as_ref().unwrap().len(),
            MAX_CAPTURED_BODY
        );
    }

    #[test]
    fn test_body_cap_splitting_utf8_char_keeps_prefix() {
        let mut parser = Http1Parser::new();
        parser.feed(
            b"GET /u HTTP/1.1\r\nHost: x\r\n\r\n",
            Direction::Egress,
            1000,
        );
        // Two ASCII bytes then 3-byte chars: 65536 - 2 is not a multiple of
        // 3, so the 64KB cap lands mid-char.
        let mut body = vec![b'a', b'a'];
        while body.len() < MAX_CAPTURED_BODY + 3 {
            body.extend_from_slice("€".as_bytes());
        }
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        parser.feed(header.as_bytes(), Direction::Ingress, 2000);
        let mut msgs = Vec::new();
        for chunk in body.chunks(4096) {
            if let ParseResult::Messages(m) = parser.feed(chunk, Direction::Ingress, 3000) {
                msgs.extend(m);
            }
        }
        assert_eq!(msgs.len(), 1);
        let text = msgs[0].payload_text.as_ref().expect("valid prefix kept");
        assert!(text.len() < MAX_CAPTURED_BODY && text.len() > MAX_CAPTURED_BODY - 4);
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
                // No request was seen: it answers one sent before
                // capture, so nothing of it is exported but its size.
                assert_eq!(msgs[0].method, None);
                assert_eq!(msgs[0].path, None);
                assert_eq!(msgs[0].status, None);
                assert_eq!(msgs[0].payload_text, None);
                assert_eq!(msgs[0].response_size_bytes, 2);
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

    // ── Sync and pairing ─────────────────────────────────────────────────

    fn msgs(r: ParseResult) -> Vec<L7Message> {
        match r {
            ParseResult::Messages(m) => m,
            ParseResult::NeedMoreData => vec![],
            ParseResult::Error(e) => panic!("error: {e}"),
        }
    }

    fn all_text(m: &L7Message) -> String {
        let mut s = format!(
            "{:?} {:?} {:?} {:?} {:?}",
            m.method, m.path, m.content_type, m.payload_text, m.request_text
        );
        for (k, v) in &m.headers {
            s.push_str(&format!(" {k}={v}"));
        }
        s
    }

    /// Feed a whole exchange list, collecting (method, path, status).
    fn run(p: &mut Http1Parser, steps: &[(&[u8], Direction)]) -> Vec<L7Message> {
        let mut out = Vec::new();
        for (i, (d, dir)) in steps.iter().enumerate() {
            out.extend(msgs(p.feed(d, *dir, 10 * (i as u64 + 1))));
        }
        out
    }

    fn summary(m: &[L7Message]) -> Vec<(Option<&str>, Option<&str>, Option<u32>)> {
        m.iter()
            .map(|m| (m.method.as_deref(), m.path.as_deref(), m.status))
            .collect()
    }

    /// The tail of a request body that holds a whole forged exchange: a
    /// parser that joins here must not export the forged request or
    /// response with text.
    const FORGED_TAIL: &[u8] = b"lue\"}\r\n\r\nPOST /reset?token=S3CRET HTTP/1.1\r\nHost: a\r\n\
          Content-Length: 13\r\n\r\npassword=S3CRET";
    const FORGED_RESP: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nS3CRET";

    #[test]
    fn joined_late_inside_a_body_exports_no_forged_message() {
        let mut p = Http1Parser::new();
        p.joined_late();
        let out = run(
            &mut p,
            &[
                (FORGED_TAIL, Direction::Egress),
                (FORGED_RESP, Direction::Ingress),
            ],
        );
        assert!(!out.is_empty(), "the exchange is still counted");
        for m in &out {
            assert!(!all_text(m).contains("S3CRET"), "{}", all_text(m));
            assert_eq!((m.path.as_deref(), m.status), (None, None));
        }
        // For the rest of the connection.
        let out = run(
            &mut p,
            &[
                (b"GET /next HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(summary(&out), vec![(Some("GET"), None, None)]);
        assert_eq!(out[0].payload_text, None);
    }

    fn manager_out(r: Option<crate::protocol::fsm::FsmResult>) -> Vec<L7Message> {
        use crate::protocol::fsm::FsmResult;
        match r {
            Some(FsmResult::Messages(v)) => v,
            Some(FsmResult::MessageComplete(v)) => vec![v],
            _ => vec![],
        }
    }

    /// The same through the connection manager (`mark_joined_late`, as the
    /// event loop does for a connection it did not see open).
    #[test]
    fn manager_join_mid_stream_exports_no_forged_message() {
        use crate::protocol::fsm::ConnectionFsmManager;
        let m = ConnectionFsmManager::new(16);
        let (client, server) = ((1, 40000), (2, 80));
        m.get_or_create_with_server(7, Protocol::Http1, Some(server));
        m.mark_joined_late(7);
        let mut out =
            manager_out(m.process_packet_from(7, client, Direction::Egress, FORGED_TAIL, 1));
        out.extend(manager_out(m.process_packet_from(
            7,
            server,
            Direction::Ingress,
            FORGED_RESP,
            2,
        )));
        assert!(!out.is_empty());
        for msg in &out {
            assert!(!all_text(msg).contains("S3CRET"), "{}", all_text(msg));
        }
    }

    /// A gap inside a body of known length, through the manager (which
    /// follows every skip with `joined_late`): the parser accounted for
    /// it, so the connection stays synced and the next exchange keeps text.
    #[test]
    fn manager_gap_inside_a_known_body_keeps_text() {
        use crate::protocol::fsm::ConnectionFsmManager;
        let m = ConnectionFsmManager::new(16);
        let (client, server) = ((1, 40000), (2, 80));
        m.get_or_create_with_server(8, Protocol::Http1, Some(server));
        m.process_packet_from(
            8,
            client,
            Direction::Egress,
            b"GET /big HTTP/1.1\r\n\r\n",
            1,
        );
        m.process_packet_from(
            8,
            server,
            Direction::Ingress,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfirst",
            2,
        );
        let out = manager_out(m.skip_from(8, server, Direction::Ingress, 95, 3));
        assert_eq!(out[0].payload_text.as_deref(), Some("first"));
        m.process_packet_from(
            8,
            client,
            Direction::Egress,
            b"GET /next HTTP/1.1\r\n\r\n",
            4,
        );
        let out = manager_out(m.process_packet_from(
            8,
            server,
            Direction::Ingress,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            5,
        ));
        assert_eq!(summary(&out), vec![(Some("GET"), Some("/next"), Some(200))]);
        assert_eq!(out[0].payload_text.as_deref(), Some("ok"));
    }

    /// A request body segment that starts like a status line stays a
    /// request body (orientation is learned once, not per segment).
    #[test]
    fn body_segment_starting_like_a_response_is_not_routed_as_one() {
        let mut p = Http1Parser::new();
        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nS3CRET";
        let head = format!(
            "POST /echo HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let out = run(
            &mut p,
            &[
                (head.as_bytes(), Direction::Egress),
                (body, Direction::Egress),
                (b"HTTP/1.1 204 No Content\r\n\r\n", Direction::Ingress),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![(Some("POST"), Some("/echo"), Some(204))]
        );
        assert_eq!(
            out[0].request_text.as_deref(),
            Some(std::str::from_utf8(body).unwrap())
        );
        assert_eq!(out[0].payload_text, None);
    }

    /// `100 Continue` is interim: the request is answered by the final
    /// response, and the next request by its own.
    #[test]
    fn interim_100_continue_does_not_answer_the_request() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"PUT /up HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n",
                    Direction::Egress,
                ),
                (b"HTTP/1.1 100 Continue\r\n\r\n", Direction::Ingress),
                (b"data", Direction::Egress),
                (
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
                    Direction::Ingress,
                ),
                (b"GET /b HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("PUT"), Some("/up"), Some(201)),
                (Some("GET"), Some("/b"), Some(404))
            ]
        );
        assert_eq!(out[0].request_text.as_deref(), Some("data"));
    }

    /// `103 Early Hints` (with headers) before the final response.
    #[test]
    fn early_hints_are_interim() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na\
                      HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("GET"), Some("/a"), Some(200)),
                (Some("GET"), Some("/b"), Some(200))
            ]
        );
        assert_eq!(out[1].payload_text.as_deref(), Some("b"));
    }

    /// A response to HEAD has no body, whatever its Content-Length says:
    /// the next response is not read as its body.
    #[test]
    fn head_response_has_no_body() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"HEAD /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nbb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("HEAD"), Some("/a"), Some(200)),
                (Some("GET"), Some("/b"), Some(200))
            ]
        );
        assert_eq!(out[1].payload_text.as_deref(), Some("bb"));
    }

    /// Pipelined requests (any method token) are answered in order.
    #[test]
    fn pipelined_requests_pair_in_order() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"PROPFIND /dav HTTP/1.1\r\nContent-Length: 0\r\n\r\n\
                      POST /p HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc\
                      GET /g HTTP/1.1\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 207 Multi-Status\r\nContent-Length: 1\r\n\r\n1",
                    Direction::Ingress,
                ),
                (
                    b"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\n2",
                    Direction::Ingress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n3",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("PROPFIND"), Some("/dav"), Some(207)),
                (Some("POST"), Some("/p"), Some(201)),
                (Some("GET"), Some("/g"), Some(200))
            ]
        );
        assert_eq!(out[1].request_text.as_deref(), Some("abc"));
        assert_eq!(out[2].payload_text.as_deref(), Some("3"));
    }

    /// HTTP/1.0 keep-alive with Content-Length pairs like 1.1.
    #[test]
    fn http10_keep_alive_pairs() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\na",
                    Direction::Ingress,
                ),
                (
                    b"GET /b HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("GET"), Some("/a"), Some(200)),
                (Some("GET"), Some("/b"), Some(200))
            ]
        );
    }

    /// A response with neither length nor chunking runs to the close: it
    /// is exported without its body, and its body (which here holds a
    /// forged response) is never parsed.
    #[test]
    fn close_delimited_body_is_never_parsed() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (b"GET /a HTTP/1.0\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n",
                    Direction::Ingress,
                ),
                (b"GET /x HTTP/1.1\r\n\r\n", Direction::Egress),
                (FORGED_RESP, Direction::Ingress),
            ],
        );
        assert_eq!(summary(&out), vec![(Some("GET"), Some("/a"), Some(200))]);
        assert_eq!(out[0].payload_text, None);
        assert_eq!(p.state_name(), "opaque");
    }

    /// CONNECT 2xx and 101 make the connection a tunnel: what follows is
    /// not HTTP/1 and is never parsed.
    #[test]
    fn tunnels_are_not_parsed() {
        for (req, resp) in [
            (
                &b"CONNECT db:5432 HTTP/1.1\r\nHost: db:5432\r\n\r\n"[..],
                &b"HTTP/1.1 200 Connection Established\r\n\r\n"[..],
            ),
            (
                b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            ),
        ] {
            let mut p = Http1Parser::new();
            let out = run(
                &mut p,
                &[
                    (req, Direction::Egress),
                    (resp, Direction::Ingress),
                    (
                        b"POST /reset?token=S3CRET HTTP/1.1\r\n\r\n",
                        Direction::Egress,
                    ),
                    (FORGED_RESP, Direction::Ingress),
                ],
            );
            assert_eq!(out.len(), 1, "{:?}", summary(&out));
            assert!(matches!(out[0].status, Some(200 | 101)));
            assert_eq!(p.state_name(), "opaque");
        }
    }

    /// An Upgrade the server declines (a 200) keeps HTTP/1 going.
    #[test]
    fn declined_upgrade_keeps_parsing() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"GET /a HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
                    Direction::Ingress,
                ),
                (b"GET /b HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].path.as_deref(), Some("/b"));
    }

    /// A chunked request body (here holding a forged request) is decoded
    /// as the body, never scanned for request lines.
    #[test]
    fn chunked_request_body_is_decoded() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                      1d;ext=1\r\nGET /forged?token=S3CRET HTTP\r\n\
                      0\r\nX-Trailer: t\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
                    Direction::Ingress,
                ),
                (b"GET /next HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("POST"), Some("/c"), Some(200)),
                (Some("GET"), Some("/next"), Some(200))
            ]
        );
        assert_eq!(
            out[0].request_text.as_deref(),
            Some("GET /forged?token=S3CRET HTTP")
        );
    }

    /// Chunk extensions and trailer fields in a response.
    #[test]
    fn chunked_response_with_extensions_and_trailers() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                      3;name=v\r\nabc\r\n0\r\nGrpc-Status: 0\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload_text.as_deref(), Some("abc"));
        assert_eq!(out[1].path.as_deref(), Some("/b"));
    }

    /// Framing the server may read differently (conflicting lengths)
    /// stops parsing; TE with CL in a request unsyncs the connection.
    #[test]
    fn ambiguous_request_framing_withholds() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"POST /a HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 30\r\n\r\nabc",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
                    Direction::Ingress,
                ),
            ],
        );
        assert!(out.is_empty());
        assert_eq!(p.state_name(), "opaque");

        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"POST /a HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n\
                      3\r\nabc\r\n0\r\n\r\n",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(summary(&out), vec![(Some("POST"), None, None)]);
    }

    /// A response with no request waiting answers one the parser did not
    /// see: every later exchange of the connection is withheld too (the
    /// queue may be one off).
    #[test]
    fn unrequested_response_unsyncs_the_connection() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (b"GET /a HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
                    Direction::Ingress,
                ),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nS3CRET",
                    Direction::Ingress,
                ),
                (b"GET /b HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("GET"), Some("/a"), Some(200)),
                (None, None, None),
                (Some("GET"), None, None)
            ]
        );
        assert!(out.iter().all(|m| !all_text(m).contains("S3CRET")));
    }

    /// A response sent before the request body ended (a 413) answers that
    /// request; the rest of its body is not taken for the next request.
    #[test]
    fn early_response_before_request_body_ends() {
        let mut p = Http1Parser::new();
        let out = run(
            &mut p,
            &[
                (
                    b"POST /up HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc",
                    Direction::Egress,
                ),
                (
                    b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n",
                    Direction::Ingress,
                ),
                (b"defghijGET /n HTTP/1.1\r\n\r\n", Direction::Egress),
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nn",
                    Direction::Ingress,
                ),
            ],
        );
        assert_eq!(
            summary(&out),
            vec![
                (Some("POST"), Some("/up"), Some(413)),
                (Some("GET"), Some("/n"), Some(200))
            ]
        );
    }
}

/// The TLS ruling (USER-GUIDE §5.3): what an HTTP/1 TLS key exports when
/// its start is unproven ([`ProtocolParser::tls_unproven_start`]) and a
/// record is lost (a ring drop leaves no trace on a TLS key): a path with
/// a credential word is withheld (no bare name), and a lost record
/// misattributes a response, the documented integrity limit.
#[cfg(test)]
mod tls_ruling {
    use super::*;
    use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};

    const CLIENT: (u32, u16) = (0, 1);
    const SERVER: (u32, u16) = (0, 2);

    fn tls_key(m: &ConnectionFsmManager, id: u64) {
        m.get_or_create_with_server(id, Protocol::Http1, Some(SERVER));
        m.start_tls(id);
    }

    fn feed(m: &ConnectionFsmManager, id: u64, from_client: bool, d: &[u8]) -> Vec<L7Message> {
        let (src, dir) = if from_client {
            (CLIENT, Direction::Egress)
        } else {
            (SERVER, Direction::Ingress)
        };
        match m.process_packet_from(id, src, dir, d, 1) {
            Some(FsmResult::Messages(v)) => v,
            Some(FsmResult::MessageComplete(v)) => vec![v],
            _ => vec![],
        }
    }

    /// The key's first record starts inside a request body, at a forged
    /// request; the server's answer to the real (unseen) request then
    /// arrives. The forged path would get the bare-name exemption a body
    /// never has (`token` last): it is withheld whole. The real response
    /// is exported under the forged request (integrity limit): its body is
    /// masked as a body is in any case.
    #[test]
    fn tls_key_starting_mid_body_withholds_the_forged_path() {
        let m = ConnectionFsmManager::new(4);
        tls_key(&m, 1);
        let mut out = feed(
            &m,
            1,
            true,
            b"GET /reset/qzkfwp/token HTTP/1.1\r\nHost: a\r\n\r\n",
        );
        out.extend(feed(
            &m,
            1,
            false,
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nreal-response",
        ));
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].path.as_deref(),
            Some(crate::protocol::FIELD_WITHHELD)
        );
        assert_eq!(out[0].payload_text.as_deref(), Some("real-response"));
    }

    /// Paths over such a key: any credential word withholds the path part
    /// whole; a path with none, or with one only in a keyed query value,
    /// goes to the usual rules.
    #[test]
    fn tls_path_holds_no_bare_name() {
        let w = Some(crate::protocol::FIELD_WITHHELD);
        for (path, want) in [
            ("/oauth/token", w),
            ("/api/password-reset/start", w),
            ("/oauth/token?grant=x", w),
            ("/users/42", Some("/users/42")),
            ("/login?password=x", Some("/login?password=x")),
        ] {
            let m = ConnectionFsmManager::new(4);
            tls_key(&m, 3);
            let req = format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n");
            feed(&m, 3, true, req.as_bytes());
            let out = feed(&m, 3, false, b"HTTP/1.1 204 No Content\r\n\r\n");
            assert_eq!(out.len(), 1, "{path}");
            assert_eq!(out[0].path.as_deref(), want, "{path}");
        }
        // A plaintext key keeps the bare name.
        let mut p = Http1Parser::new();
        p.feed(
            b"GET /oauth/token HTTP/1.1\r\nHost: a\r\n\r\n",
            Direction::Egress,
            1,
        );
        match p.feed(b"HTTP/1.1 204 No Content\r\n\r\n", Direction::Ingress, 2) {
            ParseResult::Messages(v) => assert_eq!(v[0].path.as_deref(), Some("/oauth/token")),
            r => panic!("{r:?}"),
        }
    }

    /// A lost record (here a whole response) on a key the parser read from
    /// its start: every later response answers the request before its own.
    /// This pins the documented integrity limit: `/two`'s answer is
    /// exported under `/one`, and moves no value under a weaker rule (a
    /// path and a response body are protected by the same rules wherever
    /// they are paired).
    #[test]
    fn tls_lost_response_record_misattributes_documented_limit() {
        let m = ConnectionFsmManager::new(4);
        tls_key(&m, 2);
        let mut out = feed(&m, 2, true, b"GET /one HTTP/1.1\r\nHost: a\r\n\r\n");
        // The response to /one is lost (ring drop: no signal on TLS).
        out.extend(feed(&m, 2, true, b"GET /two HTTP/1.1\r\nHost: a\r\n\r\n"));
        out.extend(feed(
            &m,
            2,
            false,
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\ntwo",
        ));
        let got: Vec<_> = out
            .iter()
            .map(|m| (m.path.as_deref(), m.status, m.payload_text.as_deref()))
            .collect();
        assert_eq!(got, vec![(Some("/one"), Some(404), Some("two"))]);
    }

    /// Review finding 3 (MED, open): a TLS record lost inside a request
    /// body leaves no mark, so the rest of the body is read as the whole
    /// of it and exported: here the tail of a password value, which no
    /// credential word precedes any more. The safe outcome below fails
    /// until per-key TLS loss detection lands (USER-GUIDE §5.3).
    #[test]
    #[ignore = "review finding 3 (MED): unmarked TLS loss inside a body exports its rest"]
    fn tls_lost_body_record_exports_no_body_rest() {
        let m = ConnectionFsmManager::new(4);
        tls_key(&m, 5);
        let body = r#"{"user":"alice","password":"Zq8vR2mW7tYk"}"#;
        let head = format!(
            "POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut out = feed(&m, 5, true, head.as_bytes());
        // The record holding the body's first part is lost.
        let cut = body.find("Zq8v").unwrap();
        out.extend(feed(&m, 5, true, &body.as_bytes()[cut..]));
        out.extend(feed(&m, 5, false, b"HTTP/1.1 204 No Content\r\n\r\n"));
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(!format!("{out:?}").contains("Zq8v"), "{out:?}");
    }
}
