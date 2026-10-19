#![allow(dead_code)]

//! HTTP/2 frame parser with per-stream state and HPACK header decompression.
//!
//! Frame format: 9-byte header (length:3 + type:1 + flags:1 + stream_id:4).
//!
//! Each direction has its own frame buffer and its own HPACK decoder: HPACK
//! dynamic tables are per direction (each endpoint indexes the headers it
//! sends), so a shared decoder corrupts both tables and later requests decode
//! to the wrong `:path`. Every header block — HEADERS, CONTINUATION and
//! PUSH_PROMISE — is decoded by its sender's decoder, in order, even when its
//! contents are not needed, to keep the tables in sync.
//!
//! A stream is emitted when the server finishes it (END_STREAM on DATA or
//! HEADERS/trailers) or either side resets it, pairing request and response.
//! For gRPC, `status` is the `grpc-status` from the trailers (or a
//! trailers-only response); otherwise it is `:status`.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

const FRAME_HEADER_SIZE: usize = 9;
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PUSH_PROMISE: u8 = 0x5;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

// Flags
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Body bytes kept per direction per stream for PII scanning.
const MAX_BODY: usize = 64 * 1024;
/// Concurrent streams tracked per connection; oldest are evicted beyond this.
const MAX_STREAMS: usize = 1024;

#[derive(Debug, Default)]
struct StreamState {
    method: Option<String>,
    path: Option<String>,
    status: Option<u32>,
    grpc_status: Option<u32>,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    request_ts: Option<u64>,
    request_size: u64,
    response_size: u64,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    /// Server already sent its response HEADERS; further ones are trailers.
    response_headers_seen: bool,
    /// Insertion order, for evicting the oldest stream at capacity.
    seq: u64,
}

/// Per-direction framing and HPACK state.
struct Side {
    buf: StreamBuffer,
    decoder: hpack::Decoder<'static>,
    /// Header block being assembled: (stream id, HEADERS flags, is push, bytes).
    pending_block: Option<(u32, u8, bool, Vec<u8>)>,
    /// Payload bytes of a DATA frame still to drop after a capture gap, and
    /// that frame's stream id and flags (END_STREAM applies once dropped).
    discard: usize,
    discard_frame: Option<(u32, u8)>,
}

impl Side {
    fn new() -> Self {
        Self {
            buf: StreamBuffer::new(),
            decoder: hpack::Decoder::new(),
            pending_block: None,
            discard: 0,
            discard_frame: None,
        }
    }
}

/// What a fully read frame means for the connection.
enum FrameEvent {
    None,
    /// Stream finished (server END_STREAM or reset): emit it.
    Complete(u32),
}

pub struct Http2Parser {
    client: Side,
    server: Side,
    /// Which capture direction carries client → server bytes. Learned from
    /// the connection preface when seen; defaults to Egress.
    client_dir: Direction,
    preface_seen: bool,
    streams: HashMap<u32, StreamState>,
    next_seq: u64,
    is_grpc: bool,
    protocol_type: Protocol,
}

impl Http2Parser {
    pub fn new(is_grpc: bool) -> Self {
        Self {
            client: Side::new(),
            server: Side::new(),
            client_dir: Direction::Egress,
            preface_seen: false,
            streams: HashMap::new(),
            next_seq: 0,
            is_grpc,
            protocol_type: if is_grpc {
                Protocol::Grpc
            } else {
                Protocol::Http2
            },
        }
    }

    pub fn current_state(&self) -> &'static str {
        if self.preface_seen {
            "streaming"
        } else {
            "preface"
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.is_grpc);
    }

    pub fn reset_for_next_transaction(&mut self) {
        self.reset();
    }

    fn is_client(&self, direction: Direction) -> bool {
        direction == self.client_dir
    }

    fn stream(&mut self, id: u32) -> &mut StreamState {
        if !self.streams.contains_key(&id) && self.streams.len() >= MAX_STREAMS {
            // A peer that never finishes streams must not grow memory.
            if let Some(oldest) = self
                .streams
                .iter()
                .min_by_key(|(_, s)| s.seq)
                .map(|(k, _)| *k)
            {
                self.streams.remove(&oldest);
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.streams.entry(id).or_insert_with(|| StreamState {
            seq,
            ..Default::default()
        })
    }

    /// Read every complete frame from one side's buffer.
    fn process_side(&mut self, from_client: bool, ts: u64, messages: &mut Vec<L7Message>) {
        loop {
            let side = if from_client {
                &mut self.client
            } else {
                &mut self.server
            };

            // Finish dropping a DATA frame cut by a capture gap.
            if side.discard > 0 {
                let n = side.discard.min(side.buf.len());
                side.buf.consume(n);
                side.discard -= n;
                if side.discard > 0 {
                    return;
                }
            }
            if let Some((stream_id, flags)) = side.discard_frame.take()
                && let FrameEvent::Complete(id) =
                    self.on_data(from_client, stream_id, flags, &[], ts)
                && let Some(msg) = self.emit(id, ts)
            {
                messages.push(msg);
            }

            let side = if from_client {
                &mut self.client
            } else {
                &mut self.server
            };
            let data = side.buf.data();
            if data.len() < FRAME_HEADER_SIZE {
                return;
            }
            let len = (data[0] as usize) << 16 | (data[1] as usize) << 8 | data[2] as usize;
            let total = FRAME_HEADER_SIZE + len;
            if data.len() < total {
                return;
            }
            let frame_type = data[3];
            let flags = data[4];
            let stream_id = u32::from_be_bytes([data[5] & 0x7F, data[6], data[7], data[8]]);
            let payload = data[FRAME_HEADER_SIZE..total].to_vec();
            side.buf.consume(total);

            let event = self.on_frame(from_client, frame_type, flags, stream_id, &payload, ts);
            if let FrameEvent::Complete(id) = event
                && let Some(msg) = self.emit(id, ts)
            {
                messages.push(msg);
            }
        }
    }

    fn on_frame(
        &mut self,
        from_client: bool,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
        ts: u64,
    ) -> FrameEvent {
        match frame_type {
            FRAME_HEADERS | FRAME_PUSH_PROMISE => {
                let mut offset = 0;
                let mut end = payload.len();
                if flags & FLAG_PADDED != 0 {
                    let pad = *payload.first().unwrap_or(&0) as usize;
                    offset = 1;
                    end = end.saturating_sub(pad);
                }
                let is_push = frame_type == FRAME_PUSH_PROMISE;
                if is_push {
                    offset += 4; // promised stream id
                } else if flags & FLAG_PRIORITY != 0 {
                    offset += 5; // stream dependency + weight
                }
                let block = payload
                    .get(offset..end.max(offset))
                    .unwrap_or_default()
                    .to_vec();
                let side = if from_client {
                    &mut self.client
                } else {
                    &mut self.server
                };
                side.pending_block = Some((stream_id, flags, is_push, block));
                if flags & FLAG_END_HEADERS != 0 {
                    return self.finish_header_block(from_client, ts);
                }
                FrameEvent::None
            }
            FRAME_CONTINUATION => {
                let side = if from_client {
                    &mut self.client
                } else {
                    &mut self.server
                };
                if let Some((_, _, _, block)) = side.pending_block.as_mut() {
                    block.extend_from_slice(payload);
                }
                if flags & FLAG_END_HEADERS != 0 {
                    return self.finish_header_block(from_client, ts);
                }
                FrameEvent::None
            }
            FRAME_DATA => {
                let body = if flags & FLAG_PADDED != 0 && !payload.is_empty() {
                    let pad = payload[0] as usize;
                    payload
                        .get(1..payload.len().saturating_sub(pad))
                        .unwrap_or_default()
                } else {
                    payload
                };
                self.on_data(from_client, stream_id, flags, body, ts)
            }
            FRAME_RST_STREAM => {
                if self.streams.contains_key(&stream_id) {
                    let code = payload
                        .get(..4)
                        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                    let stream = self.stream(stream_id);
                    stream.headers.push(("rst_stream".into(), code.to_string()));
                    return FrameEvent::Complete(stream_id);
                }
                FrameEvent::None
            }
            FRAME_SETTINGS | FRAME_PING | FRAME_WINDOW_UPDATE | FRAME_GOAWAY => FrameEvent::None,
            _ => FrameEvent::None,
        }
    }

    fn on_data(
        &mut self,
        from_client: bool,
        stream_id: u32,
        flags: u8,
        body: &[u8],
        _ts: u64,
    ) -> FrameEvent {
        if stream_id == 0 {
            return FrameEvent::None;
        }
        let stream = self.stream(stream_id);
        let (buf, size) = if from_client {
            (&mut stream.request_body, &mut stream.request_size)
        } else {
            (&mut stream.response_body, &mut stream.response_size)
        };
        *size += body.len() as u64;
        let room = MAX_BODY.saturating_sub(buf.len());
        buf.extend_from_slice(&body[..body.len().min(room)]);
        if !from_client && flags & FLAG_END_STREAM != 0 {
            return FrameEvent::Complete(stream_id);
        }
        FrameEvent::None
    }

    /// Decode a complete header block with the sender's decoder and apply it.
    fn finish_header_block(&mut self, from_client: bool, ts: u64) -> FrameEvent {
        let side = if from_client {
            &mut self.client
        } else {
            &mut self.server
        };
        let Some((stream_id, flags, is_push, block)) = side.pending_block.take() else {
            return FrameEvent::None;
        };
        // hpack can panic on malformed input; a failed block still has to be
        // skipped so later frames parse (its table updates are lost).
        let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| side.decoder.decode(&block)))
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        if is_push {
            return FrameEvent::None; // decoded only to keep the server table in sync
        }

        let mut grpc = false;
        let stream = self.stream(stream_id);
        let trailers = !from_client && stream.response_headers_seen;
        if from_client && stream.request_ts.is_none() {
            stream.request_ts = Some(ts);
        }
        if !from_client {
            stream.response_headers_seen = true;
        }
        for (name, value) in decoded {
            let name = String::from_utf8_lossy(&name).to_lowercase();
            let value = String::from_utf8_lossy(&value).into_owned();
            match name.as_str() {
                ":method" if from_client => stream.method = Some(value.clone()),
                ":path" if from_client => stream.path = Some(value.clone()),
                ":status" if !from_client => stream.status = value.parse().ok(),
                "content-type" => {
                    if value.starts_with("application/grpc") {
                        grpc = true;
                    }
                    if !trailers {
                        stream.content_type = Some(value.clone());
                    }
                }
                "grpc-status" => stream.grpc_status = value.parse().ok(),
                _ => {}
            }
            stream.headers.push((name, value));
        }
        if grpc {
            self.is_grpc = true;
            self.protocol_type = Protocol::Grpc;
        }
        if !from_client && flags & FLAG_END_STREAM != 0 {
            return FrameEvent::Complete(stream_id);
        }
        FrameEvent::None
    }

    fn emit(&mut self, stream_id: u32, ts: u64) -> Option<L7Message> {
        let stream = self.streams.remove(&stream_id)?;
        let mut msg = L7Message::new(self.protocol_type, Direction::Ingress, ts);
        msg.method = stream.method;
        // gRPC: report "pkg.Service/Method" (from `/pkg.Service/Method`)
        // whether the connection was identified by port or by content-type.
        if self.is_grpc
            && let Some(rpc) = stream.path.as_deref().and_then(|p| p.strip_prefix('/'))
            && rpc.contains('/')
        {
            msg.method = Some(rpc.to_string());
        }
        msg.path = stream.path;
        msg.status = if self.is_grpc {
            stream.grpc_status.or(stream.status)
        } else {
            stream.status
        };
        msg.content_type = stream.content_type;
        msg.headers = stream.headers;
        msg.request_size_bytes = stream.request_size;
        msg.response_size_bytes = stream.response_size;
        msg.latency_ns = stream.request_ts.map(|t| ts.saturating_sub(t));
        let text = |body: &[u8]| {
            if self.is_grpc {
                grpc_text(body)
            } else {
                body_text(body)
            }
        };
        msg.request_text = text(&stream.request_body);
        msg.payload_text = text(&stream.response_body);
        Some(msg)
    }

    /// Bytes `n` of the stream from `direction` were never captured. Only a
    /// gap that ends inside the DATA frame being read can be accounted for;
    /// anything else may have lost HPACK state or frame boundaries.
    fn skip_side(&mut self, from_client: bool, n: usize) -> bool {
        let side = if from_client {
            &mut self.client
        } else {
            &mut self.server
        };
        if side.discard > 0 {
            side.discard = match side.discard.checked_sub(n) {
                Some(rest) => rest,
                None => return false,
            };
            return true;
        }
        let data = side.buf.data();
        if data.len() < FRAME_HEADER_SIZE || data[3] != FRAME_DATA {
            return false;
        }
        let len = (data[0] as usize) << 16 | (data[1] as usize) << 8 | data[2] as usize;
        let missing = (FRAME_HEADER_SIZE + len).saturating_sub(data.len());
        if n > missing {
            return false;
        }
        let flags = data[4];
        let stream_id = u32::from_be_bytes([data[5] & 0x7F, data[6], data[7], data[8]]);
        let have_body = data.len() - FRAME_HEADER_SIZE;
        // Count the bytes we will never see toward the stream's size.
        let lost = (n + (missing - n)) as u64;
        side.buf.clear();
        side.discard = missing - n;
        side.discard_frame = Some((stream_id, flags));
        let stream = self.stream(stream_id);
        let size = if from_client {
            &mut stream.request_size
        } else {
            &mut stream.response_size
        };
        *size += have_body as u64 + lost;
        true
    }
}

/// Body as text for PII scanning (valid UTF-8 prefix; `None` if empty/binary).
fn body_text(body: &[u8]) -> Option<String> {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&body[..e.valid_up_to()]).ok()?,
        Err(_) => return None,
    };
    (!text.is_empty()).then(|| text.to_string())
}

/// Readable text from gRPC messages: each is `[compressed:1][len:4][bytes]`;
/// protobuf is binary, so keep printable UTF-8 runs (string fields — where
/// names, emails and addresses live). Compressed messages are skipped.
fn grpc_text(body: &[u8]) -> Option<String> {
    let mut runs: Vec<String> = Vec::new();
    let mut pos = 0;
    while pos + 5 <= body.len() {
        let compressed = body[pos] != 0;
        let len = u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]])
            as usize;
        let msg = &body[pos + 5..(pos + 5 + len).min(body.len())];
        pos += 5 + len;
        if compressed {
            continue;
        }
        let text = String::from_utf8_lossy(msg);
        let mut run = String::new();
        for c in text.chars() {
            if !c.is_control() && c != char::REPLACEMENT_CHARACTER {
                run.push(c);
            } else {
                if run.chars().count() >= 4 {
                    runs.push(std::mem::take(&mut run));
                }
                run.clear();
            }
        }
        if run.chars().count() >= 4 {
            runs.push(run);
        }
    }
    (!runs.is_empty()).then(|| runs.join(" "))
}

impl ProtocolParser for Http2Parser {
    fn feed(&mut self, data: &[u8], direction: Direction, ts: u64) -> ParseResult {
        let mut data = data;
        if !self.preface_seen {
            // The side that sends the preface is the client, whatever the
            // capture direction says (TLS uprobes report process-relative
            // directions, which are inverted on servers).
            if data.starts_with(HTTP2_PREFACE) {
                self.client_dir = direction;
                self.preface_seen = true;
                data = &data[HTTP2_PREFACE.len()..];
            } else if !data.is_empty() {
                self.preface_seen = true; // joined mid-connection
            }
        }
        let from_client = self.is_client(direction);
        let side = if from_client {
            &mut self.client
        } else {
            &mut self.server
        };
        if side.buf.extend(data).is_err() {
            return ParseResult::Error("HTTP/2 buffer overflow".into());
        }
        let mut messages = Vec::new();
        self.process_side(from_client, ts, &mut messages);
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn skip(&mut self, direction: Direction, n: usize, ts: u64) -> Option<ParseResult> {
        let from_client = self.is_client(direction);
        if !self.skip_side(from_client, n) {
            return None;
        }
        let mut messages = Vec::new();
        self.process_side(from_client, ts, &mut messages);
        Some(if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        })
    }

    fn protocol(&self) -> Protocol {
        self.protocol_type
    }
    fn state_name(&self) -> &'static str {
        self.current_state()
    }
    fn protocol_version(&self) -> Option<&str> {
        Some("2")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut f = Vec::with_capacity(FRAME_HEADER_SIZE + len);
        f.push((len >> 16) as u8);
        f.push((len >> 8) as u8);
        f.push(len as u8);
        f.push(frame_type);
        f.push(flags);
        f.extend_from_slice(&stream_id.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn encode(encoder: &mut hpack::Encoder<'static>, headers: &[(&str, &str)]) -> Vec<u8> {
        encoder.encode(headers.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())))
    }

    fn messages(r: ParseResult) -> Vec<L7Message> {
        match r {
            ParseResult::Messages(m) => m,
            _ => Vec::new(),
        }
    }

    /// Client preface + SETTINGS.
    fn preface() -> Vec<u8> {
        let mut d = HTTP2_PREFACE.to_vec();
        d.extend(make_frame(FRAME_SETTINGS, 0, 0, &[]));
        d
    }

    #[test]
    fn test_settings_frame() {
        let mut parser = Http2Parser::new(false);
        let settings = make_frame(FRAME_SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]);
        assert!(matches!(
            parser.feed(&settings, Direction::Ingress, 1000),
            ParseResult::NeedMoreData
        ));
    }

    #[test]
    fn test_bodyless_get_completes_on_response() {
        // GET with END_STREAM on HEADERS (no DATA), 200 + body.
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        let h = encode(
            &mut ce,
            &[
                (":method", "GET"),
                (":path", "/index.html"),
                (":scheme", "https"),
            ],
        );
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &h,
        ));
        assert!(messages(p.feed(&req, Direction::Egress, 1000)).is_empty());

        let mut resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(
                &mut se,
                &[(":status", "200"), ("content-type", "text/html")],
            ),
        );
        resp.extend(make_frame(
            FRAME_DATA,
            FLAG_END_STREAM,
            1,
            b"<html>hi</html>",
        ));
        let msgs = messages(p.feed(&resp, Direction::Ingress, 1600));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].method.as_deref(), Some("GET"));
        assert_eq!(msgs[0].path.as_deref(), Some("/index.html"));
        assert_eq!(msgs[0].status, Some(200));
        assert_eq!(msgs[0].payload_text.as_deref(), Some("<html>hi</html>"));
        assert_eq!(msgs[0].latency_ns, Some(600));
    }

    #[test]
    fn test_headers_only_response_completes() {
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut ce, &[(":method", "DELETE"), (":path", "/item/7")]),
        ));
        p.feed(&req, Direction::Egress, 0);
        let resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut se, &[(":status", "204")]),
        );
        let msgs = messages(p.feed(&resp, Direction::Ingress, 1));
        assert_eq!(msgs[0].status, Some(204));
    }

    #[test]
    fn test_per_direction_hpack_tables_keep_paths_correct() {
        // Both sides insert into their own dynamic tables; with a shared
        // decoder the second request's indexed :path resolved wrongly.
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        p.feed(&preface(), Direction::Egress, 0);
        for (i, path) in ["/a/first", "/b/second", "/a/first", "/c/third", "/b/second"]
            .iter()
            .enumerate()
        {
            let id = 1 + 2 * i as u32;
            let req = make_frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                id,
                &encode(
                    &mut ce,
                    &[(":method", "GET"), (":path", path), ("x-trace", "abc")],
                ),
            );
            p.feed(&req, Direction::Egress, 10);
            let resp = make_frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                id,
                &encode(
                    &mut se,
                    &[
                        (":status", "200"),
                        ("server", "envoy"),
                        ("x-resp", &format!("r{i}")),
                    ],
                ),
            );
            let msgs = messages(p.feed(&resp, Direction::Ingress, 20));
            assert_eq!(msgs[0].path.as_deref(), Some(*path), "request {i}");
            assert_eq!(msgs[0].status, Some(200));
        }
    }

    #[test]
    fn test_interleaved_streams_pair_correctly() {
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut ce, &[(":method", "POST"), (":path", "/a")]),
        ));
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            3,
            &encode(&mut ce, &[(":method", "POST"), (":path", "/b")]),
        ));
        req.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, 3, b"body-b"));
        req.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, b"body-a"));
        p.feed(&req, Direction::Egress, 0);
        let mut resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &encode(&mut se, &[(":status", "201")]),
        );
        resp.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut se, &[(":status", "500")]),
        ));
        let msgs = messages(p.feed(&resp, Direction::Ingress, 5));
        let got: Vec<_> = msgs
            .iter()
            .map(|m| (m.path.clone().unwrap(), m.status, m.request_text.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("/b".into(), Some(201), Some("body-b".into())),
                ("/a".into(), Some(500), Some("body-a".into())),
            ]
        );
    }

    #[test]
    fn test_continuation_frame() {
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            0,
            1,
            &encode(&mut ce, &[(":method", "GET")]),
        ));
        req.extend(make_frame(
            FRAME_CONTINUATION,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut ce, &[(":path", "/cont")]),
        ));
        p.feed(&req, Direction::Egress, 0);
        let resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut se, &[(":status", "200")]),
        );
        let msgs = messages(p.feed(&resp, Direction::Ingress, 1));
        assert_eq!(msgs[0].method.as_deref(), Some("GET"));
        assert_eq!(msgs[0].path.as_deref(), Some("/cont"));
    }

    #[test]
    fn test_grpc_status_from_trailers_and_trailers_only() {
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(true);
        let grpc_req = |ce: &mut hpack::Encoder<'static>, id: u32, path: &str| {
            let mut f = make_frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                id,
                &encode(
                    ce,
                    &[
                        (":method", "POST"),
                        (":path", path),
                        ("content-type", "application/grpc"),
                    ],
                ),
            );
            let mut msg = vec![0u8];
            msg.extend(9u32.to_be_bytes());
            msg.extend(b"\x0a\x07bob@x.y");
            f.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, id, &msg));
            f
        };
        let mut req = preface();
        req.extend(grpc_req(&mut ce, 1, "/pkg.Svc/Ok"));
        req.extend(grpc_req(&mut ce, 3, "/pkg.Svc/Missing"));
        p.feed(&req, Direction::Egress, 0);

        // Normal: HEADERS, DATA, trailers with grpc-status 0.
        let mut resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(
                &mut se,
                &[(":status", "200"), ("content-type", "application/grpc")],
            ),
        );
        let mut reply = vec![0u8];
        reply.extend(5u32.to_be_bytes());
        reply.extend(b"\x0a\x03yes");
        resp.extend(make_frame(FRAME_DATA, 0, 1, &reply));
        resp.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut se, &[("grpc-status", "0")]),
        ));
        // Trailers-only error: one HEADERS with END_STREAM.
        resp.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &encode(
                &mut se,
                &[
                    (":status", "200"),
                    ("content-type", "application/grpc"),
                    ("grpc-status", "5"),
                ],
            ),
        ));
        let msgs = messages(p.feed(&resp, Direction::Ingress, 1));
        assert_eq!(msgs.len(), 2);
        assert_eq!(
            (msgs[0].path.as_deref(), msgs[0].status),
            (Some("/pkg.Svc/Ok"), Some(0))
        );
        assert_eq!(msgs[0].request_text.as_deref(), Some("bob@x.y"));
        assert_eq!(msgs[0].payload_text.as_deref(), None); // "yes" is < 4 chars
        assert_eq!(
            (msgs[1].path.as_deref(), msgs[1].status),
            (Some("/pkg.Svc/Missing"), Some(5))
        );
    }

    #[test]
    fn test_rst_stream_emits_and_frees_stream() {
        let mut ce = hpack::Encoder::new();
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut ce, &[(":method", "GET"), (":path", "/slow")]),
        ));
        req.extend(make_frame(FRAME_RST_STREAM, 0, 1, &8u32.to_be_bytes())); // CANCEL
        let msgs = messages(p.feed(&req, Direction::Egress, 0));
        assert_eq!(msgs[0].path.as_deref(), Some("/slow"));
        assert!(msgs[0].headers.contains(&("rst_stream".into(), "8".into())));
        assert!(p.streams.is_empty());
    }

    #[test]
    fn test_unfinished_streams_are_capped() {
        let mut ce = hpack::Encoder::new();
        let mut p = Http2Parser::new(false);
        p.feed(&preface(), Direction::Egress, 0);
        for i in 0..(MAX_STREAMS as u32 + 500) {
            let h = encode(&mut ce, &[(":method", "GET"), (":path", "/x")]);
            p.feed(
                &make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1 + 2 * i, &h),
                Direction::Egress,
                0,
            );
        }
        assert!(p.streams.len() <= MAX_STREAMS);
    }

    #[test]
    fn test_preface_sets_client_direction() {
        // TLS uprobes on a server report the client's bytes as Ingress.
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut ce, &[(":method", "GET"), (":path", "/inverted")]),
        ));
        p.feed(&req, Direction::Ingress, 0);
        let resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut se, &[(":status", "200")]),
        );
        let msgs = messages(p.feed(&resp, Direction::Egress, 1));
        assert_eq!(msgs[0].path.as_deref(), Some("/inverted"));
    }

    #[test]
    fn test_gap_inside_data_frame_is_accounted() {
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut ce, &[(":method", "GET"), (":path", "/big")]),
        ));
        p.feed(&req, Direction::Egress, 0);
        let mut resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut se, &[(":status", "200")]),
        );
        let frame = make_frame(FRAME_DATA, FLAG_END_STREAM, 1, &vec![b'a'; 16_000]);
        resp.extend_from_slice(&frame[..4096]); // captured part
        p.feed(&resp, Direction::Ingress, 5);
        // 10_000 bytes lost, the last 1_913 of the frame arrive next.
        assert!(p.skip(Direction::Ingress, 10_000, 6).is_some());
        let msgs = messages(p.feed(&frame[4096 + 10_000..], Direction::Ingress, 7));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].response_size_bytes, 16_000);
        assert_eq!(msgs[0].status, Some(200));
    }

    #[test]
    fn test_metadata() {
        let p = Http2Parser::new(false);
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Http2);
        assert_eq!(p.state_name(), "preface");
        assert_eq!(ProtocolParser::protocol_version(&p), Some("2"));
    }

    #[test]
    fn test_grpc_mode() {
        let p = Http2Parser::new(true);
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Grpc);
    }
}
