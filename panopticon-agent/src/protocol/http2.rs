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
/// Decoded header bytes kept per stream (name + value + 32 per header, the
/// RFC 7541 entry size). A small block that indexes one large dynamic-table
/// entry thousands of times would otherwise decode to hundreds of MB.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Encoded header block bytes buffered across HEADERS + CONTINUATION frames.
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// Largest dynamic-table size update accepted. hpack applies any size the
/// peer sends; RFC 7541 §6.3 makes one above the SETTINGS limit an error.
const MAX_HPACK_TABLE: usize = 64 * 1024;
/// Longest content-type value classified; a longer one is unknown (and
/// its body treated as protobuf). Bounds the work an indexed value
/// repeated many times in one block can cost.
const MAX_CONTENT_TYPE: usize = 256;

#[derive(Debug, Default)]
struct StreamState {
    method: Option<String>,
    path: Option<String>,
    status: Option<u32>,
    grpc_status: Option<u32>,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    /// Decoded header bytes kept so far, bounded by `MAX_HEADER_BYTES`.
    header_bytes: usize,
    request_ts: Option<u64>,
    request_size: u64,
    response_size: u64,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    /// Server already sent its response HEADERS; further ones are trailers.
    response_headers_seen: bool,
    /// Bytes of the request / response body were lost, or the body began
    /// before this parser saw the stream's HEADERS: what remains may hold
    /// a credential's value without its name, so it is not exported.
    request_gap: bool,
    response_gap: bool,
    /// A gap inside this stream's body; it becomes `*_gap` when more body
    /// bytes of the stream are kept (a cut end keeps the prefix).
    request_gap_pending: bool,
    response_gap_pending: bool,
    /// The request / response may be gRPC or protobuf: such a content-type
    /// was decoded, whether or not the header budget kept it, or it was
    /// oversized or repeated (see `emit` for blocks not decoded at all).
    request_protobuf: bool,
    response_protobuf: bool,
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
    /// A header block of this side failed to decode or was skipped: the
    /// HPACK table may differ from the peer's (insertions before an error
    /// are kept, later ones missed), so a later block could decode a value
    /// under another header's name. No header of this side is exported
    /// again.
    headers_lost: bool,
}

impl Side {
    fn new() -> Self {
        Self {
            buf: StreamBuffer::new(),
            decoder: hpack::Decoder::new(),
            pending_block: None,
            discard: 0,
            discard_frame: None,
            headers_lost: false,
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
                // An oversized block is dropped; later CONTINUATIONs then
                // find no pending block and are ignored.
                side.pending_block =
                    (block.len() <= MAX_HEADER_BLOCK).then_some((stream_id, flags, is_push, block));
                side.headers_lost |= side.pending_block.is_none();
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
                    if block.len() + payload.len() > MAX_HEADER_BLOCK {
                        side.pending_block = None;
                        side.headers_lost = true;
                    } else {
                        block.extend_from_slice(payload);
                    }
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
        // A body this parser did not see start (late join, replaced after a
        // gap) is a tail; so are bytes kept after a gap in the body.
        if !body.is_empty() {
            if from_client && (stream.request_ts.is_none() || stream.request_gap_pending) {
                stream.request_gap = true;
            }
            if !from_client && (!stream.response_headers_seen || stream.response_gap_pending) {
                stream.response_gap = true;
            }
        }
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
        if hpack_oversized_table_update(&block) {
            side.headers_lost = true;
            return FrameEvent::None;
        }
        let budget = if is_push {
            0
        } else {
            MAX_HEADER_BYTES
                .saturating_sub(self.streams.get(&stream_id).map_or(0, |s| s.header_bytes))
        };
        let side = if from_client {
            &mut self.client
        } else {
            &mut self.server
        };
        // Decode with a byte budget: the callback borrows from the dynamic
        // table, so headers past the budget are never copied. The whole
        // block is still decoded to keep the table in sync.
        let mut decoded = Vec::new();
        let mut used = 0usize;
        // The body's kind is read from the block's content-type, kept
        // within the budget or not: (gRPC, gRPC or protobuf). Only the
        // first one is classified, and only up to MAX_CONTENT_TYPE bytes; an
        // oversized or repeated content-type makes the kind unknown.
        let (mut grpc, mut protobuf, mut content_types) = (false, false, 0usize);
        // hpack can panic on malformed input; a failed block still has to be
        // skipped so later frames parse (its table updates are lost).
        if !side.headers_lost {
            let ok = std::panic::catch_unwind(AssertUnwindSafe(|| {
                side.decoder.decode_with_cb(&block, |n, v| {
                    used = used.saturating_add(n.len() + v.len() + 32);
                    if n.eq_ignore_ascii_case(b"content-type") {
                        content_types += 1;
                        if content_types > 1 || v.len() > MAX_CONTENT_TYPE {
                            protobuf = true;
                        } else {
                            grpc |= v.starts_with(b"application/grpc");
                            protobuf |= contains(&v, b"grpc") || contains(&v, b"protobuf");
                        }
                    }
                    if used <= budget {
                        decoded.push((n.into_owned(), v.into_owned()));
                    }
                })
            }));
            if !matches!(ok, Ok(Ok(()))) {
                decoded.clear();
                side.headers_lost = true;
            }
        }
        if is_push {
            return FrameEvent::None; // decoded only to keep the server table in sync
        }

        let stream = self.stream(stream_id);
        if from_client {
            stream.request_protobuf |= protobuf;
        } else {
            stream.response_protobuf |= protobuf;
        }
        let trailers = !from_client && stream.response_headers_seen;
        if from_client && stream.request_ts.is_none() {
            stream.request_ts = Some(ts);
        }
        if !from_client {
            stream.response_headers_seen = true;
        }
        stream.header_bytes = stream.header_bytes.saturating_add(used.min(budget));
        for (name, value) in decoded {
            let name = String::from_utf8_lossy(&name).to_lowercase();
            let value = String::from_utf8_lossy(&value).into_owned();
            match name.as_str() {
                ":method" if from_client => stream.method = Some(value.clone()),
                ":path" if from_client => stream.path = Some(value.clone()),
                ":status" if !from_client => stream.status = value.parse().ok(),
                "content-type" => {
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
        // Protobuf without its schema carries field numbers, not names: a
        // password field cannot be told from any other string, so its text
        // is not exported while credentials are protected.
        // Each body by its own side's content-type, decoded whether or not
        // the header budget kept it. A side that lost a header block
        // (joined mid-connection, oversized, failed or skipped, including
        // a final block after an informational one) has an unknown
        // content-type: its bodies are treated as protobuf.
        let request_protobuf = stream.request_protobuf || self.client.headers_lost;
        let response_protobuf = stream.response_protobuf || self.server.headers_lost;
        let text = |body: &[u8], protobuf: bool| {
            if (self.is_grpc || protobuf) && super::mask_credentials_enabled() {
                None
            } else if self.is_grpc {
                grpc_text(body)
            } else {
                body_text(body)
            }
        };
        msg.request_text =
            text(&stream.request_body, request_protobuf).filter(|_| !stream.request_gap);
        msg.payload_text =
            text(&stream.response_body, response_protobuf).filter(|_| !stream.response_gap);
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
        let payload = &data[FRAME_HEADER_SIZE..];
        // The frame's data captured so far is the body's next bytes: kept
        // as its provable prefix (the pad-length byte and padding are not
        // data).
        let prefix = if flags & FLAG_PADDED != 0 {
            let end = len.saturating_sub(payload.first().map_or(len, |&p| p as usize));
            payload.get(1..end.min(payload.len())).unwrap_or_default()
        } else {
            payload
        }
        .to_vec();
        let other = (payload.len() - prefix.len()) as u64;
        side.buf.clear();
        side.discard = missing - n;
        side.discard_frame = Some((stream_id, flags));
        self.on_data(from_client, stream_id, 0, &prefix, 0);
        let stream = self.stream(stream_id);
        let size = if from_client {
            stream.request_gap_pending = true;
            &mut stream.request_size
        } else {
            stream.response_gap_pending = true;
            &mut stream.response_size
        };
        // The bytes we will never see count toward the stream's size.
        *size += other + missing as u64;
        true
    }
}

/// Body as text for PII scanning (valid UTF-8 prefix; `None` if empty/binary).
/// HPACK integer with an `prefix`-bit prefix (RFC 7541 §5.1): (value, bytes).
fn hpack_int(buf: &[u8], prefix: u32) -> Option<(usize, usize)> {
    let mask = (1usize << prefix) - 1;
    let first = *buf.first()? as usize & mask;
    if first < mask {
        return Some((first, 1));
    }
    let mut value = mask;
    // At most 4 continuation bytes (28 bits): larger values are refused.
    for (i, &b) in buf.iter().enumerate().skip(1).take(4) {
        value += ((b & 0x7f) as usize) << (7 * (i - 1));
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// True if `block` holds a dynamic-table size update above
/// `MAX_HPACK_TABLE`, or cannot be walked. hpack accepts any size, so the
/// representations are walked here first (§6) to clamp it.
fn hpack_oversized_table_update(block: &[u8]) -> bool {
    let walk = || -> Option<bool> {
        let mut i = 0;
        while i < block.len() {
            let b = block[i];
            let prefix = match b {
                _ if b & 0x80 != 0 => 7, // indexed
                _ if b & 0x40 != 0 => 6, // literal, incremental indexing
                _ if b & 0x20 != 0 => 5, // size update
                _ => 4,                  // literal, not / never indexed
            };
            let (n, used) = hpack_int(&block[i..], prefix)?;
            i += used;
            match prefix {
                7 => {}
                5 if n > MAX_HPACK_TABLE => return Some(true),
                5 => {}
                _ => {
                    // Literal name (index 0) and value strings.
                    for _ in 0..if n == 0 { 2 } else { 1 } {
                        let (len, used) = hpack_int(block.get(i..)?, 7)?;
                        i = i.checked_add(used)?.checked_add(len)?;
                    }
                }
            }
        }
        Some(false)
    };
    walk().unwrap_or(true)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    #[cfg(test)]
    tests::SCANNED.with(|n| n.set(n.get() + haystack.len()));
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

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
                // This parser's first bytes. Whether they are the
                // connection's start is decided by the connection manager,
                // which latches a replacement parser (`joined_late`)
                // otherwise; a preface never clears a latch.
                self.client_dir = direction;
                self.preface_seen = true;
                data = &data[HTTP2_PREFACE.len()..];
            } else if !data.is_empty() {
                // Joined mid-connection: header blocks and bodies before
                // these bytes were never seen.
                self.preface_seen = true;
                self.joined_late();
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

    /// The parser did not see some of the connection (a side's start, or
    /// bytes it could not account for): both sides count as having lost a
    /// header block, so no header is decoded and bodies are withheld while
    /// credentials are masked, for the rest of this parser's life. Always
    /// latches; the one gap that does not call it is a DATA-frame gap
    /// `skip` accounted for (see `ConnectionFsmManager::skip_from`).
    fn joined_late(&mut self) {
        self.client.headers_lost = true;
        self.server.headers_lost = true;
    }

    fn at_frame_boundary(&self) -> bool {
        [&self.client, &self.server]
            .iter()
            .all(|s| s.buf.data().is_empty() && s.discard == 0 && s.pending_block.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// Content-type bytes scanned by `contains` on this thread.
        pub static SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Codex R6 N4: bytes lost inside a HEADERS frame replace the parser;
    /// the replacement (and any parser that did not see the connection
    /// start with the client preface) treats its headers and bodies as
    /// unknown for the rest of the connection.
    #[test]
    fn test_replacement_parser_keeps_bodies_withheld() {
        use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};
        let m = ConnectionFsmManager::new(4);
        m.get_or_create(1, Protocol::Http2);
        let mut req = preface();
        let mut ce = hpack::Encoder::new();
        let headers = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut ce, &[(":method", "POST"), (":path", "/a")]),
        );
        req.extend_from_slice(&headers[..headers.len() - 3]); // cut inside HEADERS
        m.process_packet(1, Direction::Egress, &req, 1);
        assert!(m.skip_from(1, (0, 0), Direction::Egress, 3, 2).is_none());
        // A new stream: static-table headers only, then a body.
        let mut req = make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &[0x83, 0x84]);
        req.extend(make_frame(
            FRAME_DATA,
            FLAG_END_STREAM,
            3,
            b"\x0a\x0cs7Kf2v9LmQ8z",
        ));
        m.process_packet(1, Direction::Egress, &req, 3);
        let status = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &[0x88],
        );
        let out = match m.process_packet(1, Direction::Ingress, &status, 4) {
            Some(FsmResult::MessageComplete(msg)) => vec![msg],
            Some(FsmResult::Messages(ms)) => ms,
            _ => vec![],
        };
        let dump = format!("{out:?}");
        assert!(!dump.contains("s7Kf"), "{dump}");
        // Same for a parser that joined mid-connection without a gap.
        let mut p = Http2Parser::new(false);
        p.feed(&req, Direction::Egress, 1);
        let out = format!("{:?}", messages(p.feed(&status, Direction::Ingress, 2)));
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Codex R7 #2: a segment starting with the preface bytes in the middle
    /// of a connection (here the payload of a DATA frame whose header came
    /// first, or after a recorded loss) replaces the parser but never
    /// clears the uncertainty: the replacement is latched.
    #[test]
    fn test_preface_mid_stream_never_clears_the_latch() {
        use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};
        let canary = b"\x0a\x0cs7Kf2v9LmQ8z";
        let new_stream = |m: &ConnectionFsmManager, sid: u32| {
            let mut req = make_frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, &[0x83, 0x84]);
            req.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, sid, canary));
            m.process_packet(1, Direction::Egress, &req, 5);
            let status = make_frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                sid,
                &[0x88],
            );
            let out = match m.process_packet(1, Direction::Ingress, &status, 6) {
                Some(FsmResult::MessageComplete(msg)) => vec![msg],
                Some(FsmResult::Messages(ms)) => ms,
                _ => vec![],
            };
            format!("{out:?}")
        };
        // A DATA frame's header, then its payload starting with the preface.
        let m = ConnectionFsmManager::new(4);
        m.get_or_create(1, Protocol::Http2);
        let mut ce = hpack::Encoder::new();
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut ce, &[(":method", "POST"), (":path", "/a")]),
        ));
        let mut payload = HTTP2_PREFACE.to_vec();
        payload.extend(make_frame(FRAME_SETTINGS, 0, 0, &[]));
        let data = make_frame(FRAME_DATA, 0, 1, &payload);
        req.extend_from_slice(&data[..FRAME_HEADER_SIZE]);
        m.process_packet(1, Direction::Egress, &req, 1);
        m.process_packet(1, Direction::Egress, &data[FRAME_HEADER_SIZE..], 2);
        let out = new_stream(&m, 3);
        assert!(!out.contains("s7Kf"), "{out}");

        // A loss recorded, then the preface at a frame boundary.
        let m = ConnectionFsmManager::new(4);
        m.get_or_create(1, Protocol::Http2);
        let mut req = preface();
        let headers = make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x83, 0x84]);
        req.extend_from_slice(&headers[..headers.len() - 1]);
        m.process_packet(1, Direction::Egress, &req, 1);
        assert!(m.skip_from(1, (0, 0), Direction::Egress, 1, 2).is_none());
        let mut again = HTTP2_PREFACE.to_vec();
        again.extend(make_frame(FRAME_SETTINGS, 0, 0, &[]));
        m.process_packet(1, Direction::Egress, &again, 3);
        let out = new_stream(&m, 3);
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Codex R7 #3: a parser that saw the connection start is still
    /// latched when told a side was not seen from its start (an unplaced
    /// TCP side: a lost SYN+ACK and first response).
    #[test]
    fn test_joined_late_always_latches() {
        let mut p = Http2Parser::new(false);
        p.feed(&preface(), Direction::Egress, 0);
        p.joined_late();
        let mut req = make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &[0x83, 0x84]);
        req.extend(make_frame(
            FRAME_DATA,
            FLAG_END_STREAM,
            3,
            b"\x0a\x0cs7Kf2v9LmQ8z",
        ));
        p.feed(&req, Direction::Egress, 1);
        let status = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &[0x88],
        );
        let out = format!("{:?}", messages(p.feed(&status, Direction::Ingress, 2)));
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Codex R5 H1: a 60,000-byte content-type indexed again and again
    /// costs one bounded check per block, and its body is withheld.
    #[test]
    fn test_content_type_classification_is_bounded() {
        let mut seed = vec![0x3f, 0xe1, 0xff, 0x03]; // table size 65,536
        seed.push(0x40 | 31); // literal, incremental indexing, name: content-type (31)
        seed.extend([0x7f, 0xe1, 0xd3, 0x03]); // value length 127 + 59,873 = 60,000
        seed.extend(std::iter::repeat_n(b'a', 60_000));
        let mut repeat = vec![0x83, 0x84]; // :method POST, :path /
        repeat.extend(std::iter::repeat_n(0xbe, 1000)); // the content-type, 1000 times
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        for (sid, block) in [(1u32, &seed), (3, &repeat)] {
            let mut first = make_frame(FRAME_HEADERS, 0, sid, &block[..block.len().min(16_000)]);
            let mut at = 16_000;
            while at < block.len() {
                let end = (at + 16_000).min(block.len());
                let flags = if end == block.len() {
                    FLAG_END_HEADERS
                } else {
                    0
                };
                first.extend(make_frame(FRAME_CONTINUATION, flags, sid, &block[at..end]));
                at = end;
            }
            if block.len() <= 16_000 {
                first[4] = FLAG_END_HEADERS;
            }
            req.extend(first);
        }
        req.extend(make_frame(
            FRAME_DATA,
            FLAG_END_STREAM,
            3,
            b"\x0a\x0cs7Kf2v9LmQ8z",
        ));
        let before = SCANNED.with(|n| n.get());
        p.feed(&req, Direction::Egress, 1);
        let scanned = SCANNED.with(|n| n.get()) - before;
        assert!(scanned <= 2 * MAX_CONTENT_TYPE, "{scanned} bytes scanned");
        let status = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &[0x88],
        );
        let out = messages(p.feed(&status, Direction::Ingress, 2));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].request_text, None, "{:?}", out[0].request_text);
    }

    /// Codex R5 H5: a 103 decoded, then a final response block over the
    /// size limit (dropped): the body's content-type is unknown, so the
    /// protobuf body is not exported.
    #[test]
    fn test_body_after_a_lost_final_header_block_is_withheld() {
        let (mut ce, mut se) = (hpack::Encoder::new(), hpack::Encoder::new());
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode(&mut ce, &[(":method", "GET"), (":path", "/x")]),
        ));
        p.feed(&req, Direction::Egress, 0);
        let mut resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut se, &[(":status", "103")]),
        );
        let big = vec![0x88u8; 70_000]; // never decoded: over MAX_HEADER_BLOCK
        resp.extend(make_frame(FRAME_HEADERS, 0, 1, &big[..40_000]));
        resp.extend(make_frame(
            FRAME_CONTINUATION,
            FLAG_END_HEADERS,
            1,
            &big[40_000..],
        ));
        resp.extend(make_frame(
            FRAME_DATA,
            FLAG_END_STREAM,
            1,
            b"\x0a\x0cs7Kf2v9LmQ8z",
        ));
        let out = messages(p.feed(&resp, Direction::Ingress, 1));
        assert_eq!(out.len(), 1);
        assert!(super::super::mask_credentials_enabled());
        assert_eq!(out[0].payload_text, None, "{:?}", out[0].payload_text);
    }

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

    /// F9: one 4000-byte dynamic-table entry indexed 2000 times is ~8 MB
    /// decoded from a ~6 KB block. Kept headers stay within the budget.
    #[test]
    fn test_hpack_bomb_is_capped() {
        let mut block = vec![0x40, 0x01, b'x', 0x7f]; // literal, incr. indexing, name "x"
        block.extend([0xa1, 0x1e]); // value length 127 + 3873 = 4000
        block.extend(std::iter::repeat_n(b'a', 4000));
        block.extend(std::iter::repeat_n(0xbe, 2000)); // indexed: dynamic entry 62
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        let mut first = make_frame(FRAME_HEADERS, 0, 1, &block[..3000]);
        first.extend(make_frame(
            FRAME_CONTINUATION,
            FLAG_END_HEADERS,
            1,
            &block[3000..],
        ));
        req.extend(first);
        p.feed(&req, Direction::Egress, 1000);
        let kept: usize = p.streams[&1]
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 32)
            .sum();
        assert!(
            kept > 0 && kept <= MAX_HEADER_BYTES,
            "kept {kept} header bytes"
        );

        // A dynamic-table size update above the cap drops the block.
        let mut p = Http2Parser::new(false);
        let mut big = vec![0x3f, 0xe1, 0xff, 0x04]; // size update to 81920
        big.extend(encode(&mut hpack::Encoder::new(), &[(":path", "/x")]));
        let mut req = preface();
        req.extend(make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &big));
        p.feed(&req, Direction::Egress, 1000);
        assert!(!p.streams.contains_key(&3));
        assert!(hpack_oversized_table_update(&big));
        assert!(!hpack_oversized_table_update(&[0x3f, 0xe1, 0x1f])); // 4096
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

    /// Joined mid-connection, the HPACK table lacks the earlier insertions:
    /// a block that refers to them fails to decode and is dropped whole, so
    /// no value is exported under another header's name.
    #[test]
    fn test_late_join_never_decodes_a_value_under_another_name() {
        let mut ce = hpack::Encoder::new();
        let first = [
            (":method", "POST"),
            (":path", "/a"),
            ("x-session-note", "canary-secret-value"),
        ];
        let before = encode(&mut ce, &first); // sent before capture started
        let mut p = Http2Parser::new(false);
        let h = encode(&mut ce, &[(":method", "POST"), (":path", "/b"), first[2]]);
        // The block refers to the dynamic table instead of repeating it.
        assert!(h.len() < before.len() - "canary-secret-value".len());
        let req = make_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &h);
        p.feed(&req, Direction::Egress, 1);
        let h = encode(&mut hpack::Encoder::new(), &[(":status", "200")]);
        let resp = make_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &h);
        for m in messages(p.feed(&resp, Direction::Ingress, 2)) {
            // The request block was dropped, not decoded.
            assert!(m.headers.iter().all(|(n, _)| n != "x-session-note"));
            for (name, value) in &m.headers {
                assert!(
                    !value.contains("canary") || name == "x-session-note",
                    "{name}: {value}"
                );
            }
            assert!(m.path.as_deref().is_none_or(|p| !p.contains("canary")));
            assert!(m.method.as_deref().is_none_or(|p| !p.contains("canary")));
        }
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
        // Codex round 4: schema-less protobuf text has no field names, so a
        // password field is indistinguishable from any other string. With
        // credential masking on (the default) it is not exported.
        assert_eq!(msgs[0].request_text.as_deref(), None);
        assert_eq!(msgs[0].payload_text.as_deref(), None);
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
        // A whole first frame, then a large one cut by the capture cap.
        resp.extend(make_frame(FRAME_DATA, 0, 1, b"prefix of the body"));
        let frame = make_frame(FRAME_DATA, FLAG_END_STREAM, 1, &vec![b'a'; 16_000]);
        resp.extend_from_slice(&frame[..4096]); // captured part
        p.feed(&resp, Direction::Ingress, 5);
        // 10_000 bytes lost, the last 1_913 of the frame arrive next.
        assert!(p.skip(Direction::Ingress, 10_000, 6).is_some());
        let msgs = messages(p.feed(&frame[4096 + 10_000..], Direction::Ingress, 7));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].response_size_bytes, 16_018);
        assert_eq!(msgs[0].status, Some(200));
        // Nothing was kept after the gap: the captured prefix, the cut
        // frame's captured bytes included, is exported.
        let text = msgs[0].payload_text.as_deref().unwrap();
        assert_eq!(text.len(), 18 + 4096 - FRAME_HEADER_SIZE);
        assert!(text.starts_with("prefix of the bodyaaa"), "{text}");
    }

    /// Codex round 5 #12: a single DATA frame carrying END_STREAM, its
    /// tail lost: the captured beginning is the body's provable prefix
    /// (padding and the pad-length byte not part of it).
    #[test]
    fn test_cut_end_of_a_single_frame_keeps_its_prefix() {
        for padded in [false, true] {
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
            let mut body = b"start of the body ".to_vec();
            body.extend(vec![b'a'; 9_000]);
            let (flags, payload) = if padded {
                let mut pl = vec![100u8];
                pl.extend(&body);
                pl.extend(vec![0u8; 100]);
                (FLAG_END_STREAM | FLAG_PADDED, pl)
            } else {
                (FLAG_END_STREAM, body.clone())
            };
            let frame = make_frame(FRAME_DATA, flags, 1, &payload);
            resp.extend_from_slice(&frame[..4096]);
            p.feed(&resp, Direction::Ingress, 5);
            let msgs = match p.skip(Direction::Ingress, frame.len() - 4096, 6) {
                Some(r) => messages(r),
                None => panic!("gap not accounted"),
            };
            assert_eq!(msgs.len(), 1, "padded {padded}");
            let text = msgs[0].payload_text.as_deref().unwrap_or("");
            let kept = 4096 - FRAME_HEADER_SIZE - usize::from(padded);
            assert_eq!(text.as_bytes(), &body[..kept], "padded {padded}");
            assert_eq!(msgs[0].response_size_bytes, payload.len() as u64);
        }
    }

    /// Joined mid-connection: the client's header block indexes table
    /// entries the agent never saw, so the request's content-type is
    /// unknown and its body (here protobuf that is valid UTF-8) is
    /// withheld while credentials are masked, as is the response's.
    #[test]
    fn test_body_under_undecodable_headers_is_withheld() {
        let mut p = Http2Parser::new(false);
        // No preface seen; :method POST, then an unknown dynamic entry.
        let mut req = make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x83, 0x80 | 70]);
        let mut msg = vec![0, 0, 0, 0, 14, 0x0a, 12];
        msg.extend_from_slice(b"s7Kf2v9LmQ8z");
        req.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, &msg));
        p.feed(&req, Direction::Egress, 1);
        let mut se = hpack::Encoder::new();
        let mut resp = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(
                &mut se,
                &[(":status", "200"), ("content-type", "text/plain")],
            ),
        );
        resp.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, b"plain reply"));
        let out = messages(p.feed(&resp, Direction::Ingress, 2));
        assert_eq!(out.len(), 1);
        assert!(super::super::mask_credentials_enabled());
        assert_eq!(out[0].request_text, None, "{:?}", out[0]);
        // Joined mid-connection (no preface): the response side's history
        // is unknown too (R6 N4), so its body is withheld as well.
        assert_eq!(out[0].payload_text, None);
    }

    /// Codex round 5 #8: gRPC is recognised from a content-type the header
    /// budget did not keep, so its protobuf body is not exported.
    #[test]
    fn test_grpc_past_the_header_budget_is_recognised() {
        let mut block = vec![0x83, 0x84]; // :method POST, :path /
        block.extend([0x40, 0x05]); // literal, incremental indexing, name
        block.extend_from_slice(b"x-pad");
        block.extend([0x7f, 0xd1, 0x0e]); // value length 127 + 1873 = 2000
        block.extend(std::iter::repeat_n(b'p', 2000));
        block.extend(std::iter::repeat_n(0xbe, 40)); // x-pad again, 40 times
        block.push(0x00); // literal, not indexed, new name
        block.push(12);
        block.extend_from_slice(b"content-type");
        block.push(16);
        block.extend_from_slice(b"application/grpc");
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block));
        // One gRPC message: field 1, string "s7Kf2v9LmQ8z".
        let mut msg = vec![0, 0, 0, 0, 14, 0x0a, 12];
        msg.extend_from_slice(b"s7Kf2v9LmQ8z");
        req.extend(make_frame(FRAME_DATA, FLAG_END_STREAM, 1, &msg));
        p.feed(&req, Direction::Egress, 1);
        let status = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &[0x88],
        );
        let out = messages(p.feed(&status, Direction::Ingress, 2));
        assert_eq!(out.len(), 1);
        assert!(super::super::mask_credentials_enabled());
        let dump = format!("{:?}", out[0]);
        assert!(!dump.contains("s7Kf"), "{dump}");
    }

    /// Codex: a block that fails to decode may still have changed the
    /// table (insertions before the error are kept, those after it are
    /// missed), so a later block can decode a credential value under
    /// another name. After a failed or skipped block, no header of that
    /// side is exported again.
    #[test]
    fn test_hpack_error_stops_header_export() {
        fn lit_new(out: &mut Vec<u8>, name: &str, value: &str) {
            out.push(0x40); // literal, incremental indexing, new name
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            out.push(value.len() as u8);
            out.extend_from_slice(value.as_bytes());
        }
        // Captured mid-connection; the peer had indexed `x-before` already.
        let mut b1 = vec![0x83, 0x84]; // :method POST, :path /
        lit_new(&mut b1, "x-note", "ok");
        b1.push(0x80 | 63); // x-before: unknown to the agent → error
        lit_new(&mut b1, "x-api-key", "old"); // missed by the agent
        let mut b2 = vec![0x83, 0x84];
        b2.push(0x40 | 62); // the peer's newest entry: x-api-key
        b2.push(12);
        b2.extend_from_slice(b"s7Kf2v9LmQ8z");
        let mut p = Http2Parser::new(false);
        let status = make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &[0x88],
        );
        let mut out = vec![];
        for (sid, block) in [(1u32, b1), (3, b2)] {
            let req = make_frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                sid,
                &block,
            );
            p.feed(&req, Direction::Egress, 1);
            let mut resp = status.clone();
            resp[5..9].copy_from_slice(&sid.to_be_bytes());
            out.extend(messages(p.feed(&resp, Direction::Ingress, 2)));
        }
        for m in &out {
            for (n, v) in &m.headers {
                assert!(!v.contains("s7Kf"), "{n}: {v}");
            }
        }
    }

    /// A DATA gap: the stream's body is incomplete, and a parser that did
    /// not see a stream's HEADERS (late join, replaced after a gap) does
    /// not export what it sees of that stream's body.
    #[test]
    fn test_body_with_a_gap_is_withheld() {
        let mut ce = hpack::Encoder::new();
        let mut p = Http2Parser::new(false);
        let mut req = preface();
        req.extend(make_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &encode(&mut ce, &[(":method", "POST"), (":path", "/login")]),
        ));
        let frame = make_frame(
            FRAME_DATA,
            0,
            1,
            br#"{"note":"a","password":"s7Kf2v9LmQ8z"}"#,
        );
        req.extend_from_slice(&frame[..9 + 11]);
        p.feed(&req, Direction::Egress, 1);
        assert!(p.skip(Direction::Egress, frame.len() - 20, 2).is_some());
        p.feed(
            &make_frame(FRAME_DATA, FLAG_END_STREAM, 1, b"tail"),
            Direction::Egress,
            3,
        );
        let h = encode(&mut hpack::Encoder::new(), &[(":status", "200")]);
        let resp = make_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &h);
        let m = messages(p.feed(&resp, Direction::Ingress, 4));
        assert_eq!(m[0].request_text, None, "{m:?}");

        // Replaced after losing a whole frame: the next frame is a tail.
        let mut p = Http2Parser::new(false);
        let tail = make_frame(FRAME_DATA, FLAG_END_STREAM, 1, br#"s7Kf2v9LmQ8z"}"#);
        p.feed(&tail, Direction::Egress, 1);
        let m = messages(p.feed(&resp, Direction::Ingress, 2));
        assert!(m.iter().all(|m| m.request_text.is_none()), "{m:?}");
    }

    #[test]
    fn test_metadata() {
        let p = Http2Parser::new(false);
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Http2);
        assert_eq!(p.state_name(), "preface");
        assert_eq!(ProtocolParser::protocol_version(&p), Some("2"));
    }

    #[test]
    fn test_grpc_text_extracts_strings() {
        let mut msg = vec![0u8, 0, 0, 0, 9, 0x0a, 7];
        msg.extend_from_slice(b"bob@x.y");
        assert_eq!(grpc_text(&msg).as_deref(), Some("bob@x.y"));
    }

    #[test]
    fn test_grpc_mode() {
        let p = Http2Parser::new(true);
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Grpc);
    }
}
