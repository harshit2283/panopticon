#![allow(dead_code)]

//! HTTP/2 frame parser with per-stream state and HPACK header decompression.
//!
//! Frame format: 9-byte header (length:3 + type:1 + flags:1 + stream_id:4).
//! Uses `hpack` crate for HPACK dynamic table decoding.

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};
use std::{collections::HashMap, panic::AssertUnwindSafe};

const FRAME_HEADER_SIZE: usize = 9;
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

// Flags
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

#[derive(Debug, Clone)]
struct StreamState {
    method: Option<String>,
    path: Option<String>,
    status: Option<u32>,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    request_ts: Option<u64>,
    request_size: u64,
    response_size: u64,
    header_buf: Vec<u8>, // for CONTINUATION frames
    is_request: bool,
    data_buf: Vec<u8>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            method: None,
            path: None,
            status: None,
            content_type: None,
            headers: Vec::new(),
            request_ts: None,
            request_size: 0,
            response_size: 0,
            header_buf: Vec::new(),
            is_request: false,
            data_buf: Vec::new(),
        }
    }
}

pub struct Http2Parser {
    buf: StreamBuffer,
    streams: HashMap<u32, StreamState>,
    decoder: hpack::Decoder<'static>,
    preface_seen: bool,
    is_grpc: bool,
    protocol_type: Protocol,
}

impl Http2Parser {
    pub fn new(is_grpc: bool) -> Self {
        Self {
            buf: StreamBuffer::new(),
            streams: HashMap::new(),
            decoder: hpack::Decoder::new(),
            preface_seen: false,
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
        self.streams.clear();
        self.decoder = hpack::Decoder::new();
        self.preface_seen = false;
        self.buf.clear();
    }

    fn process(&mut self, ts: u64) -> ParseResult {
        let mut messages = Vec::new();

        // Skip HTTP/2 connection preface if present
        if !self.preface_seen {
            let data = self.buf.data();
            if data.starts_with(HTTP2_PREFACE) {
                self.buf.consume(HTTP2_PREFACE.len());
                self.preface_seen = true;
            } else if data.len() >= HTTP2_PREFACE.len() {
                self.preface_seen = true; // not a preface, proceed
            }
        }

        loop {
            let data = self.buf.data();
            if data.len() < FRAME_HEADER_SIZE {
                break;
            }

            let frame_len = (data[0] as usize) << 16 | (data[1] as usize) << 8 | data[2] as usize;
            let frame_type = data[3];
            let flags = data[4];
            let stream_id = u32::from_be_bytes([data[5] & 0x7F, data[6], data[7], data[8]]);

            let total = FRAME_HEADER_SIZE + frame_len;
            if data.len() < total {
                break;
            }

            let payload = data[FRAME_HEADER_SIZE..total].to_vec();
            self.buf.consume(total);

            match frame_type {
                FRAME_HEADERS => {
                    self.handle_headers(stream_id, flags, &payload, ts);
                    if flags & FLAG_END_HEADERS != 0
                        && let Some(msg) = self.try_decode_headers(stream_id, flags, ts)
                    {
                        messages.push(msg);
                    }
                }
                FRAME_CONTINUATION => {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.header_buf.extend_from_slice(&payload);
                    }
                    if flags & FLAG_END_HEADERS != 0
                        && let Some(msg) = self.try_decode_headers(stream_id, flags, ts)
                    {
                        messages.push(msg);
                    }
                }
                FRAME_DATA => {
                    let end_stream = flags & FLAG_END_STREAM != 0;
                    let data_payload = if flags & FLAG_PADDED != 0 && !payload.is_empty() {
                        let pad_len = payload[0] as usize;
                        if payload.len() > 1 + pad_len {
                            &payload[1..payload.len() - pad_len]
                        } else {
                            &[]
                        }
                    } else {
                        &payload
                    };

                    let stream = self
                        .streams
                        .entry(stream_id)
                        .or_insert_with(StreamState::new);
                    if stream.is_request {
                        stream.request_size += data_payload.len() as u64;
                    } else {
                        stream.response_size += data_payload.len() as u64;
                    }
                    // Store small amounts of data for PII scanning
                    if stream.data_buf.len() < 65536 {
                        let room = 65536 - stream.data_buf.len();
                        let take = data_payload.len().min(room);
                        stream.data_buf.extend_from_slice(&data_payload[..take]);
                    }

                    if end_stream && let Some(msg) = self.emit_message(stream_id, ts) {
                        messages.push(msg);
                    }
                }
                FRAME_SETTINGS | FRAME_PING | FRAME_WINDOW_UPDATE | FRAME_GOAWAY => {
                    // Connection-level frames — skip
                }
                _ => {}
            }
        }

        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn handle_headers(&mut self, stream_id: u32, flags: u8, payload: &[u8], ts: u64) {
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(StreamState::new);
        if stream.request_ts.is_none() {
            stream.request_ts = Some(ts);
            stream.is_request = true;
        } else {
            stream.is_request = false;
        }

        let mut offset = 0;
        if flags & FLAG_PADDED != 0 && !payload.is_empty() {
            offset = 1; // pad length byte
        }
        if flags & FLAG_PRIORITY != 0 {
            offset += 5; // stream dep(4) + weight(1)
        }
        if offset < payload.len() {
            stream.header_buf.extend_from_slice(&payload[offset..]);
        }
    }

    fn try_decode_headers(&mut self, stream_id: u32, _flags: u8, _ts: u64) -> Option<L7Message> {
        let stream = self.streams.get_mut(&stream_id)?;
        let header_bytes = std::mem::take(&mut stream.header_buf);

        let decoded =
            std::panic::catch_unwind(AssertUnwindSafe(|| self.decoder.decode(&header_bytes)))
                .ok()?
                .ok()?;

        for (name, value) in &decoded {
            let name_str = String::from_utf8_lossy(name).to_lowercase();
            let value_str = String::from_utf8_lossy(value).into_owned();

            match name_str.as_str() {
                ":method" => stream.method = Some(value_str.clone()),
                ":path" => stream.path = Some(value_str.clone()),
                ":status" => stream.status = value_str.parse().ok(),
                "content-type" => {
                    stream.content_type = Some(value_str.clone());
                    if value_str.starts_with("application/grpc") {
                        self.is_grpc = true;
                        self.protocol_type = Protocol::Grpc;
                    }
                }
                "grpc-status" => {
                    if let Ok(code) = value_str.parse::<u32>() {
                        stream.status = Some(code);
                    }
                }
                _ => {}
            }
            stream.headers.push((name_str, value_str));
        }

        None // Don't emit yet — wait for END_STREAM on DATA
    }

    fn emit_message(&mut self, stream_id: u32, ts: u64) -> Option<L7Message> {
        let stream = self.streams.remove(&stream_id)?;
        let mut msg = L7Message::new(self.protocol_type, Direction::Ingress, ts);
        msg.method = stream.method;
        msg.path = stream.path;
        msg.status = stream.status;
        msg.content_type = stream.content_type;
        msg.headers = stream.headers;
        msg.request_size_bytes = stream.request_size;
        msg.response_size_bytes = stream.response_size;
        if let Some(req_ts) = stream.request_ts {
            msg.latency_ns = Some(ts.saturating_sub(req_ts));
        }
        if !stream.data_buf.is_empty()
            && let Ok(text) = std::str::from_utf8(&stream.data_buf)
        {
            msg.payload_text = Some(text.to_string());
        }
        Some(msg)
    }

    pub fn reset_for_next_transaction(&mut self) {
        self.streams.clear();
        self.decoder = hpack::Decoder::new();
        self.preface_seen = false;
        self.buf.clear();
    }
}

impl ProtocolParser for Http2Parser {
    fn feed(&mut self, data: &[u8], _direction: Direction, ts: u64) -> ParseResult {
        if self.buf.extend(data).is_err() {
            return ParseResult::Error("HTTP/2 buffer overflow".into());
        }
        self.process(ts)
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
        let sid = stream_id.to_be_bytes();
        f.extend_from_slice(&sid);
        f.extend_from_slice(payload);
        f
    }

    fn encode_headers_simple(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut encoder = hpack::Encoder::new();
        let h: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        encoder.encode(h.into_iter())
    }

    #[test]
    fn test_settings_frame() {
        let mut parser = Http2Parser::new(false);
        let settings = make_frame(FRAME_SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]);
        let result = parser.feed(&settings, Direction::Ingress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));
    }

    #[test]
    fn test_simple_request() {
        let mut parser = Http2Parser::new(false);

        // Client preface
        let mut data = Vec::new();
        data.extend_from_slice(HTTP2_PREFACE);

        // SETTINGS
        data.extend_from_slice(&make_frame(FRAME_SETTINGS, 0, 0, &[]));

        // Request HEADERS on stream 1
        let hdrs = encode_headers_simple(&[
            (":method", "GET"),
            (":path", "/index.html"),
            (":scheme", "https"),
        ]);
        data.extend_from_slice(&make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &hdrs));

        // Request DATA + END_STREAM
        data.extend_from_slice(&make_frame(FRAME_DATA, FLAG_END_STREAM, 1, b""));

        let result = parser.feed(&data, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("/index.html"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_multiplexed_streams() {
        let mut parser = Http2Parser::new(false);

        let mut data = Vec::new();
        data.extend_from_slice(HTTP2_PREFACE);
        data.extend_from_slice(&make_frame(FRAME_SETTINGS, 0, 0, &[]));

        // Stream 1 request
        let h1 = encode_headers_simple(&[(":method", "GET"), (":path", "/a")]);
        data.extend_from_slice(&make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &h1));

        // Stream 3 request
        let h3 = encode_headers_simple(&[(":method", "POST"), (":path", "/b")]);
        data.extend_from_slice(&make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &h3));

        // End both streams
        data.extend_from_slice(&make_frame(FRAME_DATA, FLAG_END_STREAM, 1, b""));
        data.extend_from_slice(&make_frame(FRAME_DATA, FLAG_END_STREAM, 3, b"body"));

        let result = parser.feed(&data, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 2);
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_continuation_frame() {
        let mut parser = Http2Parser::new(false);

        let mut data = Vec::new();
        data.extend_from_slice(HTTP2_PREFACE);
        data.extend_from_slice(&make_frame(FRAME_SETTINGS, 0, 0, &[]));

        // HEADERS without END_HEADERS
        let hdrs = encode_headers_simple(&[(":method", "GET")]);
        data.extend_from_slice(&make_frame(FRAME_HEADERS, 0, 1, &hdrs));

        // CONTINUATION with END_HEADERS
        let more_hdrs = encode_headers_simple(&[(":path", "/cont")]);
        data.extend_from_slice(&make_frame(
            FRAME_CONTINUATION,
            FLAG_END_HEADERS,
            1,
            &more_hdrs,
        ));

        // End stream
        data.extend_from_slice(&make_frame(FRAME_DATA, FLAG_END_STREAM, 1, b""));

        let result = parser.feed(&data, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("/cont"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
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
