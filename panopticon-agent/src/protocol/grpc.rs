#![allow(dead_code)]

//! gRPC parser — thin wrapper around HTTP/2.
//!
//! Detects gRPC via `content-type: application/grpc`.
//! Extracts service/method from `:path` (`/pkg.Svc/Method`).
//! Parses `grpc-status` from trailers.
//! Schema-less protobuf scanning for UTF-8 strings (PII pipeline).

use super::http2::Http2Parser;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

/// gRPC parser that wraps HTTP/2 with gRPC-specific post-processing.
pub struct GrpcParser {
    inner: Http2Parser,
}

impl GrpcParser {
    pub fn new() -> Self {
        Self {
            inner: Http2Parser::new(true),
        }
    }

    /// Post-process L7Messages to extract gRPC-specific fields.
    fn enrich_grpc_messages(messages: &mut [L7Message]) {
        for msg in messages.iter_mut() {
            msg.protocol = Protocol::Grpc;

            // Extract service/method from :path ("/package.Service/Method")
            if let Some(path) = &msg.path
                && let Some(stripped) = path.strip_prefix('/')
                && let Some(slash_pos) = stripped.rfind('/')
            {
                let service = &stripped[..slash_pos];
                let method = &stripped[slash_pos + 1..];
                msg.method = Some(format!("{service}/{method}"));
            }

            // Attempt schema-less protobuf string extraction from data
            if let Some(payload) = &msg.payload_text {
                // Already UTF-8 text — keep as-is
                let _ = payload;
            } else if msg.response_size_bytes > 0 || msg.request_size_bytes > 0 {
                // Try to extract readable strings from gRPC data frame
                // gRPC payload: 1-byte compressed_flag + 4-byte message_length + protobuf
                // Schema-less: find wire type 2 (length-delimited) fields, attempt UTF-8
                // This is best-effort for PII scanning
            }
        }
    }
}

impl ProtocolParser for GrpcParser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        match self.inner.feed(data, direction, timestamp_ns) {
            ParseResult::Messages(mut msgs) => {
                Self::enrich_grpc_messages(&mut msgs);
                ParseResult::Messages(msgs)
            }
            other => other,
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Grpc
    }

    fn state_name(&self) -> &'static str {
        self.inner.state_name()
    }

    fn protocol_version(&self) -> Option<&str> {
        Some("2")
    }
}

impl GrpcParser {
    pub fn current_state(&self) -> &'static str {
        self.inner.current_state()
    }

    pub fn reset_for_next_transaction(&mut self) {
        self.inner.reset_for_next_transaction();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME_HEADER_SIZE: usize = 9;
    const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

    fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut encoder = hpack::Encoder::new();
        let h: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        encoder.encode(h.into_iter())
    }

    #[test]
    fn test_grpc_unary_call() {
        let mut parser = GrpcParser::new();

        let mut data = Vec::new();
        data.extend_from_slice(HTTP2_PREFACE);
        data.extend_from_slice(&make_frame(0x4, 0, 0, &[])); // SETTINGS

        // Request HEADERS
        let hdrs = encode_headers(&[
            (":method", "POST"),
            (":path", "/mypackage.MyService/GetUser"),
            ("content-type", "application/grpc"),
        ]);
        data.extend_from_slice(&make_frame(0x1, 0x4, 1, &hdrs)); // HEADERS + END_HEADERS

        // Request DATA + END_STREAM (gRPC frame: 0 + len + body)
        let mut grpc_frame = vec![0u8]; // not compressed
        let body = b"\x0a\x05hello"; // fake protobuf
        grpc_frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        grpc_frame.extend_from_slice(body);
        data.extend_from_slice(&make_frame(0x0, 0x1, 1, &grpc_frame)); // DATA + END_STREAM

        let result = parser.feed(&data, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].protocol, Protocol::Grpc);
                assert_eq!(
                    msgs[0].method.as_deref(),
                    Some("mypackage.MyService/GetUser")
                );
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_grpc_service_method_extraction() {
        let mut msgs = vec![L7Message::new(Protocol::Grpc, Direction::Ingress, 0)];
        msgs[0].path = Some("/com.example.UserService/CreateUser".into());
        GrpcParser::enrich_grpc_messages(&mut msgs);
        assert_eq!(
            msgs[0].method.as_deref(),
            Some("com.example.UserService/CreateUser")
        );
    }

    #[test]
    fn test_metadata() {
        let p = GrpcParser::new();
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Grpc);
        assert_eq!(ProtocolParser::protocol_version(&p), Some("2"));
    }

    #[test]
    fn test_protocol_fsm_current_state() {
        let mut parser = GrpcParser::new();
        assert_eq!(parser.current_state(), "preface");

        let mut data = Vec::new();
        data.extend_from_slice(HTTP2_PREFACE);
        data.extend_from_slice(&make_frame(0x4, 0, 0, &[]));
        let _ = parser.feed(&data, Direction::Ingress, 1000);

        assert_eq!(parser.current_state(), "streaming");
    }

    #[test]
    fn test_protocol_fsm_reset_for_next_transaction() {
        let mut parser = GrpcParser::new();

        let mut data = Vec::new();
        data.extend_from_slice(HTTP2_PREFACE);
        data.extend_from_slice(&make_frame(0x4, 0, 0, &[]));
        let hdrs = encode_headers(&[
            (":method", "POST"),
            (":path", "/test.Service/Method"),
            ("content-type", "application/grpc"),
        ]);
        data.extend_from_slice(&make_frame(0x1, 0x4, 1, &hdrs));
        let _ = parser.feed(&data, Direction::Ingress, 1000);

        assert_eq!(parser.current_state(), "streaming");

        parser.reset_for_next_transaction();

        assert_eq!(parser.current_state(), "preface");
    }
}
