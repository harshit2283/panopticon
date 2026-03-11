#![allow(dead_code)]

//! AMQP 0-9-1 protocol parser (RabbitMQ, port 5672).
//!
//! AMQP uses a frame-based protocol over TCP. Each frame has a 7-byte header
//! (type + channel + size), followed by payload and a 0xCE frame-end marker.
//! This parser extracts method frames for key operations like Basic.Publish,
//! Basic.Deliver, Queue.Declare, and connection/channel management.

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Constants ────────────────────────────────────────────────────────────

/// AMQP 0-9-1 protocol header: "AMQP\x00\x00\x09\x01"
const AMQP_PROTOCOL_HEADER: &[u8] = b"AMQP\x00\x00\x09\x01";

/// Frame end marker.
const FRAME_END: u8 = 0xCE;

/// Frame types.
const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;

/// Maximum frame size we'll accept (256 KB).
const MAX_FRAME_SIZE: u32 = 256 * 1024;

// ── AMQP Class/Method IDs ────────────────────────────────────────────────

fn method_name(class_id: u16, method_id: u16) -> &'static str {
    match (class_id, method_id) {
        (10, 10) => "Connection.Start",
        (10, 11) => "Connection.StartOk",
        (10, 30) => "Connection.Tune",
        (10, 31) => "Connection.TuneOk",
        (10, 40) => "Connection.Open",
        (10, 41) => "Connection.OpenOk",
        (10, 50) => "Connection.Close",
        (10, 51) => "Connection.CloseOk",
        (20, 10) => "Channel.Open",
        (20, 11) => "Channel.OpenOk",
        (20, 40) => "Channel.Close",
        (20, 41) => "Channel.CloseOk",
        (40, 10) => "Exchange.Declare",
        (40, 11) => "Exchange.DeclareOk",
        (50, 10) => "Queue.Declare",
        (50, 11) => "Queue.DeclareOk",
        (50, 20) => "Queue.Bind",
        (50, 21) => "Queue.BindOk",
        (60, 20) => "Basic.Qos",
        (60, 21) => "Basic.QosOk",
        (60, 40) => "Basic.Publish",
        (60, 50) => "Basic.Return",
        (60, 60) => "Basic.Deliver",
        (60, 70) => "Basic.Get",
        (60, 71) => "Basic.GetOk",
        (60, 80) => "Basic.Ack",
        (60, 90) => "Basic.Reject",
        (60, 120) => "Basic.Nack",
        _ => "Unknown",
    }
}

// ── Parser State ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Waiting for AMQP protocol header.
    AwaitingHeader,
    /// Connected, parsing frames.
    Connected,
}

/// AMQP 0-9-1 protocol parser.
pub struct AmqpParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
}

impl AmqpParser {
    pub fn new() -> Self {
        Self {
            state: State::AwaitingHeader,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
        }
    }

    /// Try to parse frames from a buffer.
    fn try_parse_frames(
        &mut self,
        buf: &mut StreamBuffer,
        direction: Direction,
        timestamp_ns: u64,
    ) -> ParseResult {
        let mut messages = Vec::new();

        loop {
            let data = buf.data();

            // Check for protocol header
            if self.state == State::AwaitingHeader {
                if data.len() < 8 {
                    return if messages.is_empty() {
                        ParseResult::NeedMoreData
                    } else {
                        ParseResult::Messages(messages)
                    };
                }

                if data.starts_with(AMQP_PROTOCOL_HEADER) {
                    buf.consume(8);
                    self.state = State::Connected;

                    let mut msg = L7Message::new(Protocol::Amqp, direction, timestamp_ns);
                    msg.method = Some("ProtocolHeader".into());
                    msg.status = Some(0);
                    messages.push(msg);
                    continue;
                } else if data.starts_with(b"AMQP") {
                    // Wrong AMQP version
                    buf.consume(8.min(data.len()));
                    self.state = State::Connected; // Try to continue anyway
                    continue;
                } else {
                    // Not a protocol header — might be a frame from server
                    // (server sends Connection.Start first, not a protocol header)
                    self.state = State::Connected;
                    // Don't consume, fall through to frame parsing
                }
            }

            // Frame parsing
            if data.len() < 7 {
                return if messages.is_empty() {
                    ParseResult::NeedMoreData
                } else {
                    ParseResult::Messages(messages)
                };
            }

            let frame_type = data[0];
            let _channel = u16::from_be_bytes([data[1], data[2]]);
            let size = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);

            if size > MAX_FRAME_SIZE {
                return ParseResult::Error(format!("AMQP: frame size {} exceeds maximum", size));
            }

            let total_frame_len = 7 + size as usize + 1; // header + payload + frame_end
            if data.len() < total_frame_len {
                return if messages.is_empty() {
                    ParseResult::NeedMoreData
                } else {
                    ParseResult::Messages(messages)
                };
            }

            // Validate frame_end marker
            if data[total_frame_len - 1] != FRAME_END {
                return ParseResult::Error(format!(
                    "AMQP: invalid frame_end byte 0x{:02X}, expected 0xCE",
                    data[total_frame_len - 1]
                ));
            }

            let payload = &data[7..7 + size as usize];

            match frame_type {
                FRAME_METHOD => {
                    if let Some(msg) = self.parse_method_frame(payload, direction, timestamp_ns) {
                        messages.push(msg);
                    }
                }
                FRAME_HEADER | FRAME_BODY => {
                    // Content frames — skip for now (opaque binary, PII risk)
                }
                FRAME_HEARTBEAT => {
                    // Heartbeat — silently consume
                }
                _ => {
                    // Unknown frame type, skip
                }
            }

            buf.consume(total_frame_len);
        }
    }

    /// Parse an AMQP method frame payload.
    fn parse_method_frame(
        &self,
        payload: &[u8],
        direction: Direction,
        timestamp_ns: u64,
    ) -> Option<L7Message> {
        if payload.len() < 4 {
            return None;
        }

        let class_id = u16::from_be_bytes([payload[0], payload[1]]);
        let method_id = u16::from_be_bytes([payload[2], payload[3]]);
        let name = method_name(class_id, method_id);

        let mut msg = L7Message::new(Protocol::Amqp, direction, timestamp_ns);
        msg.method = Some(name.into());
        msg.status = Some(0);

        let args = &payload[4..];

        match (class_id, method_id) {
            (50, 10) => {
                // Queue.Declare: ticket(2) + queue_name(short_string)
                if args.len() >= 3
                    && let Some(queue_name) = read_short_string(args, 2)
                {
                    msg.path = Some(queue_name);
                }
            }
            (60, 40) => {
                // Basic.Publish: ticket(2) + exchange(short_string) + routing_key(short_string)
                if args.len() >= 3 {
                    let mut offset = 2; // skip ticket
                    if let Some((exchange, next)) = read_short_string_with_offset(args, offset) {
                        offset = next;
                        if let Some(routing_key) = read_short_string(args, offset) {
                            if exchange.is_empty() {
                                msg.path = Some(routing_key);
                            } else {
                                msg.path = Some(format!("{}/{}", exchange, routing_key));
                            }
                        } else if !exchange.is_empty() {
                            msg.path = Some(exchange);
                        }
                    }
                }
            }
            (60, 60) => {
                // Basic.Deliver: consumer_tag(short_string) + delivery_tag(8) +
                // redelivered(1) + exchange(short_string) + routing_key(short_string)
                if args.len() >= 2 {
                    let mut offset = 0;
                    // Skip consumer_tag
                    if let Some((_, next)) = read_short_string_with_offset(args, offset) {
                        offset = next;
                        offset += 8 + 1; // delivery_tag + redelivered
                        if offset < args.len()
                            && let Some((exchange, next2)) =
                                read_short_string_with_offset(args, offset)
                            && let Some(routing_key) = read_short_string(args, next2)
                        {
                            if exchange.is_empty() {
                                msg.path = Some(routing_key);
                            } else {
                                msg.path = Some(format!("{}/{}", exchange, routing_key));
                            }
                        }
                    }
                }
            }
            (10, 50) | (20, 40) => {
                // Connection.Close / Channel.Close: reply_code(2) + reply_text(short_string)
                if args.len() >= 2 {
                    let reply_code = u16::from_be_bytes([args[0], args[1]]);
                    if reply_code != 0 {
                        msg.status = Some(reply_code as u32);
                    }
                    if let Some(reply_text) = read_short_string(args, 2) {
                        msg.payload_text = Some(reply_text);
                    }
                }
            }
            _ => {}
        }

        Some(msg)
    }
}

impl ProtocolParser for AmqpParser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        match direction {
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("AMQP client buffer overflow".into());
                }
                // We need to take a mutable reference to client_buf while also
                // accessing self.state, so extract the buffer temporarily.
                let mut buf = std::mem::take(&mut self.client_buf);
                let result = self.try_parse_frames(&mut buf, direction, timestamp_ns);
                self.client_buf = buf;
                result
            }
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("AMQP server buffer overflow".into());
                }
                let mut buf = std::mem::take(&mut self.server_buf);
                let result = self.try_parse_frames(&mut buf, direction, timestamp_ns);
                self.server_buf = buf;
                result
            }
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Amqp
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            State::AwaitingHeader => "awaiting_header",
            State::Connected => "connected",
        }
    }
}

// ── AMQP String Helpers ──────────────────────────────────────────────────

/// Read an AMQP short string (1-byte length + bytes) at the given offset.
fn read_short_string(data: &[u8], offset: usize) -> Option<String> {
    read_short_string_with_offset(data, offset).map(|(s, _)| s)
}

/// Read an AMQP short string, returning (string, offset_after_string).
fn read_short_string_with_offset(data: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset >= data.len() {
        return None;
    }
    let len = data[offset] as usize;
    let start = offset + 1;
    let end = start + len;
    if end > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[start..end]).into_owned();
    Some((s, end))
}

// ── Test helpers ─────────────────────────────────────────────────────────

#[cfg(test)]
mod test_helpers {
    use super::*;

    /// Build an AMQP method frame.
    pub fn build_method_frame(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&class_id.to_be_bytes());
        payload.extend_from_slice(&method_id.to_be_bytes());
        payload.extend_from_slice(args);

        let mut frame = Vec::new();
        frame.push(FRAME_METHOD);
        frame.extend_from_slice(&channel.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.push(FRAME_END);
        frame
    }

    /// Build an AMQP heartbeat frame.
    pub fn build_heartbeat_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(FRAME_HEARTBEAT);
        frame.extend_from_slice(&0u16.to_be_bytes()); // channel 0
        frame.extend_from_slice(&0u32.to_be_bytes()); // size 0
        frame.push(FRAME_END);
        frame
    }

    /// Encode an AMQP short string.
    pub fn encode_short_string(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(s.len() as u8);
        buf.extend_from_slice(s.as_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_protocol_header_detection() {
        let mut parser = AmqpParser::new();

        let result = parser.feed(AMQP_PROTOCOL_HEADER, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("ProtocolHeader"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
        assert_eq!(parser.state, State::Connected);
    }

    #[test]
    fn test_connection_handshake() {
        let mut parser = AmqpParser::new();

        // Client sends protocol header
        parser.feed(AMQP_PROTOCOL_HEADER, Direction::Egress, 1000);

        // Server sends Connection.Start (class=10, method=10)
        let mut args = Vec::new();
        args.push(0); // version-major
        args.push(9); // version-minor
        // server-properties (empty table): 4-byte length = 0
        args.extend_from_slice(&0u32.to_be_bytes());
        // mechanisms (long string)
        let mechanisms = b"PLAIN";
        args.extend_from_slice(&(mechanisms.len() as u32).to_be_bytes());
        args.extend_from_slice(mechanisms);
        // locales (long string)
        let locales = b"en_US";
        args.extend_from_slice(&(locales.len() as u32).to_be_bytes());
        args.extend_from_slice(locales);

        let frame = build_method_frame(0, 10, 10, &args);
        let result = parser.feed(&frame, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Connection.Start"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }

        // Client sends Connection.Open (class=10, method=40)
        let mut open_args = Vec::new();
        open_args.extend_from_slice(&encode_short_string("/"));
        open_args.extend_from_slice(&encode_short_string("")); // reserved1
        open_args.push(0); // reserved2

        let frame = build_method_frame(0, 10, 40, &open_args);
        let result = parser.feed(&frame, Direction::Egress, 3000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Connection.Open"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_basic_publish() {
        let mut parser = AmqpParser::new();
        parser.state = State::Connected; // Skip handshake

        // Basic.Publish: ticket(2) + exchange(short_string) + routing_key(short_string)
        let mut args = Vec::new();
        args.extend_from_slice(&0u16.to_be_bytes()); // ticket
        args.extend_from_slice(&encode_short_string("amq.direct"));
        args.extend_from_slice(&encode_short_string("orders"));
        args.push(0); // mandatory + immediate flags

        let frame = build_method_frame(1, 60, 40, &args);
        let result = parser.feed(&frame, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Basic.Publish"));
                assert_eq!(msgs[0].path.as_deref(), Some("amq.direct/orders"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_basic_deliver() {
        let mut parser = AmqpParser::new();
        parser.state = State::Connected;

        // Basic.Deliver: consumer_tag + delivery_tag(8) + redelivered(1) +
        //                exchange(short_string) + routing_key(short_string)
        let mut args = Vec::new();
        args.extend_from_slice(&encode_short_string("ctag1.0")); // consumer_tag
        args.extend_from_slice(&1u64.to_be_bytes()); // delivery_tag
        args.push(0); // redelivered
        args.extend_from_slice(&encode_short_string("amq.topic"));
        args.extend_from_slice(&encode_short_string("events.user"));

        let frame = build_method_frame(1, 60, 60, &args);
        let result = parser.feed(&frame, Direction::Ingress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Basic.Deliver"));
                assert_eq!(msgs[0].path.as_deref(), Some("amq.topic/events.user"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_queue_declare() {
        let mut parser = AmqpParser::new();
        parser.state = State::Connected;

        // Queue.Declare: ticket(2) + queue_name(short_string)
        let mut args = Vec::new();
        args.extend_from_slice(&0u16.to_be_bytes()); // ticket
        args.extend_from_slice(&encode_short_string("task_queue"));

        let frame = build_method_frame(1, 50, 10, &args);
        let result = parser.feed(&frame, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Queue.Declare"));
                assert_eq!(msgs[0].path.as_deref(), Some("task_queue"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_heartbeat_ignored() {
        let mut parser = AmqpParser::new();
        parser.state = State::Connected;

        let heartbeat = build_heartbeat_frame();
        let result = parser.feed(&heartbeat, Direction::Ingress, 1000);
        // Heartbeat produces no messages
        assert!(matches!(result, ParseResult::NeedMoreData));
    }

    #[test]
    fn test_multi_packet_reassembly() {
        let mut parser = AmqpParser::new();
        parser.state = State::Connected;

        let mut args = Vec::new();
        args.extend_from_slice(&0u16.to_be_bytes());
        args.extend_from_slice(&encode_short_string("test_queue"));
        let frame = build_method_frame(1, 50, 10, &args);

        // Split frame across two feeds
        let mid = frame.len() / 2;
        let result = parser.feed(&frame[..mid], Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let result = parser.feed(&frame[mid..], Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Queue.Declare"));
                assert_eq!(msgs[0].path.as_deref(), Some("test_queue"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_invalid_frame_end() {
        let mut parser = AmqpParser::new();
        parser.state = State::Connected;

        let mut args = Vec::new();
        args.extend_from_slice(&0u16.to_be_bytes());
        args.extend_from_slice(&encode_short_string("q"));
        let mut frame = build_method_frame(1, 50, 10, &args);

        // Corrupt the frame end byte
        let last = frame.len() - 1;
        frame[last] = 0xFF;

        let result = parser.feed(&frame, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::Error(_)));
    }

    #[test]
    fn test_parser_protocol() {
        let parser = AmqpParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Amqp);
        assert_eq!(parser.state_name(), "awaiting_header");
    }
}
