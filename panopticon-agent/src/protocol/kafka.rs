#![allow(dead_code)]

//! Kafka binary protocol parser (port 9092).
//!
//! Kafka uses a length-prefixed binary protocol over TCP. This parser
//! implements header-only parsing: it reads message framing, API key,
//! correlation ID, and client ID, with topic name extraction for
//! Produce and Fetch requests.

use std::collections::VecDeque;

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Constants ────────────────────────────────────────────────────────────

/// Maximum pending requests before dropping oldest.
const MAX_PENDING_REQUESTS: usize = 256;

/// Maximum message size we'll accept (16 MB — Kafka default is 1 MB).
const MAX_MESSAGE_SIZE: i32 = 16 * 1024 * 1024;

// ── Kafka API Keys ───────────────────────────────────────────────────────

fn api_key_name(key: i16) -> String {
    match key {
        0 => "Produce".into(),
        1 => "Fetch".into(),
        2 => "ListOffsets".into(),
        3 => "Metadata".into(),
        4 => "LeaderAndIsr".into(),
        5 => "StopReplica".into(),
        6 => "UpdateMetadata".into(),
        7 => "ControlledShutdown".into(),
        8 => "OffsetCommit".into(),
        9 => "OffsetFetch".into(),
        10 => "FindCoordinator".into(),
        11 => "JoinGroup".into(),
        12 => "Heartbeat".into(),
        13 => "LeaveGroup".into(),
        14 => "SyncGroup".into(),
        15 => "DescribeGroups".into(),
        16 => "ListGroups".into(),
        17 => "SaslHandshake".into(),
        18 => "ApiVersions".into(),
        19 => "CreateTopics".into(),
        20 => "DeleteTopics".into(),
        _ => format!("Unknown({})", key),
    }
}

// ── Parser State ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Waiting for data.
    Idle,
    /// Accumulating bytes for a message.
    Buffering,
}

/// Pending request info: (correlation_id, api_key_name, topic, request_timestamp).
type PendingRequest = (i32, String, Option<String>, u64);

/// Kafka binary protocol parser.
pub struct KafkaParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    /// FIFO queue of pending requests for response correlation.
    pending_requests: VecDeque<PendingRequest>,
}

impl KafkaParser {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            pending_requests: VecDeque::new(),
        }
    }

    /// Try to parse complete Kafka requests from the client buffer.
    fn try_parse_request(&mut self, timestamp_ns: u64) -> ParseResult {
        let mut messages = Vec::new();

        loop {
            let data = self.client_buf.data();
            if data.len() < 4 {
                self.state = if data.is_empty() {
                    State::Idle
                } else {
                    State::Buffering
                };
                break;
            }

            // Read message_size (i32, big-endian)
            let message_size = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);

            if message_size <= 0 || message_size > MAX_MESSAGE_SIZE {
                return ParseResult::Error(format!("Kafka: invalid message size {}", message_size));
            }

            let total_len = 4 + message_size as usize;
            if data.len() < total_len {
                self.state = State::Buffering;
                break;
            }

            // We have a complete message
            let msg_data = &data[4..total_len];

            if msg_data.len() < 8 {
                self.client_buf.consume(total_len);
                continue;
            }

            let api_key = i16::from_be_bytes([msg_data[0], msg_data[1]]);
            let api_version = i16::from_be_bytes([msg_data[2], msg_data[3]]);
            let correlation_id =
                i32::from_be_bytes([msg_data[4], msg_data[5], msg_data[6], msg_data[7]]);

            // Read client_id (nullable string: i16 length + bytes)
            let mut client_id: Option<String> = None;
            let mut payload_offset = 8;
            if msg_data.len() >= 10 {
                let client_id_len = i16::from_be_bytes([msg_data[8], msg_data[9]]);
                payload_offset = 10;
                if client_id_len > 0 {
                    let cid_len = client_id_len as usize;
                    if msg_data.len() >= 10 + cid_len {
                        client_id =
                            Some(String::from_utf8_lossy(&msg_data[10..10 + cid_len]).into_owned());
                        payload_offset = 10 + cid_len;
                    }
                }
            }

            let key_name = api_key_name(api_key);

            // Extract topic name for Produce/Fetch
            let topic =
                extract_topic_from_request(api_key, api_version, &msg_data[payload_offset..]);

            // Enqueue for response matching
            if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
                self.pending_requests.pop_front();
            }
            self.pending_requests.push_back((
                correlation_id,
                key_name.clone(),
                topic.clone(),
                timestamp_ns,
            ));

            let mut msg = L7Message::new(Protocol::Kafka, Direction::Egress, timestamp_ns);
            msg.method = Some(key_name);
            msg.path = topic;
            if let Some(ref cid) = client_id {
                msg.payload_text = Some(cid.clone());
            }
            msg.request_size_bytes = total_len as u64;
            msg.headers
                .push(("api_version".into(), api_version.to_string()));

            messages.push(msg);
            self.client_buf.consume(total_len);
            self.state = State::Idle;
        }

        if !messages.is_empty() {
            ParseResult::Messages(messages)
        } else {
            ParseResult::NeedMoreData
        }
    }

    /// Try to parse complete Kafka responses from the server buffer.
    fn try_parse_response(&mut self, timestamp_ns: u64) -> ParseResult {
        let mut messages = Vec::new();

        loop {
            let data = self.server_buf.data();
            if data.len() < 4 {
                self.state = if data.is_empty() {
                    State::Idle
                } else {
                    State::Buffering
                };
                break;
            }

            let message_size = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);

            if message_size <= 0 || message_size > MAX_MESSAGE_SIZE {
                return ParseResult::Error(format!(
                    "Kafka: invalid response message size {}",
                    message_size
                ));
            }

            let total_len = 4 + message_size as usize;
            if data.len() < total_len {
                self.state = State::Buffering;
                break;
            }

            let msg_data = &data[4..total_len];

            if msg_data.len() < 4 {
                self.server_buf.consume(total_len);
                continue;
            }

            let correlation_id =
                i32::from_be_bytes([msg_data[0], msg_data[1], msg_data[2], msg_data[3]]);

            let mut msg = L7Message::new(Protocol::Kafka, Direction::Ingress, timestamp_ns);
            msg.response_size_bytes = total_len as u64;

            // Match with pending request
            if let Some(pos) = self
                .pending_requests
                .iter()
                .position(|(cid, _, _, _)| *cid == correlation_id)
            {
                let (_, key_name, topic, req_ts) = self.pending_requests.remove(pos).unwrap();
                msg.method = Some(key_name);
                msg.path = topic;
                msg.latency_ns = Some(timestamp_ns.saturating_sub(req_ts));
            }

            // Try to extract error code from response payload
            // For most response types, the first field after correlation_id
            // is throttle_time_ms (i32), then error_code (i16) may follow
            if msg_data.len() >= 10 {
                let error_code = i16::from_be_bytes([msg_data[8], msg_data[9]]);
                if error_code != 0 {
                    msg.status = Some(error_code as u32);
                } else {
                    msg.status = Some(0);
                }
            } else {
                msg.status = Some(0);
            }

            messages.push(msg);
            self.server_buf.consume(total_len);
            self.state = State::Idle;
        }

        if !messages.is_empty() {
            ParseResult::Messages(messages)
        } else {
            ParseResult::NeedMoreData
        }
    }
}

impl ProtocolParser for KafkaParser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        match direction {
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("Kafka client buffer overflow".into());
                }
                self.try_parse_request(timestamp_ns)
            }
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("Kafka server buffer overflow".into());
                }
                self.try_parse_response(timestamp_ns)
            }
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Kafka
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            State::Idle => "idle",
            State::Buffering => "buffering",
        }
    }
}

// ── Topic Extraction ─────────────────────────────────────────────────────

/// Extract topic name from Produce (0) or Fetch (1) request payload.
/// The payload starts after client_id. Format varies by API version,
/// but topic name is typically the first string in the request body.
fn extract_topic_from_request(api_key: i16, _api_version: i16, payload: &[u8]) -> Option<String> {
    match api_key {
        0 => {
            // Produce: transactional_id (nullable string, v3+), acks (i16), timeout (i32),
            // then topic_data array: i32 count, then for each: string topic_name, ...
            // For simplicity, skip to find the first non-null string that looks like a topic.
            // At minimum: skip acks(2) + timeout(4) = 6, then array_count(4), then string.
            if payload.len() < 12 {
                return None;
            }
            // Try: acks(2) + timeout(4) + array_len(4) + string_len(2) = 12 minimum
            let offset = 6; // skip acks + timeout
            read_kafka_string(payload, offset)
                .map(|(s, _)| s)
                .filter(|s| !s.is_empty())
        }
        1 => {
            // Fetch: replica_id(4) + max_wait(4) + min_bytes(4) + [max_bytes(4) v3+]
            // + [isolation_level(1) v4+] + topic_array...
            // Simple approach: skip first 12 bytes, then read array + first topic
            if payload.len() < 16 {
                return None;
            }
            let offset = 12; // skip replica_id + max_wait + min_bytes
            read_kafka_string(payload, offset)
                .map(|(s, _)| s)
                .filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

/// Read a Kafka string (i16 length + bytes) at the given offset.
/// Returns (string, offset_after_string) or None.
fn read_kafka_string(data: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset + 2 > data.len() {
        return None;
    }
    // First try reading as array count (i32) + string (i16 len)
    if offset + 6 <= data.len() {
        let array_count = i32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if array_count > 0 && array_count < 1000 {
            let str_offset = offset + 4;
            if str_offset + 2 <= data.len() {
                let str_len = i16::from_be_bytes([data[str_offset], data[str_offset + 1]]);
                if str_len > 0 && (str_offset + 2 + str_len as usize) <= data.len() {
                    let s = String::from_utf8_lossy(
                        &data[str_offset + 2..str_offset + 2 + str_len as usize],
                    )
                    .into_owned();
                    return Some((s, str_offset + 2 + str_len as usize));
                }
            }
        }
    }
    // Direct string read
    let str_len = i16::from_be_bytes([data[offset], data[offset + 1]]);
    if str_len <= 0 {
        return None;
    }
    let end = offset + 2 + str_len as usize;
    if end > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[offset + 2..end]).into_owned();
    Some((s, end))
}

#[cfg(test)]
mod test_helpers {
    /// Build a Kafka request frame.
    pub fn build_kafka_request(
        api_key: i16,
        api_version: i16,
        correlation_id: i32,
        client_id: Option<&str>,
        extra_payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&api_key.to_be_bytes());
        body.extend_from_slice(&api_version.to_be_bytes());
        body.extend_from_slice(&correlation_id.to_be_bytes());
        // client_id (nullable string)
        match client_id {
            Some(cid) => {
                body.extend_from_slice(&(cid.len() as i16).to_be_bytes());
                body.extend_from_slice(cid.as_bytes());
            }
            None => {
                body.extend_from_slice(&(-1i16).to_be_bytes());
            }
        }
        body.extend_from_slice(extra_payload);

        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Build a Kafka response frame.
    pub fn build_kafka_response(correlation_id: i32, extra_payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(extra_payload);

        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Build a Produce request with a topic name.
    pub fn build_produce_request(correlation_id: i32, client_id: &str, topic: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        // acks (i16)
        payload.extend_from_slice(&1i16.to_be_bytes());
        // timeout (i32)
        payload.extend_from_slice(&30000i32.to_be_bytes());
        // topic_data array: count=1
        payload.extend_from_slice(&1i32.to_be_bytes());
        // topic name (i16 len + bytes)
        payload.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        payload.extend_from_slice(topic.as_bytes());

        build_kafka_request(0, 0, correlation_id, Some(client_id), &payload)
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_api_versions_round_trip() {
        let mut parser = KafkaParser::new();

        // ApiVersions request (api_key=18)
        let req = build_kafka_request(18, 0, 1, Some("test-client"), &[]);
        let result = parser.feed(&req, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("ApiVersions"));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("test-client"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }

        // ApiVersions response
        let resp = build_kafka_response(1, &[0u8; 8]); // padding for throttle + error
        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("ApiVersions"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_produce_request_topic_extraction() {
        let mut parser = KafkaParser::new();

        let req = build_produce_request(42, "my-producer", "orders.events");
        let result = parser.feed(&req, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Produce"));
                assert_eq!(msgs[0].path.as_deref(), Some("orders.events"));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("my-producer"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_fetch_request_topic_extraction() {
        let mut parser = KafkaParser::new();

        // Fetch request (api_key=1)
        let mut payload = Vec::new();
        // replica_id (i32)
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        // max_wait (i32)
        payload.extend_from_slice(&500i32.to_be_bytes());
        // min_bytes (i32)
        payload.extend_from_slice(&1i32.to_be_bytes());
        // topic array: count=1
        payload.extend_from_slice(&1i32.to_be_bytes());
        // topic name
        let topic = "user.clicks";
        payload.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        payload.extend_from_slice(topic.as_bytes());

        let req = build_kafka_request(1, 0, 100, Some("consumer-1"), &payload);
        let result = parser.feed(&req, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Fetch"));
                assert_eq!(msgs[0].path.as_deref(), Some("user.clicks"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_multi_packet_reassembly() {
        let mut parser = KafkaParser::new();

        let req = build_kafka_request(18, 0, 1, Some("test"), &[]);

        // Split across two feeds
        let mid = req.len() / 2;
        let result = parser.feed(&req[..mid], Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let result = parser.feed(&req[mid..], Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("ApiVersions"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_api_key() {
        let mut parser = KafkaParser::new();

        let req = build_kafka_request(42, 0, 1, None, &[]);
        let result = parser.feed(&req, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Unknown(42)"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_response_with_error_code() {
        let mut parser = KafkaParser::new();

        // Send request first
        let req = build_kafka_request(3, 0, 50, Some("metadata-client"), &[]);
        parser.feed(&req, Direction::Egress, 1000);

        // Response with error code
        let mut resp_payload = Vec::new();
        resp_payload.extend_from_slice(&0i32.to_be_bytes()); // throttle_time_ms
        resp_payload.extend_from_slice(&3i16.to_be_bytes()); // error_code = 3 (UNKNOWN_TOPIC)
        let resp = build_kafka_response(50, &resp_payload);

        let result = parser.feed(&resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("Metadata"));
                assert_eq!(msgs[0].status, Some(3));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_pipeline_two_requests_two_responses() {
        let mut parser = KafkaParser::new();

        // Two requests back-to-back
        let req1 = build_kafka_request(18, 0, 1, Some("c1"), &[]);
        let req2 = build_kafka_request(3, 0, 2, Some("c1"), &[]);
        let mut combined = req1;
        combined.extend_from_slice(&req2);

        let result = parser.feed(&combined, Direction::Egress, 1000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 2);
                assert_eq!(msgs[0].method.as_deref(), Some("ApiVersions"));
                assert_eq!(msgs[1].method.as_deref(), Some("Metadata"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }

        // Two responses
        let resp1 = build_kafka_response(1, &[0u8; 8]);
        let resp2 = build_kafka_response(2, &[0u8; 8]);
        let mut combined_resp = resp1;
        combined_resp.extend_from_slice(&resp2);

        let result = parser.feed(&combined_resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 2);
                assert_eq!(msgs[0].method.as_deref(), Some("ApiVersions"));
                assert_eq!(msgs[1].method.as_deref(), Some("Metadata"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
                assert_eq!(msgs[1].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_buffer_overflow() {
        let mut parser = KafkaParser::new();

        // Fill the buffer until overflow
        let large_data = vec![0u8; 257 * 1024]; // > 256KB default
        let result = parser.feed(&large_data, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::Error(_)));
    }

    #[test]
    fn test_parser_protocol() {
        let parser = KafkaParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Kafka);
        assert_eq!(parser.state_name(), "idle");
    }
}
