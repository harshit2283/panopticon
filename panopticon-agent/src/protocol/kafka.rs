#![allow(dead_code)]

//! Kafka binary protocol parser (port 9092).
//!
//! Kafka frames are a 4-byte big-endian size followed by a request or
//! response. Requests carry `api_key`, `api_version`, `correlation_id` and
//! `client_id`; responses echo the `correlation_id`. Since KIP-482, "flexible"
//! API versions use request header v2 / response header v1 (tagged fields)
//! and compact (varint-length) strings, arrays and bytes in the body — the
//! versions current clients (librdkafka 2.x, the Java client) negotiate.
//!
//! One message is exported per request/response exchange, when the response
//! arrives (Produce with `acks=0` gets no response and is exported on the
//! request). For Produce, Fetch and Metadata the body is decoded for:
//! - `path`: the topic(s) — for Fetch v13+ (topic IDs only) names are
//!   resolved from IDs seen in Metadata responses;
//! - `status`: the first non-zero error code (top-level, topic or partition);
//! - `request_text` / `payload_text`: record keys and values of produced /
//!   fetched record batches (uncompressed batches only), for PII scanning.
//!
//! Frames larger than [`FRAME_PREFIX_CAP`] and frames with capture gaps are
//! decoded from the bytes that were seen; the rest of the frame is counted
//! and dropped, so the stream stays in sync.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Constants ────────────────────────────────────────────────────────────

/// Maximum pending requests before dropping oldest.
const MAX_PENDING_REQUESTS: usize = 256;

/// Maximum message size we'll accept (128 MB; Kafka's default socket request
/// limit is 100 MB).
const MAX_MESSAGE_SIZE: i32 = 128 * 1024 * 1024;

/// Frames larger than this are decoded from their first `FRAME_PREFIX_CAP`
/// bytes; the remainder is skipped instead of buffered.
const FRAME_PREFIX_CAP: usize = 64 * 1024;

/// Upper bound on the record text collected from one frame.
const MAX_RECORD_TEXT: usize = 64 * 1024;

/// Topics listed in `path` before it is cut short.
const MAX_PATH_TOPICS: usize = 8;

/// Topic-ID → name entries remembered from Metadata responses.
const MAX_TOPIC_IDS: usize = 16 * 1024;

// ── Kafka API Keys ───────────────────────────────────────────────────────

fn api_key_name(key: i16) -> String {
    let name = match key {
        0 => "Produce",
        1 => "Fetch",
        2 => "ListOffsets",
        3 => "Metadata",
        4 => "LeaderAndIsr",
        5 => "StopReplica",
        6 => "UpdateMetadata",
        7 => "ControlledShutdown",
        8 => "OffsetCommit",
        9 => "OffsetFetch",
        10 => "FindCoordinator",
        11 => "JoinGroup",
        12 => "Heartbeat",
        13 => "LeaveGroup",
        14 => "SyncGroup",
        15 => "DescribeGroups",
        16 => "ListGroups",
        17 => "SaslHandshake",
        18 => "ApiVersions",
        19 => "CreateTopics",
        20 => "DeleteTopics",
        21 => "DeleteRecords",
        22 => "InitProducerId",
        23 => "OffsetForLeaderEpoch",
        24 => "AddPartitionsToTxn",
        25 => "AddOffsetsToTxn",
        26 => "EndTxn",
        27 => "WriteTxnMarkers",
        28 => "TxnOffsetCommit",
        29 => "DescribeAcls",
        30 => "CreateAcls",
        31 => "DeleteAcls",
        32 => "DescribeConfigs",
        33 => "AlterConfigs",
        34 => "AlterReplicaLogDirs",
        35 => "DescribeLogDirs",
        36 => "SaslAuthenticate",
        37 => "CreatePartitions",
        38 => "CreateDelegationToken",
        39 => "RenewDelegationToken",
        40 => "ExpireDelegationToken",
        41 => "DescribeDelegationToken",
        42 => "DeleteGroups",
        43 => "ElectLeaders",
        44 => "IncrementalAlterConfigs",
        45 => "AlterPartitionReassignments",
        46 => "ListPartitionReassignments",
        47 => "OffsetDelete",
        48 => "DescribeClientQuotas",
        49 => "AlterClientQuotas",
        50 => "DescribeUserScramCredentials",
        51 => "AlterUserScramCredentials",
        55 => "DescribeQuorum",
        56 => "AlterPartition",
        57 => "UpdateFeatures",
        58 => "Envelope",
        60 => "DescribeCluster",
        61 => "DescribeProducers",
        64 => "UnregisterBroker",
        65 => "DescribeTransactions",
        66 => "ListTransactions",
        67 => "AllocateProducerIds",
        68 => "ConsumerGroupHeartbeat",
        69 => "ConsumerGroupDescribe",
        71 => "GetTelemetrySubscriptions",
        72 => "PushTelemetry",
        74 => "ListClientMetricsResources",
        75 => "DescribeTopicPartitions",
        _ => return format!("Unknown({})", key),
    };
    name.into()
}

/// First "flexible" version of each API (KIP-482): request header v2,
/// response header v1, compact encodings and tagged fields in the body.
fn first_flexible_version(api_key: i16) -> Option<i16> {
    Some(match api_key {
        0 => 9,
        1 => 12,
        2 => 6,
        3 => 9,
        4 => 4,
        5 => 2,
        6 => 6,
        7 => 3,
        8 => 8,
        9 => 6,
        10 => 3,
        11 => 6,
        12 => 4,
        13 => 4,
        14 => 4,
        15 => 5,
        16 => 3,
        18 => 3,
        19 => 5,
        20 => 4,
        21 => 2,
        22 => 2,
        23 => 4,
        24 => 3,
        25 => 3,
        26 => 3,
        27 => 1,
        28 => 3,
        29 => 2,
        30 => 2,
        31 => 2,
        32 => 4,
        33 => 2,
        34 => 2,
        35 => 2,
        36 => 2,
        37 => 2,
        38 => 2,
        39 => 2,
        40 => 2,
        41 => 2,
        42 => 2,
        43 => 2,
        44 => 1,
        45..=75 => 0,
        _ => return None, // 17 SaslHandshake and unknown keys: never
    })
}

fn is_flexible(api_key: i16, api_version: i16) -> bool {
    first_flexible_version(api_key).is_some_and(|v| api_version >= v)
}

// ── Topic IDs ────────────────────────────────────────────────────────────

/// Topic IDs are cluster-wide UUIDs, so names learned from a Metadata
/// response on one connection resolve Fetch (v13+) traffic on any other.
fn topic_names() -> &'static Mutex<HashMap<[u8; 16], String>> {
    static NAMES: OnceLock<Mutex<HashMap<[u8; 16], String>>> = OnceLock::new();
    NAMES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_topic_id(id: [u8; 16], name: &str) {
    if id == [0; 16] || name.is_empty() {
        return;
    }
    if let Ok(mut names) = topic_names().lock() {
        if names.len() >= MAX_TOPIC_IDS && !names.contains_key(&id) {
            names.clear();
        }
        names.insert(id, name.to_string());
    }
}

/// Name for a topic ID, or its hex form if no Metadata response named it.
fn topic_name_for_id(id: &[u8; 16]) -> String {
    if let Some(name) = topic_names().lock().ok().and_then(|n| n.get(id).cloned()) {
        return name;
    }
    id.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Wire Reader ──────────────────────────────────────────────────────────

/// Bounds-checked reader over a (possibly truncated) Kafka message body.
/// Every read returns `None` when the data runs out.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    flexible: bool,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], flexible: bool) -> Self {
        Self {
            data,
            pos: 0,
            flexible,
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn i8(&mut self) -> Option<i8> {
        self.take(1).map(|b| b[0] as i8)
    }

    fn i16(&mut self) -> Option<i16> {
        self.take(2).map(|b| i16::from_be_bytes([b[0], b[1]]))
    }

    fn i32(&mut self) -> Option<i32> {
        self.take(4)
            .map(|b| i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn uuid(&mut self) -> Option<[u8; 16]> {
        self.take(16).map(|b| b.try_into().unwrap())
    }

    fn uvarint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.take(1)?[0];
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    /// Zig-zag signed varint (record fields).
    fn varint(&mut self) -> Option<i64> {
        let v = self.uvarint()?;
        Some(((v >> 1) as i64) ^ -((v & 1) as i64))
    }

    /// Length of a nullable string / bytes / array field: `None` = out of
    /// data, `Some(None)` = null.
    fn len(&mut self, classic: fn(&mut Self) -> Option<i64>) -> Option<Option<usize>> {
        let n = if self.flexible {
            (self.uvarint()? as i64).wrapping_sub(1)
        } else {
            classic(self)?
        };
        Some(if n < 0 { None } else { Some(n as usize) })
    }

    fn string_len(&mut self) -> Option<Option<usize>> {
        self.len(|r| r.i16().map(i64::from))
    }

    fn bytes_len(&mut self) -> Option<Option<usize>> {
        self.len(|r| r.i32().map(i64::from))
    }

    fn array_len(&mut self) -> Option<Option<usize>> {
        self.len(|r| r.i32().map(i64::from))
    }

    /// Nullable string (compact in flexible versions); null reads as "".
    fn string(&mut self) -> Option<String> {
        match self.string_len()? {
            Some(n) => Some(String::from_utf8_lossy(self.take(n)?).into_owned()),
            None => Some(String::new()),
        }
    }

    fn skip_string(&mut self) -> Option<()> {
        match self.string_len()? {
            Some(n) => self.skip(n),
            None => Some(()),
        }
    }

    /// Skip a tagged-field section (flexible versions only).
    fn tagged_fields(&mut self) -> Option<()> {
        if !self.flexible {
            return Some(());
        }
        for _ in 0..self.uvarint()? {
            self.uvarint()?;
            let size = self.uvarint()? as usize;
            self.skip(size)?;
        }
        Some(())
    }

    /// Skip an array of fixed-size elements.
    fn skip_array(&mut self, elem: usize) -> Option<()> {
        if let Some(n) = self.array_len()? {
            self.skip(n.checked_mul(elem)?)?;
        }
        Some(())
    }

    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }
}

// ── Parsed Bodies ────────────────────────────────────────────────────────

/// What was decoded from one request or response body. Decoding stops at
/// the first field that runs past the captured data; fields found until then
/// are kept.
#[derive(Default, Debug)]
struct BodyInfo {
    topics: Vec<String>,
    /// Topics whose partitions carried records (Fetch responses).
    topics_with_records: Vec<String>,
    error_code: i16,
    text: String,
    acks: Option<i16>,
}

impl BodyInfo {
    fn add_topic(&mut self, name: String) {
        if !name.is_empty() && !self.topics.contains(&name) {
            self.topics.push(name);
        }
    }

    fn set_error(&mut self, code: i16) {
        if self.error_code == 0 {
            self.error_code = code;
        }
    }
}

fn read_topic(r: &mut Reader<'_>, by_id: bool) -> Option<String> {
    if by_id {
        r.uuid().map(|id| topic_name_for_id(&id))
    } else {
        r.string()
    }
}

/// Produce request: [transactional_id] acks timeout [topic [partition records]].
fn parse_produce_request(r: &mut Reader<'_>, version: i16, info: &mut BodyInfo) -> Option<()> {
    if version >= 3 {
        r.skip_string()?; // transactional_id
    }
    info.acks = Some(r.i16()?);
    r.i32()?; // timeout_ms
    for _ in 0..r.array_len()?.unwrap_or(0) {
        let topic = read_topic(r, version >= 13)?;
        info.add_topic(topic);
        for _ in 0..r.array_len()?.unwrap_or(0) {
            r.i32()?; // partition index
            if let Some(n) = r.bytes_len()? {
                let avail = n.min(r.rest().len());
                decode_records(&r.rest()[..avail], &mut info.text);
                r.skip(n)?;
            }
            r.tagged_fields()?;
        }
        r.tagged_fields()?;
    }
    Some(())
}

fn parse_produce_response(r: &mut Reader<'_>, version: i16, info: &mut BodyInfo) -> Option<()> {
    for _ in 0..r.array_len()?.unwrap_or(0) {
        let topic = read_topic(r, version >= 13)?;
        info.add_topic(topic);
        for _ in 0..r.array_len()?.unwrap_or(0) {
            r.i32()?; // partition index
            info.set_error(r.i16()?);
            r.skip(8)?; // base_offset
            if version >= 2 {
                r.skip(8)?; // log_append_time_ms
            }
            if version >= 5 {
                r.skip(8)?; // log_start_offset
            }
            if version >= 8 {
                for _ in 0..r.array_len()?.unwrap_or(0) {
                    r.i32()?; // batch_index
                    r.skip_string()?; // batch_index_error_message
                    r.tagged_fields()?;
                }
                r.skip_string()?; // error_message
            }
            r.tagged_fields()?;
        }
        r.tagged_fields()?;
    }
    Some(())
}

fn parse_metadata_request(r: &mut Reader<'_>, version: i16, info: &mut BodyInfo) -> Option<()> {
    for _ in 0..r.array_len()?.unwrap_or(0) {
        if version >= 10 {
            let id = r.uuid()?;
            let name = r.string()?;
            info.add_topic(if name.is_empty() && id != [0; 16] {
                topic_name_for_id(&id)
            } else {
                name
            });
        } else {
            let name = r.string()?;
            info.add_topic(name);
        }
        r.tagged_fields()?;
    }
    Some(())
}

fn parse_metadata_response(r: &mut Reader<'_>, version: i16, info: &mut BodyInfo) -> Option<()> {
    if version >= 3 {
        r.i32()?; // throttle_time_ms
    }
    for _ in 0..r.array_len()?.unwrap_or(0) {
        r.i32()?; // node_id
        r.skip_string()?; // host
        r.i32()?; // port
        if version >= 1 {
            r.skip_string()?; // rack
        }
        r.tagged_fields()?;
    }
    if version >= 2 {
        r.skip_string()?; // cluster_id
    }
    if version >= 1 {
        r.i32()?; // controller_id
    }
    for _ in 0..r.array_len()?.unwrap_or(0) {
        info.set_error(r.i16()?);
        let name = r.string()?;
        if version >= 10 {
            remember_topic_id(r.uuid()?, &name);
        }
        if version >= 1 {
            r.i8()?; // is_internal
        }
        for _ in 0..r.array_len()?.unwrap_or(0) {
            info.set_error(r.i16()?);
            r.skip(8)?; // partition_index, leader_id
            if version >= 7 {
                r.skip(4)?; // leader_epoch
            }
            r.skip_array(4)?; // replica_nodes
            r.skip_array(4)?; // isr_nodes
            if version >= 5 {
                r.skip_array(4)?; // offline_replicas
            }
            r.tagged_fields()?;
        }
        if version >= 8 {
            r.i32()?; // topic_authorized_operations
        }
        r.tagged_fields()?;
    }
    Some(())
}

fn parse_fetch_request(r: &mut Reader<'_>, version: i16, info: &mut BodyInfo) -> Option<()> {
    if version <= 14 {
        r.i32()?; // replica_id (a tagged field from v15)
    }
    r.skip(8)?; // max_wait_ms, min_bytes
    if version >= 3 {
        r.i32()?; // max_bytes
    }
    if version >= 4 {
        r.i8()?; // isolation_level
    }
    if version >= 7 {
        r.skip(8)?; // session_id, session_epoch
    }
    for _ in 0..r.array_len()?.unwrap_or(0) {
        let topic = read_topic(r, version >= 13)?;
        info.add_topic(topic);
        for _ in 0..r.array_len()?.unwrap_or(0) {
            r.i32()?; // partition
            if version >= 9 {
                r.i32()?; // current_leader_epoch
            }
            r.skip(8)?; // fetch_offset
            if version >= 12 {
                r.i32()?; // last_fetched_epoch
            }
            if version >= 5 {
                r.skip(8)?; // log_start_offset
            }
            r.i32()?; // partition_max_bytes
            r.tagged_fields()?;
        }
        r.tagged_fields()?;
    }
    Some(())
}

fn parse_fetch_response(r: &mut Reader<'_>, version: i16, info: &mut BodyInfo) -> Option<()> {
    if version >= 1 {
        r.i32()?; // throttle_time_ms
    }
    if version >= 7 {
        info.set_error(r.i16()?);
        r.i32()?; // session_id
    }
    for _ in 0..r.array_len()?.unwrap_or(0) {
        let topic = read_topic(r, version >= 13)?;
        info.add_topic(topic.clone());
        for _ in 0..r.array_len()?.unwrap_or(0) {
            r.i32()?; // partition_index
            info.set_error(r.i16()?);
            r.skip(8)?; // high_watermark
            if version >= 4 {
                r.skip(8)?; // last_stable_offset
            }
            if version >= 5 {
                r.skip(8)?; // log_start_offset
            }
            if version >= 4 {
                for _ in 0..r.array_len()?.unwrap_or(0) {
                    r.skip(16)?; // producer_id, first_offset
                    r.tagged_fields()?;
                }
            }
            if version >= 11 {
                r.i32()?; // preferred_read_replica
            }
            if let Some(n) = r.bytes_len()? {
                if n > 0 && !info.topics_with_records.contains(&topic) {
                    info.topics_with_records.push(topic.clone());
                }
                let avail = n.min(r.rest().len());
                decode_records(&r.rest()[..avail], &mut info.text);
                r.skip(n)?;
            }
            r.tagged_fields()?;
        }
        r.tagged_fields()?;
    }
    Some(())
}

/// Responses whose body starts with `[throttle_time_ms] error_code`.
fn leading_error_code(api_key: i16, version: i16, r: &mut Reader<'_>) -> Option<i16> {
    let throttle_first = match api_key {
        18 | 17 | 36 => false, // ApiVersions, SaslHandshake, SaslAuthenticate
        10 if version <= 3 => version >= 1,
        12..=14 => version >= 1, // Heartbeat, LeaveGroup, SyncGroup
        11 => version >= 2,      // JoinGroup
        22 => true,              // InitProducerId
        _ => return None,
    };
    if throttle_first {
        r.i32()?;
    }
    r.i16()
}

/// Kafka record batches (magic 2) or legacy message sets (magic 0/1): append
/// each record's key and value (lossy UTF-8) to `out`, up to
/// `MAX_RECORD_TEXT`. Compressed batches are skipped. Stops at the end of
/// the captured data; a batch cut short yields its complete records.
fn decode_records(mut data: &[u8], out: &mut String) {
    while data.len() >= 17 && out.len() < MAX_RECORD_TEXT {
        let len = i32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        if len <= 0 {
            return;
        }
        let end = (12 + len as usize).min(data.len());
        let magic = data[16];
        let batch = &data[..end];
        if magic == 2 {
            decode_batch_v2(batch, out);
        } else {
            decode_message_v0(batch, magic, out);
        }
        data = &data[end..];
    }
}

fn push_text(out: &mut String, bytes: &[u8]) {
    if bytes.is_empty() || out.len() >= MAX_RECORD_TEXT {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    let text = String::from_utf8_lossy(bytes);
    out.push_str(super::truncate_utf8(&text, MAX_RECORD_TEXT - out.len()));
}

/// RecordBatch: 61-byte header, then `records_count` varint-framed records.
fn decode_batch_v2(batch: &[u8], out: &mut String) {
    if batch.len() < 61 {
        return;
    }
    let attributes = i16::from_be_bytes([batch[21], batch[22]]);
    if attributes & 0x7 != 0 {
        return; // compressed
    }
    let count = i32::from_be_bytes([batch[57], batch[58], batch[59], batch[60]]);
    let mut r = Reader::new(&batch[61..], false);
    for _ in 0..count.max(0) {
        let Some(len) = r.varint() else { return };
        let Some(rec) = r.take(len.max(0) as usize) else {
            return;
        };
        let mut rr = Reader::new(rec, false);
        let parsed = (|| {
            rr.i8()?; // attributes
            rr.varint()?; // timestamp delta
            rr.varint()?; // offset delta
            let klen = rr.varint()?;
            let key = if klen > 0 {
                rr.take(klen as usize)?
            } else {
                &[][..]
            };
            let vlen = rr.varint()?;
            let value = if vlen > 0 {
                rr.take(vlen as usize)?
            } else {
                &[][..]
            };
            Some((key, value))
        })();
        if let Some((key, value)) = parsed {
            push_text(out, key);
            push_text(out, value);
        }
    }
}

/// Legacy message (magic 0/1): offset, size, crc, magic, attributes,
/// [timestamp], key, value.
fn decode_message_v0(msg: &[u8], magic: u8, out: &mut String) {
    let mut r = Reader::new(msg, false);
    let parsed = (|| {
        r.skip(12 + 4 + 1)?; // offset, size, crc, magic
        let attributes = r.i8()?;
        if attributes & 0x7 != 0 {
            return None;
        }
        if magic == 1 {
            r.skip(8)?;
        }
        let key = match r.bytes_len()? {
            Some(n) => r.take(n)?,
            None => &[][..],
        };
        let value = match r.bytes_len()? {
            Some(n) => r.take(n.min(r.rest().len()))?,
            None => &[][..],
        };
        Some((key, value))
    })();
    if let Some((key, value)) = parsed {
        push_text(out, key);
        push_text(out, value);
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

/// A request waiting for its response.
struct PendingRequest {
    correlation_id: i32,
    api_key: i16,
    api_version: i16,
    client_id: Option<String>,
    info: BodyInfo,
    timestamp_ns: u64,
    size: u64,
}

/// One direction of the stream.
#[derive(Default)]
struct Side {
    buf: StreamBuffer,
    /// Bytes of the current frame still to drop: it was decoded from a
    /// prefix (too large to buffer, or cut by a capture gap).
    discard: usize,
}

impl Side {
    /// Drop what is left of a frame decoded early; returns unconsumed data.
    fn strip<'d>(&mut self, data: &'d [u8]) -> &'d [u8] {
        let n = self.discard.min(data.len());
        self.discard -= n;
        &data[n..]
    }
}

/// Kafka binary protocol parser.
pub struct KafkaParser {
    state: State,
    client: Side,
    server: Side,
    /// Pending requests, matched to responses by correlation ID.
    pending_requests: VecDeque<PendingRequest>,
}

/// Frame complete in the buffer, or a prefix of it.
struct Frame<'a> {
    body: &'a [u8],
    /// Size on the wire, including the 4-byte length.
    total_len: usize,
}

impl KafkaParser {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            client: Side::default(),
            server: Side::default(),
            pending_requests: VecDeque::new(),
        }
    }

    fn side(&mut self, direction: Direction) -> &mut Side {
        match direction {
            Direction::Egress => &mut self.client,
            Direction::Ingress => &mut self.server,
        }
    }

    /// Decode every complete frame in `direction`'s buffer (and a large
    /// frame's prefix once `FRAME_PREFIX_CAP` bytes of it are in).
    fn drain(&mut self, direction: Direction, timestamp_ns: u64) -> ParseResult {
        // Taken out so frames can be decoded in place while `self` is updated.
        let mut buf = std::mem::take(&mut self.side(direction).buf);
        let result = self.drain_buf(&mut buf, direction, timestamp_ns);
        self.side(direction).buf = buf;
        result
    }

    fn drain_buf(
        &mut self,
        buf: &mut StreamBuffer,
        direction: Direction,
        timestamp_ns: u64,
    ) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            let data = buf.data();
            if data.len() < 4 {
                self.state = if data.is_empty() {
                    State::Idle
                } else {
                    State::Buffering
                };
                break;
            }
            let size = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if size <= 0 || size > MAX_MESSAGE_SIZE {
                return ParseResult::Error(format!("Kafka: invalid message size {}", size));
            }
            let total_len = 4 + size as usize;
            let have = data.len();
            if have < total_len && have < FRAME_PREFIX_CAP {
                self.state = State::Buffering;
                break;
            }
            let take = have.min(total_len);
            self.frame(
                direction,
                &Frame {
                    body: &data[4..take],
                    total_len,
                },
                timestamp_ns,
                &mut messages,
            );
            buf.consume(take);
            self.side(direction).discard = total_len - take;
            self.state = State::Idle;
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn frame(
        &mut self,
        direction: Direction,
        frame: &Frame<'_>,
        timestamp_ns: u64,
        out: &mut Vec<L7Message>,
    ) {
        match direction {
            Direction::Egress => self.request(frame, timestamp_ns, out),
            Direction::Ingress => self.response(frame, timestamp_ns, out),
        }
    }

    fn request(&mut self, frame: &Frame<'_>, timestamp_ns: u64, out: &mut Vec<L7Message>) {
        let b = frame.body;
        if b.len() < 8 {
            return;
        }
        let api_key = i16::from_be_bytes([b[0], b[1]]);
        let api_version = i16::from_be_bytes([b[2], b[3]]);
        let correlation_id = i32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let flexible = is_flexible(api_key, api_version);

        // Header: client_id is a classic nullable string even in header v2.
        let mut r = Reader::new(&b[8..], false);
        let client_id = r.string().filter(|s| !s.is_empty());
        let mut info = BodyInfo::default();
        if client_id.is_some() || r.pos > 0 {
            r.flexible = flexible;
            if r.tagged_fields().is_some() {
                let _ = match api_key {
                    0 => parse_produce_request(&mut r, api_version, &mut info),
                    1 => parse_fetch_request(&mut r, api_version, &mut info),
                    3 => parse_metadata_request(&mut r, api_version, &mut info),
                    _ => None,
                };
            }
        }

        let pending = PendingRequest {
            correlation_id,
            api_key,
            api_version,
            client_id,
            info,
            timestamp_ns,
            size: frame.total_len as u64,
        };
        // acks=0: the broker never answers.
        if api_key == 0 && pending.info.acks == Some(0) {
            out.push(build_message(pending, None, timestamp_ns));
            return;
        }
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            self.pending_requests.pop_front();
        }
        self.pending_requests.push_back(pending);
    }

    fn response(&mut self, frame: &Frame<'_>, timestamp_ns: u64, out: &mut Vec<L7Message>) {
        let b = frame.body;
        if b.len() < 4 {
            return;
        }
        let correlation_id = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let Some(pos) = self
            .pending_requests
            .iter()
            .position(|p| p.correlation_id == correlation_id)
        else {
            return; // no request seen (e.g. joined mid-connection)
        };
        let pending = self.pending_requests.remove(pos).unwrap();
        let (key, version) = (pending.api_key, pending.api_version);
        // ApiVersions responses always use header v0 (no tagged fields).
        let mut r = Reader::new(&b[4..], is_flexible(key, version) && key != 18);
        let mut info = BodyInfo::default();
        let mut status = None;
        if r.tagged_fields().is_some() {
            let parsed = match key {
                0 => parse_produce_response(&mut r, version, &mut info),
                1 => parse_fetch_response(&mut r, version, &mut info),
                3 => parse_metadata_response(&mut r, version, &mut info),
                _ => leading_error_code(key, version, &mut r).map(|c| info.set_error(c)),
            };
            // A body cut short still reports an error seen before the cut.
            if parsed.is_some() || info.error_code != 0 || matches!(key, 0 | 1 | 3) {
                status = Some(info.error_code as u16 as u32);
            }
        }
        let mut msg = build_message(pending, Some(info), timestamp_ns);
        msg.status = status;
        msg.response_size_bytes = frame.total_len as u64;
        out.push(msg);
    }
}

/// The exported message for a request and (unless `acks=0`) its response.
fn build_message(req: PendingRequest, resp: Option<BodyInfo>, timestamp_ns: u64) -> L7Message {
    let mut msg = L7Message::new(Protocol::Kafka, Direction::Ingress, timestamp_ns);
    msg.method = Some(api_key_name(req.api_key));
    msg.latency_ns = resp
        .as_ref()
        .map(|_| timestamp_ns.saturating_sub(req.timestamp_ns));
    msg.request_size_bytes = req.size;
    msg.headers
        .push(("api_version".into(), req.api_version.to_string()));
    if let Some(cid) = req.client_id {
        msg.headers.push(("client_id".into(), cid));
    }
    // Topics: those that returned records (Fetch), else those named in the
    // request, else in the response.
    let topics = match &resp {
        Some(r) if !r.topics_with_records.is_empty() => &r.topics_with_records,
        Some(r) if req.info.topics.is_empty() => &r.topics,
        _ => &req.info.topics,
    };
    if !topics.is_empty() {
        let mut path = topics
            .iter()
            .take(MAX_PATH_TOPICS)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        if topics.len() > MAX_PATH_TOPICS {
            path.push_str(",...");
        }
        msg.path = Some(path);
    }
    if !req.info.text.is_empty() {
        msg.request_text = Some(req.info.text);
    }
    if let Some(r) = resp
        && !r.text.is_empty()
    {
        msg.payload_text = Some(r.text);
    }
    msg
}

impl ProtocolParser for KafkaParser {
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        let side = self.side(direction);
        let data = side.strip(data);
        if side.buf.extend(data).is_err() {
            return ParseResult::Error("Kafka buffer overflow".into());
        }
        self.drain(direction, timestamp_ns)
    }

    /// `n` bytes of `direction` were not captured. Inside a frame whose
    /// length is known, decode the part that was seen and drop the rest of
    /// the frame as it arrives; anything else loses frame sync.
    fn skip(&mut self, direction: Direction, n: usize, timestamp_ns: u64) -> Option<ParseResult> {
        let side = self.side(direction);
        if side.discard > 0 {
            if n <= side.discard {
                side.discard -= n;
                return Some(ParseResult::NeedMoreData);
            }
            return None;
        }
        let data = side.buf.data();
        if data.len() < 4 {
            return None;
        }
        let size = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if size <= 0 || size > MAX_MESSAGE_SIZE {
            return None;
        }
        let total_len = 4 + size as usize;
        let have = data.len();
        if have + n > total_len {
            return None;
        }
        let body = data[4..].to_vec();
        let mut messages = Vec::new();
        self.frame(
            direction,
            &Frame {
                body: &body,
                total_len,
            },
            timestamp_ns,
            &mut messages,
        );
        let side = self.side(direction);
        side.buf.clear();
        side.discard = total_len - have - n;
        self.state = State::Idle;
        Some(if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Frame builders ───────────────────────────────────────────────────

    /// Flexible versions of the APIs used here (independent of the parser's
    /// table, so the tests also run against other implementations).
    fn flex(key: i16, version: i16) -> bool {
        match key {
            0 => version >= 9,
            1 => version >= 12,
            3 => version >= 9,
            12 => version >= 4,
            18 => version >= 3,
            _ => false,
        }
    }

    fn uvarint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn varint(v: i64, out: &mut Vec<u8>) {
        uvarint(((v << 1) ^ (v >> 63)) as u64, out);
    }

    /// Body encoder: classic or compact (flexible) encodings.
    struct W {
        b: Vec<u8>,
        flex: bool,
    }

    impl W {
        fn new(flex: bool) -> Self {
            Self {
                b: Vec::new(),
                flex,
            }
        }
        fn i8(&mut self, v: i8) -> &mut Self {
            self.b.push(v as u8);
            self
        }
        fn i16(&mut self, v: i16) -> &mut Self {
            self.b.extend_from_slice(&v.to_be_bytes());
            self
        }
        fn i32(&mut self, v: i32) -> &mut Self {
            self.b.extend_from_slice(&v.to_be_bytes());
            self
        }
        fn i64(&mut self, v: i64) -> &mut Self {
            self.b.extend_from_slice(&v.to_be_bytes());
            self
        }
        fn len(&mut self, n: Option<usize>, classic16: bool) -> &mut Self {
            match (self.flex, n) {
                (true, Some(n)) => uvarint(n as u64 + 1, &mut self.b),
                (true, None) => uvarint(0, &mut self.b),
                (false, n) => {
                    let n = n.map(|n| n as i32).unwrap_or(-1);
                    if classic16 {
                        self.b.extend_from_slice(&(n as i16).to_be_bytes());
                    } else {
                        self.b.extend_from_slice(&n.to_be_bytes());
                    }
                }
            }
            self
        }
        fn str(&mut self, s: Option<&str>) -> &mut Self {
            self.len(s.map(str::len), true);
            if let Some(s) = s {
                self.b.extend_from_slice(s.as_bytes());
            }
            self
        }
        fn bytes(&mut self, s: &[u8]) -> &mut Self {
            self.len(Some(s.len()), false);
            self.b.extend_from_slice(s);
            self
        }
        fn arr(&mut self, n: usize) -> &mut Self {
            self.len(Some(n), false)
        }
        fn tags(&mut self) -> &mut Self {
            if self.flex {
                self.b.push(0);
            }
            self
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut f = (body.len() as i32).to_be_bytes().to_vec();
        f.extend_from_slice(body);
        f
    }

    fn request(key: i16, version: i16, cid: i32, client: Option<&str>, body: &[u8]) -> Vec<u8> {
        let flex = flex(key, version);
        let mut w = W::new(false);
        w.i16(key).i16(version).i32(cid).str(client);
        if flex {
            w.b.push(0); // header tagged fields
        }
        w.b.extend_from_slice(body);
        frame(&w.b)
    }

    fn response(key: i16, version: i16, cid: i32, body: &[u8]) -> Vec<u8> {
        let mut b = cid.to_be_bytes().to_vec();
        if flex(key, version) && key != 18 {
            b.push(0);
        }
        b.extend_from_slice(body);
        frame(&b)
    }

    /// Uncompressed RecordBatch (magic 2) of (key, value) records.
    fn record_batch(records: &[(&str, &str)]) -> Vec<u8> {
        let mut recs = Vec::new();
        for (i, (k, v)) in records.iter().enumerate() {
            let mut r = vec![0u8]; // attributes
            varint(0, &mut r); // timestamp delta
            varint(i as i64, &mut r); // offset delta
            varint(k.len() as i64, &mut r);
            r.extend_from_slice(k.as_bytes());
            varint(v.len() as i64, &mut r);
            r.extend_from_slice(v.as_bytes());
            varint(0, &mut r); // headers
            varint(r.len() as i64, &mut recs);
            recs.extend_from_slice(&r);
        }
        let mut b = Vec::new();
        b.extend_from_slice(&0i64.to_be_bytes()); // base offset
        b.extend_from_slice(&((49 + recs.len()) as i32).to_be_bytes()); // batch length
        b.extend_from_slice(&0i32.to_be_bytes()); // leader epoch
        b.push(2); // magic
        b.extend_from_slice(&0u32.to_be_bytes()); // crc
        b.extend_from_slice(&0i16.to_be_bytes()); // attributes
        b.extend_from_slice(&((records.len() as i32) - 1).to_be_bytes());
        b.extend_from_slice(&0i64.to_be_bytes()); // base timestamp
        b.extend_from_slice(&0i64.to_be_bytes()); // max timestamp
        b.extend_from_slice(&(-1i64).to_be_bytes()); // producer id
        b.extend_from_slice(&(-1i16).to_be_bytes()); // producer epoch
        b.extend_from_slice(&(-1i32).to_be_bytes()); // base sequence
        b.extend_from_slice(&(records.len() as i32).to_be_bytes());
        b.extend_from_slice(&recs);
        b
    }

    /// Produce request body (v3+ shape: transactional_id first).
    fn produce_body(version: i16, topics: &[(&str, Vec<u8>)], acks: i16) -> Vec<u8> {
        let mut w = W::new(flex(0, version));
        if version >= 3 {
            w.str(None);
        }
        w.i16(acks).i32(30000).arr(topics.len());
        for (t, records) in topics {
            w.str(Some(t)).arr(1).i32(0).bytes(records).tags().tags();
        }
        w.tags();
        w.b
    }

    fn produce_response_body(version: i16, topic: &str, error: i16) -> Vec<u8> {
        let mut w = W::new(flex(0, version));
        w.arr(1).str(Some(topic)).arr(1).i32(0).i16(error).i64(5);
        if version >= 2 {
            w.i64(-1);
        }
        if version >= 5 {
            w.i64(0);
        }
        if version >= 8 {
            w.arr(0).str(None);
        }
        w.tags().tags().i32(0).tags();
        w.b
    }

    fn one(r: ParseResult) -> L7Message {
        match r {
            ParseResult::Messages(mut m) if m.len() == 1 => m.pop().unwrap(),
            other => panic!("expected one message, got {other:?}"),
        }
    }

    /// The exchange's message, exported on the response.
    fn feed_exchange(p: &mut KafkaParser, req: &[u8], resp: &[u8]) -> L7Message {
        p.feed(req, Direction::Egress, 1000);
        one(p.feed(resp, Direction::Ingress, 3000))
    }

    // ── Tests ────────────────────────────────────────────────────────────

    #[test]
    fn exchange_is_one_message_with_latency_and_client_id() {
        let mut p = KafkaParser::new();
        let req = request(18, 0, 1, Some("test-client"), &[]);
        let resp = response(18, 0, 1, &[0, 0, 0, 0, 0, 0]);
        let r = p.feed(&req, Direction::Egress, 1000);
        assert!(
            matches!(r, ParseResult::NeedMoreData),
            "request alone must not be exported: {r:?}"
        );
        let m = one(p.feed(&resp, Direction::Ingress, 3000));
        assert_eq!(m.method.as_deref(), Some("ApiVersions"));
        assert_eq!(m.latency_ns, Some(2000));
        assert_eq!(m.status, Some(0));
        assert!(
            m.headers
                .contains(&("client_id".to_string(), "test-client".to_string()))
        );
        assert!(m.payload_text.is_none(), "client id is not body text");
    }

    #[test]
    fn produce_v3_skips_transactional_id_for_topic() {
        let mut p = KafkaParser::new();
        let batch = record_batch(&[("k1", "hello")]);
        let req = request(
            0,
            7,
            9,
            Some("p"),
            &produce_body(7, &[("orders", batch)], 1),
        );
        let resp = response(0, 7, 9, &produce_response_body(7, "orders", 0));
        let m = feed_exchange(&mut p, &req, &resp);
        assert_eq!(m.method.as_deref(), Some("Produce"));
        assert_eq!(m.path.as_deref(), Some("orders"));
        assert_eq!(m.status, Some(0));
    }

    #[test]
    fn produce_flexible_v10_topics_records_and_error() {
        let mut p = KafkaParser::new();
        let topics = [
            (
                "user.events",
                record_batch(&[("k-tok_1_", r#"{"email":"a@example.com"}"#)]),
            ),
            ("audit-log_v2", record_batch(&[("k2", "v2"), ("k3", "v3")])),
        ];
        let req = request(0, 10, 77, Some("rdkafka"), &produce_body(10, &topics, -1));
        let resp = response(0, 10, 77, &produce_response_body(10, "user.events", 10));
        let m = feed_exchange(&mut p, &req, &resp);
        assert_eq!(m.method.as_deref(), Some("Produce"));
        assert_eq!(m.path.as_deref(), Some("user.events,audit-log_v2"));
        assert_eq!(m.status, Some(10), "MESSAGE_TOO_LARGE");
        let text = m.request_text.unwrap();
        for part in ["k-tok_1_", "a@example.com", "k2", "v2", "v3"] {
            assert!(text.contains(part), "{part} missing from {text:?}");
        }
    }

    #[test]
    fn produce_acks_zero_is_exported_without_response() {
        let mut p = KafkaParser::new();
        let req = request(
            0,
            9,
            3,
            None,
            &produce_body(9, &[("t", record_batch(&[("k", "v")]))], 0),
        );
        let m = one(p.feed(&req, Direction::Egress, 1000));
        assert_eq!(m.path.as_deref(), Some("t"));
        assert!(m.latency_ns.is_none());
    }

    #[test]
    fn metadata_v12_topic_and_unknown_topic_error() {
        let mut p = KafkaParser::new();
        let mut w = W::new(true);
        w.arr(1).b.extend_from_slice(&[0; 16]); // topic_id: none, lookup by name
        w.str(Some("missing.tok_5_")).tags();
        w.i8(1).i8(0).tags(); // allow_auto_topic_creation, include_topic_auth_ops
        let req = request(3, 12, 40, Some("c"), &w.b);

        let mut w = W::new(true);
        w.i32(0); // throttle
        w.arr(1)
            .i32(1)
            .str(Some("10.0.0.1"))
            .i32(9092)
            .str(None)
            .tags();
        w.str(Some("cluster")).i32(1);
        w.arr(1).i16(3).str(Some("missing.tok_5_"));
        w.b.extend_from_slice(&[0; 16]);
        w.i8(0).arr(0).i32(0).tags();
        w.tags();
        let resp = response(3, 12, 40, &w.b);
        let m = feed_exchange(&mut p, &req, &resp);
        assert_eq!(m.method.as_deref(), Some("Metadata"));
        assert_eq!(m.path.as_deref(), Some("missing.tok_5_"));
        assert_eq!(m.status, Some(3), "UNKNOWN_TOPIC_OR_PARTITION");
    }

    fn fetch_v16_response(cid: i32, topic_id: [u8; 16], records: &[u8]) -> Vec<u8> {
        let mut w = W::new(true);
        w.i32(0).i16(0).i32(123); // throttle, error, session
        w.arr(1).b.extend_from_slice(&topic_id);
        w.arr(1).i32(0).i16(0).i64(10).i64(10).i64(0).arr(0).i32(-1);
        w.bytes(records).tags().tags();
        w.tags();
        response(1, 16, cid, &w.b)
    }

    fn fetch_v16_request(cid: i32) -> Vec<u8> {
        let mut w = W::new(true);
        w.i32(500).i32(1).i32(1 << 20).i8(0).i32(123).i32(4);
        w.arr(0).arr(0).str(Some("")).tags(); // topics, forgotten, rack
        request(1, 16, cid, Some("consumer"), &w.b)
    }

    #[test]
    fn fetch_v16_resolves_topic_id_and_extracts_records() {
        let id = [7u8; 16];
        // Learn the name from a Metadata v12 response on another connection.
        let mut meta = KafkaParser::new();
        let mut w = W::new(true);
        w.arr(0).i8(1).i8(0).tags();
        let req = request(3, 12, 1, Some("c"), &w.b);
        let mut w = W::new(true);
        w.i32(0).arr(0).str(None).i32(1);
        w.arr(1).i16(0).str(Some("payments.settled"));
        w.b.extend_from_slice(&id);
        w.i8(0).arr(0).i32(0).tags().tags();
        feed_exchange(&mut meta, &req, &response(3, 12, 1, &w.b));

        let mut p = KafkaParser::new();
        let batch = record_batch(&[("k-tok_9_", r#"{"email":"z@example.com"}"#)]);
        let m = feed_exchange(
            &mut p,
            &fetch_v16_request(5),
            &fetch_v16_response(5, id, &batch),
        );
        assert_eq!(m.method.as_deref(), Some("Fetch"));
        assert_eq!(m.path.as_deref(), Some("payments.settled"));
        assert_eq!(m.status, Some(0));
        let text = m.payload_text.unwrap();
        assert!(text.contains("k-tok_9_") && text.contains("z@example.com"));
    }

    #[test]
    fn capture_gap_inside_large_response_keeps_sync() {
        let mut p = KafkaParser::new();
        let big = "x".repeat(20_000);
        let batch = record_batch(&[("k-first", "v-first"), ("k-big", big.as_str())]);
        let resp = fetch_v16_response(5, [1; 16], &batch);
        assert!(matches!(
            p.feed(&fetch_v16_request(5), Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));
        // 4 KB captured, the rest of the GSO packet lost.
        assert!(matches!(
            p.feed(&resp[..4096], Direction::Ingress, 2000),
            ParseResult::NeedMoreData
        ));
        let m = one(p
            .skip(Direction::Ingress, resp.len() - 4096, 2000)
            .expect("gap inside a frame of known length is recoverable"));
        assert!(m.payload_text.unwrap().contains("v-first"));
        assert_eq!(m.response_size_bytes, resp.len() as u64);

        // The next exchange still parses.
        let req = request(18, 3, 6, Some("c"), &[0, 0, 0]);
        let m = feed_exchange(&mut p, &req, &response(18, 3, 6, &[0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(m.method.as_deref(), Some("ApiVersions"));
    }

    #[test]
    fn frame_larger_than_buffer_is_decoded_from_prefix() {
        let mut p = KafkaParser::new();
        let big = "y".repeat(300 * 1024);
        let batch = record_batch(&[("k-a", "v-a"), ("k-b", big.as_str())]);
        let resp = fetch_v16_response(8, [2; 16], &batch);
        p.feed(&fetch_v16_request(8), Direction::Egress, 1000);
        let mut msgs = Vec::new();
        for chunk in resp.chunks(1448) {
            match p.feed(chunk, Direction::Ingress, 2000) {
                ParseResult::Messages(m) => msgs.extend(m),
                ParseResult::NeedMoreData => {}
                ParseResult::Error(e) => panic!("{e}"),
            }
        }
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].payload_text.as_deref().unwrap().contains("v-a"));
        let req = request(18, 3, 9, Some("c"), &[0, 0, 0]);
        let m = feed_exchange(&mut p, &req, &response(18, 3, 9, &[0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(m.method.as_deref(), Some("ApiVersions"));
    }

    #[test]
    fn pipelined_requests_matched_by_correlation_id() {
        let mut p = KafkaParser::new();
        let mut reqs = request(18, 0, 1, Some("c1"), &[]);
        reqs.extend(request(12, 0, 2, Some("c1"), &[]));
        assert!(matches!(
            p.feed(&reqs, Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));
        // Out of order responses.
        let mut resps = response(12, 0, 2, &[0, 27]);
        resps.extend(response(18, 0, 1, &[0, 0, 0, 0, 0, 0]));
        match p.feed(&resps, Direction::Ingress, 2000) {
            ParseResult::Messages(m) => {
                assert_eq!(m[0].method.as_deref(), Some("Heartbeat"));
                assert_eq!(m[0].status, Some(27), "REBALANCE_IN_PROGRESS");
                assert_eq!(m[1].method.as_deref(), Some("ApiVersions"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn multi_packet_reassembly() {
        let mut p = KafkaParser::new();
        let req = request(18, 0, 1, Some("test"), &[]);
        let mid = req.len() / 2;
        assert!(matches!(
            p.feed(&req[..mid], Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));
        assert_eq!(p.state_name(), "buffering");
        p.feed(&req[mid..], Direction::Egress, 1000);
        let m = one(p.feed(&response(18, 0, 1, &[0, 0]), Direction::Ingress, 2000));
        assert_eq!(m.method.as_deref(), Some("ApiVersions"));
    }

    #[test]
    fn unknown_api_key_named() {
        let mut p = KafkaParser::new();
        let m = feed_exchange(
            &mut p,
            &request(99, 0, 1, None, &[]),
            &response(99, 0, 1, &[]),
        );
        assert_eq!(m.method.as_deref(), Some("Unknown(99)"));
        assert_eq!(m.status, None, "layout unknown: no status guessed");
    }

    #[test]
    fn invalid_size_is_an_error() {
        let mut p = KafkaParser::new();
        let r = p.feed(&[0xff, 0xff, 0xff, 0xff, 0], Direction::Egress, 1000);
        assert!(matches!(r, ParseResult::Error(_)));
    }

    #[test]
    fn test_parser_protocol() {
        let parser = KafkaParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Kafka);
        assert_eq!(parser.state_name(), "idle");
    }
}
