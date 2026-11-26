#![allow(dead_code)]

//! AMQP 0-9-1 protocol parser (RabbitMQ, port 5672).
//!
//! AMQP uses a frame-based protocol over TCP. Each frame has a 7-byte header
//! (type + channel + size), followed by payload and a 0xCE frame-end marker.
//! Messages ("content") travel as a method frame (Basic.Publish / Deliver /
//! GetOk / Return), a content header frame (body size, properties) and zero
//! or more body frames.
//!
//! Exported messages:
//! - **Basic.Publish**, **Basic.Deliver**, **Basic.Return**: once their
//!   content is complete; `path` is `exchange/routing_key` (the routing key
//!   alone for the default exchange), the body is `request_text` (publish)
//!   or `payload_text` (deliver, return), `status` is the reply code for a
//!   Return.
//! - **Synchronous methods** (Queue.Declare, Basic.Get, Basic.Consume,
//!   Exchange.Declare, Channel.Open, ...): one message per request/reply,
//!   at the reply, with latency. `path` is the queue / exchange / vhost. If
//!   the server closes the channel instead of replying, the request is
//!   exported with the Channel.Close reply code as `status` (e.g. 404 for a
//!   Basic.Get on a missing queue). Basic.Get carries the GetOk body.
//! - **Basic.Ack / Nack / Reject** (either side) and server-initiated
//!   **Channel.Close / Connection.Close**: as they arrive.
//!
//! The connection handshake (Start/Tune and their replies, which carry the
//! credentials) is not exported beyond Connection.Open. Capture gaps inside
//! a frame are counted against the frame size; anything else resyncs on the
//! next plausible frame. A body with bytes kept after a gap inside it (a
//! gap in a body frame that is not its last, or frame sync lost while it
//! was assembled) exports no body text, only its size; a gap that only
//! cuts its end keeps the captured prefix. Once a direction loses frame
//! sync, the frames the resync finds are not proven real (they may lie
//! inside a body), so its messages export no text for the rest of the
//! connection ([`Side::unsynced`]). A parser that joins a stream after its
//! first byte (capture attached to an open connection, protocol detected
//! mid-stream) treats both directions so from the start
//! ([`ProtocolParser::joined_late`]).

use std::collections::{HashMap, VecDeque};

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

/// Maximum frame size we'll accept (256 KB; RabbitMQ negotiates 128 KB).
const MAX_FRAME_SIZE: u32 = 256 * 1024;

/// Body text kept per message, for PII scanning.
const MAX_BODY_TEXT: usize = 64 * 1024;

/// Outstanding synchronous requests remembered per channel.
const MAX_PENDING_PER_CHANNEL: usize = 64;

/// Channels tracked per connection.
const MAX_CHANNELS: usize = 2048;

// ── AMQP Class/Method IDs ────────────────────────────────────────────────

fn method_name(class_id: u16, method_id: u16) -> String {
    let name = match (class_id, method_id) {
        (10, 10) => "Connection.Start",
        (10, 11) => "Connection.StartOk",
        (10, 20) => "Connection.Secure",
        (10, 21) => "Connection.SecureOk",
        (10, 30) => "Connection.Tune",
        (10, 31) => "Connection.TuneOk",
        (10, 40) => "Connection.Open",
        (10, 41) => "Connection.OpenOk",
        (10, 50) => "Connection.Close",
        (10, 51) => "Connection.CloseOk",
        (10, 60) => "Connection.Blocked",
        (10, 61) => "Connection.Unblocked",
        (10, 70) => "Connection.UpdateSecret",
        (10, 71) => "Connection.UpdateSecretOk",
        (20, 10) => "Channel.Open",
        (20, 11) => "Channel.OpenOk",
        (20, 20) => "Channel.Flow",
        (20, 21) => "Channel.FlowOk",
        (20, 40) => "Channel.Close",
        (20, 41) => "Channel.CloseOk",
        (40, 10) => "Exchange.Declare",
        (40, 11) => "Exchange.DeclareOk",
        (40, 20) => "Exchange.Delete",
        (40, 21) => "Exchange.DeleteOk",
        (40, 30) => "Exchange.Bind",
        (40, 31) => "Exchange.BindOk",
        (40, 40) => "Exchange.Unbind",
        (40, 51) => "Exchange.UnbindOk",
        (50, 10) => "Queue.Declare",
        (50, 11) => "Queue.DeclareOk",
        (50, 20) => "Queue.Bind",
        (50, 21) => "Queue.BindOk",
        (50, 30) => "Queue.Purge",
        (50, 31) => "Queue.PurgeOk",
        (50, 40) => "Queue.Delete",
        (50, 41) => "Queue.DeleteOk",
        (50, 50) => "Queue.Unbind",
        (50, 51) => "Queue.UnbindOk",
        (60, 10) => "Basic.Qos",
        (60, 11) => "Basic.QosOk",
        (60, 20) => "Basic.Consume",
        (60, 21) => "Basic.ConsumeOk",
        (60, 30) => "Basic.Cancel",
        (60, 31) => "Basic.CancelOk",
        (60, 40) => "Basic.Publish",
        (60, 50) => "Basic.Return",
        (60, 60) => "Basic.Deliver",
        (60, 70) => "Basic.Get",
        (60, 71) => "Basic.GetOk",
        (60, 72) => "Basic.GetEmpty",
        (60, 80) => "Basic.Ack",
        (60, 90) => "Basic.Reject",
        (60, 100) => "Basic.RecoverAsync",
        (60, 110) => "Basic.Recover",
        (60, 111) => "Basic.RecoverOk",
        (60, 120) => "Basic.Nack",
        (85, 10) => "Confirm.Select",
        (85, 11) => "Confirm.SelectOk",
        (90, 10) => "Tx.Select",
        (90, 11) => "Tx.SelectOk",
        (90, 20) => "Tx.Commit",
        (90, 21) => "Tx.CommitOk",
        (90, 30) => "Tx.Rollback",
        (90, 31) => "Tx.RollbackOk",
        _ => return format!("Unknown({class_id}.{method_id})"),
    };
    name.into()
}

/// Client methods the server answers with a reply method on the same
/// channel. Returns the byte/bit of the `no-wait` flag, if the method has
/// one (then no reply comes when it is set): (offset of the bits octet is
/// found while parsing, so only the bit index is listed here).
fn sync_request(class_id: u16, method_id: u16) -> Option<Option<u8>> {
    Some(match (class_id, method_id) {
        (10, 40) | (10, 50) | (20, 10) | (20, 20) | (20, 40) => None,
        (40, 10) => Some(4), // Exchange.Declare: passive durable auto-delete internal no-wait
        (40, 20) => Some(1), // Exchange.Delete: if-unused no-wait
        (40, 30) | (40, 40) => Some(0),
        (50, 10) => Some(4), // Queue.Declare: passive durable exclusive auto-delete no-wait
        (50, 20) => Some(0), // Queue.Bind
        (50, 30) => Some(0), // Queue.Purge
        (50, 40) => Some(2), // Queue.Delete: if-unused if-empty no-wait
        (50, 50) => None,    // Queue.Unbind
        (60, 10) => None,    // Basic.Qos
        (60, 20) => Some(3), // Basic.Consume: no-local no-ack exclusive no-wait
        (60, 30) => Some(0), // Basic.Cancel
        (60, 70) => None,    // Basic.Get
        (60, 110) => None,   // Basic.Recover
        (85, 10) => Some(0), // Confirm.Select
        (90, 10) | (90, 20) | (90, 30) => None,
        _ => return None,
    })
}

/// Server methods that answer a synchronous client request.
fn is_sync_reply(class_id: u16, method_id: u16) -> bool {
    matches!(
        (class_id, method_id),
        (10, 41)
            | (10, 51)
            | (20, 11)
            | (20, 21)
            | (20, 41)
            | (40, 11)
            | (40, 21)
            | (40, 31)
            | (40, 51)
            | (50, 11)
            | (50, 21)
            | (50, 31)
            | (50, 41)
            | (50, 51)
            | (60, 11)
            | (60, 21)
            | (60, 31)
            | (60, 71)
            | (60, 72)
            | (60, 111)
            | (85, 11)
            | (90, 11)
            | (90, 21)
            | (90, 31)
    )
}

// ── Wire Reader ──────────────────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
    }

    fn shortstr(&mut self) -> Option<String> {
        let n = self.u8()? as usize;
        Some(String::from_utf8_lossy(self.take(n)?).into_owned())
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

/// A content-carrying method waiting for its header and body frames.
struct Content {
    msg: L7Message,
    /// From the content header; `None` until it arrives.
    body_size: Option<u64>,
    /// `body_size` was read on an unsynced side: never exported.
    size_unproven: bool,
    received: u64,
    body: Vec<u8>,
    /// Basic.GetOk: completes the channel's pending Basic.Get.
    get_ok: bool,
    /// Bytes of this content's body may have been lost (a capture gap
    /// inside a body frame, or frame sync lost while it was assembled);
    /// it becomes `gapped` if more body bytes follow.
    gap_pending: bool,
    /// Body bytes were kept after a gap inside the body: what is left may
    /// hold a credential's value without its name, so no body text is
    /// exported (sizes are), as for HTTP/1 and HTTP/2 (security scan F3).
    /// A gap that only cuts the body's end keeps the captured prefix.
    gapped: bool,
}

/// A synchronous request waiting for its reply.
struct Pending {
    msg: L7Message,
    timestamp_ns: u64,
}

#[derive(Default)]
struct Channel {
    /// Publish being assembled (client side).
    publish: Option<Content>,
    /// Deliver / GetOk / Return being assembled (server side).
    delivery: Option<Content>,
    pending: VecDeque<Pending>,
}

/// One direction of the stream.
#[derive(Default)]
struct Side {
    buf: StreamBuffer,
    /// Bytes of the current frame not yet seen (capture gap): dropped as
    /// they arrive.
    discard: usize,
    /// Frame boundary lost: scan for the next plausible frame.
    resync: bool,
    /// Frame sync was lost on this direction at least once. The scan for
    /// the next plausible frame can land inside a body (a gapped body's
    /// bytes, or frames forged in a message), and nothing later proves the
    /// frames found are real: for the rest of the connection, messages of
    /// this direction export no text (path, headers, content type or
    /// body), only values from closed sets or counted by the agent: a known
    /// method name (`Unknown` otherwise), a reply code ([`scrub`]), timing,
    /// and sizes as received (never a declared body size). Also set when
    /// the client's first bytes are not the protocol header.
    unsynced: bool,
}

/// AMQP 0-9-1 protocol parser.
pub struct AmqpParser {
    state: State,
    client: Side,
    server: Side,
    channels: HashMap<u16, Channel>,
    /// The last call was [`ProtocolParser::skip`], which accounted for the
    /// gap on its direction itself (kept the frame size or lost sync).
    /// The connection manager follows every skip with
    /// [`ProtocolParser::joined_late`], which this flag lets through once
    /// without latching both directions.
    skip_accounted: bool,
}

impl AmqpParser {
    pub fn new() -> Self {
        Self {
            state: State::AwaitingHeader,
            client: Side::default(),
            server: Side::default(),
            channels: HashMap::new(),
            skip_accounted: false,
        }
    }

    fn side(&mut self, direction: Direction) -> &mut Side {
        match direction {
            Direction::Egress => &mut self.client,
            Direction::Ingress => &mut self.server,
        }
    }

    fn channel(&mut self, id: u16) -> &mut Channel {
        if self.channels.len() >= MAX_CHANNELS && !self.channels.contains_key(&id) {
            self.channels.clear();
        }
        self.channels.entry(id).or_default()
    }

    /// Frame sync lost on `direction`: scan for the next plausible frame.
    /// The bytes skipped meanwhile may belong to any content being
    /// assembled in that direction, on any channel.
    fn lose_sync(&mut self, direction: Direction) {
        let side = self.side(direction);
        side.resync = true;
        side.unsynced = true;
        self.gap_in_contents(direction);
    }

    /// Messages produced while reading `direction`: once it lost sync
    /// ([`Side::unsynced`]), none of their text is exported.
    fn scrub_unsynced(&mut self, direction: Direction, out: &mut [L7Message]) {
        if self.side(direction).unsynced {
            out.iter_mut().for_each(scrub);
        }
    }

    /// Bytes of `direction` were lost where the channel is not known: every
    /// content being assembled in that direction may miss body bytes.
    fn gap_in_contents(&mut self, direction: Direction) {
        for ch in self.channels.values_mut() {
            let content = match direction {
                Direction::Egress => ch.publish.as_mut(),
                Direction::Ingress => ch.delivery.as_mut(),
            };
            if let Some(c) = content {
                c.gap_pending = true;
            }
        }
    }

    /// Parse the frames buffered for `direction`.
    fn drain(&mut self, direction: Direction, ts: u64) -> ParseResult {
        let mut buf = std::mem::take(&mut self.side(direction).buf);
        let mut out = Vec::new();
        loop {
            let data = buf.data();
            if direction == Direction::Egress && self.state == State::AwaitingHeader {
                if data.len() < 8 && b"AMQP".starts_with(&data[..data.len().min(4)]) {
                    break; // header still arriving
                }
                self.state = State::Connected;
                if data.starts_with(b"AMQP") {
                    buf.consume(8); // AMQP_PROTOCOL_HEADER (or another version)
                    continue;
                }
                // No protocol header: the client's stream did not start
                // here, so a frame read from it may lie inside a body.
                for d in [Direction::Egress, Direction::Ingress] {
                    self.side(d).unsynced = true;
                }
            }
            if self.side(direction).resync {
                match find_frame(data) {
                    Some(at) => {
                        buf.consume(at);
                        self.side(direction).resync = false;
                        continue;
                    }
                    None => {
                        // Keep a tail that may hold the start of a frame.
                        let keep = data.len().min(7);
                        buf.consume(data.len() - keep);
                        break;
                    }
                }
            }
            if data.len() < 7 {
                break;
            }
            let size = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
            if size > MAX_FRAME_SIZE {
                self.lose_sync(direction);
                buf.consume(1);
                continue;
            }
            let total = 7 + size as usize + 1;
            if data.len() < total {
                break;
            }
            if data[total - 1] != FRAME_END {
                self.lose_sync(direction);
                buf.consume(1);
                continue;
            }
            self.frame(direction, &data[..total - 1], size as usize, ts, &mut out);
            buf.consume(total);
        }
        self.side(direction).buf = buf;
        self.scrub_unsynced(direction, &mut out);
        if out.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(out)
        }
    }

    /// One frame without its end marker. `size` is the payload size on the
    /// wire (larger than `frame.len() - 7` when the capture had a gap).
    fn frame(
        &mut self,
        direction: Direction,
        frame: &[u8],
        size: usize,
        ts: u64,
        out: &mut Vec<L7Message>,
    ) {
        let channel = u16::from_be_bytes([frame[1], frame[2]]);
        let payload = &frame[7..];
        match frame[0] {
            FRAME_METHOD => self.method(direction, channel, payload, ts, out),
            FRAME_HEADER => {
                let mut r = Reader::new(payload);
                let header = (|| {
                    r.u16()?; // class
                    r.u16()?; // weight
                    let body_size = r.u64()?;
                    let flags = r.u16()?;
                    // content-type is the first property (flag bit 15).
                    let content_type = if flags & 0x8000 != 0 {
                        r.shortstr()
                    } else {
                        None
                    };
                    Some((body_size, content_type))
                })();
                // On an unsynced side this header may be body bytes: its
                // declared size is 8 raw bytes. It still ends the content,
                // but only the bytes received are exported as the size.
                let unsynced = self.side(direction).unsynced;
                let content = self.content(direction, channel);
                if let (Some(c), Some((body_size, content_type))) = (content, header) {
                    c.body_size = Some(body_size);
                    c.size_unproven = unsynced;
                    c.msg.content_type = content_type;
                }
                self.complete(direction, channel, ts, out);
            }
            FRAME_BODY => {
                if let Some(c) = self.content(direction, channel) {
                    // Body bytes after a gap inside this body.
                    c.gapped |= c.gap_pending && !payload.is_empty();
                    let room = MAX_BODY_TEXT.saturating_sub(c.body.len());
                    c.body
                        .extend_from_slice(&payload[..payload.len().min(room)]);
                    c.received += size as u64;
                    // A frame cut by a capture gap ([`ProtocolParser::skip`]):
                    // the rest of it was lost.
                    c.gap_pending |= payload.len() < size;
                }
                self.complete(direction, channel, ts, out);
            }
            _ => {} // heartbeat, unknown
        }
    }

    fn content(&mut self, direction: Direction, channel: u16) -> Option<&mut Content> {
        let ch = self.channels.get_mut(&channel)?;
        match direction {
            Direction::Egress => ch.publish.as_mut(),
            Direction::Ingress => ch.delivery.as_mut(),
        }
    }

    /// Export the channel's content if all of its body has arrived.
    fn complete(&mut self, direction: Direction, channel: u16, ts: u64, out: &mut Vec<L7Message>) {
        let done = self
            .content(direction, channel)
            .is_some_and(|c| c.body_size.is_some_and(|n| c.received >= n));
        if done {
            self.flush(direction, channel, ts, out);
        }
    }

    /// Export the channel's content as it stands (complete, or cut short by
    /// the next method frame).
    fn flush(&mut self, direction: Direction, channel: u16, ts: u64, out: &mut Vec<L7Message>) {
        let Some(ch) = self.channels.get_mut(&channel) else {
            return;
        };
        let content = match direction {
            Direction::Egress => ch.publish.take(),
            Direction::Ingress => ch.delivery.take(),
        };
        let Some(mut c) = content else { return };
        let size = match c.body_size {
            Some(n) if !c.size_unproven => n,
            _ => c.received,
        };
        if c.gapped {
            // Sizes only ([`Content::gapped`]).
            zeroize::Zeroize::zeroize(&mut c.body);
        } else if !c.body.is_empty() {
            let text = String::from_utf8_lossy(&c.body).into_owned();
            match direction {
                Direction::Egress => c.msg.request_text = Some(text),
                Direction::Ingress => c.msg.payload_text = Some(text),
            }
        }
        if c.get_ok {
            // GetOk answers the channel's Basic.Get.
            let mut msg = match ch.pending.pop_front() {
                Some(p) => {
                    let mut m = p.msg;
                    m.latency_ns = Some(ts.saturating_sub(p.timestamp_ns));
                    m
                }
                None => {
                    let mut m = L7Message::new(Protocol::Amqp, Direction::Ingress, ts);
                    m.method = Some("Basic.Get".into());
                    m
                }
            };
            msg.direction = Direction::Ingress;
            msg.timestamp_ns = ts;
            msg.status = Some(0);
            msg.payload_text = c.msg.payload_text;
            msg.content_type = c.msg.content_type;
            msg.headers.extend(c.msg.headers);
            msg.response_size_bytes = size;
            out.push(msg);
        } else {
            match direction {
                Direction::Egress => c.msg.request_size_bytes = size,
                Direction::Ingress => c.msg.response_size_bytes = size,
            }
            out.push(c.msg);
        }
    }

    fn method(
        &mut self,
        direction: Direction,
        channel: u16,
        payload: &[u8],
        ts: u64,
        out: &mut Vec<L7Message>,
    ) {
        // A new method ends any content still being assembled on the channel.
        self.flush(direction, channel, ts, out);
        if payload.len() < 4 {
            return;
        }
        let class_id = u16::from_be_bytes([payload[0], payload[1]]);
        let method_id = u16::from_be_bytes([payload[2], payload[3]]);
        let mut msg = L7Message::new(Protocol::Amqp, direction, ts);
        msg.method = Some(method_name(class_id, method_id));
        msg.status = Some(0);
        let mut r = Reader::new(&payload[4..]);

        match (direction, class_id, method_id) {
            // ── Content methods ──
            (Direction::Egress, 60, 40) => {
                // Basic.Publish: ticket exchange routing-key bits
                let _ = (|| {
                    r.u16()?;
                    let exchange = r.shortstr()?;
                    let rk = r.shortstr()?;
                    msg.path = Some(route(&exchange, &rk));
                    Some(())
                })();
                self.start_content(direction, channel, msg, false);
            }
            (Direction::Ingress, 60, 60) => {
                // Basic.Deliver: consumer-tag delivery-tag redelivered exchange routing-key
                let _ = (|| {
                    let tag = r.shortstr()?;
                    let delivery_tag = r.u64()?;
                    r.u8()?;
                    let exchange = r.shortstr()?;
                    let rk = r.shortstr()?;
                    msg.path = Some(route(&exchange, &rk));
                    msg.headers.push(("consumer_tag".into(), tag));
                    msg.headers
                        .push(("delivery_tag".into(), delivery_tag.to_string()));
                    Some(())
                })();
                self.start_content(direction, channel, msg, false);
            }
            (Direction::Ingress, 60, 71) => {
                // Basic.GetOk: delivery-tag redelivered exchange routing-key message-count
                let _ = (|| {
                    let delivery_tag = r.u64()?;
                    r.u8()?;
                    let exchange = r.shortstr()?;
                    let rk = r.shortstr()?;
                    msg.headers.push(("exchange".into(), exchange));
                    msg.headers.push(("routing_key".into(), rk));
                    msg.headers
                        .push(("delivery_tag".into(), delivery_tag.to_string()));
                    Some(())
                })();
                self.start_content(direction, channel, msg, true);
            }
            (Direction::Ingress, 60, 50) => {
                // Basic.Return: reply-code reply-text exchange routing-key
                let _ = (|| {
                    let code = r.u16()?;
                    msg.status = Some(u32::from(code));
                    let text = r.shortstr()?;
                    msg.headers.push(("reply_text".into(), text));
                    let exchange = r.shortstr()?;
                    let rk = r.shortstr()?;
                    msg.path = Some(route(&exchange, &rk));
                    Some(())
                })();
                self.start_content(direction, channel, msg, false);
            }
            // ── Acknowledgements ──
            (_, 60, 80) | (_, 60, 90) | (_, 60, 120) => {
                if let Some(tag) = r.u64() {
                    msg.headers.push(("delivery_tag".into(), tag.to_string()));
                }
                out.push(msg);
            }
            // ── Closes ──
            (Direction::Ingress, 10, 50) | (Direction::Ingress, 20, 40) => {
                // Server-initiated close: fails the pending request, if any.
                let code = r.u16().unwrap_or(0);
                let text = r.shortstr().unwrap_or_default();
                let status = if code == 200 { 0 } else { u32::from(code) };
                let pending = self
                    .channels
                    .remove(&channel)
                    .and_then(|mut ch| ch.pending.pop_front());
                let mut m = match pending {
                    Some(p) => {
                        let mut m = p.msg;
                        m.latency_ns = Some(ts.saturating_sub(p.timestamp_ns));
                        m.direction = Direction::Ingress;
                        m.timestamp_ns = ts;
                        m
                    }
                    None => msg,
                };
                m.status = Some(status);
                m.headers.push(("reply_text".into(), text));
                out.push(m);
                if class_id == 10 {
                    self.channels.clear();
                }
            }
            // ── Synchronous replies ──
            (Direction::Ingress, c, m) if is_sync_reply(c, m) => {
                let Some(p) = self.channel(channel).pending.pop_front() else {
                    return;
                };
                let mut m_out = p.msg;
                m_out.latency_ns = Some(ts.saturating_sub(p.timestamp_ns));
                m_out.direction = Direction::Ingress;
                m_out.timestamp_ns = ts;
                if (c, m) == (60, 72) {
                    m_out.headers.push(("empty".into(), "true".into()));
                }
                if (c, m) == (50, 11) && m_out.path.as_deref().unwrap_or("").is_empty() {
                    // Server-named queue.
                    m_out.path = r.shortstr();
                }
                if (c, m) == (20, 41) || (c, m) == (10, 51) {
                    // Client-initiated close: the channel is gone.
                    if c == 10 {
                        self.channels.clear();
                    } else {
                        self.channels.remove(&channel);
                    }
                }
                out.push(m_out);
            }
            // ── Synchronous requests ──
            (Direction::Egress, c, m) => {
                let Some(no_wait_bit) = sync_request(c, m) else {
                    return; // handshake replies (StartOk/TuneOk carry credentials), unknown
                };
                let no_wait = request_args(&mut msg, c, m, &mut r, no_wait_bit);
                if no_wait {
                    out.push(msg);
                    return;
                }
                // A request read from an unsynced side keeps no text: its
                // reply, from the other side, exports it.
                if self.side(direction).unsynced {
                    scrub(&mut msg);
                }
                let ch = self.channel(channel);
                if ch.pending.len() >= MAX_PENDING_PER_CHANNEL {
                    ch.pending.pop_front();
                }
                ch.pending.push_back(Pending {
                    msg,
                    timestamp_ns: ts,
                });
            }
            _ => {} // handshake (Start, Tune), unmatched
        }
    }

    fn start_content(&mut self, direction: Direction, channel: u16, msg: L7Message, get_ok: bool) {
        let content = Content {
            msg,
            body_size: None,
            size_unproven: false,
            received: 0,
            body: Vec::new(),
            get_ok,
            gap_pending: false,
            gapped: false,
        };
        let ch = self.channel(channel);
        match direction {
            Direction::Egress => ch.publish = Some(content),
            Direction::Ingress => ch.delivery = Some(content),
        }
    }
}

/// AMQP 0-9-1 reply codes (spec section 1.9): the only statuses an
/// unsynced side exports.
const REPLY_CODES: [u32; 18] = [
    311, 312, 313, 320, 402, 403, 404, 405, 406, 501, 502, 503, 504, 505, 506, 530, 540, 541,
];

/// Drop every text field of a message read from a direction that lost frame
/// sync ([`Side::unsynced`]): its frame may be body bytes, so only values
/// from closed sets stay: a known method name (`Unknown` for any other,
/// without its ids), a status that is a reply code, timing and sizes.
fn scrub(m: &mut L7Message) {
    if m.method
        .as_deref()
        .is_some_and(|n| n.starts_with("Unknown("))
    {
        m.method = Some("Unknown".into());
    }
    if m.status
        .is_some_and(|c| c != 0 && !REPLY_CODES.contains(&c))
    {
        m.status = None;
    }
    for f in [
        &mut m.path,
        &mut m.request_text,
        &mut m.payload_text,
        &mut m.content_type,
    ] {
        if let Some(mut s) = f.take() {
            zeroize::Zeroize::zeroize(&mut s);
        }
    }
    for (mut k, mut v) in m.headers.drain(..) {
        zeroize::Zeroize::zeroize(&mut k);
        zeroize::Zeroize::zeroize(&mut v);
    }
}

/// `exchange/routing_key`, or the routing key alone (default exchange).
fn route(exchange: &str, rk: &str) -> String {
    if exchange.is_empty() {
        rk.to_string()
    } else {
        format!("{exchange}/{rk}")
    }
}

/// Fill `path` (and status for closes) of a synchronous request; returns
/// whether its no-wait flag is set.
fn request_args(
    msg: &mut L7Message,
    class_id: u16,
    method_id: u16,
    r: &mut Reader<'_>,
    no_wait_bit: Option<u8>,
) -> bool {
    let bits = (|| {
        match (class_id, method_id) {
            (10, 40) => {
                msg.path = Some(r.shortstr()?); // virtual host
                None
            }
            (10, 50) | (20, 40) => {
                let code = r.u16()?;
                msg.status = Some(if code == 200 { 0 } else { u32::from(code) });
                None
            }
            (40, 10) => {
                r.u16()?;
                msg.path = Some(r.shortstr()?);
                r.shortstr()?; // type
                r.u8()
            }
            (40, 20) | (40, 30) | (40, 40) => {
                r.u16()?;
                msg.path = Some(r.shortstr()?); // (destination) exchange
                if (class_id, method_id) != (40, 20) {
                    r.shortstr()?; // source
                    r.shortstr()?; // routing key
                }
                r.u8()
            }
            (50, 10) | (50, 30) | (50, 40) => {
                r.u16()?;
                msg.path = Some(r.shortstr()?);
                r.u8()
            }
            (50, 20) | (50, 50) => {
                r.u16()?;
                msg.path = Some(r.shortstr()?);
                let exchange = r.shortstr()?;
                let rk = r.shortstr()?;
                msg.headers.push(("binding".into(), route(&exchange, &rk)));
                r.u8()
            }
            (60, 20) => {
                r.u16()?;
                msg.path = Some(r.shortstr()?);
                r.shortstr()?; // consumer tag
                r.u8()
            }
            (60, 30) => {
                r.shortstr()?; // consumer tag
                r.u8()
            }
            (60, 70) => {
                r.u16()?;
                msg.path = Some(r.shortstr()?);
                None
            }
            (85, 10) => r.u8(),
            _ => None,
        }
    })();
    match (no_wait_bit, bits) {
        (Some(bit), Some(b)) => b & (1 << bit) != 0,
        _ => false,
    }
}

/// Offset of the first plausible frame header in `data`: known type, sane
/// size, and the frame-end marker in place when the frame is in `data`.
fn find_frame(data: &[u8]) -> Option<usize> {
    (0..data.len().saturating_sub(7)).find(|&i| {
        let t = data[i];
        if !matches!(
            t,
            FRAME_METHOD | FRAME_HEADER | FRAME_BODY | FRAME_HEARTBEAT
        ) {
            return false;
        }
        let size = u32::from_be_bytes([data[i + 3], data[i + 4], data[i + 5], data[i + 6]]);
        if size > MAX_FRAME_SIZE || (t == FRAME_HEARTBEAT && size != 0) {
            return false;
        }
        let end = i + 7 + size as usize;
        end >= data.len() || data[end] == FRAME_END
    })
}

impl ProtocolParser for AmqpParser {
    /// The stream was not seen from its first byte: a frame boundary found
    /// from here may lie inside a body (a forged frame in a message), so
    /// neither direction exports text for the rest of the connection
    /// ([`Side::unsynced`]). Not after a [`skip`](Self::skip), which
    /// already handled its own direction (`skip_accounted`).
    fn joined_late(&mut self) {
        if std::mem::take(&mut self.skip_accounted) {
            return;
        }
        for direction in [Direction::Egress, Direction::Ingress] {
            self.side(direction).unsynced = true;
            self.gap_in_contents(direction);
        }
    }

    /// Over TLS this parser latches as for a late join (its ruling;
    /// [`ProtocolParser::tls_unproven_start`]).
    fn tls_unproven_start(&mut self) {
        self.joined_late();
    }

    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        self.skip_accounted = false;
        let side = self.side(direction);
        let n = side.discard.min(data.len());
        side.discard -= n;
        let data = &data[n..];
        if side.buf.extend(data).is_err() {
            // Cannot be a valid frame (> MAX_FRAME_SIZE): resync.
            side.buf.clear();
            let _ = side.buf.extend(&data[data.len().saturating_sub(7)..]);
            self.lose_sync(direction);
        }
        self.drain(direction, timestamp_ns)
    }

    /// `n` bytes were not captured. Inside a frame of known size the frame
    /// is processed from what was seen (a body frame counts all of its bytes
    /// towards the message) and the rest of it is dropped; otherwise the
    /// parser resyncs on the next plausible frame, and the direction
    /// exports no text from then on ([`Side::unsynced`]). Either way a
    /// content that may have lost body bytes exports no body text once more
    /// body bytes follow ([`Content::gapped`]).
    fn skip(&mut self, direction: Direction, n: usize, timestamp_ns: u64) -> Option<ParseResult> {
        self.skip_accounted = true;
        let side = self.side(direction);
        if side.discard >= n {
            side.discard -= n;
            return Some(ParseResult::NeedMoreData);
        }
        let data = side.buf.data();
        let whole = if !side.resync && side.discard == 0 && data.len() >= 7 {
            let size = u32::from_be_bytes([data[3], data[4], data[5], data[6]]) as usize;
            let total = 7 + size + 1;
            (size as u32 <= MAX_FRAME_SIZE && data.len() + n <= total).then_some((size, total))
        } else {
            None
        };
        let Some((size, total)) = whole else {
            side.buf.clear();
            side.discard = 0;
            self.lose_sync(direction);
            return Some(ParseResult::NeedMoreData);
        };
        let seen = data.to_vec();
        let have = seen.len();
        side.buf.clear();
        side.discard = total - have - n;
        let mut out = Vec::new();
        // Drop the end marker if it was captured.
        let frame = &seen[..have.min(total - 1)];
        self.frame(direction, frame, size, timestamp_ns, &mut out);
        self.scrub_unsynced(direction, &mut out);
        Some(if out.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(out)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![kind];
        f.extend_from_slice(&channel.to_be_bytes());
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        f.extend_from_slice(payload);
        f.push(FRAME_END);
        f
    }

    fn method(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
        let mut p = class_id.to_be_bytes().to_vec();
        p.extend_from_slice(&method_id.to_be_bytes());
        p.extend_from_slice(args);
        frame(FRAME_METHOD, channel, &p)
    }

    fn s(v: &str) -> Vec<u8> {
        let mut b = vec![v.len() as u8];
        b.extend_from_slice(v.as_bytes());
        b
    }

    fn header(channel: u16, body_size: u64, content_type: Option<&str>) -> Vec<u8> {
        let mut p = 60u16.to_be_bytes().to_vec();
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&body_size.to_be_bytes());
        match content_type {
            Some(ct) => {
                p.extend_from_slice(&0x8000u16.to_be_bytes());
                p.extend(s(ct));
            }
            None => p.extend_from_slice(&0u16.to_be_bytes()),
        }
        frame(FRAME_HEADER, channel, &p)
    }

    fn publish(channel: u16, exchange: &str, rk: &str, body: &[u8]) -> Vec<u8> {
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s(exchange));
        args.extend(s(rk));
        args.push(0);
        let mut f = method(channel, 60, 40, &args);
        f.extend(header(channel, body.len() as u64, Some("application/json")));
        f.extend(frame(FRAME_BODY, channel, body));
        f
    }

    fn connected() -> AmqpParser {
        let mut p = AmqpParser::new();
        p.feed(AMQP_PROTOCOL_HEADER, Direction::Egress, 1);
        p
    }

    #[test]
    fn protocol_header_not_exported() {
        let mut p = AmqpParser::new();
        let r = p.feed(AMQP_PROTOCOL_HEADER, Direction::Egress, 1);
        assert!(matches!(r, ParseResult::NeedMoreData), "{r:?}");
        assert_eq!(p.state_name(), "connected");
    }

    fn msgs(r: ParseResult) -> Vec<L7Message> {
        match r {
            ParseResult::Messages(m) => m,
            ParseResult::NeedMoreData => vec![],
            ParseResult::Error(e) => panic!("{e}"),
        }
    }

    #[test]
    fn publish_exported_once_with_body() {
        let mut p = connected();
        let body = br#"{"id":"tok_1_","email":"a@example.com"}"#;
        let m = msgs(p.feed(
            &publish(1, "o3.topic", "orders.tok_1_", body),
            Direction::Egress,
            10,
        ));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("Basic.Publish"));
        assert_eq!(m[0].path.as_deref(), Some("o3.topic/orders.tok_1_"));
        assert_eq!(
            m[0].request_text.as_deref(),
            Some(std::str::from_utf8(body).unwrap())
        );
        assert_eq!(m[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(m[0].request_size_bytes, body.len() as u64);
    }

    #[test]
    fn publish_default_exchange_path_is_routing_key() {
        let mut p = connected();
        let m = msgs(p.feed(&publish(1, "", "q.default", b"x"), Direction::Egress, 10));
        assert_eq!(m[0].path.as_deref(), Some("q.default"));
    }

    #[test]
    fn publish_body_split_across_frames_and_packets() {
        let mut p = connected();
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s("ex"));
        args.extend(s("rk"));
        args.push(0);
        let mut wire = method(1, 60, 40, &args);
        wire.extend(header(1, 6, None));
        wire.extend(frame(FRAME_BODY, 1, b"abc"));
        wire.extend(frame(FRAME_BODY, 1, b"def"));
        let (a, b) = wire.split_at(wire.len() - 5);
        assert!(msgs(p.feed(a, Direction::Egress, 10)).is_empty());
        let m = msgs(p.feed(b, Direction::Egress, 11));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].request_text.as_deref(), Some("abcdef"));
    }

    #[test]
    fn deliver_carries_body_and_route() {
        let mut p = connected();
        let mut args = s("ctag1.0");
        args.extend_from_slice(&7u64.to_be_bytes());
        args.push(0);
        args.extend(s("o3.fanout"));
        args.extend(s("fan.tok_3_"));
        let mut wire = method(1, 60, 60, &args);
        wire.extend(header(1, 5, None));
        wire.extend(frame(FRAME_BODY, 1, b"hello"));
        let m = msgs(p.feed(&wire, Direction::Ingress, 10));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("Basic.Deliver"));
        assert_eq!(m[0].path.as_deref(), Some("o3.fanout/fan.tok_3_"));
        assert_eq!(m[0].payload_text.as_deref(), Some("hello"));
        assert!(
            m[0].headers
                .contains(&("delivery_tag".to_string(), "7".to_string()))
        );
    }

    #[test]
    fn basic_get_joined_with_get_ok_body() {
        let mut p = connected();
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s("q.get"));
        args.push(0);
        assert!(msgs(p.feed(&method(2, 60, 70, &args), Direction::Egress, 100)).is_empty());
        let mut ok = 1u64.to_be_bytes().to_vec();
        ok.push(0);
        ok.extend(s(""));
        ok.extend(s("q.get"));
        ok.extend_from_slice(&0u32.to_be_bytes());
        let mut wire = method(2, 60, 71, &ok);
        wire.extend(header(2, 4, None));
        wire.extend(frame(FRAME_BODY, 2, b"body"));
        let m = msgs(p.feed(&wire, Direction::Ingress, 300));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("Basic.Get"));
        assert_eq!(m[0].path.as_deref(), Some("q.get"));
        assert_eq!(m[0].status, Some(0));
        assert_eq!(m[0].payload_text.as_deref(), Some("body"));
        assert_eq!(m[0].latency_ns, Some(200));
    }

    #[test]
    fn basic_get_on_missing_queue_reports_channel_close_code() {
        let mut p = connected();
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s("missing.tok_9_"));
        args.push(0);
        assert!(msgs(p.feed(&method(3, 60, 70, &args), Direction::Egress, 100)).is_empty());
        let mut close = 404u16.to_be_bytes().to_vec();
        close.extend(s("NOT_FOUND - no queue 'missing.tok_9_' in vhost '/'"));
        close.extend_from_slice(&60u16.to_be_bytes());
        close.extend_from_slice(&70u16.to_be_bytes());
        let m = msgs(p.feed(&method(3, 20, 40, &close), Direction::Ingress, 150));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("Basic.Get"));
        assert_eq!(m[0].path.as_deref(), Some("missing.tok_9_"));
        assert_eq!(m[0].status, Some(404));
    }

    #[test]
    fn basic_return_has_reply_code_and_body() {
        let mut p = connected();
        let mut args = 312u16.to_be_bytes().to_vec();
        args.extend(s("NO_ROUTE"));
        args.extend(s("o3.direct"));
        args.extend(s("nowhere.tok_4_"));
        let mut wire = method(1, 60, 50, &args);
        wire.extend(header(1, 2, None));
        wire.extend(frame(FRAME_BODY, 1, b"hi"));
        let m = msgs(p.feed(&wire, Direction::Ingress, 10));
        assert_eq!(m[0].method.as_deref(), Some("Basic.Return"));
        assert_eq!(m[0].status, Some(312));
        assert_eq!(m[0].path.as_deref(), Some("o3.direct/nowhere.tok_4_"));
        assert_eq!(m[0].payload_text.as_deref(), Some("hi"));
    }

    #[test]
    fn queue_declare_is_one_message_at_reply() {
        let mut p = connected();
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s("task_queue"));
        args.push(0b0000_0010); // durable
        args.extend_from_slice(&0u32.to_be_bytes());
        assert!(msgs(p.feed(&method(1, 50, 10, &args), Direction::Egress, 1)).is_empty());
        let mut ok = s("task_queue");
        ok.extend_from_slice(&0u32.to_be_bytes());
        ok.extend_from_slice(&0u32.to_be_bytes());
        let m = msgs(p.feed(&method(1, 50, 11, &ok), Direction::Ingress, 5));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("Queue.Declare"));
        assert_eq!(m[0].path.as_deref(), Some("task_queue"));
        assert_eq!(m[0].latency_ns, Some(4));
    }

    #[test]
    fn no_wait_request_exported_immediately() {
        let mut p = connected();
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s("q"));
        args.push(0b0001_0000); // no-wait
        args.extend_from_slice(&0u32.to_be_bytes());
        let m = msgs(p.feed(&method(1, 50, 10, &args), Direction::Egress, 1));
        assert_eq!(m[0].method.as_deref(), Some("Queue.Declare"));
    }

    #[test]
    fn handshake_credentials_not_exported() {
        let mut p = connected();
        let mut start_ok = vec![0, 0, 0, 0];
        start_ok.extend(s("PLAIN"));
        start_ok.extend_from_slice(&14u32.to_be_bytes());
        start_ok.extend_from_slice(b"\0guest\0secret!");
        assert!(msgs(p.feed(&method(0, 10, 11, &start_ok), Direction::Egress, 1)).is_empty());
        let mut open = s("/");
        open.extend(s(""));
        open.push(0);
        assert!(msgs(p.feed(&method(0, 10, 40, &open), Direction::Egress, 2)).is_empty());
        let m = msgs(p.feed(&method(0, 10, 41, &s("")), Direction::Ingress, 3));
        assert_eq!(m[0].method.as_deref(), Some("Connection.Open"));
        assert_eq!(m[0].path.as_deref(), Some("/"));
    }

    #[test]
    fn acks_exported_with_delivery_tag() {
        let mut p = connected();
        let mut args = 42u64.to_be_bytes().to_vec();
        args.push(0);
        let m = msgs(p.feed(&method(1, 60, 80, &args), Direction::Egress, 1));
        assert_eq!(m[0].method.as_deref(), Some("Basic.Ack"));
        assert!(
            m[0].headers
                .contains(&("delivery_tag".to_string(), "42".to_string()))
        );
    }

    #[test]
    fn capture_gap_inside_body_frame_keeps_sync() {
        let mut p = connected();
        let body = vec![b'x'; 6000];
        let mut wire = publish(1, "ex", "rk.tok_5_", &body);
        let next = publish(1, "ex", "rk.tok_6_", b"small");
        // First 4096 bytes captured, the rest of the packet lost.
        assert!(msgs(p.feed(&wire[..4096], Direction::Egress, 1)).is_empty());
        let m = msgs(
            crate::protocol::skip_as_manager(&mut p, Direction::Egress, wire.len() - 4096, 1)
                .expect("AMQP never asks for a reset"),
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].path.as_deref(), Some("ex/rk.tok_5_"));
        assert_eq!(m[0].request_size_bytes, 6000);
        wire.clear();
        let m = msgs(p.feed(&next, Direction::Egress, 2));
        assert_eq!(m[0].path.as_deref(), Some("ex/rk.tok_6_"));
    }

    /// Publish method + header for a body of `size` bytes, sent as the
    /// body frames that follow.
    fn publish_head(channel: u16, size: u64) -> Vec<u8> {
        let mut args = 0u16.to_be_bytes().to_vec();
        args.extend(s("ex"));
        args.extend(s("rk"));
        args.push(0);
        let mut f = method(channel, 60, 40, &args);
        f.extend(header(channel, size, Some("application/json")));
        f
    }

    /// Security scan F3: a gap inside a body frame that is not the last
    /// may remove a credential's name and keep its value in a later frame:
    /// the joined body is not exported, its size is.
    #[test]
    fn gap_inside_a_multi_frame_body_withholds_its_text() {
        let mut p = connected();
        let first = frame(FRAME_BODY, 1, &[b'a'; 3000]);
        let second = frame(FRAME_BODY, 1, b"\"hunter2-value\"}");
        let size = 3000 + 16;
        let mut wire = publish_head(1, size);
        wire.extend(&first[..1000]); // 7-byte header + 993 body bytes
        assert!(msgs(p.feed(&wire, Direction::Egress, 1)).is_empty());
        let lost = first.len() - 1000;
        assert!(
            msgs(crate::protocol::skip_as_manager(&mut p, Direction::Egress, lost, 2).unwrap())
                .is_empty()
        );
        let m = msgs(p.feed(&second, Direction::Egress, 3));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].request_text, None, "no body text after a gap");
        assert_eq!(m[0].request_size_bytes, size);
        assert_eq!(m[0].path.as_deref(), Some("ex/rk"));

        // The same on the server side (Basic.Deliver).
        let mut args = s("ctag1.0");
        args.extend_from_slice(&7u64.to_be_bytes());
        args.push(0);
        args.extend(s("ex"));
        args.extend(s("rk"));
        let mut wire = method(2, 60, 60, &args);
        wire.extend(header(2, size, None));
        let first = frame(FRAME_BODY, 2, &[b'a'; 3000]);
        wire.extend(&first[..1000]);
        assert!(msgs(p.feed(&wire, Direction::Ingress, 4)).is_empty());
        assert!(
            msgs(crate::protocol::skip_as_manager(&mut p, Direction::Ingress, lost, 5).unwrap())
                .is_empty()
        );
        let m = msgs(p.feed(
            &frame(FRAME_BODY, 2, b"\"hunter2-value\"}"),
            Direction::Ingress,
            6,
        ));
        assert_eq!(m[0].method.as_deref(), Some("Basic.Deliver"));
        assert_eq!(m[0].payload_text, None);
        assert_eq!(m[0].response_size_bytes, size);
    }

    /// A gap that loses frame sync (here: whole frames between two body
    /// frames) withholds the body text too, whatever channel it was on.
    #[test]
    fn lost_frame_sync_inside_a_body_withholds_its_text() {
        let mut p = connected();
        let mut wire = publish_head(3, 30);
        wire.extend(frame(FRAME_BODY, 3, b"0123456789"));
        assert!(msgs(p.feed(&wire, Direction::Egress, 1)).is_empty());
        // The next body frame (10 bytes + 8 framing) is lost whole.
        assert!(
            msgs(crate::protocol::skip_as_manager(&mut p, Direction::Egress, 18, 2).unwrap())
                .is_empty()
        );
        let third = frame(FRAME_BODY, 3, b"abcdefghij");
        assert!(msgs(p.feed(&third, Direction::Egress, 3)).is_empty());
        // The lost frame never counted: the next method ends the content.
        let m = msgs(p.feed(&publish(3, "ex", "rk", b"next"), Direction::Egress, 4));
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].request_text, None, "no body text after the gap");
        assert_eq!(m[0].request_size_bytes, 30);
        // Sync was lost: later messages of this direction keep no text.
        assert_eq!(m[1].request_text, None);
        assert_eq!(m[1].request_size_bytes, 4);
    }

    /// A gap that only cuts the body's end keeps the captured prefix, as
    /// for HTTP: no byte after the gap is joined to it.
    #[test]
    fn gap_in_the_last_body_frame_keeps_the_prefix() {
        let mut p = connected();
        let head = b"{\"id\":\"tok_9_\",\"x\":";
        let mut wire = publish_head(1, (head.len() + 3000) as u64);
        wire.extend(frame(FRAME_BODY, 1, head));
        let last = frame(FRAME_BODY, 1, &[b'z'; 3000]);
        wire.extend(&last[..507]); // 7-byte header + 500 body bytes
        assert!(msgs(p.feed(&wire, Direction::Egress, 1)).is_empty());
        let m = msgs(
            crate::protocol::skip_as_manager(&mut p, Direction::Egress, last.len() - 507, 2)
                .unwrap(),
        );
        assert_eq!(m.len(), 1);
        let text = m[0].request_text.as_deref().expect("prefix kept");
        assert!(text.starts_with("{\"id\":\"tok_9_\""), "{text}");
        assert_eq!(text.len(), head.len() + 500);
        // A method frame after it starts clean.
        let m = msgs(p.feed(&publish(1, "ex", "rk", b"clean"), Direction::Egress, 3));
        assert_eq!(m[0].request_text.as_deref(), Some("clean"));
    }

    /// A gap that loses frame sync inside a body frame: the resync scan
    /// can land on bytes of that body that read as frames (here, a whole
    /// Basic.Publish forged inside it). Nothing parsed from such frames may
    /// export the body's bytes, as a body, a path or a header.
    #[test]
    fn resync_inside_a_body_exports_none_of_its_bytes() {
        let mut p = connected();
        let forged = publish(5, "leak", "rk.S3CRET", b"S3CRET-tail");
        let mut body = b"{\"x\":\"".to_vec();
        body.extend(&forged);
        body.extend(b"\"}");
        let wire = publish(1, "ex", "rk", &body);
        // Method and header frames whole, then the body frame's first 3
        // bytes (type, channel) lost: its boundary is lost too.
        let head = wire.len() - (7 + body.len() + 1);
        assert!(msgs(p.feed(&wire[..head], Direction::Egress, 1)).is_empty());
        assert!(
            msgs(crate::protocol::skip_as_manager(&mut p, Direction::Egress, 3, 2).unwrap())
                .is_empty()
        );
        let mut rest = wire[head + 3..].to_vec();
        rest.extend(publish(1, "ex", "rk.after", b"after"));
        let out = msgs(p.feed(&rest, Direction::Egress, 3));
        for m in &out {
            let all = format!(
                "{:?} {:?} {:?} {:?}",
                m.path, m.request_text, m.payload_text, m.headers
            );
            assert!(!all.contains("S3CRET"), "{all}");
        }
        // The direction stays unproven for the connection: later messages
        // keep method and sizes, no text.
        let m = msgs(p.feed(
            &publish(1, "ex", "rk.later", b"later"),
            Direction::Egress,
            4,
        ));
        assert_eq!(m[0].method.as_deref(), Some("Basic.Publish"));
        assert_eq!(m[0].path, None);
        assert_eq!(m[0].request_text, None);
        assert_eq!(m[0].request_size_bytes, 5);
        // The other direction is unaffected.
        let mut args = s("ctag1.0");
        args.extend_from_slice(&7u64.to_be_bytes());
        args.push(0);
        args.extend(s("ex"));
        args.extend(s("rk"));
        let mut d = method(2, 60, 60, &args);
        d.extend(header(2, 2, None));
        d.extend(frame(FRAME_BODY, 2, b"ok"));
        let m = msgs(p.feed(&d, Direction::Ingress, 5));
        assert_eq!(m[0].payload_text.as_deref(), Some("ok"));
    }

    /// A content header arriving while the content is gap-pending (no new
    /// method frame between): bytes after it are never joined to the
    /// prefix kept before the gap.
    #[test]
    fn header_after_a_body_gap_joins_nothing() {
        let mut p = connected();
        let mut wire = publish_head(1, 3000 + 16);
        let first = frame(FRAME_BODY, 1, &[b'a'; 3000]);
        wire.extend(&first[..1000]);
        assert!(msgs(p.feed(&wire, Direction::Egress, 1)).is_empty());
        let mut out = msgs(
            crate::protocol::skip_as_manager(&mut p, Direction::Egress, first.len() - 1000, 2)
                .unwrap(),
        );
        let mut next = header(1, 5, None);
        next.extend(frame(FRAME_BODY, 1, b"hello"));
        out.extend(msgs(p.feed(&next, Direction::Egress, 3)));
        for m in &out {
            let text = m.request_text.as_deref().unwrap_or("");
            assert!(!text.contains("hello"), "{text}");
            assert!(text.bytes().all(|c| c == b'a'), "{text}");
        }
    }

    #[test]
    fn resyncs_after_garbage() {
        let mut p = connected();
        let mut wire = b"\x01\x00\x01garbage-bytes".to_vec();
        wire.extend(publish(1, "ex", "rk", b"ok"));
        let m = msgs(p.feed(&wire, Direction::Egress, 1));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("Basic.Publish"));
        assert_eq!(m[0].request_size_bytes, 2);
        // Found by the resync scan: not proven to be a real frame, so no
        // text ([`Side::unsynced`]).
        assert_eq!(m[0].path, None);
        assert_eq!(m[0].request_text, None);
    }

    fn all_text(m: &L7Message) -> String {
        format!(
            "{:?} {:?} {:?} {:?}",
            m.path, m.request_text, m.payload_text, m.headers
        )
    }

    /// A body that holds a whole Basic.Publish forged by the sender.
    fn body_with_forged_publish() -> (Vec<u8>, Vec<u8>) {
        let forged = publish(5, "leak", "rk.S3CRET", b"S3CRET-tail");
        let mut body = b"{\"x\":\"".to_vec();
        body.extend(&forged);
        body.extend(b"\"}");
        (publish(1, "ex", "rk", &body), forged)
    }

    /// Delta review (MED): on an unsynced side a content header may be
    /// body bytes, so its declared size (8 raw bytes) is never exported:
    /// the size is the bytes received.
    #[test]
    fn unsynced_content_header_size_is_not_exported() {
        let mut p = connected();
        p.joined_late();
        let mut wire = publish_head(1, 1_936_416_620);
        wire.extend(frame(FRAME_BODY, 1, b"ok"));
        wire.extend(publish(1, "ex", "rk", b"next"));
        let m = msgs(p.feed(&wire, Direction::Egress, 1));
        assert!(!m.is_empty(), "{m:?}");
        assert_eq!(m[0].request_size_bytes, 2, "{m:?}");
        assert!(!format!("{m:?}").contains("1936416620"));
    }

    /// A client stream that does not begin with the protocol header did
    /// not start where the parser did: both sides are unsynced.
    #[test]
    fn stream_without_protocol_header_is_unsynced() {
        let mut p = AmqpParser::new();
        let m = msgs(p.feed(
            &publish(1, "ex", "rk.S3CRET", b"S3CRET"),
            Direction::Egress,
            1,
        ));
        assert!(p.client.unsynced && p.server.unsynced);
        for m in &m {
            assert_eq!(
                (m.path.as_deref(), m.request_text.as_deref()),
                (None, None),
                "{m:?}"
            );
        }
    }

    /// What an unsynced side exports beyond sizes and timing comes from
    /// closed sets: its class and method ids, and a reply code, are bytes
    /// of the frame, which may lie inside a body.
    #[test]
    fn unsynced_scrub_keeps_closed_sets_only() {
        let mut m = L7Message::new(Protocol::Amqp, Direction::Ingress, 1);
        m.method = Some("Unknown(29.13)".into());
        m.status = Some(12_345);
        scrub(&mut m);
        assert_eq!((m.method.as_deref(), m.status), (Some("Unknown"), None));
        let mut m = L7Message::new(Protocol::Amqp, Direction::Ingress, 1);
        m.method = Some("Channel.Close".into());
        m.status = Some(404);
        scrub(&mut m);
        assert_eq!(
            (m.method.as_deref(), m.status),
            (Some("Channel.Close"), Some(404))
        );
    }

    /// Review (MED): capture joined mid-stream (attached to an open
    /// connection, or detected after its first bytes), right at a forged
    /// frame inside a body. Nothing parsed from it may export text, in
    /// either direction, for the rest of the connection.
    #[test]
    fn joined_late_inside_a_body_exports_no_forged_frame() {
        let (wire, forged) = body_with_forged_publish();
        let at = wire
            .windows(forged.len())
            .position(|w| w == forged)
            .unwrap();
        let mut p = AmqpParser::new();
        p.joined_late();
        let mut out = msgs(p.feed(&wire[at..], Direction::Egress, 1));
        out.extend(msgs(p.feed(
            &publish(1, "ex", "rk.later", b"later"),
            Direction::Egress,
            2,
        )));
        assert!(
            out.iter()
                .any(|m| m.method.as_deref() == Some("Basic.Publish"))
        );
        for m in &out {
            let all = all_text(m);
            assert!(!all.contains("S3CRET") && !all.contains("later"), "{all}");
            assert_eq!(m.path, None);
        }
        let mut d = method(2, 60, 60, &{
            let mut a = s("ctag1.0");
            a.extend_from_slice(&7u64.to_be_bytes());
            a.push(0);
            a.extend(s("ex"));
            a.extend(s("rk"));
            a
        });
        d.extend(header(2, 2, None));
        d.extend(frame(FRAME_BODY, 2, b"ok"));
        for m in msgs(p.feed(&d, Direction::Ingress, 3)) {
            assert_eq!(m.payload_text, None, "{}", all_text(&m));
            assert_eq!(m.path, None);
        }
    }

    /// The same through the connection manager: a connection first seen
    /// mid-stream (`mark_joined_late`, as the event loop does for a
    /// connection it did not see open) exports nothing of the forged frame.
    #[test]
    fn manager_join_mid_stream_exports_no_forged_frame() {
        use super::super::fsm::{ConnectionFsmManager, FsmResult};
        let (wire, forged) = body_with_forged_publish();
        let at = wire
            .windows(forged.len())
            .position(|w| w == forged)
            .unwrap();
        let m = ConnectionFsmManager::new(16);
        let (client, server) = ((1, 40000), (2, 5672));
        m.get_or_create_with_server(7, Protocol::Amqp, Some(server));
        m.mark_joined_late(7);
        let out = match m.process_packet_from(7, client, Direction::Egress, &wire[at..], 1) {
            Some(FsmResult::Messages(v)) => v,
            Some(FsmResult::MessageComplete(v)) => vec![v],
            _ => vec![],
        };
        assert!(!out.is_empty());
        for msg in &out {
            assert!(!all_text(msg).contains("S3CRET"), "{}", all_text(msg));
        }
    }

    /// A gap inside a frame of known size, through the manager (which
    /// follows every skip with `joined_late`): the parser accounted for it,
    /// so the connection keeps exporting text.
    #[test]
    fn manager_gap_inside_a_known_frame_keeps_text() {
        use super::super::fsm::{ConnectionFsmManager, FsmResult};
        let m = ConnectionFsmManager::new(16);
        let (client, server) = ((1, 40000), (2, 5672));
        m.get_or_create_with_server(8, Protocol::Amqp, Some(server));
        m.process_packet_from(8, client, Direction::Egress, AMQP_PROTOCOL_HEADER, 1);
        let wire = publish(1, "ex", "rk", &[b'a'; 100]);
        let cut = wire.len() - 1 - 40; // 40 body bytes and the end marker lost
        m.process_packet_from(8, client, Direction::Egress, &wire[..cut], 2);
        m.skip_from(8, client, Direction::Egress, 41, 3);
        let out = match m.process_packet_from(
            8,
            client,
            Direction::Egress,
            &publish(1, "ex", "rk.next", b"next"),
            4,
        ) {
            Some(FsmResult::Messages(v)) => v,
            Some(FsmResult::MessageComplete(v)) => vec![v],
            _ => vec![],
        };
        let next = out.iter().find(|x| x.path.as_deref() == Some("ex/rk.next"));
        assert!(
            next.is_some(),
            "{:?}",
            out.iter().map(all_text).collect::<Vec<_>>()
        );
    }

    /// What `raise_packet_cap` (conn_cap.rs) is for: one packet carrying
    /// several messages (a consumer's deliveries look the same), cut at
    /// the default `max_packet_bytes`, 16384. The cut crosses frame
    /// boundaries, so the direction is unsynced for good: a later message
    /// keeps no routing key. Captured whole (the raised cap), it does.
    #[test]
    fn manager_packet_cut_across_frames_latches() {
        use super::super::fsm::{ConnectionFsmManager, FsmResult};
        let mut packet = Vec::new();
        for i in 0..4 {
            packet.extend(publish(1, "ex", &format!("rk{i}"), &[b'a'; 6000]));
        }
        assert!(packet.len() > 16384);
        let next_path = |cut: Option<usize>| {
            let m = ConnectionFsmManager::new(16);
            let (client, server) = ((1, 40000), (2, 5672));
            m.get_or_create_with_server(9, Protocol::Amqp, Some(server));
            m.process_packet_from(9, client, Direction::Egress, AMQP_PROTOCOL_HEADER, 1);
            let seen = cut.unwrap_or(packet.len());
            m.process_packet_from(9, client, Direction::Egress, &packet[..seen], 2);
            if seen < packet.len() {
                m.skip_from(9, client, Direction::Egress, packet.len() - seen, 3);
            }
            let next = publish(1, "ex", "rk.next", b"next");
            let out = match m.process_packet_from(9, client, Direction::Egress, &next, 4) {
                Some(FsmResult::Messages(v)) => v,
                Some(FsmResult::MessageComplete(v)) => vec![v],
                _ => vec![],
            };
            out.iter().any(|x| x.path.as_deref() == Some("ex/rk.next"))
        };
        assert!(next_path(None), "whole packet: in sync");
        assert!(!next_path(Some(16384)), "cut at 16384: unsynced");
    }

    #[test]
    fn heartbeat_ignored() {
        let mut p = connected();
        let hb = frame(FRAME_HEARTBEAT, 0, &[]);
        assert!(msgs(p.feed(&hb, Direction::Ingress, 1)).is_empty());
    }

    #[test]
    fn test_parser_protocol() {
        let parser = AmqpParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Amqp);
        assert_eq!(parser.state_name(), "awaiting_header");
    }
}
