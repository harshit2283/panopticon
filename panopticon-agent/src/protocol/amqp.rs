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
//! next plausible frame.

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
    received: u64,
    body: Vec<u8>,
    /// Basic.GetOk: completes the channel's pending Basic.Get.
    get_ok: bool,
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
}

/// AMQP 0-9-1 protocol parser.
pub struct AmqpParser {
    state: State,
    client: Side,
    server: Side,
    channels: HashMap<u16, Channel>,
}

impl AmqpParser {
    pub fn new() -> Self {
        Self {
            state: State::AwaitingHeader,
            client: Side::default(),
            server: Side::default(),
            channels: HashMap::new(),
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
                self.side(direction).resync = true;
                buf.consume(1);
                continue;
            }
            let total = 7 + size as usize + 1;
            if data.len() < total {
                break;
            }
            if data[total - 1] != FRAME_END {
                self.side(direction).resync = true;
                buf.consume(1);
                continue;
            }
            self.frame(direction, &data[..total - 1], size as usize, ts, &mut out);
            buf.consume(total);
        }
        self.side(direction).buf = buf;
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
                let content = self.content(direction, channel);
                if let (Some(c), Some((body_size, content_type))) = (content, header) {
                    c.body_size = Some(body_size);
                    c.msg.content_type = content_type;
                }
                self.complete(direction, channel, ts, out);
            }
            FRAME_BODY => {
                if let Some(c) = self.content(direction, channel) {
                    let room = MAX_BODY_TEXT.saturating_sub(c.body.len());
                    c.body
                        .extend_from_slice(&payload[..payload.len().min(room)]);
                    c.received += size as u64;
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
        let size = c.body_size.unwrap_or(c.received);
        if !c.body.is_empty() {
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
            received: 0,
            body: Vec::new(),
            get_ok,
        };
        let ch = self.channel(channel);
        match direction {
            Direction::Egress => ch.publish = Some(content),
            Direction::Ingress => ch.delivery = Some(content),
        }
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
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        let side = self.side(direction);
        let n = side.discard.min(data.len());
        side.discard -= n;
        let data = &data[n..];
        if side.buf.extend(data).is_err() {
            // Cannot be a valid frame (> MAX_FRAME_SIZE): resync.
            side.buf.clear();
            side.resync = true;
            let _ = side.buf.extend(&data[data.len().saturating_sub(7)..]);
        }
        self.drain(direction, timestamp_ns)
    }

    /// `n` bytes were not captured. Inside a frame of known size the frame
    /// is processed from what was seen (a body frame counts all of its bytes
    /// towards the message) and the rest of it is dropped; otherwise the
    /// parser resyncs on the next plausible frame.
    fn skip(&mut self, direction: Direction, n: usize, timestamp_ns: u64) -> Option<ParseResult> {
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
            side.resync = true;
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
            p.skip(Direction::Egress, wire.len() - 4096, 1)
                .expect("AMQP never asks for a reset"),
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].path.as_deref(), Some("ex/rk.tok_5_"));
        assert_eq!(m[0].request_size_bytes, 6000);
        wire.clear();
        let m = msgs(p.feed(&next, Direction::Egress, 2));
        assert_eq!(m[0].path.as_deref(), Some("ex/rk.tok_6_"));
    }

    #[test]
    fn resyncs_after_garbage() {
        let mut p = connected();
        let mut wire = b"\x01\x00\x01garbage-bytes".to_vec();
        wire.extend(publish(1, "ex", "rk", b"ok"));
        let m = msgs(p.feed(&wire, Direction::Egress, 1));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].path.as_deref(), Some("ex/rk"));
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
