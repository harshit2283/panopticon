#![allow(dead_code)]

//! Redis RESP protocol parser.
//!
//! RESP (Redis Serialization Protocol) is line-delimited with type prefixes:
//! - `+` Simple String
//! - `-` Error
//! - `:` Integer
//! - `$` Bulk String (length-prefixed)
//! - `*` Array (element count)
//!
//! Hand-written recursive descent — no `nom` needed for this simple format.

use std::collections::VecDeque;

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// ── Parser State ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Waiting for a command (client) or response (server).
    Idle,
    /// Parsing an in-progress value.
    Parsing,
}

/// Redis RESP protocol parser.
///
/// Replies carry no request id: each one answers the oldest pending
/// command. The parser follows what changes that correspondence:
/// subscription commands answered by one acknowledgement per channel
/// (pushes in RESP3, arrays in RESP2), published messages that answer
/// nothing, `EXEC` answering every command queued since `MULTI`. Protocol
/// and subscription state come only from the server's replies (`HELLO`'s
/// reply, acknowledgement counts, `+RESET`). Whatever it cannot prove — a
/// stream not seen from its first byte ([`ProtocolParser::joined_late`]), a
/// reply with no pending command, `MONITOR`'s stream, `UNSUBSCRIBE` with
/// no channel, `CLIENT REPLY OFF|SKIP` (no acknowledgement shows whether
/// the server took them), a malformed `CLIENT REPLY`, `MULTI`, `EXEC`,
/// `DISCARD` or `RESET`, an oversized transaction — ends matching for the
/// connection: every later reply is exported without its text, so a
/// credential reply is never exported under another command.
pub struct RedisParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    /// Commands awaiting a reply, oldest first (pipelining).
    pending_queue: VecDeque<Pending>,
    /// Commands queued since `MULTI` (their replies arrive under `EXEC`).
    transaction: Option<Vec<Vec<String>>>,
    /// Bytes of the commands in `transaction`.
    transaction_bytes: usize,
    /// RESP3 in use, as the server answered `HELLO` (or sent a push):
    /// subscription traffic is pushes.
    resp3: bool,
    /// The server acknowledged a subscription and its last count was not
    /// zero: in RESP2, `message` arrays answer no command.
    subscribed: bool,
    /// Correspondence lost for good: every later reply text is withheld.
    desync: bool,
}

/// A command awaiting its reply.
struct Pending {
    /// The command, credentials already masked.
    parts: Vec<String>,
    timestamp_ns: u64,
    expect: Expect,
}

enum Expect {
    /// One reply.
    Reply,
    /// One acknowledgement per channel still to come.
    Subscription(usize),
    /// An array of the results of these queued commands.
    Exec(Vec<Vec<String>>),
    /// `+OK`, then a stream of monitored commands answering nothing.
    Monitor,
    /// `HELLO [protover]`: a successful reply switches to that protocol.
    Hello(Option<u8>),
    /// `RESET`: `+RESET` returns the connection to its initial state.
    Reset,
}

/// Queued commands (and their bytes) one transaction may hold before the
/// parser stops matching replies on the connection.
const MAX_TRANSACTION_COMMANDS: usize = 1024;
const MAX_TRANSACTION_BYTES: usize = 64 * 1024;

/// Commands awaiting replies past this mean the server is not answering
/// what we think it is: stop matching.
const MAX_PENDING: usize = 4096;

const SUBSCRIBE_COMMANDS: &[&str] = &[
    "SUBSCRIBE",
    "PSUBSCRIBE",
    "SSUBSCRIBE",
    "UNSUBSCRIBE",
    "PUNSUBSCRIBE",
    "SUNSUBSCRIBE",
];

impl RedisParser {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            pending_queue: VecDeque::new(),
            transaction: None,
            transaction_bytes: 0,
            resp3: false,
            subscribed: false,
            desync: false,
        }
    }

    /// Try to parse complete RESP values from the client buffer.
    fn try_parse_request(&mut self, timestamp_ns: u64) -> ParseResult {
        loop {
            let data = self.client_buf.data();
            if data.is_empty() {
                break;
            }

            match parse_resp_value(data) {
                RespParse::Complete(value, consumed) => {
                    self.client_buf.consume(consumed);
                    let mut parts = flatten_to_strings(&value);
                    if super::mask_credentials_enabled() {
                        mask_credentials(&mut parts);
                    }
                    if !parts.is_empty() {
                        self.track_command(parts, timestamp_ns);
                    }
                    self.state = State::Idle;
                }
                RespParse::Incomplete => {
                    self.state = State::Parsing;
                    break;
                }
                RespParse::Error(e) => return ParseResult::Error(e),
            }
        }
        ParseResult::NeedMoreData
    }

    /// Record what reply, if any, `parts` will get.
    fn track_command(&mut self, parts: Vec<String>, timestamp_ns: u64) {
        let cmd = parts[0].to_ascii_uppercase();
        let arg = |i: usize| parts.get(i).map(|a| a.to_ascii_uppercase());
        let mut expect = Expect::Reply;
        let queued_in_transaction = self.transaction.is_some()
            && !matches!(
                cmd.as_str(),
                "EXEC" | "DISCARD" | "MULTI" | "WATCH" | "RESET"
            );
        // Commands that change how replies line up, sent with arguments the
        // server would refuse: we cannot tell what it did.
        let malformed = match cmd.as_str() {
            "MULTI" | "EXEC" | "DISCARD" | "RESET" => parts.len() != 1,
            _ => false,
        };
        if malformed && !queued_in_transaction {
            self.lose_correspondence();
            return;
        }
        match cmd.as_str() {
            // Inside MULTI a command is only queued (`+QUEUED`); its result
            // comes back in EXEC's array.
            // Run at EXEC, these change how later replies line up (or the
            // protocol) without a reply we can check: stop matching.
            c if queued_in_transaction
                && (matches!(c, "CLIENT" | "HELLO" | "MONITOR")
                    || SUBSCRIBE_COMMANDS.contains(&c)) =>
            {
                self.lose_correspondence();
                return;
            }
            _ if queued_in_transaction => {
                self.transaction_bytes += parts.iter().map(String::len).sum::<usize>();
                let queued = self.transaction.get_or_insert_with(Vec::new);
                queued.push(parts.clone());
                if queued.len() > MAX_TRANSACTION_COMMANDS
                    || self.transaction_bytes > MAX_TRANSACTION_BYTES
                {
                    self.lose_correspondence();
                    return;
                }
            }
            "CLIENT" if arg(1).as_deref() == Some("REPLY") => {
                // OFF and SKIP are never acknowledged, so a refusal (ACL,
                // syntax) is invisible: stop matching. ON is answered.
                if !(parts.len() == 3 && arg(2).as_deref() == Some("ON")) {
                    self.lose_correspondence();
                    return;
                }
            }
            "HELLO" => {
                expect = Expect::Hello(match arg(1).as_deref() {
                    Some("2") => Some(2),
                    Some("3") => Some(3),
                    _ => None,
                })
            }
            "RESET" => {
                self.transaction = None;
                self.transaction_bytes = 0;
                expect = Expect::Reset;
            }
            "MULTI" => {
                self.transaction = Some(Vec::new());
                self.transaction_bytes = 0;
            }
            "DISCARD" => self.transaction = None,
            // With no MULTI seen (capture started inside the transaction)
            // nothing lines up, and all of a result array is masked.
            "EXEC" => expect = Expect::Exec(self.transaction.take().unwrap_or_default()),
            "MONITOR" => expect = Expect::Monitor,
            c if SUBSCRIBE_COMMANDS.contains(&c) => {
                // (P|S)UNSUBSCRIBE with no channel: one ack per current
                // subscription, a number we do not track.
                if parts.len() < 2 {
                    self.lose_correspondence();
                    return;
                }
                expect = Expect::Subscription(parts.len() - 1);
            }
            _ => {}
        }
        if self.desync {
            return;
        }
        if self.pending_queue.len() >= MAX_PENDING {
            self.lose_correspondence();
            return;
        }
        self.pending_queue.push_back(Pending {
            parts,
            timestamp_ns,
            expect,
        });
    }

    fn lose_correspondence(&mut self) {
        self.desync = true;
        self.pending_queue.clear();
        self.transaction = None;
        self.transaction_bytes = 0;
    }

    /// Try to parse complete RESP values from the server buffer and produce L7Messages.
    fn try_parse_response(&mut self, timestamp_ns: u64) -> ParseResult {
        let mut messages = Vec::new();

        loop {
            let data = self.server_buf.data();
            if data.is_empty() {
                break;
            }

            match parse_resp_value(data) {
                RespParse::Complete(value, consumed) => {
                    self.server_buf.consume(consumed);
                    self.state = State::Idle;
                    if let Some(msg) = self.answer(value, timestamp_ns) {
                        messages.push(msg);
                    }
                }
                RespParse::Incomplete => {
                    self.state = State::Parsing;
                    break;
                }
                RespParse::Error(e) => return ParseResult::Error(e),
            }
        }

        if !messages.is_empty() {
            ParseResult::Messages(messages)
        } else {
            ParseResult::NeedMoreData
        }
    }

    /// The message for one server value, if it answers a command.
    fn answer(&mut self, mut value: RespValue, timestamp_ns: u64) -> Option<L7Message> {
        let kind = subscription_kind(&value);
        if let RespValue::Push(_) = value {
            self.resp3 = true;
        }
        let ack = kind
            .as_deref()
            .is_some_and(|k| SUBSCRIBE_COMMANDS.iter().any(|c| c.eq_ignore_ascii_case(k)));
        let push = matches!(value, RespValue::Push(_));
        let published = kind
            .as_deref()
            .is_some_and(|k| matches!(k, "message" | "pmessage" | "smessage"));
        if let Some(Pending {
            parts,
            expect: Expect::Subscription(left),
            ..
        }) = self.pending_queue.front_mut()
            && (push || !self.resp3)
        {
            // Only the pending command's own acknowledgement counts: an
            // ordinary array of the same shape (a script's result) must not
            // change subscription state.
            if kind.as_deref() == Some(parts[0].to_ascii_lowercase().as_str()) {
                if let Some(count) = subscription_count(&value) {
                    // The server's own count of this connection's subscriptions.
                    self.subscribed = count > 0;
                }
                *left -= 1;
                if *left > 0 {
                    return None;
                }
            } else if push || (self.subscribed && published) {
                return None; // out-of-band, before the acknowledgement
            } else {
                // Not what the subscription command gets: ambiguous.
                self.lose_correspondence();
            }
        } else if push {
            // Out-of-band (published message, invalidation, server-side
            // unsubscribe): answers no command.
            if ack && let Some(count) = subscription_count(&value) {
                self.subscribed = count > 0;
            }
            return None;
        } else if self.subscribed
            && !self.resp3
            && (ack
                || kind
                    .as_deref()
                    .is_some_and(|k| matches!(k, "message" | "pmessage" | "smessage")))
        {
            // RESP2 published message or unsolicited ack.
            return None;
        }

        let mut msg = L7Message::new(Protocol::Redis, Direction::Ingress, timestamp_ns);
        msg.status = Some(matches!(value, RespValue::Error(_)) as u32);
        let pending = if self.desync {
            None
        } else {
            self.pending_queue.pop_front()
        };
        let Some(Pending {
            parts,
            timestamp_ns: req_ts,
            expect,
        }) = pending
        else {
            // No command known to answer: withhold the text.
            return Some(msg);
        };
        msg.method = Some(parts[0].to_uppercase());
        if parts.len() > 1 {
            msg.path = Some(parts[1].clone());
        }
        // Arguments after the key (SET value, HSET field/value
        // pairs, ...) carry the data written: scan it for PII.
        if parts.len() > 2 {
            msg.request_text = Some(parts[2..].join(" "));
            // CONFIG GET takes parameter names (patterns), never values.
            msg.request_text_is_name =
                parts[0].eq_ignore_ascii_case("CONFIG") && parts[1].eq_ignore_ascii_case("GET");
        }
        msg.latency_ns = Some(timestamp_ns.saturating_sub(req_ts));
        match &expect {
            Expect::Subscription(_) if !ack && !matches!(value, RespValue::Error(_)) => {
                // Not the acknowledgement it should be: lost track.
                self.lose_correspondence();
                return Some(msg);
            }
            Expect::Monitor => self.lose_correspondence(),
            Expect::Hello(Some(v)) if !matches!(value, RespValue::Error(_)) => {
                self.resp3 = *v == 3;
            }
            Expect::Reset if !matches!(value, RespValue::Error(_)) => {
                self.resp3 = false;
                self.subscribed = false;
            }
            _ => {}
        }
        if super::mask_credentials_enabled() {
            match &expect {
                Expect::Exec(queued) => mask_exec_reply(queued, &mut value),
                _ => mask_reply_credentials(&parts, &mut value),
            }
            mask_reply_shapes(&mut value);
        }
        msg.payload_text = match &value {
            RespValue::Error(e) => Some(e.clone()),
            v => resp_value_to_text(v),
        };
        Some(msg)
    }

    pub fn current_state(&self) -> &'static str {
        match self.state {
            State::Idle => "idle",
            State::Parsing => "parsing",
        }
    }

    pub fn reset_for_next_transaction(&mut self) {
        *self = Self::new();
    }
}

impl ProtocolParser for RedisParser {
    /// Replies pair with commands by order only: without the stream's
    /// start, the first reply may answer a command sent before capture.
    fn joined_late(&mut self) {
        self.lose_correspondence();
    }

    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult {
        match direction {
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("Redis client buffer overflow".into());
                }
                self.try_parse_request(timestamp_ns)
            }
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("Redis server buffer overflow".into());
                }
                self.try_parse_response(timestamp_ns)
            }
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Redis
    }

    fn state_name(&self) -> &'static str {
        self.current_state()
    }
}

/// Replace the secrets a command carries with [`super::REDACTED_CREDENTIAL`]
/// before it is queued, so no sink, in any privacy mode, ever sees them (as
/// the AMQP and Kafka parsers drop their auth exchanges):
/// `AUTH [user] pw`, `HELLO … AUTH user pw`, `MIGRATE … AUTH pw | AUTH2 user pw`,
/// `CONFIG SET` / `SENTINEL SET` of a credential-named parameter
/// ([`super::is_credential_name`]) and the password rules
/// (`>pw`, `<pw`, `#hash`, `!hash`) of `ACL SETUSER`.
fn mask_credentials(parts: &mut [String]) {
    let mask = |s: &mut String| {
        zeroize::Zeroize::zeroize(s);
        *s = super::REDACTED_CREDENTIAL.to_string();
    };
    let Some(cmd) = parts.first().map(|c| c.to_ascii_uppercase()) else {
        return;
    };
    let arg_is = |parts: &[String], i: usize, names: &[&str]| {
        parts
            .get(i)
            .is_some_and(|a| names.iter().any(|n| a.eq_ignore_ascii_case(n)))
    };
    match cmd.as_str() {
        "AUTH" => parts[1..].iter_mut().for_each(mask),
        "HELLO" | "MIGRATE" => {
            let mut i = 1;
            while i < parts.len() {
                // HELLO's AUTH and MIGRATE's AUTH2 take user + password.
                let n = if arg_is(parts, i, &["AUTH2"])
                    || (cmd == "HELLO" && arg_is(parts, i, &["AUTH"]))
                {
                    2
                } else if arg_is(parts, i, &["AUTH"]) {
                    1
                } else {
                    0
                };
                let end = (i + 1 + n).min(parts.len());
                parts[i + 1..end].iter_mut().for_each(mask);
                i += 1 + n;
            }
        }
        // CONFIG SET name value ...; SENTINEL SET master name value ...
        "CONFIG" | "SENTINEL" if arg_is(parts, 1, &["SET"]) => {
            let mut i = if cmd == "CONFIG" { 2 } else { 3 };
            while i + 1 < parts.len() {
                if super::is_credential_name(&parts[i]) {
                    mask(&mut parts[i + 1]);
                }
                i += 2;
            }
        }
        "ACL" if arg_is(parts, 1, &["SETUSER"]) => parts
            .iter_mut()
            .skip(3)
            .filter(|r| r.starts_with(['>', '<', '#', '!']))
            .for_each(mask),
        _ => {}
    }
}

/// Mask the secrets a reply carries, given the command it answers:
/// `CONFIG GET` values of credential-named parameters (name/value pairs,
/// RESP2 array or RESP3 map; see [`super::is_credential_name`]), and the
/// whole reply of `ACL LIST` (password hashes), `ACL GETUSER` (password
/// hashes) and `ACL GENPASS` (a fresh password).
fn mask_reply_credentials(cmd: &[String], value: &mut RespValue) {
    let is = |i: usize, name: &str| cmd.get(i).is_some_and(|a| a.eq_ignore_ascii_case(name));
    if is(0, "ACL") && (is(1, "LIST") || is(1, "GETUSER") || is(1, "GENPASS")) {
        if !matches!(value, RespValue::Error(_)) {
            *value = redacted();
        }
    } else if is(0, "CONFIG")
        && is(1, "GET")
        && let RespValue::Array(Some(items)) = value
    {
        mask_pairs(items);
    }
}

/// `EXEC`'s array answers the queued commands in order; when it does not
/// line up with them, all of it is masked.
fn mask_exec_reply(queued: &[Vec<String>], value: &mut RespValue) {
    match value {
        RespValue::Array(Some(items)) if items.len() == queued.len() => {
            for (cmd, item) in queued.iter().zip(items.iter_mut()) {
                mask_reply_credentials(cmd, item);
            }
        }
        RespValue::Array(Some(items)) if !items.is_empty() => *value = redacted(),
        _ => {}
    }
}

/// Mask credentials by the shape of a reply, whatever the command (a
/// script or a command we did not see may return them): the value after a
/// credential-named element at an even position of any array or map
/// (`CONFIG GET` output, a hash with a `password` field, `ACL GETUSER`'s
/// `passwords`), and `ACL LIST` lines carrying a password rule.
fn mask_reply_shapes(value: &mut RespValue) {
    match value {
        RespValue::Array(Some(items)) | RespValue::Push(items) => {
            mask_pairs(items);
            items.iter_mut().for_each(mask_reply_shapes);
        }
        RespValue::SimpleString(s) if is_acl_rule_line(s) => *value = redacted(),
        RespValue::BulkString(Some(b)) if is_acl_rule_line(&String::from_utf8_lossy(b)) => {
            *value = redacted()
        }
        _ => {}
    }
}

fn mask_pairs(items: &mut [RespValue]) {
    for pair in items.chunks_mut(2) {
        if let [name, v] = pair
            && resp_element_to_string(name).is_some_and(|n| super::is_credential_name(&n))
        {
            *v = redacted();
        }
    }
}

/// An `ACL LIST` line: `user <name> ... #<hash>` or `>password`.
fn is_acl_rule_line(s: &str) -> bool {
    s.starts_with("user ")
        && s.split(' ')
            .skip(2)
            .any(|r| r.starts_with(['#', '>', '<', '!']))
}

fn redacted() -> RespValue {
    RespValue::SimpleString(super::REDACTED_CREDENTIAL.to_string())
}

/// The channel count closing a subscription acknowledgement.
fn subscription_count(value: &RespValue) -> Option<i64> {
    match value {
        RespValue::Array(Some(items)) | RespValue::Push(items) => match items.get(2)? {
            RespValue::Integer(n) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

/// The first element of an array or push, lowercased: `subscribe`,
/// `message`, ...
fn subscription_kind(value: &RespValue) -> Option<String> {
    match value {
        RespValue::Array(Some(items)) | RespValue::Push(items) => {
            resp_element_to_string(items.first()?).map(|k| k.to_ascii_lowercase())
        }
        _ => None,
    }
}

// ── RESP Value Types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),   // None = null bulk string
    Array(Option<Vec<RespValue>>), // None = null array
    /// RESP3 out-of-band push (pub/sub, client-side caching invalidation):
    /// not a reply to any pending command.
    Push(Vec<RespValue>),
}

enum RespParse {
    Complete(RespValue, usize), // value + bytes consumed
    Incomplete,
    Error(String),
}

/// Parse a single RESP value from the beginning of `data`.
/// Max nesting of RESP arrays. Parsing recurses per level and agent workers
/// run on small (2MB) tokio stacks; real commands/replies nest 1–3 deep.
const MAX_RESP_DEPTH: usize = 32;
/// Upper bound on elements pre-allocated for an array. The count is
/// peer-controlled: `Vec::with_capacity(huge)` aborts the whole process.
const MAX_PREALLOC_ELEMENTS: usize = 1024;

fn parse_resp_value(data: &[u8]) -> RespParse {
    parse_resp_value_at(data, 0)
}

fn parse_resp_value_at(data: &[u8], depth: usize) -> RespParse {
    if data.is_empty() {
        return RespParse::Incomplete;
    }

    match data[0] {
        b'+' => parse_simple_string(data),
        b'-' => parse_error(data),
        b':' => parse_integer(data),
        b'$' => parse_bulk_string(data),
        b'*' | b'%' | b'~' | b'>' | b'|' if depth >= MAX_RESP_DEPTH => {
            RespParse::Error(format!("RESP nesting deeper than {MAX_RESP_DEPTH}"))
        }
        b'*' => parse_array(data, depth),
        // ── RESP3 (negotiated with HELLO 3; default in current clients) ──
        b'_' => match find_crlf(data) {
            Some(pos) => RespParse::Complete(RespValue::BulkString(None), pos + 2),
            None => RespParse::Incomplete,
        },
        b'#' | b',' | b'(' => match find_crlf(data) {
            // boolean / double / big number: keep the literal text
            Some(pos) => RespParse::Complete(
                RespValue::SimpleString(String::from_utf8_lossy(&data[1..pos]).into_owned()),
                pos + 2,
            ),
            None => RespParse::Incomplete,
        },
        b'!' => match parse_bulk_string(data) {
            RespParse::Complete(RespValue::BulkString(b), n) => RespParse::Complete(
                RespValue::Error(String::from_utf8_lossy(&b.unwrap_or_default()).into_owned()),
                n,
            ),
            other => other,
        },
        b'=' => match parse_bulk_string(data) {
            // verbatim string: "txt:" / "mkd:" format prefix
            RespParse::Complete(RespValue::BulkString(Some(b)), n) => RespParse::Complete(
                RespValue::BulkString(Some(b.get(4..).unwrap_or_default().to_vec())),
                n,
            ),
            other => other,
        },
        b'%' => parse_aggregate(data, depth, 2, |v| RespValue::Array(Some(v))),
        b'~' => parse_aggregate(data, depth, 1, |v| RespValue::Array(Some(v))),
        b'>' => parse_aggregate(data, depth, 1, RespValue::Push),
        b'|' => {
            // Attribute: metadata map that precedes the actual reply.
            match parse_aggregate(data, depth, 2, |v| RespValue::Array(Some(v))) {
                RespParse::Complete(_, attr_len) => {
                    match parse_resp_value_at(&data[attr_len..], depth + 1) {
                        RespParse::Complete(value, n) => RespParse::Complete(value, attr_len + n),
                        other => other,
                    }
                }
                other => other,
            }
        }
        _ => RespParse::Error("unknown RESP type byte".into()),
    }
}

/// Find `\r\n` in data, returning the index of `\r`.
fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Parse `+<string>\r\n`
fn parse_simple_string(data: &[u8]) -> RespParse {
    match find_crlf(data) {
        Some(pos) => {
            let s = String::from_utf8_lossy(&data[1..pos]).into_owned();
            RespParse::Complete(RespValue::SimpleString(s), pos + 2)
        }
        None => RespParse::Incomplete,
    }
}

/// Parse `-<error>\r\n`
fn parse_error(data: &[u8]) -> RespParse {
    match find_crlf(data) {
        Some(pos) => {
            let s = String::from_utf8_lossy(&data[1..pos]).into_owned();
            RespParse::Complete(RespValue::Error(s), pos + 2)
        }
        None => RespParse::Incomplete,
    }
}

/// Parse `:<integer>\r\n`
fn parse_integer(data: &[u8]) -> RespParse {
    match find_crlf(data) {
        Some(pos) => {
            let s = std::str::from_utf8(&data[1..pos]).unwrap_or("0");
            match s.parse::<i64>() {
                Ok(n) => RespParse::Complete(RespValue::Integer(n), pos + 2),
                Err(_) => RespParse::Error("invalid RESP integer".into()),
            }
        }
        None => RespParse::Incomplete,
    }
}

/// Parse `$<len>\r\n<data>\r\n` or `$-1\r\n` (null)
fn parse_bulk_string(data: &[u8]) -> RespParse {
    let crlf_pos = match find_crlf(data) {
        Some(pos) => pos,
        None => return RespParse::Incomplete,
    };

    let len_str = std::str::from_utf8(&data[1..crlf_pos]).unwrap_or("");
    let len: i64 = match len_str.parse() {
        Ok(n) => n,
        Err(_) => return RespParse::Error("invalid bulk string length".into()),
    };

    if len < 0 {
        // Null bulk string
        return RespParse::Complete(RespValue::BulkString(None), crlf_pos + 2);
    }

    let len = len as usize;
    let data_start = crlf_pos + 2;
    let data_end = data_start + len;
    let total = data_end + 2; // +2 for trailing \r\n

    if data.len() < total {
        return RespParse::Incomplete;
    }

    let bytes = data[data_start..data_end].to_vec();
    RespParse::Complete(RespValue::BulkString(Some(bytes)), total)
}

/// RESP3 aggregate: `<type><count>\r\n` followed by `count * per_entry`
/// values (2 per entry for maps and attributes, 1 for sets and pushes).
fn parse_aggregate(
    data: &[u8],
    depth: usize,
    per_entry: usize,
    wrap: impl FnOnce(Vec<RespValue>) -> RespValue,
) -> RespParse {
    let crlf_pos = match find_crlf(data) {
        Some(pos) => pos,
        None => return RespParse::Incomplete,
    };
    let count_str = std::str::from_utf8(&data[1..crlf_pos]).unwrap_or("");
    let count: usize = match count_str.parse() {
        Ok(n) => n,
        Err(_) => return RespParse::Error("invalid RESP3 count".into()),
    };
    let total = count.saturating_mul(per_entry);
    let mut offset = crlf_pos + 2;
    let mut elements = Vec::with_capacity(total.min(MAX_PREALLOC_ELEMENTS));
    for _ in 0..total {
        if offset >= data.len() {
            return RespParse::Incomplete;
        }
        match parse_resp_value_at(&data[offset..], depth + 1) {
            RespParse::Complete(value, consumed) => {
                elements.push(value);
                offset += consumed;
            }
            other => return other,
        }
    }
    RespParse::Complete(wrap(elements), offset)
}

/// Parse `*<count>\r\n<elements...>` or `*-1\r\n` (null)
fn parse_array(data: &[u8], depth: usize) -> RespParse {
    let crlf_pos = match find_crlf(data) {
        Some(pos) => pos,
        None => return RespParse::Incomplete,
    };

    let count_str = std::str::from_utf8(&data[1..crlf_pos]).unwrap_or("");
    let count: i64 = match count_str.parse() {
        Ok(n) => n,
        Err(_) => return RespParse::Error("invalid array count".into()),
    };

    if count < 0 {
        return RespParse::Complete(RespValue::Array(None), crlf_pos + 2);
    }

    let mut offset = crlf_pos + 2;
    // Grow as elements actually arrive; never trust the declared count.
    let mut elements = Vec::with_capacity((count as usize).min(MAX_PREALLOC_ELEMENTS));

    for _ in 0..count {
        if offset >= data.len() {
            return RespParse::Incomplete;
        }
        match parse_resp_value_at(&data[offset..], depth + 1) {
            RespParse::Complete(value, consumed) => {
                elements.push(value);
                offset += consumed;
            }
            RespParse::Incomplete => return RespParse::Incomplete,
            RespParse::Error(e) => return RespParse::Error(e),
        }
    }

    RespParse::Complete(RespValue::Array(Some(elements)), offset)
}

/// Extract string values from a RESP value (for command parsing).
fn flatten_to_strings(value: &RespValue) -> Vec<String> {
    match value {
        RespValue::Array(Some(elements)) => {
            elements.iter().filter_map(resp_element_to_string).collect()
        }
        _ => {
            if let Some(s) = resp_element_to_string(value) {
                vec![s]
            } else {
                vec![]
            }
        }
    }
}

fn resp_element_to_string(value: &RespValue) -> Option<String> {
    match value {
        RespValue::SimpleString(s) => Some(s.clone()),
        RespValue::BulkString(Some(bytes)) => Some(String::from_utf8_lossy(bytes).into_owned()),
        RespValue::Integer(n) => Some(n.to_string()),
        _ => None,
    }
}

fn resp_value_to_text(value: &RespValue) -> Option<String> {
    match value {
        RespValue::SimpleString(s) => Some(s.clone()),
        RespValue::BulkString(Some(bytes)) => Some(String::from_utf8_lossy(bytes).into_owned()),
        RespValue::BulkString(None) => Some("(nil)".into()),
        RespValue::Integer(n) => Some(format!("(integer) {n}")),
        RespValue::Error(e) => Some(format!("(error) {e}")),
        RespValue::Array(None) => Some("(nil)".into()),
        RespValue::Array(Some(elements)) | RespValue::Push(elements) => {
            let parts: Vec<String> = elements.iter().filter_map(resp_value_to_text).collect();
            Some(parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_set_command() {
        let mut parser = RedisParser::new();

        // Client sends: *3\r\n$3\r\nSET\r\n$8\r\nuser:123\r\n$5\r\nhello\r\n
        // Note: "user:123" is 8 bytes, so the correct RESP length prefix is $8.
        let cmd = b"*3\r\n$3\r\nSET\r\n$8\r\nuser:123\r\n$5\r\nhello\r\n";
        let result = parser.feed(cmd, Direction::Egress, 1000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        // Server responds: +OK\r\n
        let resp = b"+OK\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SET"));
                assert_eq!(msgs[0].path.as_deref(), Some("user:123"));
                assert_eq!(msgs[0].status, Some(0));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_get_missing_key_returns_null_bulk() {
        let mut parser = RedisParser::new();
        parser.feed(
            b"*2\r\n$3\r\nGET\r\n$8\r\no:tok_5_\r\n",
            Direction::Egress,
            1000,
        );
        match parser.feed(b"$-1\r\n", Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("o:tok_5_"));
            }
            other => panic!("expected GET message for a null reply, got {other:?}"),
        }
    }

    #[test]
    fn test_resp3_replies() {
        // HELLO 3 map reply, RESP3 null, boolean, double, verbatim, blob error.
        let mut parser = RedisParser::new();
        let cmds = b"*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n\
            *2\r\n$3\r\nGET\r\n$4\r\nnone\r\n\
            *2\r\n$6\r\nEXISTS\r\n$1\r\nk\r\n\
            *2\r\n$5\r\nSCORE\r\n$1\r\nk\r\n\
            *2\r\n$4\r\nINFO\r\n$1\r\nk\r\n\
            *2\r\n$4\r\nFAIL\r\n$1\r\nk\r\n";
        parser.feed(cmds, Direction::Egress, 1000);
        let replies = b"%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n\
            _\r\n\
            >2\r\n$10\r\ninvalidate\r\n*1\r\n$1\r\nk\r\n\
            #t\r\n\
            ,3.14\r\n\
            |1\r\n$3\r\nttl\r\n:5\r\n=9\r\ntxt:hello\r\n\
            !10\r\nERR boom!!\r\n";
        match parser.feed(replies, Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                let got: Vec<_> = msgs
                    .iter()
                    .map(|m| {
                        (
                            m.method.clone().unwrap(),
                            m.status.unwrap(),
                            m.payload_text.clone(),
                        )
                    })
                    .collect();
                assert_eq!(got.len(), 6, "{got:?}"); // the push answers nothing
                assert_eq!(got[1], ("GET".into(), 0, Some("(nil)".into())));
                assert_eq!(got[2].2.as_deref(), Some("t"));
                assert_eq!(got[3].2.as_deref(), Some("3.14"));
                assert_eq!(got[4].2.as_deref(), Some("hello"));
                assert_eq!(got[5].1, 1);
            }
            other => panic!("expected RESP3 replies, got {other:?}"),
        }
    }

    #[test]
    fn test_set_value_is_request_text() {
        let mut parser = RedisParser::new();
        parser.feed(
            b"*3\r\n$3\r\nSET\r\n$4\r\nuser\r\n$17\r\nbob@example.com!!\r\n",
            Direction::Egress,
            1000,
        );
        match parser.feed(b"+OK\r\n", Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].request_text.as_deref(), Some("bob@example.com!!"));
            }
            other => panic!("expected SET message, got {other:?}"),
        }
    }

    fn resp(args: &[&str]) -> Vec<u8> {
        let mut out = format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            out.extend(format!("${}\r\n{a}\r\n", a.len()).bytes());
        }
        out
    }

    #[test]
    fn test_credentials_never_leave_the_parser() {
        let cases: &[&[&str]] = &[
            &["AUTH", "s3cretpw"],
            &["auth", "alice", "s3cretpw"],
            &[
                "HELLO", "3", "AUTH", "default", "s3cretpw", "SETNAME", "app",
            ],
            &[
                "MIGRATE", "h", "6379", "", "0", "5000", "AUTH", "s3cretpw", "KEYS", "k",
            ],
            &[
                "MIGRATE", "h", "6379", "", "0", "5000", "AUTH2", "u", "s3cretpw",
            ],
            &["CONFIG", "SET", "requirepass", "s3cretpw"],
            &["CONFIG", "SET", "tls-key-file-pass", "s3cretpw"],
            &["SENTINEL", "SET", "mymaster", "auth-pass", "s3cretpw"],
            &[
                "CONFIG",
                "SET",
                "maxmemory",
                "1gb",
                "masterauth",
                "s3cretpw",
            ],
            &["ACL", "SETUSER", "bob", "on", ">s3cretpw", "~*", "+@all"],
        ];
        for args in cases {
            let mut parser = RedisParser::new();
            parser.feed(&resp(args), Direction::Egress, 1);
            let ParseResult::Messages(msgs) = parser.feed(b"+OK\r\n", Direction::Ingress, 2) else {
                panic!("no message for {args:?}");
            };
            let m = &msgs[0];
            let all = format!("{:?} {:?} {:?}", m.method, m.path, m.request_text);
            assert!(!all.contains("s3cretpw"), "{args:?} leaked: {all}");
            assert!(all.contains(crate::protocol::REDACTED_CREDENTIAL), "{all}");
        }
        // Ordinary arguments stay readable.
        let mut parser = RedisParser::new();
        parser.feed(
            &resp(&["HELLO", "3", "SETNAME", "app"]),
            Direction::Egress,
            1,
        );
        let ParseResult::Messages(msgs) = parser.feed(b"+OK\r\n", Direction::Ingress, 2) else {
            panic!()
        };
        assert_eq!(msgs[0].request_text.as_deref(), Some("SETNAME app"));
    }

    /// `CONFIG GET requirepass` after the built-in rules (USER-GUIDE 5.3):
    /// the command names a parameter, a bare name, and is exported; its
    /// reply, the name then its masked value, stays withheld.
    #[test]
    fn test_config_get_credential_after_the_builtin_rules() {
        let mut parser = RedisParser::new();
        parser.feed(
            &resp(&["CONFIG", "GET", "requirepass"]),
            Direction::Egress,
            1,
        );
        let reply = b"*2\r\n$11\r\nrequirepass\r\n$8\r\ns3cretpw\r\n";
        let ParseResult::Messages(mut msgs) = parser.feed(reply, Direction::Ingress, 2) else {
            panic!()
        };
        crate::pii::mask_credentials(&mut msgs[0]);
        assert_eq!(msgs[0].method.as_deref(), Some("CONFIG"));
        assert_eq!(msgs[0].path.as_deref(), Some("GET"));
        assert_eq!(msgs[0].request_text.as_deref(), Some("requirepass"));
        assert_eq!(
            msgs[0].payload_text.as_deref(),
            Some(crate::protocol::FIELD_WITHHELD)
        );
        // CONFIG SET: the masked value next to the name withholds it.
        let mut parser = RedisParser::new();
        parser.feed(
            &resp(&["CONFIG", "SET", "requirepass", "s3cretpw"]),
            Direction::Egress,
            1,
        );
        let ParseResult::Messages(mut msgs) = parser.feed(b"+OK\r\n", Direction::Ingress, 2) else {
            panic!()
        };
        crate::pii::mask_credentials(&mut msgs[0]);
        assert_eq!(
            msgs[0].request_text.as_deref(),
            Some(crate::protocol::FIELD_WITHHELD)
        );
        // Codex round 1 #4: a value that reads like a credential name is
        // not a name: SET's value and GET's reply stay withheld.
        let mut parser = RedisParser::new();
        parser.feed(
            &resp(&["SET", "user:alice:password", "swordfish_password"]),
            Direction::Egress,
            1,
        );
        let ParseResult::Messages(mut msgs) = parser.feed(b"+OK\r\n", Direction::Ingress, 2) else {
            panic!()
        };
        assert!(!msgs[0].request_text_is_name);
        crate::pii::mask_credentials(&mut msgs[0]);
        assert_eq!(
            msgs[0].request_text.as_deref(),
            Some(crate::protocol::FIELD_WITHHELD)
        );
        let mut parser = RedisParser::new();
        parser.feed(&resp(&["GET", "user:alice:password"]), Direction::Egress, 1);
        let reply = b"$18\r\nswordfish_password\r\n";
        let ParseResult::Messages(mut msgs) = parser.feed(reply, Direction::Ingress, 2) else {
            panic!()
        };
        crate::pii::mask_credentials(&mut msgs[0]);
        assert_eq!(
            msgs[0].payload_text.as_deref(),
            Some(crate::protocol::FIELD_WITHHELD)
        );
    }

    /// Replies that carry a secret: `CONFIG GET` values of secret
    /// parameters, and the hashes or passwords of `ACL LIST|GETUSER|GENPASS`.
    #[test]
    fn test_credential_replies_never_leave_the_parser() {
        let cases: &[(&[&str], &[u8])] = &[
            (
                &["CONFIG", "GET", "requirepass"],
                b"*2\r\n$11\r\nrequirepass\r\n$8\r\ns3cretpw\r\n",
            ),
            (
                &["config", "get", "*"],
                b"*6\r\n$9\r\nmaxmemory\r\n$3\r\n1gb\r\n$10\r\nmasterauth\r\n$8\r\ns3cretpw\r\n\
                  $17\r\ntls-key-file-pass\r\n$8\r\ns3cretpw\r\n",
            ),
            // RESP3 map reply.
            (
                &["CONFIG", "GET", "masterauth"],
                b"%1\r\n$10\r\nmasterauth\r\n$8\r\ns3cretpw\r\n",
            ),
            (
                &["ACL", "LIST"],
                b"*1\r\n$33\r\nuser bob on #s3cretpw ~* &* +@all\r\n",
            ),
            (
                &["ACL", "GETUSER", "bob"],
                b"*4\r\n$5\r\nflags\r\n*1\r\n$2\r\non\r\n$9\r\npasswords\r\n*1\r\n$8\r\ns3cretpw\r\n",
            ),
            (&["ACL", "GENPASS"], b"$8\r\ns3cretpw\r\n"),
        ];
        for (args, reply) in cases {
            let mut parser = RedisParser::new();
            parser.feed(&resp(args), Direction::Egress, 1);
            let ParseResult::Messages(msgs) = parser.feed(reply, Direction::Ingress, 2) else {
                panic!("no message for {args:?}");
            };
            let text = msgs[0].payload_text.clone().unwrap_or_default();
            assert!(!text.contains("s3cretpw"), "{args:?} leaked: {text}");
            assert!(
                text.contains(crate::protocol::REDACTED_CREDENTIAL),
                "{text}"
            );
        }
        // Other parameters stay readable.
        let mut parser = RedisParser::new();
        parser.feed(&resp(&["CONFIG", "GET", "*"]), Direction::Egress, 1);
        let ParseResult::Messages(msgs) = parser.feed(cases[1].1, Direction::Ingress, 2) else {
            panic!()
        };
        assert!(
            msgs[0]
                .payload_text
                .as_deref()
                .unwrap()
                .starts_with("maxmemory, 1gb, masterauth, <"),
            "{:?}",
            msgs[0].payload_text
        );
    }

    /// Feed client commands and server bytes in order; return every
    /// exported reply text (None when withheld).
    fn exchange(steps: &[(&[&str], &[u8])]) -> Vec<Option<String>> {
        let mut parser = RedisParser::new();
        let mut out = Vec::new();
        for (cmd, reply) in steps {
            if !cmd.is_empty() {
                parser.feed(&resp(cmd), Direction::Egress, 1);
            }
            if !reply.is_empty()
                && let ParseResult::Messages(msgs) = parser.feed(reply, Direction::Ingress, 2)
            {
                out.extend(msgs.into_iter().map(|m| m.payload_text));
            }
        }
        out
    }

    fn leaks_secret(out: &[Option<String>]) -> bool {
        leaks(out)
    }

    fn leaks(out: &[Option<String>]) -> bool {
        out.iter().flatten().any(|t| t.contains("s3cretpw"))
    }

    /// Results of credential commands queued in MULTI arrive under EXEC.
    #[test]
    fn test_exec_results_are_masked_per_queued_command() {
        let out = exchange(&[
            (&["MULTI"], b"+OK\r\n"),
            (&["CONFIG", "GET", "requirepass"], b"+QUEUED\r\n"),
            (&["ACL", "GENPASS"], b"+QUEUED\r\n"),
            (&["GET", "k"], b"+QUEUED\r\n"),
            (
                &["EXEC"],
                b"*3\r\n*2\r\n$11\r\nrequirepass\r\n$8\r\ns3cretpw\r\n$8\r\ns3cretpw\r\n$5\r\nvalue\r\n",
            ),
            (&["ACL", "GENPASS"], b"$8\r\ns3cretpw\r\n"),
        ]);
        assert!(!leaks(&out), "{out:?}");
        assert!(out[4].as_deref().unwrap().ends_with("value"), "{out:?}");
        // EXEC whose MULTI came before capture started: the queued
        // commands are unknown, so the whole result is masked.
        let out = exchange(&[(&["EXEC"], b"*1\r\n$8\r\ns3cretpw\r\n")]);
        assert_eq!(out, vec![Some("<REDACTED>".to_string())]);
        // A subscription command inside MULTI is only queued.
        let out = exchange(&[
            (&["MULTI"], b"+OK\r\n"),
            (&["SUBSCRIBE", "a", "b"], b"+QUEUED\r\n"),
            (&["ACL", "GENPASS"], b"+QUEUED\r\n"),
            (
                &["EXEC"],
                b"*2\r\n*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n$8\r\ns3cretpw\r\n",
            ),
            (&["ACL", "GENPASS"], b"$8\r\ns3cretpw\r\n"),
        ]);
        assert!(!leaks(&out), "{out:?}");
        // DISCARD drops the transaction: a later EXEC-less reply is plain.
        let out = exchange(&[
            (&["MULTI"], b"+OK\r\n"),
            (&["ACL", "GENPASS"], b"+QUEUED\r\n"),
            (&["DISCARD"], b"+OK\r\n"),
            (&["GET", "k"], b"$5\r\nvalue\r\n"),
        ]);
        assert_eq!(out[3].as_deref(), Some("value"));
    }

    /// Replies stay matched to their commands through RESP3 subscription
    /// pushes, RESP2 subscription acks and messages, and CLIENT REPLY.
    #[test]
    fn test_reply_correspondence_survives_subscriptions_and_client_reply() {
        let genpass: (&[&str], &[u8]) = (&["ACL", "GENPASS"], b"$8\r\ns3cretpw\r\n");
        // RESP3: the acks are pushes.
        let out = exchange(&[
            (&["HELLO", "3"], b"%1\r\n$6\r\nserver\r\n$5\r\nredis\r\n"),
            (
                &["SUBSCRIBE", "ch"],
                b">3\r\n$9\r\nsubscribe\r\n$2\r\nch\r\n:1\r\n",
            ),
            genpass,
        ]);
        assert!(!leaks(&out), "{out:?}");
        // RESP2: one array ack per channel, then messages, then unsubscribe.
        let out = exchange(&[
            (
                &["SUBSCRIBE", "a", "b"],
                b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n*3\r\n$9\r\nsubscribe\r\n$1\r\nb\r\n:2\r\n",
            ),
            (&[], b"*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n"),
            (
                &["UNSUBSCRIBE", "a", "b"],
                b"*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:1\r\n*3\r\n$11\r\nunsubscribe\r\n$1\r\nb\r\n:0\r\n",
            ),
            genpass,
        ]);
        assert!(!leaks(&out), "{out:?}");
        // CLIENT REPLY SKIP / OFF: those commands get no reply.
        for steps in [
            &[
                (&["CLIENT", "REPLY", "SKIP"][..], &b""[..]),
                (&["PING"], b""),
                genpass,
            ][..],
            &[
                (&["CLIENT", "REPLY", "OFF"], b""),
                (&["PING"], b""),
                (&["CLIENT", "REPLY", "ON"], b"+OK\r\n"),
                genpass,
            ],
        ] {
            let out = exchange(steps);
            assert!(!leaks(&out), "{out:?}");
        }
    }

    /// Codex round 3: protocol state taken from requests the server may
    /// have refused, and unbounded transaction history.
    #[test]
    fn test_state_comes_from_server_replies() {
        let genpass: (&[&str], &[u8]) = (&["ACL", "GENPASS"], b"$8\r\ns3cretpw\r\n");
        let mut leaks = Vec::new();
        for (what, steps) in [
            (
                "unsubscribe to zero, then a list holding \"message\"",
                vec![
                    (
                        &["SUBSCRIBE", "a"][..],
                        &b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n"[..],
                    ),
                    (
                        &["UNSUBSCRIBE", "a"],
                        b"*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n",
                    ),
                    (
                        &["LRANGE", "l", "0", "-1"],
                        b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$1\r\ny\r\n",
                    ),
                    genpass,
                ],
            ),
            (
                "HELLO 2 after HELLO 3",
                vec![
                    (&["HELLO", "3"][..], &b"%1\r\n$5\r\nproto\r\n:3\r\n"[..]),
                    (&["HELLO", "2"], b"*2\r\n$5\r\nproto\r\n:2\r\n"),
                    (
                        &["SUBSCRIBE", "a"],
                        b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
                    ),
                    (&[], b"*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n"),
                    (
                        &["UNSUBSCRIBE", "a"],
                        b"*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n",
                    ),
                    genpass,
                    (&["GET", "k"], b"$1\r\nv\r\n"),
                ],
            ),
        ] {
            let out = exchange(&steps);
            if leaks_secret(&out) {
                leaks.push(format!("{what}: {out:?}"));
            }
        }
        // Pipelined: every command is sent before the first reply arrives.
        for (what, cmds, replies) in [
            (
                "CLIENT REPLY OFF with an extra argument is refused",
                &[
                    &["CLIENT", "REPLY", "OFF", "extra"][..],
                    &["ACL", "GENPASS"],
                    &["CLIENT", "REPLY", "ON"],
                    &["GET", "k"],
                ][..],
                &b"-ERR syntax error\r\n$8\r\ns3cretpw\r\n+OK\r\n$1\r\nv\r\n"[..],
            ),
            (
                "CLIENT REPLY SKIP with an extra argument is refused",
                &[
                    &["CLIENT", "REPLY", "SKIP", "extra"][..],
                    &["ACL", "GENPASS"],
                    &["GET", "k"],
                    &["GET", "j"],
                ][..],
                &b"-ERR syntax error\r\n$8\r\ns3cretpw\r\n$1\r\nv\r\n$1\r\nw\r\n"[..],
            ),
            (
                // Codex round 4: a script's array shaped like an ack.
                "EVAL returning {'subscribe','x',1}",
                &[
                    &["EVAL", "return {'subscribe','x',1}", "0"][..],
                    &["ACL", "GENPASS"],
                    &["GET", "k"],
                ][..],
                &b"*3\r\n$9\r\nsubscribe\r\n$1\r\nx\r\n:1\r\n$8\r\ns3cretpw\r\n$1\r\nv\r\n"[..],
            ),
            (
                "a reply to SUBSCRIBE that is not its acknowledgement",
                &[&["SUBSCRIBE", "a"][..], &["ACL", "GENPASS"], &["GET", "k"]][..],
                &b"*3\r\n$7\r\nmessage\r\n$1\r\na\r\n:1\r\n$8\r\ns3cretpw\r\n$1\r\nv\r\n"[..],
            ),
        ] {
            let mut parser = RedisParser::new();
            for c in cmds {
                parser.feed(&resp(c), Direction::Egress, 1);
            }
            let out: Vec<Option<String>> = match parser.feed(replies, Direction::Ingress, 2) {
                ParseResult::Messages(m) => m.into_iter().map(|m| m.payload_text).collect(),
                _ => vec![],
            };
            if leaks_secret(&out) {
                leaks.push(format!("{what}: {out:?}"));
            }
        }
        assert!(leaks.is_empty(), "{leaks:#?}");
    }

    /// MULTI keeps a bounded history of queued commands.
    #[test]
    fn test_transaction_history_is_bounded() {
        let mut parser = RedisParser::new();
        parser.feed(&resp(&["MULTI"]), Direction::Egress, 1);
        parser.feed(b"+OK\r\n", Direction::Ingress, 2);
        for i in 0..5000 {
            parser.feed(&resp(&["SET", &format!("k{i}"), "v"]), Direction::Egress, 3);
            parser.feed(b"+QUEUED\r\n", Direction::Ingress, 4);
        }
        let kept = parser.transaction.as_ref().map_or(0, Vec::len);
        assert!(kept <= 1024, "{kept} queued commands kept");
    }

    /// A reply with no known command (capture joined mid-stream, MONITOR's
    /// stream) is withheld; credential shapes are masked whatever the
    /// command (a hash with a password field).
    #[test]
    fn test_unmatched_replies_fail_closed() {
        let out = exchange(&[(&[], b"$8\r\ns3cretpw\r\n")]);
        assert_eq!(out, vec![None]);
        let out = exchange(&[
            (&["MONITOR"], b"+OK\r\n"),
            (
                &[],
                b"+1339518083.107412 [0 127.0.0.1:60866] \"GET\" \"s3cretpw\"\r\n",
            ),
        ]);
        assert!(!leaks(&out), "{out:?}");
        assert_eq!(out[1], None);
        let out = exchange(&[(
            &["HGETALL", "user:1"],
            b"*4\r\n$4\r\nname\r\n$3\r\nbob\r\n$8\r\npassword\r\n$8\r\ns3cretpw\r\n",
        )]);
        assert!(!leaks(&out), "{out:?}");
        assert!(
            out[0].as_deref().unwrap().starts_with("name, bob"),
            "{out:?}"
        );
    }

    #[test]
    fn test_parse_errors_do_not_quote_input() {
        for bad in [
            &b":12-34-5678\r\n"[..],
            b"$12-34-5678\r\n",
            b"*12-34-5678\r\n",
            b"%12-34-5678\r\n",
        ] {
            let mut parser = RedisParser::new();
            match parser.feed(bad, Direction::Ingress, 1) {
                ParseResult::Error(e) => assert!(!e.contains("12-34"), "{e}"),
                other => panic!("expected an error, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_huge_array_count_does_not_abort() {
        // Found by fuzzing: a peer-declared count was passed straight to
        // Vec::with_capacity, aborting the whole agent process.
        let mut parser = RedisParser::new();
        let _ = parser.feed(b"*99999999999999\r\n$3\r\nGET\r\n", Direction::Egress, 1000);
        let _ = parser.feed(b"*9223372036854775807\r\n", Direction::Ingress, 2000);
    }

    #[test]
    fn test_deep_nesting_is_rejected_without_stack_overflow() {
        // 100k nested arrays would recurse 100k frames; workers run on small
        // stacks, so run on a 256KB thread to prove the depth limit holds.
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let nested = b"*1\r\n".repeat(100_000);
                assert!(matches!(parse_resp_value(&nested), RespParse::Error(_)));
            })
            .unwrap();
        handle
            .join()
            .expect("deep RESP nesting must not overflow the stack");
    }

    #[test]
    fn test_get_command() {
        let mut parser = RedisParser::new();

        let cmd = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b"$5\r\nhello\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("GET"));
                assert_eq!(msgs[0].path.as_deref(), Some("mykey"));
                assert_eq!(msgs[0].payload_text.as_deref(), Some("hello"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_multi_packet_bulk_string() {
        let mut parser = RedisParser::new();

        // Send GET command
        let cmd = b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        // Server response split across three packets ("helloworld" = 10 bytes).
        // $10\r\n declares a 10-byte bulk string: "hell"(4) + "oworl"(5) + "d"(1) = "helloworld".
        let resp1 = b"$10\r\nhell";
        let result = parser.feed(resp1, Direction::Ingress, 2000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let resp2 = b"oworl";
        let result = parser.feed(resp2, Direction::Ingress, 2000);
        assert!(matches!(result, ParseResult::NeedMoreData));

        let resp3 = b"d\r\n";
        let result = parser.feed(resp3, Direction::Ingress, 3000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].payload_text.as_deref(), Some("helloworld"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_error_response() {
        let mut parser = RedisParser::new();

        let cmd = b"*1\r\n$4\r\nINFO\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b"-ERR unknown command 'INFO'\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].status, Some(1));
                assert!(msgs[0].payload_text.as_ref().unwrap().contains("ERR"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_pipeline() {
        let mut parser = RedisParser::new();

        // Client sends two commands back-to-back (pipeline) at the same timestamp
        let cmd =
            b"*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\n1\r\n*3\r\n$3\r\nSET\r\n$1\r\nb\r\n$1\r\n2\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        // Server responds with two +OK — must produce exactly 2 messages, in order
        let resp = b"+OK\r\n+OK\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(
                    msgs.len(),
                    2,
                    "pipelined requests must each produce a message"
                );
                assert_eq!(msgs[0].method.as_deref(), Some("SET"));
                assert_eq!(msgs[0].path.as_deref(), Some("a"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
                assert_eq!(msgs[1].method.as_deref(), Some("SET"));
                assert_eq!(msgs[1].path.as_deref(), Some("b"));
                assert_eq!(msgs[1].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_null_bulk_string() {
        let mut parser = RedisParser::new();

        let cmd = b"*2\r\n$3\r\nGET\r\n$11\r\nnonexistent\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b"$-1\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].payload_text.as_deref(), Some("(nil)"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_integer_response() {
        let mut parser = RedisParser::new();

        let cmd = b"*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n";
        parser.feed(cmd, Direction::Egress, 1000);

        let resp = b":42\r\n";
        let result = parser.feed(resp, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("INCR"));
                assert_eq!(msgs[0].path.as_deref(), Some("counter"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_parser_protocol() {
        let parser = RedisParser::new();
        assert_eq!(ProtocolParser::protocol(&parser), Protocol::Redis);
        assert_eq!(parser.state_name(), "idle");
    }

    #[test]
    fn test_current_state() {
        let mut parser = RedisParser::new();
        assert_eq!(parser.current_state(), "idle");

        parser.state = State::Parsing;
        assert_eq!(parser.current_state(), "parsing");
    }

    #[test]
    fn test_reset_for_next_transaction() {
        let mut parser = RedisParser::new();

        parser.feed(&resp(&["MULTI"]), Direction::Egress, 1);
        parser.feed(&resp(&["CLIENT", "REPLY", "OFF"]), Direction::Egress, 1);
        assert!(parser.desync);
        parser.client_buf.extend(b"data").unwrap();
        parser.server_buf.extend(b"response").unwrap();
        parser.state = State::Parsing;

        parser.reset_for_next_transaction();

        assert!(parser.client_buf.is_empty());
        assert!(parser.server_buf.is_empty());
        assert!(parser.pending_queue.is_empty());
        assert!(parser.transaction.is_none() && !parser.desync);
        assert_eq!(parser.state, State::Idle);
    }
}
