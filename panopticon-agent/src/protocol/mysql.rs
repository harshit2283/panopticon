#![allow(dead_code)]

//! MySQL wire protocol parser.
//!
//! Wire format: 3-byte length (LE) + 1-byte seq_id + payload.
//! Detects server version at handshake (MySQL 5.7 vs 8.0+ via auth plugin).
//!
//! Covers the text protocol (COM_QUERY, including MySQL 8 query attributes)
//! and prepared statements (COM_STMT_PREPARE / EXECUTE, the binary protocol
//! Go, JDBC and most ORMs use): statements are remembered by id so each
//! EXECUTE is reported with its SQL and its bound parameter values.
//!
//! **Pairing.** MySQL answers commands in order, so a reply is paired
//! with the command in flight. Commands are read only from an allowlist
//! whose replies the parser models: one exchange per COM_QUERY /
//! COM_STMT_EXECUTE (every result set of a multi-statement or `CALL`,
//! up to the last without `SERVER_MORE_RESULTS_EXISTS`, and a
//! `LOAD DATA LOCAL INFILE` file transfer), COM_STMT_PREPARE, the
//! single-packet replies of COM_PING, COM_INIT_DB and similar, and the
//! no-reply COM_QUIT, COM_STMT_CLOSE and COM_STMT_SEND_LONG_DATA. Any
//! other command (COM_CHANGE_USER, COM_FIELD_LIST, COM_STMT_FETCH, a
//! cursor EXECUTE, the replication commands, unknown ones), a reply packet
//! out of sequence, server bytes with no command in flight, a reply the
//! parser cannot read, or a connection joined mid-stream
//! ([`ProtocolParser::joined_late`]) makes the connection `untrusted` for
//! the rest of its life: exchanges are still exported, with the
//! statement's keyword only (no statement text, bound value, status or
//! latency). TLS (SSLRequest) and the compressed protocol stop parsing.
//!
//! **Errors.** A server error is exported as its code (`status`) and its
//! SQLSTATE (header `sqlstate`), never its message: messages echo
//! statement text and values (`Incorrect integer value: 'hunter2' for
//! column 'pin'`). No OK `info` text, warning or row is exported either.

use std::collections::{HashMap, VecDeque};

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

// Command bytes (include/my_command.h).
const COM_QUIT: u8 = 0x01;
const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_CREATE_DB: u8 = 0x05;
const COM_DROP_DB: u8 = 0x06;
const COM_REFRESH: u8 = 0x07;
const COM_SHUTDOWN: u8 = 0x08;
const COM_STATISTICS: u8 = 0x09;
const COM_PROCESS_KILL: u8 = 0x0c;
const COM_DEBUG: u8 = 0x0d;
const COM_PING: u8 = 0x0e;
const COM_CHANGE_USER: u8 = 0x11;
const COM_BINLOG_DUMP: u8 = 0x12;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const COM_STMT_CLOSE: u8 = 0x19;
const COM_STMT_RESET: u8 = 0x1a;
const COM_SET_OPTION: u8 = 0x1b;
const COM_STMT_FETCH: u8 = 0x1c;
const COM_RESET_CONNECTION: u8 = 0x1f;

/// Capability flags (HandshakeResponse41).
const CLIENT_COMPRESS: u32 = 0x0000_0020;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
const CLIENT_ZSTD_COMPRESSION: u32 = 0x0400_0000;
const CLIENT_QUERY_ATTRIBUTES: u32 = 0x0800_0000;
/// Server status flag: another result set follows this one.
const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;
/// COM_STMT_EXECUTE flag: a parameter count follows the iteration count.
const PARAMETER_COUNT_AVAILABLE: u8 = 0x08;
/// COM_STMT_EXECUTE cursor type bits (read-only, for-update, scrollable):
/// the rows then come through COM_STMT_FETCH.
const CURSOR_TYPE_MASK: u8 = 0x07;

/// Prepared statements remembered per connection.
const MAX_PREPARED: usize = 256;
/// Bound-parameter text kept per EXECUTE.
const MAX_PARAM_TEXT: usize = 4096;
const ERR_MARKER: u8 = 0xFF;
const OK_MARKER: u8 = 0x00;
const EOF_MARKER: u8 = 0xFE;
/// LOCAL INFILE request: the client sends a file's contents next.
const LOCAL_INFILE_MARKER: u8 = 0xFB;
/// AuthMoreData packet header during authentication.
const AUTH_MORE_DATA: u8 = 0x01;
/// A packet this long is continued by the next one.
const MAX_PACKET_PAYLOAD: usize = 0xFF_FFFF;

#[derive(Debug, Clone, PartialEq)]
enum State {
    WaitingForHandshake,
    InAuth,
    Ready,
    InQuery,
    InResponse {
        cols_expected: usize,
        cols_received: usize,
        past_col_eof: bool,
    },
    /// Skipping the parameter / column definitions after COM_STMT_PREPARE_OK.
    SkipDefs,
    /// LOCAL INFILE: the client is sending the file, until an empty packet.
    Infile,
    /// TLS or compression: nothing more is read.
    Opaque,
}

/// What the command in flight expects back.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Pending {
    /// COM_QUERY / COM_STMT_EXECUTE: OK, ERR or a result set; reported.
    Query,
    /// COM_STMT_PREPARE: PREPARE_OK (+ definitions) or ERR; reported on ERR.
    Prepare,
    /// PING, INIT_DB, STMT_RESET...: a single OK/ERR/EOF; not reported.
    Simple,
}

/// One step of skipping definitions after PREPARE_OK.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DefSkip {
    Packets(usize),
    /// EOF terminator whose presence depends on CLIENT_DEPRECATE_EOF, when
    /// the handshake was not seen.
    OptionalEof,
}

/// A statement prepared on this connection.
#[derive(Debug, Clone)]
struct Stmt {
    sql: String,
    num_params: usize,
    /// Parameter types from the last EXECUTE that bound them; later
    /// executes may omit them.
    types: Vec<u8>,
}

/// One wire packet.
struct Packet {
    seq: u8,
    payload: Vec<u8>,
    /// Bytes on the wire, header included.
    total: usize,
}

/// What reading one reply packet did.
enum Reply {
    /// The exchange is complete: its message.
    Done(Box<L7Message>),
    /// A packet was consumed; the exchange goes on (or the state moved).
    Progress,
    /// Needs more bytes.
    Need,
}

pub struct MysqlParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    server_version: Option<String>,
    auth_plugin: Option<String>,
    query_ts: Option<u64>,
    query_text: Option<String>,
    /// Server bytes were lost mid-response (capture gap). Packets cannot be
    /// re-framed, so the response is closed when the client sends its next
    /// command (MySQL is strictly request/response).
    resync_server: bool,
    /// Client capability flags from the handshake response, if seen.
    client_caps: Option<u32>,
    pending: Pending,
    prepared: HashMap<u32, Stmt>,
    /// SQL of the statement being prepared, until PREPARE_OK names its id.
    preparing: Option<String>,
    skip_defs: VecDeque<DefSkip>,
    /// Bound parameter values of the EXECUTE in flight.
    param_text: Option<String>,
    /// Sequence id the next packet of the exchange in flight must carry.
    next_seq: u8,
    /// The last server packet was a full-size one: the next continues it.
    server_cont: bool,
    /// A server error answered the exchange in flight (multi-results stop
    /// at it): its code and SQLSTATE.
    error: Option<(u32, Option<String>)>,
    /// The client sent a command before the previous reply ended: after a
    /// server gap the next command no longer marks a reply boundary.
    pipelined: bool,
    /// Replies can no longer be tied to their command, or framing to the
    /// stream; see the module docs. For good.
    untrusted: bool,
    /// The last call was [`ProtocolParser::skip`], which accounted for the
    /// gap itself. The connection manager follows every skip with
    /// [`ProtocolParser::joined_late`], which this flag lets through once.
    skip_accounted: bool,
}

impl MysqlParser {
    pub fn new() -> Self {
        Self {
            state: State::WaitingForHandshake,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            server_version: None,
            resync_server: false,
            auth_plugin: None,
            query_ts: None,
            query_text: None,
            client_caps: None,
            pending: Pending::Query,
            prepared: HashMap::new(),
            preparing: None,
            skip_defs: VecDeque::new(),
            param_text: None,
            next_seq: 0,
            server_cont: false,
            error: None,
            pipelined: false,
            untrusted: false,
            skip_accounted: false,
        }
    }

    /// `Some(true/false)` once the handshake response was seen.
    fn deprecate_eof(&self) -> Option<bool> {
        self.client_caps.map(|c| c & CLIENT_DEPRECATE_EOF != 0)
    }

    fn try_read_packet(buf: &StreamBuffer) -> Option<Packet> {
        let data = buf.data();
        if data.len() < 4 {
            return None;
        }
        let payload_len = data[0] as usize | (data[1] as usize) << 8 | (data[2] as usize) << 16;
        let total = 4 + payload_len;
        if data.len() < total {
            return None;
        }
        Some(Packet {
            seq: data[3],
            payload: data[4..total].to_vec(),
            total,
        })
    }

    /// Read the next server packet of the exchange in flight, checking its
    /// sequence id; a continuation of a full-size packet is consumed and
    /// skipped (it is never a reply boundary).
    fn next_server_packet(&mut self) -> Option<Packet> {
        loop {
            let p = Self::try_read_packet(&self.server_buf)?;
            self.server_buf.consume(p.total);
            if p.seq != self.next_seq {
                self.untrusted = true;
            }
            self.next_seq = p.seq.wrapping_add(1);
            let cont =
                std::mem::replace(&mut self.server_cont, p.payload.len() == MAX_PACKET_PAYLOAD);
            if !cont {
                return Some(p);
            }
        }
    }

    fn process(&mut self, ts: u64) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            match self.state.clone() {
                State::Opaque => {
                    self.client_buf.clear();
                    self.server_buf.clear();
                    break;
                }
                State::WaitingForHandshake => {
                    if !self.parse_handshake() {
                        break;
                    }
                }
                State::InAuth => {
                    if !self.complete_auth() {
                        break;
                    }
                }
                State::Ready => {
                    if !self.parse_command(ts) {
                        // Server bytes with no command in flight answer
                        // nothing the parser knows of.
                        if !self.server_buf.is_empty() && self.state == State::Ready {
                            self.untrusted = true;
                            self.server_buf.clear();
                        }
                        break;
                    }
                }
                State::InQuery | State::InResponse { .. } | State::SkipDefs
                    if self.resync_server =>
                {
                    self.server_buf.clear();
                    let data = self.client_buf.data();
                    // Next command packet: [len:3][seq=0][command byte].
                    if data.len() < 5 || data[3] != 0 {
                        break;
                    }
                    self.skip_defs.clear();
                    self.preparing = None;
                    if self.pending == Pending::Query {
                        let mut msg = self.build_msg(ts);
                        // Closed by the next command, not by the response
                        // end: the outcome and latency are unknown.
                        msg.status = None;
                        msg.latency_ns = None;
                        msg.headers.clear();
                        if self.untrusted {
                            scrub(&mut msg);
                        }
                        messages.push(msg);
                    } else {
                        self.query_text = None;
                        self.query_ts = None;
                    }
                    self.error = None;
                    self.server_cont = false;
                    self.resync_server = false;
                    self.state = State::Ready;
                }
                State::SkipDefs => {
                    if !self.skip_definitions() {
                        break;
                    }
                }
                State::Infile => {
                    if !self.read_infile() {
                        break;
                    }
                }
                State::InQuery => match self.parse_response(ts) {
                    Reply::Done(msg) => {
                        messages.push(*msg);
                        self.state = State::Ready;
                    }
                    Reply::Progress => {}
                    Reply::Need => break,
                },
                State::InResponse {
                    cols_expected,
                    cols_received,
                    past_col_eof,
                } => match self.read_result_set(ts, cols_expected, cols_received, past_col_eof) {
                    Reply::Done(msg) => {
                        messages.push(*msg);
                        self.state = State::Ready;
                    }
                    Reply::Progress => {}
                    Reply::Need => break,
                },
            }
        }
        // A command waiting while a reply is still being read: the client
        // pipelines.
        if matches!(
            self.state,
            State::InQuery | State::InResponse { .. } | State::SkipDefs
        ) && !self.resync_server
            && Self::try_read_packet(&self.client_buf).is_some()
        {
            self.pipelined = true;
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn parse_handshake(&mut self) -> bool {
        let Some(p) = Self::try_read_packet(&self.server_buf) else {
            // The first packet seen is a client one. An auth packet
            // (sequence id >= 1) is how a TLS key starts: the greeting went
            // in cleartext, on another key. Whether this stream was seen
            // from its start is the connection manager's call
            // (`joined_late`). A command (sequence id 0) with no auth seen
            // means the agent attached after it: replies are unproven.
            if let Some(c) = Self::try_read_packet(&self.client_buf) {
                self.state = if c.seq == 0 {
                    self.untrusted = true;
                    State::Ready
                } else {
                    State::InAuth
                };
                return true;
            }
            return false;
        };
        self.server_buf.consume(p.total);
        let payload = p.payload;
        if p.seq != 0 || payload.is_empty() || payload[0] != 0x0a {
            // Not a greeting: joined after it.
            self.untrusted = true;
            self.state = State::Ready;
            return true;
        }
        if !self.untrusted {
            if let Some(null_pos) = payload[1..].iter().position(|&b| b == 0) {
                self.server_version =
                    Some(String::from_utf8_lossy(&payload[1..1 + null_pos]).into_owned());
            }
            let payload_str = String::from_utf8_lossy(&payload);
            if payload_str.contains("caching_sha2_password") {
                self.auth_plugin = Some("caching_sha2_password".into());
            } else if payload_str.contains("mysql_native_password") {
                self.auth_plugin = Some("mysql_native_password".into());
            }
        }
        self.state = State::InAuth;
        true
    }

    fn complete_auth(&mut self) -> bool {
        if let Some(c) = Self::try_read_packet(&self.client_buf) {
            // A command (sequence id 0) while auth looked unfinished: the
            // auth reply was missed, so the parser is out of step with the
            // server. Drain one pending auth OK/ERR and go on untrusted.
            if c.seq == 0 {
                if let Some(s) = Self::try_read_packet(&self.server_buf)
                    && matches!(s.payload.first(), Some(&OK_MARKER | &ERR_MARKER))
                {
                    self.server_buf.consume(s.total);
                }
                self.untrusted = true;
                self.state = State::Ready;
                return true;
            }
            // HandshakeResponse41 (or SSLRequest): capability flags first.
            if self.client_caps.is_none() && c.payload.len() >= 32 {
                let caps =
                    u32::from_le_bytes([c.payload[0], c.payload[1], c.payload[2], c.payload[3]]);
                if caps & CLIENT_PROTOCOL_41 != 0 {
                    self.client_caps = Some(caps);
                    // SSLRequest: the response cut after its 32 fixed bytes.
                    // TLS records follow; the plaintext, if captured, is
                    // another key, whose full response (CLIENT_SSL set too)
                    // is parsed as usual.
                    if caps & CLIENT_SSL != 0 && c.payload.len() == 32 {
                        self.state = State::Opaque;
                        return true;
                    }
                }
            }
            self.client_buf.consume(c.total);
        }
        let Some(s) = Self::try_read_packet(&self.server_buf) else {
            return false;
        };
        self.server_buf.consume(s.total);
        let payload = s.payload;
        if !payload.is_empty() && (payload[0] == OK_MARKER || payload[0] == ERR_MARKER) {
            self.state = State::Ready;
            if payload[0] == OK_MARKER
                && self
                    .client_caps
                    .is_some_and(|c| c & (CLIENT_COMPRESS | CLIENT_ZSTD_COMPRESSION) != 0)
            {
                // Compressed packets from here on: not parsed.
                self.state = State::Opaque;
            }
            return true;
        }
        // Auth continues: AuthMoreData (caching_sha2_password, MySQL 8's
        // default: 0x01 0x03 = fast-auth ok, then an OK follows) or
        // AuthSwitchRequest. Treating these as "auth done" left the real OK
        // queued, so every later response paired with the previous query.
        if !payload.is_empty() && (payload[0] == AUTH_MORE_DATA || payload[0] == EOF_MARKER) {
            return true;
        }
        // An auth reply of no known shape: go on, untrusted.
        self.untrusted = true;
        self.state = State::Ready;
        true
    }

    fn parse_command(&mut self, ts: u64) -> bool {
        let Some(p) = Self::try_read_packet(&self.client_buf) else {
            return false;
        };
        self.client_buf.consume(p.total);
        let payload = p.payload;
        if payload.is_empty() {
            return true;
        }
        // A command starts an exchange at sequence id 0; a full-size
        // packet would continue into the next one (a statement of 16 MiB
        // or more), which is not followed.
        if p.seq != 0 || payload.len() == MAX_PACKET_PAYLOAD {
            self.untrusted = true;
        }
        self.next_seq = p.seq.wrapping_add(1);
        self.server_cont = false;
        self.error = None;
        match payload[0] {
            COM_QUERY => {
                let sql = self.strip_query_attributes(&payload[1..]);
                self.query_text = Some(String::from_utf8_lossy(sql).into_owned());
                self.begin(Pending::Query, ts);
            }
            COM_STMT_PREPARE => {
                let sql = String::from_utf8_lossy(&payload[1..]).into_owned();
                self.query_text = Some(sql.clone());
                self.preparing = Some(sql);
                self.begin(Pending::Prepare, ts);
            }
            COM_STMT_EXECUTE => {
                // A cursor's rows come through COM_STMT_FETCH, which is not
                // followed.
                if payload.get(5).is_some_and(|f| f & CURSOR_TYPE_MASK != 0) {
                    self.untrusted = true;
                }
                self.start_execute(&payload);
                self.begin(Pending::Query, ts);
            }
            // No reply.
            COM_STMT_CLOSE => {
                if let Some(id) = payload.get(1..5) {
                    self.prepared
                        .remove(&u32::from_le_bytes([id[0], id[1], id[2], id[3]]));
                }
            }
            COM_STMT_SEND_LONG_DATA | COM_QUIT => {}
            // One reply packet (OK, ERR, EOF, or COM_STATISTICS' string).
            COM_INIT_DB | COM_PING | COM_STMT_RESET | COM_SET_OPTION | COM_RESET_CONNECTION
            | COM_CREATE_DB | COM_DROP_DB | COM_REFRESH | COM_SHUTDOWN | COM_STATISTICS
            | COM_PROCESS_KILL | COM_DEBUG => {
                if payload[0] == COM_RESET_CONNECTION {
                    self.prepared.clear();
                }
                self.begin(Pending::Simple, ts);
            }
            // Replies the parser does not model: an auth exchange
            // (COM_CHANGE_USER), definitions, fetched rows, a replication
            // stream (COM_BINLOG_DUMP and the rest), or anything unknown.
            // Their replies would be read as the next command's.
            _ => {
                if matches!(
                    payload[0],
                    COM_CHANGE_USER | COM_BINLOG_DUMP | COM_STMT_FETCH
                ) {
                    self.prepared.clear();
                }
                self.untrusted = true;
            }
        }
        true
    }

    fn begin(&mut self, pending: Pending, ts: u64) {
        self.pending = pending;
        self.query_ts = Some(ts);
        self.state = State::InQuery;
    }

    /// SQL text of a COM_QUERY body, past the query attributes that MySQL
    /// 8.0.23+ clients prepend when CLIENT_QUERY_ATTRIBUTES is negotiated.
    fn strip_query_attributes<'a>(&self, body: &'a [u8]) -> &'a [u8] {
        let negotiated = match self.client_caps {
            Some(caps) => caps & CLIENT_QUERY_ATTRIBUTES != 0,
            // Handshake not seen: SQL never starts with NUL, while a block
            // without attributes is "0 parameters, 1 parameter set".
            None => body.starts_with(&[0x00, 0x01]),
        };
        if !negotiated {
            return body;
        }
        let mut r = Reader::new(body);
        let Some(count) = r.lenenc() else { return body };
        let Some(_sets) = r.lenenc() else { return body };
        if count > 0 {
            let count = count as usize;
            let Some(nulls) = r.take(count.div_ceil(8)) else {
                return body;
            };
            let nulls = nulls.to_vec();
            if r.u8() != Some(1) {
                return body; // attributes always carry their types
            }
            let mut types = Vec::with_capacity(count);
            for _ in 0..count {
                let Some(t) = r.take(2) else { return body };
                types.push(t[0]);
                if r.lenenc_bytes().is_none() {
                    return body; // attribute name
                }
            }
            for (i, &t) in types.iter().enumerate() {
                if nulls[i / 8] & (1 << (i % 8)) == 0 && r.binary_value(t).is_none() {
                    return body;
                }
            }
        }
        r.rest()
    }

    /// Record the SQL and bound parameters of a COM_STMT_EXECUTE:
    /// [0x17][stmt_id:4][flags:1][iterations:4], then if there are
    /// parameters: [count:lenenc, with CLIENT_QUERY_ATTRIBUTES][null bitmap]
    /// [new_params_bound:1][type:2 (+ name:lenenc with query attributes)]*n
    /// [values].
    fn start_execute(&mut self, payload: &[u8]) {
        let mut r = Reader::new(&payload[1..]);
        let (Some(id), Some(flags), Some(_)) = (r.u32(), r.u8(), r.u32()) else {
            return;
        };
        let Some(stmt) = self.prepared.get_mut(&id) else {
            // Prepared before the agent attached: SQL unknown.
            self.query_text = Some("EXECUTE".into());
            return;
        };
        self.query_text = Some(stmt.sql.clone());
        let rest = r.rest();
        // Which layout applies depends on CLIENT_QUERY_ATTRIBUTES; without
        // the handshake, keep the one that accounts for every byte.
        let layouts: &[bool] = match self.client_caps {
            Some(caps) => {
                if caps & CLIENT_QUERY_ATTRIBUTES != 0 {
                    &[true]
                } else {
                    &[false]
                }
            }
            None => &[true, false],
        };
        let Some((types, values)) = layouts
            .iter()
            .find_map(|&attrs| decode_exec_params(rest, flags, stmt, attrs))
        else {
            return;
        };
        if let Some(types) = types {
            stmt.types = types;
        }
        if !values.is_empty() {
            self.param_text = Some(values.join(", "));
        }
    }

    /// Consume definition packets queued by PREPARE_OK. False = need data.
    fn skip_definitions(&mut self) -> bool {
        while let Some(step) = self.skip_defs.front().copied() {
            let Some(p) = Self::try_read_packet(&self.server_buf) else {
                return false;
            };
            match step {
                DefSkip::Packets(n) => {
                    let _ = self.next_server_packet();
                    if n > 1 {
                        self.skip_defs[0] = DefSkip::Packets(n - 1);
                    } else {
                        self.skip_defs.pop_front();
                    }
                }
                DefSkip::OptionalEof => {
                    if is_eof(&p.payload) {
                        let _ = self.next_server_packet();
                    }
                    self.skip_defs.pop_front();
                }
            }
        }
        self.state = State::Ready;
        true
    }

    /// LOCAL INFILE: the client's file packets (never exported) up to the
    /// empty one; then the server's OK or ERR answers the statement.
    fn read_infile(&mut self) -> bool {
        let Some(p) = Self::try_read_packet(&self.client_buf) else {
            return false;
        };
        let mut payload = p.payload;
        zeroize::Zeroize::zeroize(&mut payload);
        self.client_buf.consume(p.total);
        if p.seq != self.next_seq {
            self.untrusted = true;
        }
        self.next_seq = p.seq.wrapping_add(1);
        if p.total == 4 {
            self.state = State::InQuery;
        }
        true
    }

    /// The exchange in flight ends here (no more result sets): its message.
    fn finish(&mut self, ts: u64) -> Reply {
        let mut m = self.build_msg(ts);
        match self.error.take() {
            Some((code, state)) => {
                m.status = Some(code);
                if let Some(s) = state {
                    m.headers.push(("sqlstate".into(), s));
                }
            }
            None => m.status = Some(0),
        }
        if self.untrusted {
            scrub(&mut m);
        }
        Reply::Done(Box::new(m))
    }

    /// An OK or EOF ended a result (`payload`): finish, or wait for the
    /// next result set when the server says more follow.
    fn end_of_result(&mut self, ts: u64, payload: &[u8]) -> Reply {
        match status_flags(payload) {
            Some(f) if f & SERVER_MORE_RESULTS_EXISTS != 0 => {
                self.state = State::InQuery;
                Reply::Progress
            }
            Some(_) => self.finish(ts),
            None => {
                self.untrusted = true;
                self.finish(ts)
            }
        }
    }

    fn parse_response(&mut self, ts: u64) -> Reply {
        let Some(p) = self.next_server_packet() else {
            return Reply::Need;
        };
        let payload = p.payload;
        if payload.is_empty() {
            self.untrusted = true;
            return Reply::Progress;
        }
        match self.pending {
            Pending::Simple => {
                self.query_text = None;
                self.query_ts = None;
                self.state = State::Ready;
                return Reply::Progress;
            }
            Pending::Prepare if payload[0] == OK_MARKER && payload.len() >= 12 => {
                // COM_STMT_PREPARE_OK: [0x00][id:4][columns:2][params:2]...
                let id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                let cols = u16::from_le_bytes([payload[5], payload[6]]) as usize;
                let params = u16::from_le_bytes([payload[7], payload[8]]) as usize;
                if let Some(sql) = self.preparing.take() {
                    if self.prepared.len() >= MAX_PREPARED && !self.prepared.contains_key(&id) {
                        self.prepared.clear();
                    }
                    self.prepared.insert(
                        id,
                        Stmt {
                            sql,
                            num_params: params,
                            types: Vec::new(),
                        },
                    );
                }
                let eof = match self.deprecate_eof() {
                    Some(true) => None,
                    Some(false) => Some(DefSkip::Packets(1)),
                    None => Some(DefSkip::OptionalEof),
                };
                self.skip_defs.clear();
                for n in [params, cols] {
                    if n > 0 {
                        self.skip_defs.push_back(DefSkip::Packets(n));
                        self.skip_defs.extend(eof);
                    }
                }
                // Not reported: the EXECUTEs that follow are.
                self.query_text = None;
                self.query_ts = None;
                self.state = State::SkipDefs;
                return Reply::Progress;
            }
            _ => {}
        }
        match payload[0] {
            OK_MARKER => self.end_of_result(ts, &payload),
            ERR_MARKER => {
                self.error = Some(err_code_and_state(&payload));
                self.finish(ts)
            }
            LOCAL_INFILE_MARKER if self.pending == Pending::Query => {
                // The packet names the file: not kept.
                self.state = State::Infile;
                Reply::Progress
            }
            _ => match decode_lenenc(&payload) {
                Some(cols) if cols > 0 => {
                    self.state = State::InResponse {
                        cols_expected: cols as usize,
                        cols_received: 0,
                        past_col_eof: false,
                    };
                    Reply::Progress
                }
                _ => {
                    // Not a reply the parser can read.
                    self.untrusted = true;
                    self.finish(ts)
                }
            },
        }
    }

    fn read_result_set(&mut self, ts: u64, ce: usize, mut cr: usize, mut past: bool) -> Reply {
        loop {
            let Some(p) = self.next_server_packet() else {
                self.state = State::InResponse {
                    cols_expected: ce,
                    cols_received: cr,
                    past_col_eof: past,
                };
                return Reply::Need;
            };
            let payload = p.payload;
            if payload.is_empty() {
                continue;
            }
            if !past {
                if cr < ce {
                    cr += 1;
                    continue;
                }
                past = true;
                // EOF after the column definitions, unless CLIENT_DEPRECATE_EOF
                // (then rows follow directly and a 0xFE packet here already
                // ends an empty result). Without the handshake, tell them
                // apart by size: EOF is 5 bytes, OK-as-EOF at least 7.
                let column_eof = match self.deprecate_eof() {
                    Some(deprecated) => !deprecated && is_eof(&payload),
                    None => payload[0] == EOF_MARKER && payload.len() == 5,
                };
                if column_eof {
                    continue;
                }
            }

            // End of rows: EOF, or with CLIENT_DEPRECATE_EOF an OK packet
            // with a 0xFE header. Never 0x00: that starts every binary row
            // and any text row whose first value is an empty string.
            if payload[0] == ERR_MARKER {
                self.error = Some(err_code_and_state(&payload));
                return self.finish(ts);
            }
            if is_eof(&payload) {
                return self.end_of_result(ts, &payload);
            }
        }
    }

    fn build_msg(&mut self, ts: u64) -> L7Message {
        let mut msg = L7Message::new(Protocol::Mysql, Direction::Ingress, ts);
        msg.method = Some("QUERY".into());
        let bound = self.param_text.take();
        match self.query_text.take() {
            Some(q) => {
                let (verb, shown, bound) = super::export_statement(q, bound);
                msg.method = verb.or(msg.method);
                msg.payload_text = Some(shown);
                msg.request_text = bound;
            }
            None => msg.request_text = bound,
        }
        if let Some(t) = self.query_ts.take() {
            msg.latency_ns = Some(ts.saturating_sub(t));
        }
        msg
    }

    pub fn current_state(&self) -> &'static str {
        match self.state {
            State::WaitingForHandshake => "waiting_for_handshake",
            State::InAuth => "in_auth",
            State::Ready => "ready",
            State::InQuery => "in_query",
            State::InResponse { .. } => "in_response",
            State::SkipDefs => "skip_definitions",
            State::Infile => "local_infile",
            State::Opaque => "opaque",
        }
    }
}

/// An untrusted connection's message: the statement keyword only.
fn scrub(m: &mut L7Message) {
    for f in [&mut m.payload_text, &mut m.request_text] {
        if let Some(mut s) = f.take() {
            zeroize::Zeroize::zeroize(&mut s);
        }
    }
    m.headers.clear();
    m.status = None;
    m.latency_ns = None;
}

/// ERR_Packet: [0xFF][code:2][#][sqlstate:5][message]. The code and the
/// SQLSTATE (when present and well formed) only; the message is never
/// read.
fn err_code_and_state(payload: &[u8]) -> (u32, Option<String>) {
    let code = payload
        .get(1..3)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as u32);
    let state = payload
        .get(3..9)
        .filter(|s| s[0] == b'#' && s[1..].iter().all(u8::is_ascii_alphanumeric))
        .map(|s| String::from_utf8_lossy(&s[1..]).into_owned());
    (code, state)
}

/// Server status flags of an OK packet ([hdr][affected:lenenc]
/// [last_insert_id:lenenc][status:2]...) or a 5-byte EOF packet
/// ([0xFE][warnings:2][status:2]).
fn status_flags(payload: &[u8]) -> Option<u16> {
    let at = if payload.first() == Some(&EOF_MARKER) && payload.len() == 5 {
        3
    } else {
        let mut r = Reader::new(payload.get(1..)?);
        r.lenenc()?;
        r.lenenc()?;
        1 + r.pos
    };
    let b = payload.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Bound parameters of an EXECUTE (bytes after the iteration count), in
/// one of the two layouts. Returns the types if the packet (re)bound them,
/// and the text values of the statement's own parameters (query attributes
/// beyond them are skipped). None unless the layout fits the packet exactly.
fn decode_exec_params(
    data: &[u8],
    flags: u8,
    stmt: &Stmt,
    attrs: bool,
) -> Option<(Option<Vec<u8>>, Vec<String>)> {
    let mut r = Reader::new(data);
    let mut n = stmt.num_params;
    if attrs && (n > 0 || flags & PARAMETER_COUNT_AVAILABLE != 0) {
        n = usize::try_from(r.lenenc()?).ok()?;
    }
    if n == 0 {
        return r.rest().is_empty().then(|| (None, Vec::new()));
    }
    if n > 4096 {
        return None;
    }
    let nulls = r.take(n.div_ceil(8))?;
    let (bound_types, types) = if r.u8()? == 1 {
        let mut types = Vec::with_capacity(n);
        for _ in 0..n {
            types.push(r.take(2)?[0]);
            if attrs {
                r.lenenc_bytes()?; // parameter name
            }
        }
        (Some(types.clone()), types)
    } else if stmt.types.len() == n {
        (None, stmt.types.clone())
    } else {
        return None; // types bound before the agent attached
    };
    let mut values = Vec::new();
    let mut total = 0;
    for (i, &t) in types.iter().enumerate() {
        if nulls[i / 8] & (1 << (i % 8)) != 0 {
            continue;
        }
        let value = r.binary_value(t)?;
        if let Some(text) = value
            && i < stmt.num_params
            && total < MAX_PARAM_TEXT
        {
            total += text.len();
            values.push(text);
        }
    }
    r.rest().is_empty().then_some((bound_types, values))
}

/// EOF packet, or OK-as-EOF (CLIENT_DEPRECATE_EOF): 0xFE header. A row
/// can only start with 0xFE for a value of 2^24+ bytes, which needs a
/// maximum-size (0xFFFFFF) packet.
fn is_eof(payload: &[u8]) -> bool {
    payload.first() == Some(&EOF_MARKER) && payload.len() < 0xFF_FFFF
}

/// Cursor over a packet payload; every read is bounds-checked.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn lenenc(&mut self) -> Option<u64> {
        let rest = self.data.get(self.pos..)?;
        let v = decode_lenenc(rest)?;
        self.pos += match rest[0] {
            0xFC => 3,
            0xFD => 4,
            0xFE => 9,
            _ => 1,
        };
        Some(v)
    }

    fn lenenc_bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.lenenc()?).ok()?;
        self.take(n)
    }

    fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    /// One binary-protocol value of column type `t`: Some(Some(text)) for
    /// strings, Some(None) for values skipped (numbers, temporal), None if
    /// the type is unknown or the value is cut short.
    fn binary_value(&mut self, t: u8) -> Option<Option<String>> {
        let fixed = match t {
            0x01 => 1,               // TINY
            0x02 | 0x0d => 2,        // SHORT, YEAR
            0x03 | 0x09 | 0x04 => 4, // LONG, INT24, FLOAT
            0x08 | 0x05 => 8,        // LONGLONG, DOUBLE
            0x06 => 0,               // NULL
            // DATE, DATETIME, TIMESTAMP, TIME: 1-byte length prefix
            0x0a | 0x0c | 0x07 | 0x0b => {
                let n = self.u8()? as usize;
                self.take(n)?;
                return Some(None);
            }
            // DECIMAL, VARCHAR, BIT, JSON, NEWDECIMAL, ENUM, SET, BLOBs,
            // VAR_STRING, STRING, GEOMETRY: length-encoded string
            0x00 | 0x0f | 0x10 | 0xf5..=0xff => {
                let v = self.lenenc_bytes()?;
                return Some(Some(String::from_utf8_lossy(v).into_owned()));
            }
            _ => return None,
        };
        self.take(fixed)?;
        Some(None)
    }
}

fn decode_lenenc(data: &[u8]) -> Option<u64> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0..=0xFB => Some(data[0] as u64),
        0xFC if data.len() >= 3 => Some(u16::from_le_bytes([data[1], data[2]]) as u64),
        0xFD if data.len() >= 4 => {
            Some(data[1] as u64 | (data[2] as u64) << 8 | (data[3] as u64) << 16)
        }
        0xFE if data.len() >= 9 => Some(u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ])),
        _ => None, // insufficient bytes for this length-encoded integer
    }
}

impl ProtocolParser for MysqlParser {
    fn feed(&mut self, data: &[u8], direction: Direction, ts: u64) -> ParseResult {
        self.skip_accounted = false;
        if self.state == State::Opaque {
            return ParseResult::NeedMoreData;
        }
        match direction {
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("MySQL server buffer overflow".into());
                }
            }
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("MySQL client buffer overflow".into());
                }
            }
        }
        self.process(ts)
    }

    fn skip(&mut self, direction: Direction, _n: usize, _timestamp_ns: u64) -> Option<ParseResult> {
        match (direction, &self.state) {
            (_, State::Opaque) => {}
            // Lost part of a response (ring drops, or a large result set in
            // a packet past `max_packet_bytes`): rows are not needed, so
            // the response is closed by the next command. That holds only
            // while the client waits for each reply: one that pipelines
            // may have sent the next command already.
            (Direction::Ingress, State::InQuery | State::InResponse { .. }) => {
                if self.pipelined || !self.client_buf.is_empty() {
                    self.untrusted = true;
                }
                self.server_buf.clear();
                self.resync_server = true;
            }
            _ => return None,
        }
        self.skip_accounted = true;
        Some(ParseResult::NeedMoreData)
    }

    fn protocol(&self) -> Protocol {
        Protocol::Mysql
    }
    fn state_name(&self) -> &'static str {
        self.current_state()
    }
    fn protocol_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    /// The stream was not seen from its first byte (or bytes were lost
    /// that `skip` could not place): a packet boundary found from here may
    /// lie inside a statement or row, and a reply may answer a command
    /// sent before capture. Untrusted for good. Not right after a `skip`
    /// that accounted for its gap (`skip_accounted`).
    fn joined_late(&mut self) {
        if std::mem::take(&mut self.skip_accounted) {
            return;
        }
        self.untrusted = true;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_long_query_with_multibyte_text_does_not_panic() {
        let mut q = vec![0x03u8];
        q.extend_from_slice(b"INSERT INTO t VALUES ('ab"); // odd length
        while q.len() < 5000 {
            q.extend_from_slice("é".as_bytes());
        }
        q.extend_from_slice(b"')");
        let mut pkt = (q.len() as u32).to_le_bytes()[..3].to_vec();
        pkt.push(0);
        pkt.extend(q);
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        p.feed(&pkt, Direction::Egress, 1);
        match p.feed(&[7, 0, 0, 1, 0, 1, 0, 2, 0, 0, 0], Direction::Ingress, 2) {
            ParseResult::Messages(m) => assert!(m[0].payload_text.as_ref().unwrap().len() <= 4096),
            other => panic!("expected INSERT, got {other:?}"),
        }
    }

    #[test]
    fn test_gap_in_result_set_closes_on_next_command() {
        fn pkt(seq: u8, body: &[u8]) -> Vec<u8> {
            let mut v = (body.len() as u32).to_le_bytes()[..3].to_vec();
            v.push(seq);
            v.extend_from_slice(body);
            v
        }
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        p.feed(&pkt(0, b"\x03SELECT * FROM big"), Direction::Egress, 1000);
        // Column count, then the capture loses most of the result set.
        p.feed(&pkt(1, b"\x03"), Direction::Ingress, 1100);
        assert!(p.skip(Direction::Ingress, 60_000, 1200).is_some());
        p.feed(b"tail of some row bytes", Direction::Ingress, 1300);
        let ParseResult::Messages(msgs) =
            p.feed(&pkt(0, b"\x03UPDATE t SET a = 1"), Direction::Egress, 2000)
        else {
            panic!("next command must close the SELECT");
        };
        assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
        assert_eq!(msgs[0].latency_ns, None);
        match p.feed(
            &pkt(1, b"\x00\x01\x00\x02\x00\x00\x00"),
            Direction::Ingress,
            2500,
        ) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].method.as_deref(), Some("UPDATE"));
                assert_eq!(msgs[0].latency_ns, Some(500));
            }
            other => panic!("UPDATE must pair with its own OK, got {other:?}"),
        }
    }

    #[test]
    fn test_caching_sha2_fast_auth_keeps_responses_aligned() {
        fn pkt(seq: u8, body: &[u8]) -> Vec<u8> {
            let mut v = (body.len() as u32).to_le_bytes()[..3].to_vec();
            v.push(seq);
            v.extend_from_slice(body);
            v
        }
        let mut greeting = vec![0x0a];
        greeting.extend_from_slice(b"8.4.11\0");
        greeting.extend_from_slice(&[0u8; 40]);
        greeting.extend_from_slice(b"caching_sha2_password\0");
        let ok = pkt(2, b"\x00\x00\x00\x02\x00\x00\x00");
        let mut err_body = vec![0xff, 0x7a, 0x04];
        err_body.extend_from_slice(b"#42S02Table 'db.missing' doesn't exist");

        let mut p = MysqlParser::new();
        let mut out = Vec::new();
        let mut feed = |p: &mut MysqlParser, d: &[u8], dir| {
            if let ParseResult::Messages(m) = p.feed(d, dir, 1) {
                out.extend(m.into_iter().map(|m| (m.method, m.status)));
            }
        };
        feed(&mut p, &pkt(0, &greeting), Direction::Ingress);
        feed(
            &mut p,
            &pkt(1, b"\x00\x00\x00\x00root\0"),
            Direction::Egress,
        );
        feed(&mut p, &pkt(2, b"\x01\x03"), Direction::Ingress); // AuthMoreData: fast auth ok
        feed(&mut p, &ok, Direction::Ingress); // the real auth OK
        feed(&mut p, &pkt(0, b"\x03SET NAMES utf8mb4"), Direction::Egress);
        feed(
            &mut p,
            &pkt(1, b"\x00\x00\x00\x02\x00\x00\x00"),
            Direction::Ingress,
        );
        feed(
            &mut p,
            &pkt(0, b"\x03SELECT * FROM missing"),
            Direction::Egress,
        );
        feed(&mut p, &pkt(1, &err_body), Direction::Ingress);
        assert_eq!(
            out,
            vec![
                (Some("SET".to_string()), Some(0)),
                (Some("SELECT".to_string()), Some(1146)),
            ]
        );
    }

    #[test]
    fn test_error_reply_pairs_with_its_own_query() {
        // Exact packets captured from MySQL 8.4 + PyMySQL: UPDATE -> OK,
        // SELECT from a missing table -> ERR 1146, UPDATE -> OK.
        fn pkt(seq: u8, body: &[u8]) -> Vec<u8> {
            let mut v = (body.len() as u32).to_le_bytes()[..3].to_vec();
            v.push(seq);
            v.extend_from_slice(body);
            v
        }
        let ok = pkt(
            1,
            b"\x00\x00\x00\x22\x00\x00\x00(Rows matched: 0  Changed: 0  Warnings: 0",
        );
        let mut err_body = vec![0xff, 0x7a, 0x04];
        err_body.extend_from_slice(b"#42S02Table 'oracle.missing_tok_17_' doesn't exist");
        let err = pkt(1, &err_body);
        let mut p = MysqlParser::new();
        p.state = State::Ready; // handshake seen
        let mut out = Vec::new();
        let mut feed = |p: &mut MysqlParser, d: &[u8], dir, ts| {
            if let ParseResult::Messages(m) = p.feed(d, dir, ts) {
                out.extend(m.into_iter().map(|m| (m.method, m.status)));
            }
        };
        feed(
            &mut p,
            &pkt(0, b"\x03UPDATE users SET a = 1 WHERE note = 'tok_16_'"),
            Direction::Egress,
            1,
        );
        feed(&mut p, &ok, Direction::Ingress, 2);
        feed(
            &mut p,
            &pkt(0, b"\x03SELECT * FROM missing_tok_17_"),
            Direction::Egress,
            3,
        );
        feed(&mut p, &err, Direction::Ingress, 4);
        feed(
            &mut p,
            &pkt(0, b"\x03UPDATE users SET a = 2 WHERE note = 'tok_18_'"),
            Direction::Egress,
            5,
        );
        feed(&mut p, &ok, Direction::Ingress, 6);
        assert_eq!(
            out,
            vec![
                (Some("UPDATE".to_string()), Some(0)),
                (Some("SELECT".to_string()), Some(1146)),
                (Some("UPDATE".to_string()), Some(0)),
            ]
        );
    }

    use super::*;

    fn make_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut p = vec![
            (len & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
            seq,
        ];
        p.extend_from_slice(payload);
        p
    }

    fn make_greeting(version: &str, plugin: &str) -> Vec<u8> {
        let mut payload = vec![0x0a];
        payload.extend_from_slice(version.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&[1, 0, 0, 0]);
        payload.extend_from_slice(&[0xAA; 8]);
        payload.push(0);
        payload.extend_from_slice(&[0xFF, 0xFF, 0x21, 0x02, 0x00, 0xFF, 0xFF, 21]);
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(&[0xBB; 13]);
        payload.extend_from_slice(plugin.as_bytes());
        payload.push(0);
        make_packet(0, &payload)
    }

    #[test]
    fn test_version_detect_80() {
        let mut p = MysqlParser::new();
        p.feed(
            &make_greeting("8.0.32", "caching_sha2_password"),
            Direction::Ingress,
            0,
        );
        assert_eq!(p.server_version.as_deref(), Some("8.0.32"));
        assert_eq!(p.auth_plugin.as_deref(), Some("caching_sha2_password"));
    }

    #[test]
    fn test_version_detect_57() {
        let mut p = MysqlParser::new();
        p.feed(
            &make_greeting("5.7.44", "mysql_native_password"),
            Direction::Ingress,
            0,
        );
        assert_eq!(p.server_version.as_deref(), Some("5.7.44"));
        assert_eq!(p.auth_plugin.as_deref(), Some("mysql_native_password"));
    }

    #[test]
    fn test_query_ok() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 1");
        p.feed(&make_packet(0, &cmd), Direction::Egress, 1000);
        let result = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            2000,
        );
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
                assert_eq!(m[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    /// The query text a MySQL COM_QUERY exchange exports.
    fn exported_query(sql: &str) -> String {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(sql.as_bytes());
        p.feed(&make_packet(0, &cmd), Direction::Egress, 1000);
        let ParseResult::Messages(m) = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            2000,
        ) else {
            panic!("expected a message for {sql}");
        };
        m[0].payload_text.clone().unwrap_or_default()
    }

    /// Every credential statement, whatever SQL form carries the value,
    /// exports only its verb; so does one comparing a password column or
    /// listing it for `VALUES`. Statements without credential context, and
    /// a `SELECT` whose credential columns are bare names in its select
    /// list, are exported as written.
    #[test]
    fn test_credential_statement_forms_export_only_the_verb() {
        for sql in [
            "SET PASSWORD FOR 'app user'@'%' = 'canary-for';",
            "SET GLOBAL `group_replication_recovery_password` = 'canary-quoted';",
            "ALTER USER app IDENTIFIED BY \"canary-a\"\"canary-b\";",
            "ALTER USER app IDENTIFIED BY _utf8mb4'canary-cs'",
            "ALTER USER app IDENTIFIED BY /* c */ 'canary-comment'",
            "ALTER USER app IDENTIFIED BY 'canary-a' 'canary-b'",
            "ALTER USER app IDENTIFIED BY 'can\\'ary-esc'",
            "ALTER USER app IDENTIFIED WITH caching_sha2_password BY 'canary'",
            "ALTER USER app IDENTIFIED BY 'canary-new' REPLACE 'canary-old'",
            "CREATE USER 'app'@'%' IDENTIFIED BY 'canary'",
            "CREATE USER app IDENTIFIED WITH mysql_native_password AS '*0123canary'",
            "CREATE USER app IDENTIFIED VIA ed25519 USING PASSWORD('canary-maria')",
            "SET PASSWORD = CONCAT('canary-x', 'canary-y')",
            "SET PASSWORD = ('canary-paren')",
            "ALTER USER app IDENTIFIED BY 'canary-trunc",
            "CHANGE MASTER TO MASTER_HOST='db1', MASTER_PASSWORD='canary'",
            "CHANGE REPLICATION SOURCE TO SOURCE_USER='repl', SOURCE_PASSWORD = 'canary'",
            "SELECT email FROM users WHERE password = 'canary'",
            "INSERT INTO users (email, password, name) VALUES ('a', 'canary', 'b')",
            "SELECT password FROM users UNION SELECT 'canary'",
        ] {
            let verb = sql.split_whitespace().next().unwrap();
            assert_eq!(
                exported_query(sql),
                format!("{verb} <statement withheld>"),
                "{sql}"
            );
        }
        for sql in [
            "REPLACE INTO t VALUES (REPLACE(name, 'a', 'b'))",
            "SELECT name, email FROM users WHERE id = 7",
            "SELECT password, email FROM users",
            "SELECT pwd, email FROM users",
        ] {
            assert_eq!(exported_query(sql), sql);
        }
    }

    /// Statements with credential context export only their verb, whatever
    /// SQL form hides the value (Codex round 3).
    #[test]
    fn test_credential_statements_are_withheld() {
        let mut leaks = Vec::new();
        for sql in [
            // NO_BACKSLASH_ESCAPES: the backslash ends nothing.
            "ALTER USER app IDENTIFIED BY 'new\\' REPLACE 'canary-old'",
            "ALTER USER app IDENTIFIED BY /*!80000 'canary-exec' */",
            "SET PASSWORD FOR ü@localhost = 'canary-u'",
            "SET PASSWORD FOR CURRENT_USER() = 'canary-cu'",
            "CREATE USER app IDENTIFIED VIA unix_socket OR mysql_native_password USING '*CANARYHASH'",
        ] {
            let out = exported_query(sql);
            if out.to_lowercase().contains("canary") {
                leaks.push(format!("{sql} -> {out}"));
            }
        }
        assert!(leaks.is_empty(), "{leaks:#?}");
        assert_eq!(
            exported_query("SET PASSWORD = 'canary'"),
            "SET <statement withheld>"
        );
    }

    #[test]
    fn test_query_error() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"BAD SQL");
        p.feed(&make_packet(0, &cmd), Direction::Egress, 1000);
        let mut err = vec![ERR_MARKER];
        err.extend_from_slice(&1064u16.to_le_bytes());
        err.push(b'#');
        err.extend_from_slice(b"42000");
        err.extend_from_slice(b"syntax error");
        let result = p.feed(&make_packet(1, &err), Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(m) => {
                // The code and SQLSTATE; never the message.
                assert_eq!(m[0].status, Some(1064));
                assert_eq!(m[0].payload_text.as_deref(), Some("BAD SQL"));
                assert_eq!(m[0].headers, vec![("sqlstate".into(), "42000".into())]);
                assert!(!format!("{m:?}").contains("syntax error"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    /// A server error echoes statement text and values (1064 quotes the
    /// statement, 1366 a bound value): its message is never exported,
    /// with or without a SQL state, whatever the statement.
    #[test]
    fn test_error_text_is_never_exported() {
        let echo = b"You have an error in your SQL syntax; check the manual near 'IDENTIFIED BY 'my-s3cret'' at line 1";
        for (query, sql_state) in [
            (
                &b"GRANT ALL ON app.* TO 'app'@'%' IDENTIFIED BY 'my-s3cret'"[..],
                true,
            ),
            (
                b"GRANT ALL ON app.* TO 'app'@'%' IDENTIFIED BY 'my-s3cret'",
                false,
            ),
            // A clean query whose error shows credential context.
            (b"SELECT 1", true),
            (b"SELECT 1", false),
        ] {
            let mut p = MysqlParser::new();
            p.state = State::Ready;
            let mut cmd = vec![COM_QUERY];
            cmd.extend_from_slice(query);
            p.feed(&make_packet(0, &cmd), Direction::Egress, 1000);
            let mut err = vec![ERR_MARKER];
            err.extend_from_slice(&1064u16.to_le_bytes());
            if sql_state {
                err.extend_from_slice(b"#42000");
            }
            err.extend_from_slice(echo);
            let ParseResult::Messages(m) = p.feed(&make_packet(1, &err), Direction::Ingress, 2000)
            else {
                panic!("expected a message");
            };
            let all = format!("{m:?}");
            assert!(!all.contains("s3cret") && !all.contains("syntax"), "{all}");
            assert_eq!(m[0].status, Some(1064));
            let state: Vec<_> = m[0].headers.iter().map(|(_, v)| v.as_str()).collect();
            assert_eq!(state, if sql_state { vec!["42000"] } else { vec![] });
        }
    }

    /// 1366 quotes a bound value: the message is dropped, the code and
    /// SQLSTATE stay.
    #[test]
    fn test_error_echoing_a_value_exports_code_and_state_only() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut err = vec![ERR_MARKER, 0x56, 0x05];
        err.extend_from_slice(
            b"#HY000Incorrect integer value: 'hunter2' for column 'pin' at row 1",
        );
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x03INSERT INTO t (pin) VALUES ('hunter2')"),
                s(1, &err),
            ],
        );
        assert_eq!(msgs[0].status, Some(1366));
        assert_eq!(msgs[0].headers, vec![("sqlstate".into(), "HY000".into())]);
        let all = format!("{:?} {:?}", msgs[0].request_text, msgs[0].headers);
        assert!(!all.contains("Incorrect"), "{all}");
        // A malformed SQLSTATE is not exported either.
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[c(0, b"\x03SELECT 1"), s(1, b"\xff\x56\x05#hu'2!rest")],
        );
        assert!(msgs[0].headers.is_empty(), "{:?}", msgs[0].headers);
    }

    #[test]
    fn test_metadata() {
        let p = MysqlParser::new();
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Mysql);
        assert_eq!(p.current_state(), "waiting_for_handshake");
    }

    #[test]
    fn test_attach_after_handshake_still_parses_query() {
        let mut p = MysqlParser::new();

        // First observed packet is a client COM_QUERY (server greeting was missed).
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 1");
        assert!(matches!(
            p.feed(&make_packet(0, &cmd), Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));

        // Server OK response should still produce a MySQL message, but the
        // greeting was missed: the reply may answer an earlier command, so
        // only the keyword is exported.
        let result = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            2000,
        );
        match result {
            ParseResult::Messages(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].protocol, Protocol::Mysql);
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!((m[0].status, &m[0].payload_text), (None, &None));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_attach_mid_auth_no_response_shift() {
        let mut p = MysqlParser::new();

        // First observed client packet is an auth response (not a command).
        let auth_response = make_packet(1, &[0x85, 0, 0, 0, 0]);
        assert!(matches!(
            p.feed(&auth_response, Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));

        // Auth OK from server.
        assert!(matches!(
            p.feed(
                &make_packet(2, &[OK_MARKER, 0, 0, 2, 0]),
                Direction::Ingress,
                1500
            ),
            ParseResult::NeedMoreData
        ));

        // Real query should still align to its own response.
        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 42");
        assert!(matches!(
            p.feed(&make_packet(0, &cmd), Direction::Egress, 2000),
            ParseResult::NeedMoreData
        ));

        let result = p.feed(
            &make_packet(1, &[OK_MARKER, 0, 0, 2, 0]),
            Direction::Ingress,
            3000,
        );
        match result {
            ParseResult::Messages(m) => {
                // An auth packet first is how a TLS key starts; whether it
                // was a late join is the manager's call (`joined_late`).
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
                assert_eq!(m[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_resultset_ok_terminator_mysql8() {
        // CLIENT_DEPRECATE_EOF (MySQL 8 clients): no delimiter after the
        // column definitions, rows follow directly, and the result set ends
        // with an OK packet that carries the 0xFE header.
        let mut p = MysqlParser::new();
        p.state = State::Ready;

        let mut cmd = vec![COM_QUERY];
        cmd.extend_from_slice(b"SELECT 1");
        assert!(matches!(
            p.feed(&make_packet(0, &cmd), Direction::Egress, 1000),
            ParseResult::NeedMoreData
        ));
        for (seq, pkt) in [(1u8, &[0x01u8][..]), (2, b"col"), (3, b"\x011")] {
            assert!(matches!(
                p.feed(&make_packet(seq, pkt), Direction::Ingress, 1500),
                ParseResult::NeedMoreData
            ));
        }
        match p.feed(
            &make_packet(4, &[EOF_MARKER, 0, 0, 2, 0, 0, 0]),
            Direction::Ingress,
            2200,
        ) {
            ParseResult::Messages(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].method.as_deref(), Some("SELECT"));
                assert_eq!(m[0].status, Some(0));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    fn feed_all(p: &mut MysqlParser, packets: &[(Direction, Vec<u8>)]) -> Vec<L7Message> {
        let mut out = Vec::new();
        for (i, (dir, pkt)) in packets.iter().enumerate() {
            if let ParseResult::Messages(m) = p.feed(pkt, *dir, 1000 + i as u64) {
                out.extend(m);
            }
        }
        out
    }

    fn c(seq: u8, body: &[u8]) -> (Direction, Vec<u8>) {
        (Direction::Egress, make_packet(seq, body))
    }

    fn s(seq: u8, body: &[u8]) -> (Direction, Vec<u8>) {
        (Direction::Ingress, make_packet(seq, body))
    }

    fn hex(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    /// PREPARE_OK for statement `id` with `cols` columns and `params` params.
    fn prepare_ok(id: u32, cols: u16, params: u16) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend(id.to_le_bytes());
        v.extend(cols.to_le_bytes());
        v.extend(params.to_le_bytes());
        v.extend([0, 0, 0]);
        v
    }

    const OK: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
    const EOF: &[u8] = &[0xFE, 0x00, 0x00, 0x02, 0x00];

    #[test]
    fn test_prepared_insert_with_query_attributes_layout() {
        // Byte-for-byte what mysql-connector-python 26.10 sends to MySQL 8.4
        // (CLIENT_QUERY_ATTRIBUTES: explicit parameter count and a name per
        // bound type), handshake not seen.
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut prepare = vec![COM_STMT_PREPARE];
        prepare.extend_from_slice(b"INSERT INTO users (id, email) VALUES (?, ?)");
        let execute =
            hex("17010000000001000000020001018000fe000000117573657230406578616d706c652e636f6d");
        let msgs = feed_all(
            &mut p,
            &[
                c(0, &prepare),
                s(1, &prepare_ok(1, 0, 2)),
                s(2, b"param-def-1"),
                s(3, b"param-def-2"),
                s(4, EOF),
                c(0, &execute),
                s(1, OK),
            ],
        );
        assert_eq!(
            msgs.len(),
            1,
            "PREPARE is not reported, EXECUTE is: {msgs:?}"
        );
        assert_eq!(msgs[0].method.as_deref(), Some("INSERT"));
        assert_eq!(
            msgs[0].payload_text.as_deref(),
            Some("INSERT INTO users (id, email) VALUES (?, ?)")
        );
        assert_eq!(msgs[0].request_text.as_deref(), Some("user0@example.com"));
        assert_eq!(msgs[0].status, Some(0));
    }

    /// A prepared statement with credential context exports no bound value.
    #[test]
    fn test_credential_statement_drops_bound_values() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut prepare = vec![COM_STMT_PREPARE];
        prepare.extend_from_slice(b"UPDATE users SET id = ?, password = ?");
        let execute =
            hex("17010000000001000000020001018000fe000000117573657230406578616d706c652e636f6d");
        let msgs = feed_all(
            &mut p,
            &[
                c(0, &prepare),
                s(1, &prepare_ok(1, 0, 2)),
                s(2, b"param-def-1"),
                s(3, b"param-def-2"),
                s(4, EOF),
                c(0, &execute),
                s(1, OK),
            ],
        );
        assert_eq!(msgs[0].request_text, None, "{msgs:?}");
        assert_eq!(
            msgs[0].payload_text.as_deref(),
            Some("UPDATE <statement withheld>")
        );
    }

    /// An execute of a statement prepared before capture started: its SQL
    /// is unknown, so its bound values are not exported.
    #[test]
    fn test_execute_of_unseen_prepare_exports_no_values() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let execute =
            hex("17010000000001000000020001018000fe000000117573657230406578616d706c652e636f6d");
        let msgs = feed_all(&mut p, &[c(0, &execute), s(1, OK)]);
        assert_eq!(msgs[0].request_text, None, "{msgs:?}");
        assert_eq!(msgs[0].payload_text.as_deref(), Some("EXECUTE"));
    }

    #[test]
    fn test_prepared_reexecute_reuses_bound_types_classic_layout() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        p.client_caps = Some(CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF);
        let mut prepare = vec![COM_STMT_PREPARE];
        prepare.extend_from_slice(b"SELECT note FROM users WHERE email = ?");
        // Classic layout: no count, no names. First execute binds the type.
        let mut first = hex("170700000000010000000001fe00");
        first.extend([0x05]);
        first.extend_from_slice(b"a@b.c");
        // Second execute: new_params_bound = 0, types reused.
        let mut second = hex("1707000000000100000000" /* nulls */).to_vec();
        second.push(0x00); // new_params_bound
        second.push(0x05);
        second.extend_from_slice(b"d@e.f");
        let msgs = feed_all(
            &mut p,
            &[
                c(0, &prepare),
                s(1, &prepare_ok(7, 1, 1)),
                s(2, b"param-def"),
                s(3, b"col-def"), // DEPRECATE_EOF: no EOF packets
                c(0, &first),
                s(1, &[0x01]),
                s(2, b"col-def"),
                s(3, &[0x00, 0x00, 0x03, b'x', b'y', b'z']), // binary row
                s(4, &[0xFE, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]),
                c(0, &second),
                s(1, &[0x01]),
                s(2, b"col-def"),
                s(3, &[0xFE, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]),
            ],
        );
        let params: Vec<_> = msgs.iter().map(|m| m.request_text.as_deref()).collect();
        assert_eq!(params, vec![Some("a@b.c"), Some("d@e.f")], "{msgs:?}");
        assert!(msgs.iter().all(|m| m.method.as_deref() == Some("SELECT")));
    }

    #[test]
    fn test_text_row_with_empty_first_column_does_not_end_result_set() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x03SELECT a, b FROM t"),
                s(1, &[0x02]),
                s(2, b"col-a"),
                s(3, b"col-b"),
                s(4, EOF),
                s(5, &[0x00, 0x01, b'x']), // a = '', b = 'x'
                s(6, &[0x01, b'y', 0x00]),
                s(7, EOF),
                c(0, b"\x03UPDATE t SET a = 1"),
                s(1, OK),
            ],
        );
        let verbs: Vec<_> = msgs.iter().map(|m| m.method.as_deref()).collect();
        assert_eq!(verbs, vec![Some("SELECT"), Some("UPDATE")]);
    }

    #[test]
    fn test_ping_between_queries_keeps_responses_paired() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, &[COM_PING]),
                s(1, OK),
                c(0, b"\x03DELETE FROM t"),
                s(
                    1,
                    &[
                        0xFF, 0x7A, 0x04, b'#', b'4', b'2', b'S', b'0', b'2', b'n', b'o',
                    ],
                ),
            ],
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].method.as_deref(), Some("DELETE"));
        assert_eq!(msgs[0].status, Some(1146));
    }

    #[test]
    fn test_query_attributes_prefix_is_stripped() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(&mut p, &[c(0, b"\x03\x00\x01SELECT 1 FROM dual"), s(1, OK)]);
        assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
        assert_eq!(msgs[0].payload_text.as_deref(), Some("SELECT 1 FROM dual"));
    }

    #[test]
    fn test_failed_prepare_is_reported_as_error() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x16SELECT * FROM missing"),
                s(
                    1,
                    &[0xFF, 0x7A, 0x04, b'#', b'4', b'2', b'S', b'0', b'2', b'x'],
                ),
                c(0, b"\x03SELECT 2"),
                s(1, OK),
            ],
        );
        let got: Vec<_> = msgs
            .iter()
            .map(|m| (m.method.as_deref(), m.status))
            .collect();
        assert_eq!(
            got,
            vec![(Some("SELECT"), Some(1146)), (Some("SELECT"), Some(0))]
        );
    }

    #[test]
    fn test_lenenc() {
        // Valid encodings
        assert_eq!(decode_lenenc(&[5]), Some(5));
        assert_eq!(decode_lenenc(&[0xFC, 1, 0]), Some(1));
        assert_eq!(decode_lenenc(&[0xFC, 0xFF, 0xFF]), Some(65535));
        assert_eq!(decode_lenenc(&[0xFD, 1, 0, 0]), Some(1));
        // Bounds check: insufficient data must return None, not panic
        assert_eq!(decode_lenenc(&[]), None);
        assert_eq!(decode_lenenc(&[0xFD]), None); // 0xFD needs 4 bytes
        assert_eq!(decode_lenenc(&[0xFD, 1, 2]), None); // 3 bytes, needs 4
        assert_eq!(decode_lenenc(&[0xFC, 1]), None); // 0xFC needs 3 bytes
        assert_eq!(decode_lenenc(&[0xFE, 1, 2, 3, 4, 5, 6, 7]), None); // 0xFE needs 9 bytes
    }

    // ── Sync and pairing ─────────────────────────────────────────────────

    fn all_text(m: &L7Message) -> String {
        format!(
            "{:?} {:?} {:?} {:?} {:?}",
            m.method, m.path, m.payload_text, m.request_text, m.headers
        )
    }

    fn pairs(msgs: &[L7Message]) -> Vec<(Option<&str>, Option<u32>)> {
        msgs.iter()
            .map(|m| (m.method.as_deref(), m.status))
            .collect()
    }

    /// An INSERT whose value holds a forged command packet, and a reply
    /// whose row holds a forged OK: what a parser joining inside them sees.
    fn forged_tail() -> (Vec<u8>, Vec<u8>) {
        let mut client = b"abc'),('".to_vec();
        client.extend(make_packet(0, b"\x03SELECT 'S3CRET' FROM dual"));
        let mut server = b"row".to_vec();
        server.extend(make_packet(1, &[OK_MARKER, 0, 0, 2, 0, 0, 0]));
        (client, server)
    }

    #[test]
    fn joined_late_inside_a_statement_exports_no_forged_command() {
        let (client, server) = forged_tail();
        let mut p = MysqlParser::new();
        p.joined_late();
        let msgs = feed_all(
            &mut p,
            &[(Direction::Egress, client), (Direction::Ingress, server)],
        );
        for m in &msgs {
            assert!(!all_text(m).contains("S3CRET"), "{}", all_text(m));
            assert_eq!(m.status, None);
        }
        // A late parser that lands on real packet boundaries stays
        // untrusted all the same.
        let mut p = MysqlParser::new();
        p.joined_late();
        let msgs = feed_all(&mut p, &[c(0, b"\x03SELECT 1"), s(1, OK)]);
        assert_eq!(pairs(&msgs), vec![(Some("SELECT"), None)]);
        assert_eq!(msgs[0].payload_text, None);
    }

    fn manager_out(r: Option<crate::protocol::fsm::FsmResult>) -> Vec<L7Message> {
        use crate::protocol::fsm::FsmResult;
        match r {
            Some(FsmResult::Messages(v)) => v,
            Some(FsmResult::MessageComplete(v)) => vec![v],
            _ => vec![],
        }
    }

    /// The same through the manager (`mark_joined_late`).
    #[test]
    fn manager_join_mid_stream_exports_no_forged_command() {
        use crate::protocol::fsm::ConnectionFsmManager;
        let (client, server) = forged_tail();
        let m = ConnectionFsmManager::new(16);
        let (cl, sv) = ((1, 40000), (2, 3306));
        m.get_or_create_with_server(7, Protocol::Mysql, Some(sv));
        m.mark_joined_late(7);
        let mut out = manager_out(m.process_packet_from(7, cl, Direction::Egress, &client, 1));
        out.extend(manager_out(m.process_packet_from(
            7,
            sv,
            Direction::Ingress,
            &server,
            2,
        )));
        for msg in &out {
            assert!(!all_text(msg).contains("S3CRET"), "{}", all_text(msg));
        }
    }

    /// A gap inside a result set, through the manager (which follows every
    /// skip with `joined_late`): accounted for, so the next command keeps
    /// its text and status.
    #[test]
    fn manager_gap_inside_a_result_set_keeps_text() {
        use crate::protocol::fsm::ConnectionFsmManager;
        let m = ConnectionFsmManager::new(16);
        let (cl, sv) = ((1, 40000), (2, 3306));
        m.get_or_create_with_server(8, Protocol::Mysql, Some(sv));
        let mut greeting = vec![0x0a];
        greeting.extend_from_slice(b"8.4.0\0");
        greeting.extend_from_slice(&[0; 40]);
        m.process_packet_from(8, sv, Direction::Ingress, &make_packet(0, &greeting), 1);
        let mut auth = (CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF)
            .to_le_bytes()
            .to_vec();
        auth.extend_from_slice(&[0; 28]);
        auth.extend_from_slice(b"root\0");
        m.process_packet_from(8, cl, Direction::Egress, &make_packet(1, &auth), 2);
        m.process_packet_from(8, sv, Direction::Ingress, &make_packet(2, OK), 3);
        m.process_packet_from(
            8,
            cl,
            Direction::Egress,
            &make_packet(0, b"\x03SELECT * FROM big"),
            4,
        );
        m.process_packet_from(8, sv, Direction::Ingress, &make_packet(1, &[0x01]), 5);
        m.skip_from(8, sv, Direction::Ingress, 60_000, 6);
        let mut out = manager_out(m.process_packet_from(
            8,
            cl,
            Direction::Egress,
            &make_packet(0, b"\x03UPDATE t SET a = 1"),
            7,
        ));
        out.extend(manager_out(m.process_packet_from(
            8,
            sv,
            Direction::Ingress,
            &make_packet(1, OK),
            8,
        )));
        assert_eq!(
            pairs(&out),
            vec![(Some("SELECT"), None), (Some("UPDATE"), Some(0))]
        );
        assert_eq!(out[1].payload_text.as_deref(), Some("UPDATE t SET a = 1"));
    }

    /// A command whose reply the parser does not model (here
    /// COM_FIELD_LIST: definitions then EOF) used to leave its reply for
    /// the next command, which then paired with the wrong packets.
    #[test]
    fn unmodelled_command_untrusts_the_connection() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x04users\0"),
                s(1, b"\x03def\x03app\x05users"),
                s(2, EOF),
                c(0, b"\x03DELETE FROM t"),
                s(1, b"\xff\x7a\x04#42S02x"),
            ],
        );
        assert_eq!(pairs(&msgs), vec![(Some("DELETE"), None)]);
        for cmd in [
            &b"\x11app\0"[..],               // COM_CHANGE_USER
            b"\x1c\x01\0\0\0\x0a\0\0\0",     // COM_STMT_FETCH
            b"\x12\x04\0\0\0\0\0\x01\0\0\0", // COM_BINLOG_DUMP
            b"\x0a",                         // COM_PROCESS_INFO
            b"\x20",                         // COM_CLONE / unknown
        ] {
            let mut p = MysqlParser::new();
            p.state = State::Ready;
            feed_all(&mut p, &[c(0, cmd)]);
            assert!(p.untrusted, "{cmd:?}");
        }
    }

    /// Commands with one reply packet (COM_STATISTICS answers with a
    /// string, not an OK) and commands with none keep pairing.
    #[test]
    fn single_and_no_reply_commands_keep_pairing() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, &[COM_STATISTICS]),
                s(1, b"Uptime: 10  Threads: 1  Questions: 5"),
                c(0, b"\x19\x01\0\0\0"),              // COM_STMT_CLOSE
                c(0, b"\x18\x01\0\0\0\0\0long data"), // COM_STMT_SEND_LONG_DATA
                c(0, b"\x03UPDATE t SET a = 1"),
                s(1, OK),
                c(0, b"\x0c\x07\0\0\0"), // COM_PROCESS_KILL
                s(1, OK),
                c(0, b"\x03DELETE FROM t"),
                s(1, b"\xff\x7a\x04#42S02x"),
            ],
        );
        assert_eq!(
            pairs(&msgs),
            vec![(Some("UPDATE"), Some(0)), (Some("DELETE"), Some(1146))]
        );
        assert!(!p.untrusted);
    }

    /// LOAD DATA LOCAL INFILE: the server asks for the file (0xFB), the
    /// client sends it, then the server answers. The file's packets (here
    /// holding what looks like a command) are never read as commands, nor
    /// exported.
    #[test]
    fn local_infile_transfer_is_one_exchange() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x03LOAD DATA LOCAL INFILE '/tmp/u.csv' INTO TABLE t"),
                s(1, b"\xfb/tmp/u.csv"),
                c(2, b"\x03SELECT 'S3CRET'\n"),
                c(3, b"alice,S3CRET\n"),
                c(4, b""),
                s(5, OK),
                c(0, b"\x03SELECT 1"),
                s(1, OK),
            ],
        );
        assert_eq!(
            pairs(&msgs),
            vec![(Some("LOAD"), Some(0)), (Some("SELECT"), Some(0))]
        );
        for m in &msgs {
            assert!(!all_text(m).contains("S3CRET"), "{}", all_text(m));
        }
        assert!(!p.untrusted);
    }

    /// A multi-statement query or a `CALL` returns several results; only
    /// the last lacks SERVER_MORE_RESULTS_EXISTS. The later ones used to
    /// answer the next command.
    #[test]
    fn multi_results_are_one_exchange() {
        const EOF_MORE: &[u8] = &[0xFE, 0x00, 0x00, 0x0a, 0x00];
        const OK_MORE: &[u8] = &[0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00];
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x03SELECT 1; UPDATE t SET a = 2; SELECT 3"),
                s(1, &[0x01]),
                s(2, b"col"),
                s(3, EOF),
                s(4, b"\x011"),
                s(5, EOF_MORE),
                s(6, OK_MORE),
                s(7, &[0x01]),
                s(8, b"col"),
                s(9, EOF),
                s(10, b"\x013"),
                s(11, EOF),
                c(0, b"\x03CALL p()"),
                s(1, &[0x01]),
                s(2, b"col"),
                s(3, EOF),
                s(4, EOF_MORE),
                s(5, OK),
                c(0, b"\x03DELETE FROM t"),
                s(1, b"\xff\x7a\x04#42S02x"),
            ],
        );
        assert_eq!(
            pairs(&msgs),
            vec![
                (Some("SELECT"), Some(0)),
                (Some("CALL"), Some(0)),
                (Some("DELETE"), Some(1146))
            ]
        );
        assert!(!p.untrusted);
    }

    /// A reply packet out of sequence, or server bytes with no command in
    /// flight, means the parser is out of step: untrusted.
    #[test]
    fn sequence_breaks_and_unsolicited_replies_untrust() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(&mut p, &[c(0, b"\x03SELECT 1"), s(3, OK)]);
        assert_eq!(pairs(&msgs), vec![(Some("SELECT"), None)]);

        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x03SELECT 1"),
                s(1, OK),
                s(1, OK),
                c(0, b"\x03SELECT 2"),
                s(1, OK),
            ],
        );
        assert_eq!(
            pairs(&msgs),
            vec![(Some("SELECT"), Some(0)), (Some("SELECT"), None)]
        );
    }

    /// After a server gap the next command closes the reply only when the
    /// client waits for each reply; a pipelining client may already have
    /// sent it.
    #[test]
    fn gap_on_a_pipelining_connection_untrusts() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        feed_all(
            &mut p,
            &[
                c(0, b"\x03SELECT * FROM big"),
                c(0, b"\x03SELECT 2"),
                s(1, &[0x01]),
            ],
        );
        assert!(p.pipelined);
        assert!(p.skip(Direction::Ingress, 60_000, 5).is_some());
        assert!(p.untrusted);
    }

    /// A cursor EXECUTE's rows come through COM_STMT_FETCH: untrusted.
    #[test]
    fn cursor_execute_untrusts() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        feed_all(&mut p, &[c(0, b"\x17\x01\0\0\0\x01\x01\0\0\0")]);
        assert!(p.untrusted);
    }

    /// A TLS key's plaintext starts with the client's full
    /// HandshakeResponse41 (sequence id 2, CLIENT_SSL set): parsed as
    /// usual, with text when the manager has the key's start, keyword only
    /// when it marks the key late.
    #[test]
    fn tls_plaintext_starts_at_the_full_handshake_response() {
        use crate::protocol::fsm::ConnectionFsmManager;
        let mut auth = (CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_DEPRECATE_EOF)
            .to_le_bytes()
            .to_vec();
        auth.extend_from_slice(&[0; 28]);
        auth.extend_from_slice(b"app\0\x14");
        auth.extend_from_slice(&[0xAB; 20]);
        for late in [false, true] {
            let m = ConnectionFsmManager::new(16);
            let (cl, sv) = ((1, 40000), (2, 3306));
            m.get_or_create_with_server(3, Protocol::Mysql, Some(sv));
            if late {
                m.mark_joined_late(3);
            }
            m.process_packet_from(3, cl, Direction::Egress, &make_packet(2, &auth), 1);
            m.process_packet_from(3, sv, Direction::Ingress, &make_packet(3, OK), 2);
            m.process_packet_from(
                3,
                cl,
                Direction::Egress,
                &make_packet(0, b"\x03UPDATE t SET a = 1"),
                3,
            );
            let out = manager_out(m.process_packet_from(
                3,
                sv,
                Direction::Ingress,
                &make_packet(1, OK),
                4,
            ));
            assert_eq!(out.len(), 1, "late={late}");
            if late {
                assert_eq!(pairs(&out), vec![(Some("UPDATE"), None)]);
                assert_eq!(out[0].payload_text, None);
            } else {
                assert_eq!(pairs(&out), vec![(Some("UPDATE"), Some(0))]);
                assert_eq!(out[0].payload_text.as_deref(), Some("UPDATE t SET a = 1"));
            }
        }
    }

    /// SSLRequest: TLS records follow, never parsed as packets.
    #[test]
    fn ssl_request_stops_parsing() {
        let mut p = MysqlParser::new();
        let mut greeting = vec![0x0a];
        greeting.extend_from_slice(b"8.4.0\0");
        greeting.extend_from_slice(&[0; 40]);
        let mut ssl = (CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes().to_vec();
        ssl.extend_from_slice(&[0; 28]);
        let msgs = feed_all(
            &mut p,
            &[
                s(0, &greeting),
                c(1, &ssl),
                (
                    Direction::Egress,
                    b"\x16\x03\x01\x02\x00\x03SELECT 1".to_vec(),
                ),
            ],
        );
        assert!(msgs.is_empty());
        assert_eq!(p.state_name(), "opaque");
    }

    /// OK `info` text and the rows of SHOW WARNINGS (which quote values)
    /// are never exported.
    #[test]
    fn ok_info_and_warning_rows_are_never_exported() {
        let mut p = MysqlParser::new();
        p.state = State::Ready;
        let mut ok_info = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00];
        ok_info.extend_from_slice(b"Rows matched: 1  Changed: 1  Warnings: 1 hunter2");
        let msgs = feed_all(
            &mut p,
            &[
                c(0, b"\x03UPDATE t SET pin = 7"),
                s(1, &ok_info),
                c(0, b"\x03SHOW WARNINGS"),
                s(1, &[0x03]),
                s(2, b"col1"),
                s(3, b"col2"),
                s(4, b"col3"),
                s(5, EOF),
                s(
                    6,
                    b"\x07Warning\x041366\x37Incorrect integer value: 'hunter2' for column 'pin'",
                ),
                s(7, EOF),
            ],
        );
        assert_eq!(msgs.len(), 2);
        for m in &msgs {
            assert!(!all_text(m).contains("hunter2"), "{}", all_text(m));
        }
    }
}

/// The TLS ruling (USER-GUIDE §5.3): what a MySQL TLS key exports when its
/// start is unproven ([`ProtocolParser::tls_unproven_start`]) and a record
/// is lost (a ring drop leaves no trace on a TLS key). Each test asserts
/// the safe outcome: it passes only if MySQL latches over TLS.
#[cfg(test)]
mod tls_ruling {
    use super::*;
    use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};

    const CLIENT: (u32, u16) = (0, 1);
    const SERVER: (u32, u16) = (0, 2);
    const OK: &[u8] = &[0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];

    fn pkt(seq: u8, body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_le_bytes()[..3].to_vec();
        v.push(seq);
        v.extend_from_slice(body);
        v
    }

    /// A TLS key whose plaintext starts with the full handshake response
    /// (as it does on a key seen from the start), then auth OK.
    fn tls_key(m: &ConnectionFsmManager, id: u64) {
        m.get_or_create_with_server(id, Protocol::Mysql, Some(SERVER));
        m.start_tls(id);
        let mut auth = (CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_DEPRECATE_EOF)
            .to_le_bytes()
            .to_vec();
        auth.extend_from_slice(&[0; 28]);
        auth.extend_from_slice(b"app\0");
        feed(m, id, true, &pkt(2, &auth));
        feed(m, id, false, &pkt(3, OK));
    }

    fn feed(m: &ConnectionFsmManager, id: u64, from_client: bool, d: &[u8]) -> Vec<L7Message> {
        let (src, dir) = if from_client {
            (CLIENT, Direction::Egress)
        } else {
            (SERVER, Direction::Ingress)
        };
        match m.process_packet_from(id, src, dir, d, 1) {
            Some(FsmResult::Messages(v)) => v,
            Some(FsmResult::MessageComplete(v)) => vec![v],
            _ => vec![],
        }
    }

    /// A lost reply record: the next command's reply answers the command
    /// before it, for the rest of the connection.
    #[test]
    #[ignore = "TLS ruling pending: MySQL does not latch over TLS"]
    fn tls_lost_reply_record_shifts_no_pair() {
        let m = ConnectionFsmManager::new(4);
        tls_key(&m, 1);
        let mut out = feed(&m, 1, true, &pkt(0, b"\x03UPDATE t SET a = 1"));
        // Its OK is lost.
        out.extend(feed(&m, 1, true, &pkt(0, b"\x03SELECT * FROM missing")));
        out.extend(feed(&m, 1, false, &pkt(1, b"\xff\x7a\x04#42S02x")));
        for msg in &out {
            assert!(
                !(msg.method.as_deref() == Some("UPDATE") && msg.status == Some(1146)),
                "SELECT's error exported under the UPDATE: {msg:?}"
            );
        }
    }

    /// A statement prepared on the key; then a record is lost and the next
    /// one starts inside an INSERT whose value holds a forged
    /// COM_STMT_EXECUTE of that statement id. The INSERT names a
    /// credential, so its text would be withheld; the forged EXECUTE's
    /// "bound value" must not be exported under the prepared SQL.
    #[test]
    #[ignore = "TLS ruling pending: MySQL does not latch over TLS"]
    fn tls_forged_execute_exports_no_bound_value() {
        let m = ConnectionFsmManager::new(4);
        tls_key(&m, 2);
        let mut prep = vec![COM_STMT_PREPARE];
        prep.extend_from_slice(b"UPDATE notes SET body = ? WHERE id = 1");
        feed(&m, 2, true, &pkt(0, &prep));
        let mut ok = vec![0x00];
        ok.extend(1u32.to_le_bytes());
        ok.extend(0u16.to_le_bytes());
        ok.extend(1u16.to_le_bytes());
        ok.extend([0, 0, 0]);
        feed(&m, 2, false, &pkt(1, &ok));
        feed(&m, 2, false, &pkt(2, b"param-def"));
        // Lost: the start of `INSERT INTO users (password) VALUES ('...`.
        // Classic layout: 1 param, null bitmap, bound, VARCHAR, the value.
        let mut exec = vec![
            COM_STMT_EXECUTE,
            1,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0x00,
            0x01,
            0x0f,
            0x00,
        ];
        exec.push(13);
        exec.extend_from_slice(b"S3CRET-hunter");
        let mut out = feed(&m, 2, true, &pkt(0, &exec));
        out.extend(feed(&m, 2, false, &pkt(1, OK)));
        assert_eq!(out.len(), 1, "{out:?}");
        for msg in &out {
            assert!(
                !format!("{:?}", msg.request_text).contains("S3CRET"),
                "body bytes exported as a bound value: {msg:?}"
            );
        }
    }
}
