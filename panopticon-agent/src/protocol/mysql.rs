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

use std::collections::{HashMap, VecDeque};

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_PING: u8 = 0x0e;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const COM_STMT_CLOSE: u8 = 0x19;
const COM_STMT_RESET: u8 = 0x1a;
const COM_SET_OPTION: u8 = 0x1b;
const COM_RESET_CONNECTION: u8 = 0x1f;

/// Capability flags (HandshakeResponse41).
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
const CLIENT_QUERY_ATTRIBUTES: u32 = 0x0800_0000;
/// COM_STMT_EXECUTE flag: a parameter count follows the iteration count.
const PARAMETER_COUNT_AVAILABLE: u8 = 0x08;

/// Prepared statements remembered per connection.
const MAX_PREPARED: usize = 256;
/// Bound-parameter text kept per EXECUTE.
const MAX_PARAM_TEXT: usize = 4096;
const ERR_MARKER: u8 = 0xFF;
const OK_MARKER: u8 = 0x00;
const EOF_MARKER: u8 = 0xFE;
/// AuthMoreData packet header during authentication.
const AUTH_MORE_DATA: u8 = 0x01;

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
        }
    }

    /// `Some(true/false)` once the handshake response was seen.
    fn deprecate_eof(&self) -> Option<bool> {
        self.client_caps.map(|c| c & CLIENT_DEPRECATE_EOF != 0)
    }

    fn try_read_packet(buf: &StreamBuffer) -> Option<(Vec<u8>, usize)> {
        let data = buf.data();
        if data.len() < 4 {
            return None;
        }
        let payload_len = data[0] as usize | (data[1] as usize) << 8 | (data[2] as usize) << 16;
        let total = 4 + payload_len;
        if data.len() < total {
            return None;
        }
        Some((data[4..total].to_vec(), total))
    }

    fn process(&mut self, ts: u64) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            match self.state.clone() {
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
                        msg.status = Some(0);
                        // Closed by the next command, not by the response end:
                        // the real latency is unknown.
                        msg.latency_ns = None;
                        messages.push(msg);
                    } else {
                        self.query_text = None;
                        self.query_ts = None;
                    }
                    self.resync_server = false;
                    self.state = State::Ready;
                }
                State::SkipDefs => {
                    if !self.skip_definitions() {
                        break;
                    }
                }
                State::InQuery => match self.parse_response(ts) {
                    Some(msg) => {
                        messages.push(msg);
                        self.state = State::Ready;
                    }
                    // A response that was consumed without a message
                    // (simple command, PREPARE_OK) moved the state on.
                    None if self.state != State::InQuery => {}
                    None => break,
                },
                State::InResponse {
                    cols_expected,
                    cols_received,
                    past_col_eof,
                } => match self.read_result_set(ts, cols_expected, cols_received, past_col_eof) {
                    RsResult::Done(msg) => {
                        messages.push(msg);
                        self.state = State::Ready;
                    }
                    RsResult::Progress(a, b, c) => {
                        self.state = State::InResponse {
                            cols_expected: a,
                            cols_received: b,
                            past_col_eof: c,
                        };
                        break;
                    }
                    RsResult::Need => break,
                },
            }
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn parse_handshake(&mut self) -> bool {
        let (payload, consumed) = match Self::try_read_packet(&self.server_buf) {
            Some(p) => p,
            None => {
                // If the agent attaches after the server greeting was already exchanged,
                // the first packet we observe can be a client auth packet or command.
                if let Some((client_payload, _)) = Self::try_read_packet(&self.client_buf) {
                    self.state = if !client_payload.is_empty()
                        && matches!(
                            client_payload[0],
                            COM_QUERY | COM_STMT_PREPARE | COM_STMT_EXECUTE
                        ) {
                        State::Ready
                    } else {
                        State::InAuth
                    };
                    return true;
                }
                return false;
            }
        };
        self.server_buf.consume(consumed);
        if payload.is_empty() || payload[0] != 0x0a {
            self.state = State::Ready;
            return true;
        }
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
        self.state = State::InAuth;
        true
    }

    fn complete_auth(&mut self) -> bool {
        if let Some((payload, c)) = Self::try_read_packet(&self.client_buf) {
            // Late attach recovery: if we already see a command packet, auth is done.
            // Drain a single pending auth ACK from server to avoid response misalignment.
            if !payload.is_empty()
                && matches!(payload[0], COM_QUERY | COM_STMT_PREPARE | COM_STMT_EXECUTE)
            {
                if let Some((server_payload, server_consumed)) =
                    Self::try_read_packet(&self.server_buf)
                    && !server_payload.is_empty()
                    && (server_payload[0] == OK_MARKER || server_payload[0] == ERR_MARKER)
                {
                    self.server_buf.consume(server_consumed);
                }
                self.state = State::Ready;
                return true;
            }
            // HandshakeResponse41: capability flags first.
            if self.client_caps.is_none() && payload.len() >= 32 {
                let caps = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                if caps & CLIENT_PROTOCOL_41 != 0 {
                    self.client_caps = Some(caps);
                }
            }
            self.client_buf.consume(c);
        }
        let (payload, consumed) = match Self::try_read_packet(&self.server_buf) {
            Some(p) => p,
            None => return false,
        };
        self.server_buf.consume(consumed);
        if !payload.is_empty() && (payload[0] == OK_MARKER || payload[0] == ERR_MARKER) {
            self.state = State::Ready;
            return true;
        }
        // Auth continues: AuthMoreData (caching_sha2_password, MySQL 8's
        // default: 0x01 0x03 = fast-auth ok, then an OK follows) or
        // AuthSwitchRequest. Treating these as "auth done" left the real OK
        // queued, so every later response paired with the previous query.
        if !payload.is_empty() && (payload[0] == AUTH_MORE_DATA || payload[0] == EOF_MARKER) {
            return true;
        }
        // Recovery: if auth response shape is unexpected, avoid getting stuck in InAuth.
        self.state = State::Ready;
        true
    }

    fn parse_command(&mut self, ts: u64) -> bool {
        let (payload, consumed) = match Self::try_read_packet(&self.client_buf) {
            Some(p) => p,
            None => return false,
        };
        self.client_buf.consume(consumed);
        if payload.is_empty() {
            return false;
        }
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
                self.start_execute(&payload);
                self.begin(Pending::Query, ts);
            }
            COM_STMT_CLOSE => {
                if let Some(id) = payload.get(1..5) {
                    self.prepared
                        .remove(&u32::from_le_bytes([id[0], id[1], id[2], id[3]]));
                }
            }
            COM_INIT_DB | COM_PING | COM_STMT_RESET | COM_SET_OPTION | COM_RESET_CONNECTION => {
                if payload[0] == COM_RESET_CONNECTION {
                    self.prepared.clear();
                }
                self.begin(Pending::Simple, ts);
            }
            // SEND_LONG_DATA and QUIT have no response; other commands are
            // not parsed.
            _ => {}
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
            let Some((payload, consumed)) = Self::try_read_packet(&self.server_buf) else {
                return false;
            };
            match step {
                DefSkip::Packets(n) => {
                    self.server_buf.consume(consumed);
                    if n > 1 {
                        self.skip_defs[0] = DefSkip::Packets(n - 1);
                    } else {
                        self.skip_defs.pop_front();
                    }
                }
                DefSkip::OptionalEof => {
                    if is_eof(&payload) {
                        self.server_buf.consume(consumed);
                    }
                    self.skip_defs.pop_front();
                }
            }
        }
        self.state = State::Ready;
        true
    }

    fn parse_response(&mut self, ts: u64) -> Option<L7Message> {
        let (payload, consumed) = Self::try_read_packet(&self.server_buf)?;
        if payload.is_empty() {
            self.server_buf.consume(consumed);
            return None;
        }
        match self.pending {
            Pending::Simple => {
                self.server_buf.consume(consumed);
                self.query_text = None;
                self.query_ts = None;
                self.state = State::Ready;
                return None;
            }
            Pending::Prepare if payload[0] == OK_MARKER && payload.len() >= 12 => {
                // COM_STMT_PREPARE_OK: [0x00][id:4][columns:2][params:2]...
                self.server_buf.consume(consumed);
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
                return None;
            }
            _ => {}
        }
        match payload[0] {
            OK_MARKER => {
                self.server_buf.consume(consumed);
                let mut m = self.build_msg(ts);
                m.status = Some(0);
                Some(m)
            }
            ERR_MARKER => {
                self.server_buf.consume(consumed);
                let mut m = self.build_msg(ts);
                if payload.len() >= 3 {
                    m.status = Some(u16::from_le_bytes([payload[1], payload[2]]) as u32);
                }
                if payload.len() > 9 && payload[3] == b'#' {
                    m.payload_text = Some(String::from_utf8_lossy(&payload[9..]).into_owned());
                } else if payload.len() > 3 {
                    m.payload_text = Some(String::from_utf8_lossy(&payload[3..]).into_owned());
                }
                Some(m)
            }
            _ => {
                self.server_buf.consume(consumed);
                match decode_lenenc(&payload) {
                    Some(cols) => {
                        self.state = State::InResponse {
                            cols_expected: cols as usize,
                            cols_received: 0,
                            past_col_eof: false,
                        };
                    }
                    None => {
                        // Malformed packet — insufficient bytes for lenenc integer.
                        // Treat as no result set; stay Ready so the connection survives.
                        self.state = State::Ready;
                    }
                }
                None
            }
        }
    }

    fn read_result_set(&mut self, ts: u64, ce: usize, mut cr: usize, mut past: bool) -> RsResult {
        loop {
            let (payload, consumed) = match Self::try_read_packet(&self.server_buf) {
                Some(p) => p,
                None => return RsResult::Progress(ce, cr, past),
            };
            self.server_buf.consume(consumed);
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
            if is_eof(&payload) || payload[0] == ERR_MARKER {
                let mut m = self.build_msg(ts);
                if payload[0] == ERR_MARKER && payload.len() >= 3 {
                    m.status = Some(u16::from_le_bytes([payload[1], payload[2]]) as u32);
                } else {
                    m.status = Some(0);
                }
                return RsResult::Done(m);
            }
        }
    }

    fn build_msg(&mut self, ts: u64) -> L7Message {
        let mut msg = L7Message::new(Protocol::Mysql, Direction::Ingress, ts);
        msg.request_text = self.param_text.take();
        msg.method = Some("QUERY".into());
        if let Some(q) = self.query_text.take() {
            if let Some(cmd) = q.split_whitespace().next() {
                msg.method = Some(cmd.to_uppercase());
            }
            msg.payload_text = Some(super::truncate_utf8(&q, 4096).to_string());
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
        }
    }
}

enum RsResult {
    Done(L7Message),
    Progress(usize, usize, bool),
    Need,
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
            // Lost part of a response, typically a large result set in a
            // GSO super-packet: rows are not needed, wait for the next command.
            (Direction::Ingress, State::InQuery | State::InResponse { .. }) => {
                self.server_buf.clear();
                self.resync_server = true;
                Some(ParseResult::NeedMoreData)
            }
            _ => None,
        }
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
                assert_eq!(m[0].status, Some(1064));
                assert!(m[0].payload_text.as_ref().unwrap().contains("syntax error"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
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

        // Server OK response should still produce a MySQL message.
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
                assert_eq!(m[0].status, Some(0));
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
}
