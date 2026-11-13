#![allow(dead_code)]

//! PostgreSQL wire protocol parser.
//!
//! Wire format: 1-byte message type + 4-byte length + payload.
//! StartupMessage has no type byte (length + protocol version instead).

use std::collections::{HashMap, VecDeque};

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

#[derive(Debug, Clone, PartialEq)]
enum State {
    WaitingForStartup,
    InAuth,
    Ready,
    InSimpleQuery,
    InExtendedQuery,
    InResponse,
    /// SSL/GSS encryption was accepted: the rest of the stream is ciphertext.
    Encrypted,
}

/// Special startup-phase request codes (in place of the protocol version).
const CANCEL_REQUEST_CODE: u32 = 80877102;
const SSL_REQUEST_CODE: u32 = 80877103;
const GSSENC_REQUEST_CODE: u32 = 80877104;

pub struct PostgresParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    server_version: Option<String>,
    query_ts: Option<u64>,
    query_text: Option<String>,
    /// Error message accumulated from `E` (ErrorResponse) — emitted on `Z` (ReadyForQuery).
    pending_error: Option<String>,
    /// Non-zero status from `E`; overrides the default success status on emit.
    pending_status: Option<u32>,
    /// An SSLRequest/GSSENCRequest was sent: the server answers with a single
    /// unframed byte ('S'/'G' = encrypt, 'N' = no) before anything else.
    awaiting_encryption_reply: bool,
    /// Server bytes were lost mid-response (capture gap): discard until the
    /// next ReadyForQuery, which ends every query cycle.
    resync_server: bool,
    /// Named prepared statements the server accepted (ParseComplete): name
    /// -> SQL. Lets a Bind/Execute cycle that reuses a statement (no Parse —
    /// what ORMs and drivers do after preparing) be attributed to its query.
    /// A name being re-Parsed or Closed is removed at once: until the server
    /// confirms, its SQL is unknown and a Bind of it exports no values.
    prepared: HashMap<String, String>,
    /// What the server still has to answer, in the order the client sent
    /// it: each Parse (several may come before one Sync) and each Sync or
    /// simple Query, whose answer is a ReadyForQuery. Read from the client
    /// bytes as they arrive (`scanned`), whatever the parser's state.
    pending: VecDeque<Pending>,
    /// Bytes at the front of `client_buf` already read into `pending`.
    scanned: usize,
    /// The server's answers could not be matched to the client's messages
    /// at some point (a connection joined mid-stream, a response gap,
    /// `pending` overflowing, an answer that matched nothing): no Parse is
    /// committed for the rest of the connection, so no bound value is
    /// exported on it.
    parses_lost: bool,
    /// Text-format parameter values from the current cycle's Bind message,
    /// and the SQL it was sent against. Applications send their data here,
    /// not in the SQL text. Exported only when that SQL is confirmed and is
    /// the SQL the event shows.
    bind_params: Option<(BindSql, String)>,
    /// The SQL of each Bind read from the client but not consumed yet, in
    /// order.
    binds: VecDeque<BindSql>,
    /// Id of the next Parse read.
    next_parse: u64,
    /// The last statement built had credential context and was withheld.
    statement_withheld: bool,
}

/// Max named statements remembered per connection.
const MAX_PREPARED_STATEMENTS: usize = 256;
/// Max bytes of bind-parameter text kept per query.
const MAX_BIND_TEXT: usize = 64 * 1024;

/// Text-format parameter values of a Bind message, joined for PII scanning.
/// Bind: portal\0 statement\0 i16 nfmt, i16 fmt[nfmt], i16 nparams,
/// (i32 len, bytes)[nparams], ... Binary-format values are skipped.
fn bind_param_text(payload: &[u8]) -> Option<String> {
    let mut pos = payload.iter().position(|&b| b == 0)? + 1;
    pos += payload[pos..].iter().position(|&b| b == 0)? + 1;
    let i16_at = |p: usize| {
        payload
            .get(p..p + 2)
            .map(|b| i16::from_be_bytes([b[0], b[1]]))
    };
    let nfmt = i16_at(pos)?.max(0) as usize;
    let formats: Vec<i16> = (0..nfmt)
        .map(|i| i16_at(pos + 2 + 2 * i))
        .collect::<Option<_>>()?;
    pos += 2 + 2 * nfmt;
    let nparams = i16_at(pos)?.max(0) as usize;
    pos += 2;
    let mut values = Vec::new();
    let mut total = 0;
    for i in 0..nparams {
        let len = payload
            .get(pos..pos + 4)
            .map(|b| i32::from_be_bytes([b[0], b[1], b[2], b[3]]))?;
        pos += 4;
        if len < 0 {
            continue; // NULL
        }
        let value = payload.get(pos..pos + len as usize)?;
        pos += len as usize;
        // One format code applies to all params; otherwise one per param.
        let format = match formats.len() {
            0 => 0,
            1 => formats[0],
            _ => *formats.get(i).unwrap_or(&0),
        };
        if format == 0 && total < MAX_BIND_TEXT {
            let text = String::from_utf8_lossy(value);
            total += text.len();
            values.push(text.into_owned());
        }
    }
    (!values.is_empty()).then(|| values.join(", "))
}

/// ReadyForQuery header: 'Z', length 5; followed by the status byte.
const READY_FOR_QUERY: &[u8] = b"Z\x00\x00\x00\x05";

/// A client message the server answers in order.
enum Pending {
    /// A Parse: its id, name ("" for the unnamed statement) and SQL,
    /// entered into `prepared` by its ParseComplete; the SQL is None when a
    /// later Close of the name or a simple Query cancelled it.
    Parse(u64, String, Option<String>),
    /// A Sync or a simple Query: answered by a ReadyForQuery.
    Sync,
}

/// The SQL a Bind was sent against, fixed when the Bind is read: the
/// statement's confirmed SQL at that point of the client's stream, or the
/// SQL of the latest Parse of that name before it, which must then be
/// confirmed (`awaits`, its id) before the values are exported.
struct BindSql {
    sql: Option<String>,
    awaits: Option<u64>,
}

/// Most client messages awaiting an answer that are tracked.
const MAX_PENDING: usize = 4096;

/// Offset of a ReadyForQuery message (header + I/T/E status) in `data`.
fn find_ready_for_query(data: &[u8]) -> Option<usize> {
    data.windows(READY_FOR_QUERY.len() + 1).position(|w| {
        w.starts_with(READY_FOR_QUERY) && matches!(w[READY_FOR_QUERY.len()], b'I' | b'T' | b'E')
    })
}

impl PostgresParser {
    pub fn new() -> Self {
        Self {
            state: State::WaitingForStartup,
            client_buf: StreamBuffer::new(),
            server_buf: StreamBuffer::new(),
            server_version: None,
            awaiting_encryption_reply: false,
            resync_server: false,
            prepared: HashMap::new(),
            pending: VecDeque::new(),
            scanned: 0,
            parses_lost: false,
            bind_params: None,
            binds: VecDeque::new(),
            next_parse: 0,
            statement_withheld: false,
            query_ts: None,
            query_text: None,
            pending_error: None,
            pending_status: None,
        }
    }

    /// Read a standard backend message: type(1) + length(4) + payload
    fn try_read_backend_msg(buf: &StreamBuffer) -> Option<(u8, Vec<u8>, usize)> {
        let data = buf.data();
        if data.len() < 5 {
            return None;
        }
        let msg_type = data[0];
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if len < 4 {
            return None;
        }
        let total = 1 + len;
        if data.len() < total {
            return None;
        }
        let payload = data[5..total].to_vec();
        Some((msg_type, payload, total))
    }

    /// Read a frontend message: type(1) + length(4) + payload
    fn try_read_frontend_msg(buf: &StreamBuffer) -> Option<(u8, Vec<u8>, usize)> {
        Self::try_read_backend_msg(buf) // same format
    }

    /// Read a startup message (no type byte): length(4) + version(4) + params
    fn try_read_startup(buf: &StreamBuffer) -> Option<(Vec<u8>, usize)> {
        let data = buf.data();
        if data.len() < 8 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if !(8..=10000).contains(&len) {
            return None;
        }
        if data.len() < len {
            return None;
        }
        Some((data[4..len].to_vec(), len))
    }

    fn process(&mut self, ts: u64) -> ParseResult {
        let mut messages = Vec::new();
        loop {
            if matches!(
                self.state,
                State::Ready | State::InSimpleQuery | State::InExtendedQuery | State::InResponse
            ) {
                self.scan_client();
            }
            match self.state.clone() {
                State::WaitingForStartup => {
                    if !self.handle_startup() {
                        break;
                    }
                }
                State::InAuth => {
                    if !self.handle_auth() {
                        break;
                    }
                }
                State::Ready => {
                    if !self.handle_ready(ts) {
                        break;
                    }
                }
                State::Encrypted => {
                    self.client_buf.clear();
                    self.scanned = 0;
                    self.server_buf.clear();
                    break;
                }
                State::InSimpleQuery | State::InExtendedQuery | State::InResponse
                    if self.resync_server
                        && matches!(self.client_buf.data().first(), Some(b'Q' | b'P' | b'B'))
                        && find_ready_for_query(self.server_buf.data()).is_none() =>
                {
                    // Resyncing after a gap and the client already started the
                    // next query (Q, P, or B for a reused prepared statement —
                    // the current cycle's own Bind was absorbed with its Parse):
                    // the previous cycle's ReadyForQuery was in the bytes we
                    // never captured. Close the previous query now.
                    let mut msg = self.build_msg(ts);
                    msg.status = Some(self.pending_status.take().unwrap_or(0));
                    // Closed by the next query, not by ReadyForQuery: the real
                    // latency is unknown.
                    msg.latency_ns = None;
                    self.pending_error = None;
                    messages.push(msg);
                    self.server_buf.clear();
                    self.resync_server = false;
                    self.state = State::Ready;
                }
                State::InSimpleQuery | State::InExtendedQuery | State::InResponse => {
                    match self.handle_response(ts) {
                        Some(msg) => {
                            messages.push(msg);
                            self.state = State::Ready;
                        }
                        None => break,
                    }
                }
            }
        }
        if messages.is_empty() {
            ParseResult::NeedMoreData
        } else {
            ParseResult::Messages(messages)
        }
    }

    fn handle_startup(&mut self) -> bool {
        // libpq (sslmode=prefer, the default) and most drivers open with an
        // SSLRequest; the server replies with ONE unframed byte. Reading that
        // byte as a framed message misaligned every later server message.
        if self.awaiting_encryption_reply {
            let Some(&reply) = self.server_buf.data().first() else {
                return false;
            };
            self.server_buf.consume(1);
            self.awaiting_encryption_reply = false;
            if reply == b'S' || reply == b'G' {
                self.state = State::Encrypted;
            }
            // 'N': the real StartupMessage follows in cleartext.
            return true;
        }

        // Joined mid-connection (the agent started after the client connected —
        // the norm for pooled connections): there is no startup message, the
        // client is already sending typed messages. StartupMessage and
        // SSLRequest begin with a big-endian length whose first byte is 0;
        // every later frontend message begins with a non-zero type byte.
        if self.client_buf.data().first().is_some_and(|&b| b != 0) {
            self.state = State::Ready;
            // Answers to messages sent before capture may still come.
            self.parses_lost = true;
            return true;
        }

        // Try reading startup from client
        if let Some((payload, consumed)) = Self::try_read_startup(&self.client_buf) {
            self.client_buf.consume(consumed);
            let code = payload
                .get(..4)
                .map_or(0, |c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
            match code {
                SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => self.awaiting_encryption_reply = true,
                CANCEL_REQUEST_CODE => {} // one-shot connection, nothing follows
                _ => self.state = State::InAuth,
            }
            return true;
        }
        // Also check if server sends first (e.g., SSL response)
        if let Some((msg_type, _payload, consumed)) = Self::try_read_backend_msg(&self.server_buf) {
            self.server_buf.consume(consumed);
            if msg_type == b'N' || msg_type == b'S' {
                // N = SSL not supported, S = SSL supported, or ParameterStatus
                return true;
            }
        }
        false
    }

    fn handle_auth(&mut self) -> bool {
        // Consume client auth messages
        while let Some((_type, _payload, consumed)) = Self::try_read_frontend_msg(&self.client_buf)
        {
            self.client_buf.consume(consumed);
        }

        // Process server messages
        while let Some((msg_type, payload, consumed)) = Self::try_read_backend_msg(&self.server_buf)
        {
            self.server_buf.consume(consumed);
            match msg_type {
                b'R' => {
                    // Authentication messages
                    if payload.len() >= 4 {
                        let auth_type =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if auth_type == 0 {
                            // AuthenticationOk — but don't transition yet, wait for ReadyForQuery
                        }
                    }
                }
                b'S' => {
                    // ParameterStatus: name\0value\0
                    self.parse_parameter_status(&payload);
                }
                b'K' => {} // BackendKeyData — skip
                b'Z' => {
                    // ReadyForQuery — auth complete
                    self.state = State::Ready;
                    return true;
                }
                b'E' => {
                    // ErrorResponse during auth
                    self.state = State::Ready;
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Consume the rest of the current extended-protocol cycle that the client
    /// sent along with Parse/Bind (Bind, Describe, Execute, Flush, Sync,
    /// Close), recording Bind parameters. Stops at the next Parse/Query, which
    /// starts another cycle.
    fn absorb_extended_cycle(&mut self) {
        while let Some((msg_type, payload, consumed)) =
            Self::try_read_frontend_msg(&self.client_buf)
        {
            match msg_type {
                b'B' => self.bind_params = self.bound(&payload),
                b'C' | b'D' | b'E' | b'H' | b'S' => {}
                _ => break,
            }
            self.consume_client(consumed);
        }
    }

    /// A Bind being consumed: the SQL it was read against (taken from
    /// `binds` whether or not it has values) and its text-format values.
    fn bound(&mut self, payload: &[u8]) -> Option<(BindSql, String)> {
        let bind = self.binds.pop_front().unwrap_or(BindSql {
            sql: None,
            awaits: None,
        });
        Some((bind, bind_param_text(payload)?))
    }

    fn consume_client(&mut self, n: usize) {
        self.client_buf.consume(n);
        self.scanned = self.scanned.saturating_sub(n);
    }

    /// Read the client messages that arrived since the last call into
    /// `pending`. A Parse or a Close of a statement forgets it at once
    /// (its SQL is unknown until the server confirms); a Close also stops
    /// an earlier Parse of that name from being committed.
    fn scan_client(&mut self) {
        let data = self.client_buf.data();
        let mut at = self.scanned;
        while let Some(head) = data.get(at..at + 5) {
            let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
            let Some(payload) = data.get(at + 5..at + 1 + len.max(4)) else {
                break;
            };
            at += 1 + len.max(4);
            let entry = match head[0] {
                b'P' => {
                    let name = extract_string(payload);
                    self.prepared.remove(&name);
                    let sql = extract_second_string(payload);
                    self.next_parse += 1;
                    Pending::Parse(self.next_parse, name, Some(sql))
                }
                b'B' => {
                    // The SQL this Bind runs: the latest Parse of its name
                    // still unanswered, else the confirmed statement.
                    let name = extract_second_string(payload);
                    let parse = self.pending.iter().rev().find_map(|p| match p {
                        Pending::Parse(id, n, sql) if *n == name => Some((*id, sql.clone())),
                        _ => None,
                    });
                    let bind = match parse {
                        Some((id, sql)) => BindSql {
                            sql,
                            awaits: Some(id),
                        },
                        None => BindSql {
                            sql: self.prepared.get(&name).cloned(),
                            awaits: None,
                        },
                    };
                    self.binds.push_back(bind);
                    continue;
                }
                b'S' => Pending::Sync,
                b'Q' => {
                    // SQL PREPARE / DEALLOCATE may redefine any name, and a
                    // simple Query ends the unnamed statement: forget every
                    // statement, confirmed or pending.
                    self.prepared.clear();
                    for p in self.pending.iter_mut() {
                        if let Pending::Parse(_, _, sql) = p {
                            *sql = None;
                        }
                    }
                    Pending::Sync
                }
                b'C' if payload.first() == Some(&b'S') => {
                    let name = extract_string(&payload[1..]);
                    self.prepared.remove(&name);
                    for p in self.pending.iter_mut() {
                        if let Pending::Parse(_, n, sql) = p
                            && *n == name
                        {
                            *sql = None;
                        }
                    }
                    continue;
                }
                _ => continue,
            };
            if self.pending.len() == MAX_PENDING {
                // As lose_parses (data still borrows client_buf).
                self.parses_lost = true;
                self.pending.clear();
            }
            if !self.parses_lost {
                self.pending.push_back(entry);
            }
        }
        self.scanned = at;
    }

    /// The answers' order is no longer known: no Parse is committed for
    /// the rest of the connection.
    fn lose_parses(&mut self) {
        self.parses_lost = true;
        self.pending.clear();
    }

    fn handle_ready(&mut self, ts: u64) -> bool {
        let (msg_type, payload, consumed) = match Self::try_read_frontend_msg(&self.client_buf) {
            Some(m) => m,
            None => return false,
        };
        self.consume_client(consumed);

        match msg_type {
            b'Q' => {
                // Simple Query
                let query = extract_string(&payload);
                self.query_text = Some(query);
                self.query_ts = Some(ts);
                self.state = State::InSimpleQuery;
                true
            }
            b'P' => {
                // Parse (extended query): name\0 + query\0 + param types
                let query = extract_second_string(&payload);
                self.query_text = Some(query);
                self.query_ts = Some(ts);
                self.state = State::InExtendedQuery;
                self.absorb_extended_cycle();
                true
            }
            b'B' => {
                // Bind without Parse: execution of an already-prepared statement.
                let statement = extract_second_string(&payload);
                let bind = self.bound(&payload);
                if let Some(query) = self.prepared.get(&statement) {
                    self.query_text = Some(query.clone());
                    self.query_ts = Some(ts);
                    self.bind_params = bind;
                    self.state = State::InExtendedQuery;
                    self.absorb_extended_cycle();
                }
                true
            }
            // Describe, Execute, Flush, Sync, Close outside a tracked cycle
            // (a Close was applied when it was read into `pending`).
            b'C' | b'D' | b'E' | b'H' | b'S' => true,
            b'X' => false, // Terminate
            _ => true,
        }
    }

    fn handle_response(&mut self, ts: u64) -> Option<L7Message> {
        if self.resync_server {
            let data = self.server_buf.data();
            match find_ready_for_query(data) {
                Some(off) => {
                    self.server_buf.consume(off);
                    self.resync_server = false;
                }
                None => {
                    // Keep a tail in case the marker is split across packets.
                    let keep = READY_FOR_QUERY.len();
                    let drop = data.len().saturating_sub(keep);
                    self.server_buf.consume(drop);
                    return None;
                }
            }
        }
        loop {
            let (msg_type, payload, consumed) = Self::try_read_backend_msg(&self.server_buf)?;
            self.server_buf.consume(consumed);

            match msg_type {
                b'T' => {} // RowDescription — skip
                b'D' => {} // DataRow — skip
                b'C' => {
                    // CommandComplete: tag\0
                    let _tag = extract_string(&payload);
                    // Don't emit yet — wait for ReadyForQuery
                }
                b'1' if !self.parses_lost => {
                    // ParseComplete answers the oldest Parse pending (the
                    // unnamed statement is kept under "").
                    match self.pending.pop_front() {
                        Some(Pending::Parse(id, name, sql)) => {
                            // Binds sent against this Parse may export now.
                            let current = self.bind_params.as_mut().map(|(b, _)| b);
                            for b in self.binds.iter_mut().chain(current) {
                                if b.awaits == Some(id) {
                                    b.awaits = None;
                                }
                            }
                            if let Some(sql) = sql
                                && (name.is_empty()
                                    || self.prepared.len() < MAX_PREPARED_STATEMENTS)
                            {
                                self.prepared.insert(name, sql);
                            }
                        }
                        Some(Pending::Sync) | None => self.lose_parses(),
                    }
                }
                b'1' => {}
                b'E' => {
                    // The server skips to the Sync: the Parses before it
                    // failed or never ran.
                    while matches!(self.pending.front(), Some(Pending::Parse(..))) {
                        self.pending.pop_front();
                    }
                    // ErrorResponse — stash the error; emit on ReadyForQuery so query_text
                    // isn't consumed here (build_msg would clear it via take()).
                    self.pending_error = Some(parse_error_response(&payload));
                    self.pending_status = Some(1);
                }
                b'Z' => {
                    // The Sync (or Query) it answers, and any Parse before it
                    // left unanswered.
                    match self.pending.iter().position(|p| matches!(p, Pending::Sync)) {
                        Some(i) => {
                            self.pending.drain(..=i);
                        }
                        None if self.parses_lost => {}
                        None => self.lose_parses(),
                    }
                    // ReadyForQuery — build message from accumulated query state + any error.
                    let mut msg = self.build_msg(ts);
                    msg.status = Some(self.pending_status.take().unwrap_or(0));
                    if let Some(err) = self.pending_error.take() {
                        // Error message takes precedence over query text in
                        // payload_text; it may quote the statement.
                        msg.payload_text =
                            Some(super::export_error_text(err, self.statement_withheld));
                    }
                    return Some(msg);
                }
                b'S' => {
                    // ParameterStatus (can arrive during query)
                    self.parse_parameter_status(&payload);
                }
                b'I' => {}                             // EmptyQueryResponse
                b'2' | b'3' | b'n' | b's' | b't' => {} // Extended query sub-responses
                _ => {}
            }
        }
    }

    fn parse_parameter_status(&mut self, payload: &[u8]) {
        // Format: name\0value\0
        if let Some(null_pos) = payload.iter().position(|&b| b == 0) {
            let name = String::from_utf8_lossy(&payload[..null_pos]);
            if name == "server_version" && null_pos + 1 < payload.len() {
                let rest = &payload[null_pos + 1..];
                if let Some(end) = rest.iter().position(|&b| b == 0) {
                    self.server_version = Some(String::from_utf8_lossy(&rest[..end]).into_owned());
                } else {
                    self.server_version = Some(String::from_utf8_lossy(rest).into_owned());
                }
            }
        }
    }

    fn build_msg(&mut self, ts: u64) -> L7Message {
        let mut msg = L7Message::new(Protocol::Postgres, Direction::Ingress, ts);
        msg.method = Some("QUERY".into());
        // Bound values only under the SQL their Bind was sent against, once
        // confirmed, and only when that is the SQL this event shows: a Bind
        // of another statement, or of one the server did not confirm,
        // exports none, and values are never paired with other SQL.
        let bound = self.bind_params.take().and_then(|(bind, values)| {
            (!self.parses_lost
                && bind.awaits.is_none()
                && bind.sql.is_some()
                && bind.sql == self.query_text)
                .then_some(values)
        });
        self.statement_withheld = false;
        match self.query_text.take() {
            Some(q) => {
                let (verb, shown, bound, withheld) = super::export_statement(q, bound);
                msg.method = verb.or(msg.method);
                msg.payload_text = Some(shown);
                msg.request_text = bound;
                self.statement_withheld = withheld;
            }
            None => msg.request_text = None,
        }
        if let Some(t) = self.query_ts.take() {
            msg.latency_ns = Some(ts.saturating_sub(t));
        }
        msg
    }

    fn current_state(&self) -> &'static str {
        match self.state {
            State::WaitingForStartup => "waiting_for_startup",
            State::InAuth => "in_auth",
            State::Ready => "ready",
            State::InSimpleQuery => "in_simple_query",
            State::InExtendedQuery => "in_extended_query",
            State::InResponse => "in_response",
            State::Encrypted => "encrypted",
        }
    }
}

fn extract_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn extract_second_string(data: &[u8]) -> String {
    // Skip first null-terminated string, return second
    if let Some(first_null) = data.iter().position(|&b| b == 0) {
        let rest = &data[first_null + 1..];
        extract_string(rest)
    } else {
        extract_string(data)
    }
}

fn parse_error_response(data: &[u8]) -> String {
    // ErrorResponse: series of type(1) + string\0, terminated by \0
    let mut message = String::new();
    let mut i = 0;
    while i < data.len() && data[i] != 0 {
        let field_type = data[i] as char;
        i += 1;
        let end = data[i..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - i);
        let value = String::from_utf8_lossy(&data[i..i + end]);
        if field_type == 'M' {
            message = value.into_owned();
        }
        i += end + 1;
    }
    message
}

impl ProtocolParser for PostgresParser {
    fn feed(&mut self, data: &[u8], direction: Direction, ts: u64) -> ParseResult {
        match direction {
            Direction::Ingress => {
                if self.server_buf.extend(data).is_err() {
                    return ParseResult::Error("PG server buffer overflow".into());
                }
            }
            Direction::Egress => {
                if self.client_buf.extend(data).is_err() {
                    return ParseResult::Error("PG client buffer overflow".into());
                }
            }
        }
        self.process(ts)
    }
    fn skip(&mut self, direction: Direction, _n: usize, _timestamp_ns: u64) -> Option<ParseResult> {
        match (direction, &self.state) {
            // Lost part of a response (typically a large result set in a
            // GSO super-packet): the row data is not needed, so drop the
            // partial message and resync on the closing ReadyForQuery.
            (
                Direction::Ingress,
                State::InSimpleQuery | State::InExtendedQuery | State::InResponse,
            ) => {
                self.server_buf.clear();
                self.resync_server = true;
                // Answers among the lost bytes: their order is unknown.
                self.lose_parses();
                Some(ParseResult::NeedMoreData)
            }
            (_, State::Encrypted) => Some(ParseResult::NeedMoreData),
            _ => None,
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Postgres
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
    use super::*;

    fn make_backend_msg(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let len = (4 + payload.len()) as u32;
        let mut pkt = vec![msg_type];
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    fn make_frontend_msg(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        make_backend_msg(msg_type, payload) // same format
    }

    fn make_startup_msg() -> Vec<u8> {
        // length(4) + version 3.0(4) + "user\0test\0\0"
        let params = b"user\0test\0\0";
        let len = (8 + params.len()) as u32;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&196608u32.to_be_bytes()); // v3.0
        pkt.extend_from_slice(params);
        pkt
    }

    fn setup_ready_parser() -> PostgresParser {
        let mut p = PostgresParser::new();
        // Feed startup
        p.feed(&make_startup_msg(), Direction::Egress, 0);
        // Feed auth ok
        p.feed(
            &make_backend_msg(b'R', &0u32.to_be_bytes()),
            Direction::Ingress,
            0,
        );
        // Feed ParameterStatus for server_version
        let mut param = b"server_version\0".to_vec();
        param.extend_from_slice(b"15.4\0");
        p.feed(&make_backend_msg(b'S', &param), Direction::Ingress, 0);
        // Feed ReadyForQuery
        p.feed(&make_backend_msg(b'Z', b"I"), Direction::Ingress, 0);
        p
    }

    fn make_ssl_request() -> Vec<u8> {
        let mut pkt = 8u32.to_be_bytes().to_vec();
        pkt.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        pkt
    }

    #[test]
    fn test_ssl_request_declined_then_query() {
        // libpq default (sslmode=prefer) against a server without SSL.
        let mut p = PostgresParser::new();
        p.feed(&make_ssl_request(), Direction::Egress, 0);
        p.feed(b"N", Direction::Ingress, 0);
        p.feed(&make_startup_msg(), Direction::Egress, 0);
        let mut auth = make_backend_msg(b'R', &0u32.to_be_bytes());
        auth.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        p.feed(&auth, Direction::Ingress, 0);
        assert_eq!(p.state, State::Ready);

        p.feed(
            &make_frontend_msg(b'Q', b"SELECT 1\0"),
            Direction::Egress,
            1000,
        );
        let mut resp = make_backend_msg(b'C', b"SELECT 1\0");
        resp.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        match p.feed(&resp, Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => assert_eq!(msgs[0].method.as_deref(), Some("SELECT")),
            other => panic!("expected a message after SSL negotiation, got {other:?}"),
        }
    }

    #[test]
    fn test_gap_in_large_result_resyncs_on_ready_for_query() {
        let mut p = setup_ready_parser();
        p.feed(
            &make_frontend_msg(b'Q', b"SELECT * FROM big\0"),
            Direction::Egress,
            1000,
        );
        // First captured part of the result: a partial DataRow stream...
        let mut part = make_backend_msg(b'T', &[0, 1, b'c', 0]);
        part.extend_from_slice(&make_backend_msg(b'D', &[0u8; 40])[..20]);
        p.feed(&part, Direction::Ingress, 1500);
        // ...then bytes the capture never saw.
        assert!(matches!(
            p.skip(Direction::Ingress, 60_000, 1600),
            Some(ParseResult::NeedMoreData)
        ));
        // Tail of a row, CommandComplete, ReadyForQuery.
        let mut tail = vec![7u8; 13];
        tail.extend_from_slice(&make_backend_msg(b'C', b"SELECT 900\0"));
        tail.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        match p.feed(&tail, Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected the query's message after resync, got {other:?}"),
        }
        assert_eq!(p.state, State::Ready);
    }

    #[test]
    fn test_gap_swallowing_ready_for_query_closes_on_next_query() {
        // The ReadyForQuery was in the truncated tail: the next thing seen is
        // the client's next query, which must pair with its own response.
        let mut p = setup_ready_parser();
        p.feed(
            &make_frontend_msg(b'Q', b"SELECT * FROM big\0"),
            Direction::Egress,
            1000,
        );
        p.feed(
            &make_backend_msg(b'T', &[0, 1, b'c', 0]),
            Direction::Ingress,
            1500,
        );
        let _ = p.skip(Direction::Ingress, 60_000, 1600);
        let first = p.feed(
            &make_frontend_msg(b'Q', b"UPDATE t SET a = 1\0"),
            Direction::Egress,
            3000,
        );
        let ParseResult::Messages(msgs) = first else {
            panic!("previous query must be closed, got {first:?}");
        };
        assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
        assert_eq!(msgs[0].latency_ns, None);
        let mut resp = make_backend_msg(b'C', b"UPDATE 1\0");
        resp.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        match p.feed(&resp, Direction::Ingress, 3500) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].method.as_deref(), Some("UPDATE"));
                assert_eq!(msgs[0].latency_ns, Some(500));
            }
            other => panic!("expected UPDATE paired with its own response, got {other:?}"),
        }
    }

    /// Bind for `statement` with text-format parameters.
    fn make_bind(statement: &str, params: &[&str]) -> Vec<u8> {
        let mut b = b"\0".to_vec(); // unnamed portal
        b.extend_from_slice(statement.as_bytes());
        b.push(0);
        b.extend_from_slice(&0i16.to_be_bytes()); // all params text
        b.extend_from_slice(&(params.len() as i16).to_be_bytes());
        for v in params {
            b.extend_from_slice(&(v.len() as i32).to_be_bytes());
            b.extend_from_slice(v.as_bytes());
        }
        b.extend_from_slice(&0i16.to_be_bytes()); // result formats
        make_frontend_msg(b'B', &b)
    }

    fn extended_cycle(parse: Option<(&str, &str)>, statement: &str, params: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some((name, sql)) = parse {
            let mut body = format!("{name}\0{sql}\0").into_bytes();
            body.extend_from_slice(&0i16.to_be_bytes());
            out.extend(make_frontend_msg(b'P', &body));
        }
        out.extend(make_bind(statement, params));
        out.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        out.extend(make_frontend_msg(b'S', b""));
        out
    }

    fn insert_done() -> Vec<u8> {
        let mut r = make_backend_msg(b'1', b"");
        r.extend(make_backend_msg(b'2', b""));
        r.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        r.extend(make_backend_msg(b'Z', b"I"));
        r
    }

    #[test]
    fn test_bind_parameters_become_request_text() {
        let mut p = setup_ready_parser();
        let sql = "INSERT INTO users (email, name) VALUES ($1, $2)";
        p.feed(
            &extended_cycle(Some(("", sql)), "", &["jane@example.com", "Jane"]),
            Direction::Egress,
            1000,
        );
        match p.feed(&insert_done(), Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].method.as_deref(), Some("INSERT"));
                assert_eq!(
                    msgs[0].request_text.as_deref(),
                    Some("jane@example.com, Jane")
                );
            }
            other => panic!("expected INSERT, got {other:?}"),
        }
    }

    /// A credential statement exports no bound value (text format).
    #[test]
    fn test_credential_statement_drops_bound_values() {
        let mut p = setup_ready_parser();
        let sql = "UPDATE users SET password = $1 WHERE id = 1";
        p.feed(
            &extended_cycle(Some(("", sql)), "", &["canary-bound"]),
            Direction::Egress,
            1000,
        );
        let ParseResult::Messages(msgs) = p.feed(&insert_done(), Direction::Ingress, 2000) else {
            panic!("expected a message");
        };
        assert_eq!(msgs[0].request_text, None, "{msgs:?}");
        assert_eq!(
            msgs[0].payload_text.as_deref(),
            Some("UPDATE <statement withheld>")
        );
    }

    #[test]
    fn test_reused_prepared_statement_is_captured() {
        // ORMs/drivers prepare once, then send only Bind/Execute/Sync.
        let mut p = setup_ready_parser();
        let sql = "INSERT INTO users (email) VALUES ($1)";
        p.feed(
            &extended_cycle(Some(("s1", sql)), "s1", &["a@example.com"]),
            Direction::Egress,
            1000,
        );
        p.feed(&insert_done(), Direction::Ingress, 1500);
        p.feed(
            &extended_cycle(None, "s1", &["b@example.com"]),
            Direction::Egress,
            2000,
        );
        // No Parse in this cycle, so no ParseComplete in its answer.
        let mut done = make_backend_msg(b'2', b"");
        done.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        done.extend(make_backend_msg(b'Z', b"I"));
        match p.feed(&done, Direction::Ingress, 2600) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs[0].method.as_deref(), Some("INSERT"));
                assert_eq!(msgs[0].payload_text.as_deref(), Some(sql));
                assert_eq!(msgs[0].request_text.as_deref(), Some("b@example.com"));
                assert_eq!(msgs[0].latency_ns, Some(600));
            }
            other => panic!("reused statement must produce a message, got {other:?}"),
        }
    }

    /// A Bind is paired with its statement's SQL only when the Parse was
    /// seen: not for a statement prepared before capture, and not after
    /// client bytes were lost (they may have re-Parsed the name with a
    /// credential statement).
    #[test]
    fn test_bind_against_unseen_parse_exports_no_values() {
        use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};
        let values = |r: Option<FsmResult>| match r {
            Some(FsmResult::MessageComplete(m)) => vec![m.request_text],
            Some(FsmResult::Messages(ms)) => ms.into_iter().map(|m| m.request_text).collect(),
            _ => vec![],
        };
        let mut p = PostgresParser::new();
        p.feed(
            &extended_cycle(None, "s1", &["canary-bound"]),
            Direction::Egress,
            1,
        );
        assert!(matches!(
            p.feed(&insert_done(), Direction::Ingress, 2),
            ParseResult::NeedMoreData
        ));

        let m = ConnectionFsmManager::new(4);
        m.get_or_create(1, Protocol::Postgres);
        let cycle = extended_cycle(Some(("s1", "SELECT $1")), "s1", &["x"]);
        m.process_packet(1, Direction::Egress, &cycle, 1);
        // Joined mid-stream (no startup seen): no Parse is learned on the
        // connection, so no bound value is exported on it.
        assert_eq!(
            values(m.process_packet(1, Direction::Ingress, &insert_done(), 2)),
            vec![None]
        );
        // Lost: Close s1, Parse s1 'ALTER ROLE app PASSWORD $1'.
        m.skip_from(1, (0, 0), Direction::Egress, 60, 3);
        let cycle = extended_cycle(None, "s1", &["canary-bound"]);
        m.process_packet(1, Direction::Egress, &cycle, 4);
        let out = values(m.process_packet(1, Direction::Ingress, &insert_done(), 5));
        assert!(
            out.iter().flatten().all(|v| !v.contains("canary")),
            "{out:?}"
        );
    }

    /// Codex: the statement cache follows the server, not the client. A
    /// Parse the server rejects (duplicate name) does not replace the
    /// statement; a Close forgets it; a full cache cannot keep a stale
    /// entry for a re-Parsed name. Binds of a statement whose SQL is not
    /// known for certain export no values.
    #[test]
    fn test_statement_cache_follows_the_server() {
        let bound = |p: &mut PostgresParser, resp: &[u8]| -> Vec<Option<String>> {
            p.feed(
                &extended_cycle(None, "s", &["canary-bound"]),
                Direction::Egress,
                5,
            );
            match p.feed(resp, Direction::Ingress, 6) {
                ParseResult::Messages(m) => m.into_iter().map(|m| m.request_text).collect(),
                _ => vec![],
            }
        };
        let no_canary = |v: &[Option<String>]| v.iter().flatten().all(|t| !t.contains("canary"));
        let mut rejected = make_backend_msg(b'E', b"SERROR\0C42P05\0Mduplicate\0\0");
        rejected.extend(make_backend_msg(b'Z', b"I"));

        // Rejected duplicate Parse.
        let mut p = setup_ready_parser();
        let pw = "INSERT INTO users (password) VALUES ($1)";
        p.feed(
            &extended_cycle(Some(("s", pw)), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1")), "s", &["y"]),
            Direction::Egress,
            3,
        );
        p.feed(&rejected, Direction::Ingress, 4);
        let out = bound(&mut p, &insert_done());
        assert!(no_canary(&out), "{out:?}");

        // Close.
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1")), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        let mut close = make_frontend_msg(b'C', b"Ss\0");
        close.extend(make_frontend_msg(b'S', b""));
        p.feed(&close, Direction::Egress, 3);
        let mut closed = make_backend_msg(b'3', b"");
        closed.extend(make_backend_msg(b'Z', b"I"));
        p.feed(&closed, Direction::Ingress, 4);
        let out = bound(&mut p, &insert_done());
        assert!(no_canary(&out), "{out:?}");

        // Full cache, then `s` re-Parsed (after a Close the agent missed).
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1")), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        for i in 0..MAX_PREPARED_STATEMENTS {
            let name = format!("f{i}");
            p.feed(
                &extended_cycle(Some((&name, "SELECT 1")), &name, &[]),
                Direction::Egress,
                3,
            );
            p.feed(&insert_done(), Direction::Ingress, 4);
        }
        p.feed(
            &extended_cycle(Some(("s", pw)), "s", &["x"]),
            Direction::Egress,
            5,
        );
        p.feed(&insert_done(), Direction::Ingress, 6);
        let out = bound(&mut p, &insert_done());
        assert!(no_canary(&out), "{out:?}");
    }

    /// Codex round 5 #7, #11: a ParseComplete commits only the Parse it
    /// answers. A Parse whose answer was lost, or that a Close in the same
    /// cycle closed, is never committed by a later acknowledgement.
    #[test]
    fn test_parse_complete_commits_only_its_parse() {
        let bound = |p: &mut PostgresParser| -> Vec<Option<String>> {
            p.feed(
                &extended_cycle(None, "s", &["canary-bound"]),
                Direction::Egress,
                9,
            );
            match p.feed(&insert_done(), Direction::Ingress, 10) {
                ParseResult::Messages(m) => m.into_iter().map(|m| m.request_text).collect(),
                _ => vec![],
            }
        };
        let no_canary = |v: &[Option<String>]| v.iter().flatten().all(|t| !t.contains("canary"));

        // #7: duplicate Parse of `s`, its rejection lost; an unnamed Parse's
        // ParseComplete must not commit `s = SELECT $1`.
        let mut p = setup_ready_parser();
        let pw = "INSERT INTO users(password) VALUES ($1)";
        p.feed(
            &extended_cycle(Some(("s", pw)), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1")), "s", &["y"]),
            Direction::Egress,
            3,
        );
        assert!(p.skip(Direction::Ingress, 40, 4).is_some());
        p.feed(
            &extended_cycle(Some(("", "SELECT 1")), "", &[]),
            Direction::Egress,
            5,
        );
        p.feed(&insert_done(), Direction::Ingress, 6);
        let out = bound(&mut p);
        assert!(no_canary(&out), "{out:?}");

        // #11: Parse `s`, Close `s`, Sync: the ParseComplete that follows
        // does not bring `s` back.
        let mut p = setup_ready_parser();
        let mut cycle = make_frontend_msg(b'P', b"s\0SELECT $1\0\0\0");
        cycle.extend(make_frontend_msg(b'C', b"Ss\0"));
        cycle.extend(make_frontend_msg(b'S', b""));
        p.feed(&cycle, Direction::Egress, 1);
        let mut resp = make_backend_msg(b'1', b"");
        resp.extend(make_backend_msg(b'3', b""));
        resp.extend(make_backend_msg(b'Z', b"I"));
        p.feed(&resp, Direction::Ingress, 2);
        let out = bound(&mut p);
        assert!(no_canary(&out), "{out:?}");
    }

    /// Parse `name` with `sql` and its Bind/Execute, no Sync.
    fn parse_bind(name: &str, sql: &str) -> Vec<u8> {
        let mut out = extended_cycle(Some((name, sql)), name, &[]);
        out.truncate(out.len() - 5); // drop the Sync
        out
    }

    /// Pipelines: several Parses before one Sync; each ParseComplete
    /// answers the oldest Parse pending. (Which statements are known is
    /// read from `prepared`: a pipeline's later cycles are exported one
    /// answer late, a separate limitation.)
    #[test]
    fn test_pipelined_parses_are_answered_in_order() {
        let ok = |n: usize| {
            let mut r = Vec::new();
            for _ in 0..n {
                r.extend(make_backend_msg(b'1', b""));
                r.extend(make_backend_msg(b'2', b""));
                r.extend(make_backend_msg(b'C', b"SELECT 1\0"));
            }
            r
        };
        let ready = || make_backend_msg(b'Z', b"I");
        let pipeline = |p: &mut PostgresParser, second: &str| {
            let mut batch = parse_bind("s1", "SELECT $1 AS one");
            batch.extend(parse_bind("s2", second));
            batch.extend(make_frontend_msg(b'S', b""));
            p.feed(&batch, Direction::Egress, 1);
        };
        let known = |p: &PostgresParser, s: &str| p.prepared.get(s).cloned();

        // Two named Parses, one Sync, two ParseCompletes: both known.
        let mut p = setup_ready_parser();
        pipeline(&mut p, "SELECT $1 AS two");
        let mut resp = ok(2);
        resp.extend(ready());
        p.feed(&resp, Direction::Ingress, 2);
        assert_eq!(known(&p, "s1").as_deref(), Some("SELECT $1 AS one"));
        assert_eq!(known(&p, "s2").as_deref(), Some("SELECT $1 AS two"));

        // A Parse error mid-pipeline: the server skips to the Sync, so s2
        // is never committed, not even by a later Parse's ParseComplete.
        let mut p = setup_ready_parser();
        pipeline(&mut p, "SELECT $1 FROM nowhere");
        let mut resp = ok(1);
        resp.extend(make_backend_msg(b'E', b"SERROR\0C42P01\0Mno table\0\0"));
        resp.extend(ready());
        p.feed(&resp, Direction::Ingress, 2);
        p.feed(
            &extended_cycle(Some(("s3", "SELECT 3")), "s3", &[]),
            Direction::Egress,
            3,
        );
        p.feed(&insert_done(), Direction::Ingress, 4);
        assert_eq!(known(&p, "s1").as_deref(), Some("SELECT $1 AS one"));
        assert_eq!(known(&p, "s2"), None);
        assert_eq!(known(&p, "s3").as_deref(), Some("SELECT 3"));

        // A lost response: no Parse is committed for the rest of the
        // connection, not even one sent once nothing is pending.
        let mut p = setup_ready_parser();
        pipeline(&mut p, "SELECT $1 AS two");
        assert!(p.skip(Direction::Ingress, 30, 2).is_some());
        p.feed(&ready(), Direction::Ingress, 3);
        p.feed(
            &extended_cycle(Some(("s3", "SELECT 3")), "s3", &[]),
            Direction::Egress,
            4,
        );
        p.feed(&insert_done(), Direction::Ingress, 5);
        assert_eq!(known(&p, "s1"), None);
        assert_eq!(known(&p, "s2"), None);
        assert_eq!(known(&p, "s3"), None);
    }

    /// Codex R5 H3: on a connection joined mid-stream an empty queue does
    /// not prove that answers from before capture are drained, so no
    /// Parse is learned there, ever.
    #[test]
    fn test_joined_connection_never_learns_a_parse() {
        let sync = || make_frontend_msg(b'S', b"");
        let parse = |name: &str, sql: &str| {
            let mut body = format!("{name}\0{sql}\0").into_bytes();
            body.extend_from_slice(&0i16.to_be_bytes());
            let mut m = make_frontend_msg(b'P', &body);
            m.extend(sync());
            m
        };
        let ready = || make_backend_msg(b'Z', b"I");
        let mut p = PostgresParser::new();
        p.feed(&parse("s", "SELECT $1"), Direction::Egress, 1);
        p.feed(&ready(), Direction::Ingress, 2); // a query from before capture
        p.feed(&parse("t", "SELECT $1"), Direction::Egress, 3);
        let mut s_done = make_backend_msg(b'1', b"");
        s_done.extend(ready());
        p.feed(&s_done, Direction::Ingress, 4);
        let mut t_rejected = make_backend_msg(b'E', b"SERROR\0C42P05\0Mduplicate\0\0");
        t_rejected.extend(ready());
        p.feed(&t_rejected, Direction::Ingress, 5);
        assert!(p.prepared.is_empty(), "{:?}", p.prepared);
        let mut bind = make_bind("t", &["s7Kf2v9LmQ8z"]);
        bind.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        bind.extend(sync());
        p.feed(&bind, Direction::Egress, 6);
        let mut done = make_backend_msg(b'2', b"");
        done.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        done.extend(ready());
        let out = format!("{:?}", p.feed(&done, Direction::Ingress, 7));
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Codex R6 N2: once server bytes are lost, a confirmed statement's
    /// Bind values are not exported either.
    #[test]
    fn test_no_bound_values_after_lost_server_bytes() {
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1::text")), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        p.feed(
            &extended_cycle(None, "s", &["s7Kf2v9LmQ8z"]),
            Direction::Egress,
            3,
        );
        assert!(p.skip(Direction::Ingress, 20, 4).is_some());
        let out = format!(
            "{:?}",
            p.feed(&make_backend_msg(b'Z', b"I"), Direction::Ingress, 5)
        );
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Codex R6 N3: a simple Query can redefine or destroy statements
    /// (PREPARE / DEALLOCATE, and any Query ends the unnamed one): every
    /// confirmed statement is forgotten.
    #[test]
    fn test_simple_query_forgets_statements() {
        let simple = |p: &mut PostgresParser, sql: &str| {
            p.feed(
                &make_frontend_msg(b'Q', format!("{sql}\0").as_bytes()),
                Direction::Egress,
                5,
            );
            let mut r = make_backend_msg(b'C', b"PREPARE\0");
            r.extend(make_backend_msg(b'Z', b"I"));
            p.feed(&r, Direction::Ingress, 6);
        };
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1::text")), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        simple(
            &mut p,
            "DEALLOCATE s; PREPARE s(text) AS INSERT INTO users(password) VALUES ($1)",
        );
        p.feed(
            &extended_cycle(None, "s", &["s7Kf2v9LmQ8z"]),
            Direction::Egress,
            7,
        );
        let out = format!("{:?}", p.feed(&insert_done(), Direction::Ingress, 8));
        assert!(!out.contains("s7Kf"), "{out}");

        // The unnamed statement, confirmed, then a Query.
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("", "SELECT $1::text")), "", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        assert!(p.prepared.contains_key(""));
        simple(&mut p, "SELECT 1");
        assert!(p.prepared.is_empty(), "{:?}", p.prepared);
    }

    /// Codex R7 #1: a Bind is judged by the SQL its statement had when the
    /// Bind was sent, not by a later redefinition in the same batch.
    #[test]
    fn test_bind_is_judged_by_the_sql_it_was_sent_against() {
        let pw = "INSERT INTO users(password) VALUES ($1)";
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", pw)), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        // Parse t; Bind s; Execute; Close s; Parse s (benign); Sync.
        let mut batch = make_frontend_msg(b'P', b"t\0SELECT $1::text\0\0\0");
        batch.extend(make_bind("s", &["s7Kf2v9LmQ8z"]));
        batch.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        batch.extend(make_frontend_msg(b'C', b"Ss\0"));
        batch.extend(make_frontend_msg(b'P', b"s\0SELECT $1::text\0\0\0"));
        batch.extend(make_frontend_msg(b'S', b""));
        p.feed(&batch, Direction::Egress, 3);
        let mut resp = make_backend_msg(b'1', b"");
        resp.extend(make_backend_msg(b'2', b""));
        resp.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        resp.extend(make_backend_msg(b'3', b""));
        resp.extend(make_backend_msg(b'1', b""));
        resp.extend(make_backend_msg(b'Z', b"I"));
        let out = format!("{:?}", p.feed(&resp, Direction::Ingress, 4));
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Codex R5 H4: a Bind's values are exported only under the SQL its
    /// own statement was confirmed with: not under another statement's
    /// Parse in the same batch, nor after the server rejected the Parse.
    #[test]
    fn test_bind_values_follow_their_own_statement() {
        let pw = "INSERT INTO users(password) VALUES ($1)";
        let values = |r: ParseResult| match r {
            ParseResult::Messages(m) => m.into_iter().map(|m| m.request_text).collect(),
            _ => vec![],
        };
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", pw)), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        // Parse u, then a Bind of s in the same batch.
        let mut batch = make_frontend_msg(b'P', b"u\0SELECT $1\0\0\0");
        batch.extend(extended_cycle(None, "s", &["s7Kf2v9LmQ8z"]));
        p.feed(&batch, Direction::Egress, 3);
        let out = values(p.feed(&insert_done(), Direction::Ingress, 4));
        assert!(out.iter().flatten().all(|v| !v.contains("s7Kf")), "{out:?}");

        // A rejected Parse: its Bind's values are not exported either.
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("u", "SELECT $1")), "u", &["s7Kf2v9LmQ8z"]),
            Direction::Egress,
            1,
        );
        let mut rejected = make_backend_msg(b'E', b"SERROR\0C42601\0Msyntax\0\0");
        rejected.extend(make_backend_msg(b'Z', b"I"));
        let out = values(p.feed(&rejected, Direction::Ingress, 2));
        assert!(out.iter().flatten().all(|v| !v.contains("s7Kf")), "{out:?}");

        // The unnamed statement, confirmed: its values are exported.
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("", "SELECT $1")), "", &["v"]),
            Direction::Egress,
            1,
        );
        let out = values(p.feed(&insert_done(), Direction::Ingress, 2));
        assert_eq!(out, vec![Some("v".to_string())]);
    }

    #[test]
    fn test_long_query_with_multibyte_text_does_not_panic() {
        // 4096 lands inside a 2-byte character: byte slicing panicked.
        let mut p = setup_ready_parser();
        let mut q = "INSERT INTO t VALUES ('ab".to_string(); // odd length
        while q.len() < 5000 {
            q.push('é');
        }
        q.push_str("')\0");
        p.feed(&make_frontend_msg(b'Q', q.as_bytes()), Direction::Egress, 1);
        let mut resp = make_backend_msg(b'C', b"INSERT 0 1\0");
        resp.extend(make_backend_msg(b'Z', b"I"));
        match p.feed(&resp, Direction::Ingress, 2) {
            ParseResult::Messages(m) => assert!(m[0].payload_text.as_ref().unwrap().len() <= 4096),
            other => panic!("expected INSERT, got {other:?}"),
        }
    }

    #[test]
    fn test_ssl_request_accepted_goes_encrypted() {
        let mut p = PostgresParser::new();
        p.feed(&make_ssl_request(), Direction::Egress, 0);
        p.feed(b"S", Direction::Ingress, 0);
        assert_eq!(p.state, State::Encrypted);
        // TLS records afterwards are ignored, not misparsed.
        let r = p.feed(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01], Direction::Egress, 1);
        assert!(matches!(r, ParseResult::NeedMoreData));
    }

    #[test]
    fn test_startup_and_auth() {
        let p = setup_ready_parser();
        assert_eq!(p.state, State::Ready);
        assert_eq!(p.server_version.as_deref(), Some("15.4"));
    }

    #[test]
    fn test_simple_query() {
        let mut p = setup_ready_parser();

        // Send simple query
        let query = b"SELECT 1\0";
        p.feed(&make_frontend_msg(b'Q', query), Direction::Egress, 1000);

        // Server: RowDescription + DataRow + CommandComplete + ReadyForQuery
        let mut response = Vec::new();
        response.extend_from_slice(&make_backend_msg(
            b'T',
            &[
                0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
            ],
        ));
        response.extend_from_slice(&make_backend_msg(b'D', &[0, 1, 0, 0, 0, 1, b'1']));
        response.extend_from_slice(&make_backend_msg(b'C', b"SELECT 1\0"));
        response.extend_from_slice(&make_backend_msg(b'Z', b"I"));

        let result = p.feed(&response, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
                assert!(msgs[0].payload_text.as_ref().unwrap().contains("SELECT 1"));
                assert_eq!(msgs[0].latency_ns, Some(1000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    /// The query text a simple-query exchange exports.
    fn exported_query(sql: &str) -> String {
        let mut p = setup_ready_parser();
        let mut q = sql.as_bytes().to_vec();
        q.push(0);
        p.feed(&make_frontend_msg(b'Q', &q), Direction::Egress, 1000);
        let mut response = make_backend_msg(b'C', b"OK\0");
        response.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        let ParseResult::Messages(msgs) = p.feed(&response, Direction::Ingress, 2000) else {
            panic!("expected a message for {sql}");
        };
        msgs[0].payload_text.clone().unwrap_or_default()
    }

    /// PostgreSQL credential statements in any string form export only their
    /// verb.
    #[test]
    fn test_credential_statement_forms_export_only_the_verb() {
        for sql in [
            "CREATE USER app WITH PASSWORD E'canary-escape';",
            "CREATE USER app WITH PASSWORD E'can\\'ary-escape';",
            "ALTER ROLE app PASSWORD/*comment*/'canary-comment';",
            "ALTER ROLE app PASSWORD -- c\n 'canary-line'",
            "ALTER ROLE app PASSWORD $$canary-dollar$$",
            "ALTER ROLE app PASSWORD $pw$canary-tag$pw$",
            "ALTER ROLE app PASSWORD 'canary-a'\n'canary-b'",
            "ALTER ROLE app PASSWORD U&'canary-u'",
            "ALTER ROLE app ENCRYPTED PASSWORD 'canary-enc' VALID UNTIL 'infinity'",
            "ALTER ROLE app WITH LOGIN PASSWORD 'canary'",
            "CREATE SUBSCRIPTION s CONNECTION 'host=db1 user=repl password=canary' PUBLICATION p",
            "UPDATE cfg SET smtp_password = 'canary'",
            "SELECT 1 # 2; ALTER ROLE app PASSWORD 'canary-hash'",
        ] {
            let verb = sql.split_whitespace().next().unwrap();
            assert_eq!(
                exported_query(sql),
                format!("{verb} <statement withheld>"),
                "{sql}"
            );
        }
    }

    /// Statements with credential context export only their verb (Codex
    /// round 3): standard_conforming_strings, nested comments.
    #[test]
    fn test_credential_statements_are_withheld() {
        let mut leaks = Vec::new();
        for sql in [
            "ALTER ROLE a PASSWORD 'first\\'; ALTER ROLE b PASSWORD 'canary-second'",
            "ALTER ROLE a PASSWORD /* x /* nested */ 'canary-in' */ 'canary-out'",
        ] {
            let out = exported_query(sql);
            if out.to_lowercase().contains("canary") {
                leaks.push(format!("{sql} -> {out}"));
            }
        }
        assert!(leaks.is_empty(), "{leaks:#?}");
        assert_eq!(
            exported_query("ALTER ROLE app PASSWORD 'canary'"),
            "ALTER <statement withheld>"
        );
    }

    #[test]
    fn test_joins_established_connection_mid_stream() {
        // Agent started after the client connected (pooled connections):
        // no startup/auth is ever seen, the first bytes are a query.
        let mut p = PostgresParser::new();
        p.feed(
            &make_frontend_msg(b'Q', b"SELECT 1\0"),
            Direction::Egress,
            1000,
        );
        let mut response = make_backend_msg(b'C', b"SELECT 1\0");
        response.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        match p.feed(&response, Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
            }
            other => panic!("expected a message from a mid-stream query, got {other:?}"),
        }
    }

    #[test]
    fn test_extended_query() {
        let mut p = setup_ready_parser();

        // Parse message: name\0 + query\0 + num_params(2)
        let mut parse_payload = Vec::new();
        parse_payload.extend_from_slice(b"stmt\0");
        parse_payload.extend_from_slice(b"SELECT $1\0");
        parse_payload.extend_from_slice(&0u16.to_be_bytes());
        p.feed(
            &make_frontend_msg(b'P', &parse_payload),
            Direction::Egress,
            1000,
        );

        // Server responses for extended query
        let mut response = Vec::new();
        response.extend_from_slice(&make_backend_msg(b'1', &[])); // ParseComplete
        response.extend_from_slice(&make_backend_msg(b'2', &[])); // BindComplete
        response.extend_from_slice(&make_backend_msg(
            b'T',
            &[
                0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
            ],
        ));
        response.extend_from_slice(&make_backend_msg(b'D', &[0, 1, 0, 0, 0, 1, b'1']));
        response.extend_from_slice(&make_backend_msg(b'C', b"SELECT 1\0"));
        response.extend_from_slice(&make_backend_msg(b'Z', b"I"));

        let result = p.feed(&response, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn test_error_response() {
        let mut p = setup_ready_parser();

        p.feed(
            &make_frontend_msg(b'Q', b"BAD SQL\0"),
            Direction::Egress,
            1000,
        );

        let mut err_payload = Vec::new();
        err_payload.push(b'S');
        err_payload.extend_from_slice(b"ERROR\0");
        err_payload.push(b'M');
        err_payload.extend_from_slice(b"syntax error\0");
        err_payload.push(b'C');
        err_payload.extend_from_slice(b"42601\0");
        err_payload.push(0); // terminator

        let mut response = Vec::new();
        response.extend_from_slice(&make_backend_msg(b'E', &err_payload));
        response.extend_from_slice(&make_backend_msg(b'Z', b"I"));

        let result = p.feed(&response, Direction::Ingress, 2000);
        match result {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                // query was set
                assert!(msgs[0].payload_text.is_some());
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    /// An error message is withheld when its statement was, and when it
    /// shows credential context itself.
    #[test]
    fn test_error_text_is_withheld() {
        for query in [
            &b"ALTER ROLE app PASSWORD 'pg-s3cret' BAD\0"[..],
            b"SELECT 1\0",
        ] {
            let mut p = setup_ready_parser();
            p.feed(&make_frontend_msg(b'Q', query), Direction::Egress, 1000);
            let mut response =
                make_backend_msg(b'E', b"SERROR\0Mnear \"PASSWORD 'pg-s3cret' BAD\"\0\0");
            response.extend_from_slice(&make_backend_msg(b'Z', b"I"));
            let ParseResult::Messages(msgs) = p.feed(&response, Direction::Ingress, 2000) else {
                panic!("expected a message");
            };
            assert_eq!(
                msgs[0].payload_text.as_deref(),
                Some("<statement withheld>")
            );
        }
    }

    #[test]
    fn test_version_detection() {
        let mut p = PostgresParser::new();
        p.feed(&make_startup_msg(), Direction::Egress, 0);

        // ParameterStatus with server_version
        let mut param = b"server_version\0".to_vec();
        param.extend_from_slice(b"16.1\0");
        p.feed(&make_backend_msg(b'S', &param), Direction::Ingress, 0);

        assert_eq!(ProtocolParser::protocol_version(&p), Some("16.1"));
    }

    #[test]
    fn test_metadata() {
        let p = PostgresParser::new();
        assert_eq!(ProtocolParser::protocol(&p), Protocol::Postgres);
        assert_eq!(p.state_name(), "waiting_for_startup");
    }
}
