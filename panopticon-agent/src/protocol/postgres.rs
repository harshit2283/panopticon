#![allow(dead_code)]

//! PostgreSQL wire protocol parser.
//!
//! Wire format: 1-byte message type + 4-byte length + payload.
//! StartupMessage has no type byte (length + protocol version instead).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::fsm::StreamBuffer;
use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser};

#[derive(Debug, Clone, PartialEq)]
enum State {
    WaitingForStartup,
    InAuth,
    /// Startup done: client messages are read into `pending` and the
    /// server's answers matched against it.
    Ready,
    /// SSL/GSS encryption was accepted: the rest of the stream is ciphertext.
    Encrypted,
}

/// Special startup-phase request codes (in place of the protocol version).
const CANCEL_REQUEST_CODE: u32 = 80877102;
const SSL_REQUEST_CODE: u32 = 80877103;
const GSSENC_REQUEST_CODE: u32 = 80877104;

/// Bound parameter text, zeroed when dropped unexported.
struct Values(String);

impl Drop for Values {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Values {
    fn take(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

/// The statement a Bind was sent against, fixed when the Bind is read:
/// the SQL of the latest unanswered Parse of its name (which must then be
/// confirmed: `parse`), or else the SQL the statement was confirmed with
/// in an earlier exchange (`reused`: a server-side function may have
/// redefined it unseen, so its values also need a matching
/// CommandComplete, [`tag_matches`]). `sql` is None when it is unknown.
#[derive(Clone)]
struct BindSql {
    sql: Option<Arc<str>>,
    parse: Option<Arc<AtomicBool>>,
    reused: bool,
}

impl BindSql {
    const UNKNOWN: BindSql = BindSql {
        sql: None,
        parse: None,
        reused: false,
    };
}

/// A portal created by a Bind: what its Executes run, and the Bind's
/// values (exported with the first Execute only).
struct Portal {
    bind: BindSql,
    values: Option<Values>,
}

/// An Execute read from the client, answered by its rows and then one
/// CommandComplete, EmptyQueryResponse, PortalSuspended or ErrorResponse.
struct Exec {
    bind: BindSql,
    values: Option<Values>,
    ts: u64,
}

/// A client message the server answers, in the order the client sent it.
/// Flush is not answered; Sync and a simple Query are answered by one
/// ReadyForQuery and end a group.
enum Pending {
    /// Answered by ParseComplete; `ok` is set then (a Bind that ran
    /// against it may export its values).
    Parse {
        id: u64,
        name: String,
        sql: Arc<str>,
        ok: Arc<AtomicBool>,
        ts: u64,
    },
    /// Answered by BindComplete. Its statement, for an error.
    Bind {
        bind: BindSql,
        ts: u64,
    },
    /// Answered by RowDescription or NoData, after a ParameterDescription
    /// for a statement (`statement`, cleared once that arrived).
    Describe {
        statement: bool,
    },
    Execute(Box<Exec>),
    /// Answered by CloseComplete.
    Close,
    Sync,
    Query {
        sql: String,
        ts: u64,
    },
    /// A FunctionCall (libpq PQfn, `lo_*`, the JDBC fastpath): answered
    /// by FunctionCallResponse or ErrorResponse, then ReadyForQuery. Not
    /// reported.
    Function,
}

impl Pending {
    fn ends_group(&self) -> bool {
        matches!(
            self,
            Pending::Sync | Pending::Query { .. } | Pending::Function
        )
    }
}

/// What a record shows as its statement.
enum Shown<'a> {
    /// The statement's SQL.
    Sql(&'a str),
    /// A statement whose SQL is not known: `EXECUTE`.
    Unknown,
    /// No statement (an error answering a Sync): the method alone.
    Nothing,
}

pub struct PostgresParser {
    state: State,
    client_buf: StreamBuffer,
    server_buf: StreamBuffer,
    server_version: Option<String>,
    /// An SSLRequest/GSSENCRequest was sent: the server answers with a single
    /// unframed byte ('S'/'G' = encrypt, 'N' = no) before anything else.
    awaiting_encryption_reply: bool,
    /// Named prepared statements the server confirmed (ParseComplete):
    /// name -> SQL ("" is the unnamed statement). A name being re-Parsed
    /// or Closed is removed at once: until the server confirms, its SQL is
    /// unknown. Shared, not copied, with Parses and Binds.
    prepared: HashMap<String, Arc<str>>,
    /// What the server still has to answer, in the client's order. Read
    /// from the client bytes as they arrive (`scan_client`).
    pending: VecDeque<Pending>,
    /// Groups (Sync or simple Query) in `pending`.
    groups: usize,
    /// The latest unanswered Parse of each name: its id, SQL and outcome.
    /// Entries leave when that Parse is answered or dropped.
    latest_parse: HashMap<String, (u64, Arc<str>, Arc<AtomicBool>)>,
    /// Parses with an id up to this were cancelled by a forget-all: their
    /// ParseComplete commits nothing.
    cut_all: u64,
    /// The same per name (a Close, or a simple Query for the unnamed
    /// statement). Cleared when nothing is pending.
    cut: HashMap<String, u64>,
    /// Id of the last Parse read.
    next_parse: u64,
    /// Portals bound and not yet executed or closed, by name.
    portals: HashMap<String, Portal>,
    /// Bytes of bound values held in `portals` and `pending`.
    held_values: usize,
    /// The connection's answers cannot be trusted to match its messages
    /// for the rest of its life (joined mid-stream, lost server bytes, a
    /// client message the queue does not model, or more unanswered
    /// messages than are tracked): records are still made, without bound
    /// values, and no Parse is learned.
    untrusted: bool,
    /// The server's answers stopped matching the client's messages (bytes
    /// lost, an unexpected message): answers are dropped until a
    /// ReadyForQuery that can be attributed, see `ready_in_doubt`.
    in_doubt: bool,
    /// Server framing was lost with bytes: find the next ReadyForQuery by
    /// its bytes. Those bytes may be row data, and so may every frame read
    /// after them, so the connection is `untrusted` from then on.
    framing_lost: bool,
    /// The current group: it already has a record (an Execute answered,
    /// or a message failed); its last Parse answered (SQL and start); an
    /// error answering its Sync.
    group_exec: bool,
    group_parse: Option<(Arc<str>, u64)>,
    group_error: Option<PgError>,
    /// The simple Query being answered: its error and status.
    query_error: Option<PgError>,
}

/// Max named statements remembered per connection.
const MAX_PREPARED_STATEMENTS: usize = 256;
/// Max portals tracked per connection.
const MAX_PORTALS: usize = 256;
/// Max bytes of bind-parameter text kept per Bind.
const MAX_BIND_TEXT: usize = 64 * 1024;
/// Max bytes of bind-parameter text held for unanswered Executes; past it
/// a Bind's values are dropped (its record has none).
const MAX_HELD_VALUES: usize = 1024 * 1024;
/// Most client messages awaiting an answer that are tracked.
const MAX_PENDING: usize = 4096;

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
            prepared: HashMap::new(),
            pending: VecDeque::new(),
            groups: 0,
            latest_parse: HashMap::new(),
            cut_all: 0,
            cut: HashMap::new(),
            next_parse: 0,
            portals: HashMap::new(),
            held_values: 0,
            untrusted: false,
            in_doubt: false,
            framing_lost: false,
            group_exec: false,
            group_parse: None,
            group_error: None,
            query_error: None,
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
            match self.state {
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
                    self.scan_client(ts);
                    if !self.handle_server(ts, &mut messages) {
                        break;
                    }
                }
                State::Encrypted => {
                    self.client_buf.clear();
                    self.server_buf.clear();
                    break;
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
            self.untrusted = true;
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
                b'S' => {
                    // ParameterStatus: name\0value\0
                    self.parse_parameter_status(&payload);
                }
                b'Z' | b'E' => {
                    // ReadyForQuery (auth complete) or an error during auth.
                    self.state = State::Ready;
                    return true;
                }
                _ => {} // Authentication, BackendKeyData
            }
        }
        false
    }

    /// Read the complete client messages into `pending` and consume them.
    /// A Parse or a Close of a statement forgets it at once (its SQL is
    /// unknown until the server confirms); a Close also cancels the
    /// unanswered Parses of that name.
    fn scan_client(&mut self, ts: u64) {
        while let Some((kind, payload, consumed)) = Self::try_read_frontend_msg(&self.client_buf) {
            self.client_buf.consume(consumed);
            let entry = match kind {
                b'P' => {
                    let name = extract_string(&payload);
                    let sql = extract_second_string(&payload);
                    if may_redefine_statements(&sql) {
                        // Executed later, it may PREPARE, DEALLOCATE or
                        // DISCARD any name: forget them all now.
                        self.forget_all();
                    }
                    self.prepared.remove(&name);
                    self.next_parse += 1;
                    let (sql, ok): (Arc<str>, _) = (sql.into(), Arc::new(AtomicBool::new(false)));
                    self.latest_parse
                        .insert(name.clone(), (self.next_parse, sql.clone(), ok.clone()));
                    Pending::Parse {
                        id: self.next_parse,
                        name,
                        sql,
                        ok,
                        ts,
                    }
                }
                b'B' => Pending::Bind {
                    bind: self.read_bind(&payload),
                    ts,
                },
                b'D' => Pending::Describe {
                    statement: payload.first() == Some(&b'S'),
                },
                b'E' => {
                    let portal = extract_string(&payload);
                    let exec = match self.portals.get_mut(&portal) {
                        Some(p) => Exec {
                            bind: p.bind.clone(),
                            values: p.values.take(),
                            ts,
                        },
                        None => Exec {
                            bind: BindSql::UNKNOWN,
                            values: None,
                            ts,
                        },
                    };
                    Pending::Execute(Box::new(exec))
                }
                b'C' => {
                    let name = extract_string(payload.get(1..).unwrap_or_default());
                    if payload.first() == Some(&b'S') {
                        self.forget_name(&name);
                    } else {
                        self.drop_portal(&name);
                    }
                    Pending::Close
                }
                b'S' => Pending::Sync,
                b'Q' => {
                    // A simple Query ends the unnamed statement; its SQL
                    // may PREPARE, DEALLOCATE or DISCARD any name only if
                    // it names one of those commands (as a word, anywhere:
                    // comments and literals included): then every
                    // statement is forgotten, confirmed or pending.
                    let sql = extract_string(&payload);
                    if may_redefine_statements(&sql) {
                        self.forget_all();
                    } else {
                        self.forget_name("");
                    }
                    // A Query inside an unfinished extended group (no Sync
                    // yet) is answered in a way the queue cannot follow.
                    if self.pending.back().is_some_and(|p| !p.ends_group()) {
                        self.enter_doubt();
                    }
                    Pending::Query { sql, ts }
                }
                b'F' => {
                    if self.pending.back().is_some_and(|p| !p.ends_group()) {
                        self.enter_doubt();
                    }
                    Pending::Function
                }
                // Flush, Terminate, CopyData, CopyDone, CopyFail: no answer
                // of their own.
                b'H' | b'X' | b'd' | b'c' | b'f' => continue,
                // Anything else may be answered in a way the queue does not
                // model: the answers can no longer be matched.
                _ => {
                    self.untrusted = true;
                    continue;
                }
            };
            if self.pending.len() >= MAX_PENDING {
                // Not tracked any more: answers cannot be matched for the
                // rest of the connection.
                self.untrusted = true;
                self.drop_pending();
            }
            if entry.ends_group() {
                self.groups += 1;
            }
            self.pending.push_back(entry);
        }
    }

    /// A Bind: the statement it runs (the latest unanswered Parse of its
    /// name, else the confirmed statement) and its values, kept under its
    /// portal.
    fn read_bind(&mut self, payload: &[u8]) -> BindSql {
        let portal = extract_string(payload);
        let name = extract_second_string(payload);
        let bind = match self.latest_parse.get(&name) {
            Some((id, sql, ok)) => {
                let cancelled = *id <= self.cut_all || self.cut.get(&name).is_some_and(|c| id <= c);
                BindSql {
                    sql: (!cancelled).then(|| sql.clone()),
                    parse: Some(ok.clone()),
                    reused: false,
                }
            }
            None => match self.prepared.get(&name) {
                Some(sql) => BindSql {
                    sql: Some(sql.clone()),
                    parse: None,
                    reused: true,
                },
                None => BindSql::UNKNOWN,
            },
        };
        let mut values = bind_param_text(payload).map(Values);
        let size = values.as_ref().map_or(0, |v| v.0.len());
        if self.held_values + size > MAX_HELD_VALUES {
            values = None;
        }
        self.drop_portal(&portal);
        if self.portals.len() < MAX_PORTALS {
            self.held_values += values.as_ref().map_or(0, |v| v.0.len());
            self.portals.insert(
                portal,
                Portal {
                    bind: bind.clone(),
                    values,
                },
            );
        }
        bind
    }

    fn drop_portal(&mut self, name: &str) {
        if let Some(p) = self.portals.remove(name) {
            self.held_values -= p.values.as_ref().map_or(0, |v| v.0.len());
        }
    }

    /// Forget every statement: confirmed ones, and unanswered Parses
    /// (never committed).
    fn forget_all(&mut self) {
        self.prepared.clear();
        self.cut_all = self.next_parse;
    }

    /// Forget one statement, confirmed or unanswered.
    fn forget_name(&mut self, name: &str) {
        self.prepared.remove(name);
        if self.latest_parse.contains_key(name) {
            self.cut.insert(name.to_string(), self.next_parse);
        }
    }

    /// Nothing can be matched any more: drop what is pending (no record),
    /// and forget the statements whose Parse was among it.
    fn drop_pending(&mut self) {
        while let Some(p) = self.pending.pop_front() {
            self.retire(p, None, 0, false);
        }
        self.groups = 0;
    }

    /// A pending message leaves the queue without its answer: its Parse
    /// may or may not have been committed, so its name is forgotten; its
    /// Execute or Query is reported (`out`) as an exchange whose outcome
    /// is not known (no values or status; latency only when
    /// the ReadyForQuery that ended it is known, `ready`).
    fn retire(&mut self, p: Pending, out: Option<&mut Vec<L7Message>>, ts: u64, ready: bool) {
        let (shown, start) = match &p {
            Pending::Parse { id, name, .. } => {
                let (id, name) = (*id, name.clone());
                self.prepared.remove(&name);
                self.parse_left(id, &name);
                return;
            }
            Pending::Execute(exec) => {
                self.held_values -= exec.values.as_ref().map_or(0, |v| v.0.len());
                (exec.bind.sql.clone(), exec.ts)
            }
            Pending::Query { sql, ts } => (Some(Arc::from(sql.as_str())), *ts),
            _ => return,
        };
        if let Some(out) = out {
            let shown = match shown.as_deref() {
                Some(sql) => Shown::Sql(sql),
                None => Shown::Unknown,
            };
            let start = ready.then_some(start);
            out.push(self.record(shown, None, None, None, ts, start, false));
        }
    }

    /// Parse `id` of `name` was answered or dropped.
    fn parse_left(&mut self, id: u64, name: &str) {
        if self.latest_parse.get(name).is_some_and(|(i, ..)| *i == id) {
            self.latest_parse.remove(name);
        }
    }

    fn pop(&mut self) -> Option<Pending> {
        let p = self.pending.pop_front()?;
        if p.ends_group() {
            self.groups -= 1;
        }
        if self.pending.is_empty() {
            self.cut.clear();
        }
        Some(p)
    }

    /// The answers no longer match: drop server messages until a
    /// ReadyForQuery that can be attributed.
    fn enter_doubt(&mut self) {
        self.in_doubt = true;
        self.query_error = None;
        self.group_error = None;
    }

    /// A ReadyForQuery while in doubt. It answers some pending group; it
    /// can be attributed only when exactly one group is pending: with the
    /// framing intact every ReadyForQuery is real and answers one tracked
    /// group (each client message that can draw one is tracked, anything
    /// else makes the connection untrusted), answers come in order, and a
    /// ReadyForQuery cannot answer a group not yet sent, so the pending
    /// groups are never fewer than those really waiting. Otherwise the
    /// oldest group is dropped and the doubt stays: the ReadyForQuery may
    /// answer a later one. Each dropped group's Executes and Query are
    /// reported without values or status, and the names it Parsed are
    /// forgotten. After lost server bytes a ReadyForQuery may be row data,
    /// so the connection is untrusted and the doubt only re-aligns the
    /// records.
    fn ready_in_doubt(&mut self, ts: u64, out: &mut Vec<L7Message>) {
        if self.groups == 0 {
            return; // answers a message sent before capture
        }
        let attributable = self.groups == 1 && !self.untrusted;
        while let Some(p) = self.pop() {
            let end = p.ends_group();
            self.retire(p, Some(out), ts, attributable);
            if end {
                break;
            }
        }
        self.group_exec = false;
        self.group_parse = None;
        if attributable || self.untrusted {
            self.in_doubt = false;
        }
    }

    /// Match server messages to `pending`. Returns false when it needs
    /// more bytes.
    fn handle_server(&mut self, ts: u64, out: &mut Vec<L7Message>) -> bool {
        if self.framing_lost {
            let data = self.server_buf.data();
            match find_ready_for_query(data) {
                Some(off) => {
                    self.server_buf.consume(off);
                    self.framing_lost = false;
                }
                None => {
                    // Keep a tail in case the marker is split across packets.
                    let keep = READY_FOR_QUERY.len();
                    let drop = data.len().saturating_sub(keep);
                    self.server_buf.consume(drop);
                    return false;
                }
            }
        }
        let Some((kind, payload, consumed)) = Self::try_read_backend_msg(&self.server_buf) else {
            return false;
        };
        // Asynchronous messages, at any time.
        match kind {
            b'S' => {
                self.server_buf.consume(consumed);
                self.parse_parameter_status(&payload);
                return true;
            }
            b'N' | b'A' => {
                self.server_buf.consume(consumed);
                return true;
            }
            _ => {}
        }
        if self.pending.is_empty() {
            if self.untrusted || self.in_doubt {
                // An answer to something sent before capture, or dropped.
                self.server_buf.consume(consumed);
                return true;
            }
            // Its request has not been read yet: wait for it.
            return false;
        }
        self.server_buf.consume(consumed);
        if !self.in_doubt && !self.answer(kind, &payload, ts, out) {
            self.enter_doubt();
        }
        if self.in_doubt && kind == b'Z' {
            self.ready_in_doubt(ts, out);
        }
        true
    }

    /// One server message answering the front of `pending`. False when it
    /// does not fit (the caller enters doubt).
    fn answer(&mut self, kind: u8, payload: &[u8], ts: u64, out: &mut Vec<L7Message>) -> bool {
        #[derive(PartialEq)]
        enum Front {
            Query,
            Parse,
            Bind,
            Describe { statement: bool },
            Execute,
            Close,
            Sync,
            Function,
        }
        let front = match self.pending.front() {
            Some(Pending::Query { .. }) => Front::Query,
            Some(Pending::Parse { .. }) => Front::Parse,
            Some(Pending::Bind { .. }) => Front::Bind,
            Some(Pending::Describe { statement }) => Front::Describe {
                statement: *statement,
            },
            Some(Pending::Execute(_)) => Front::Execute,
            Some(Pending::Close) => Front::Close,
            Some(Pending::Sync) => Front::Sync,
            Some(Pending::Function) => Front::Function,
            None => return false,
        };
        match (front, kind) {
            (Front::Query, b'Z') => {
                let Some(Pending::Query { sql, ts: start }) = self.pop() else {
                    unreachable!("front is a Query")
                };
                let error = self.query_error.take();
                let status = Some(error.is_some() as u32);
                let shown = Shown::Sql(&sql);
                out.push(self.record(shown, None, error, status, ts, Some(start), true));
            }
            (Front::Query, b'E') => {
                // A multi-statement Query stops at its first error.
                if self.query_error.is_none() {
                    self.query_error = Some(parse_error_response(payload));
                }
            }
            // Rows, tags, empty statements, COPY: within the Query.
            (Front::Query, b'T' | b'D' | b'C' | b'I' | b'G' | b'H' | b'W' | b'd' | b'c') => {}
            (Front::Parse, b'1') => {
                let Some(Pending::Parse {
                    id,
                    name,
                    sql,
                    ok,
                    ts: start,
                }) = self.pop()
                else {
                    unreachable!("front is a Parse")
                };
                ok.store(true, Ordering::Relaxed);
                self.parse_left(id, &name);
                let cancelled = id <= self.cut_all || self.cut.get(&name).is_some_and(|c| id <= *c);
                // On an untrusted connection a ParseComplete may answer a
                // Parse sent before capture: nothing is learned.
                if !cancelled
                    && !self.untrusted
                    && (name.is_empty() || self.prepared.len() < MAX_PREPARED_STATEMENTS)
                {
                    self.prepared.insert(name, sql.clone());
                }
                self.group_parse = Some((sql, start));
            }
            (Front::Bind, b'2') | (Front::Close, b'3') => {
                self.pop();
            }
            (Front::Describe { statement: true }, b't') => {
                if let Some(Pending::Describe { statement }) = self.pending.front_mut() {
                    *statement = false;
                }
            }
            (Front::Describe { statement: false }, b'T' | b'n') => {
                self.pop();
            }
            (Front::Execute, b'D' | b'G' | b'H' | b'W' | b'd' | b'c') => {}
            (Front::Execute, b'C' | b'I' | b's') => {
                let Some(Pending::Execute(exec)) = self.pop() else {
                    unreachable!("front is an Execute")
                };
                let tag = (kind == b'C').then(|| extract_string(payload));
                out.push(self.exec_record(*exec, tag, None, ts));
            }
            (Front::Sync, b'Z') => {
                self.pop();
                // A group with no record yet (a driver preparing a
                // statement: Parse and Sync): one record for its Parse.
                if let (false, Some((sql, start))) = (self.group_exec, self.group_parse.take()) {
                    let shown = Shown::Sql(&sql);
                    out.push(self.record(shown, None, None, Some(0), ts, Some(start), true));
                }
                // An error answering the Sync itself (at commit): no
                // statement of its own.
                if let Some(error) = self.group_error.take() {
                    let shown = Shown::Nothing;
                    out.push(self.record(shown, None, Some(error), Some(1), ts, None, true));
                }
                self.group_exec = false;
                self.group_parse = None;
            }
            (Front::Function, b'V' | b'E') => {}
            (Front::Function, b'Z') => {
                self.pop();
            }
            (Front::Sync, b'E') => {
                self.group_error = Some(parse_error_response(payload));
            }
            (
                Front::Parse | Front::Bind | Front::Describe { .. } | Front::Execute | Front::Close,
                b'E',
            ) => {
                // The front message failed: it gets the record, under its
                // own statement (a failed Parse its SQL, a failed Bind or
                // Execute the statement it ran; a Describe or Close none).
                // The server then skips to the Sync:
                // the messages before it never ran and are not reported.
                let error = Some(parse_error_response(payload));
                let record = match self.pop().expect("front checked") {
                    Pending::Execute(exec) => self.exec_record(*exec, None, error, ts),
                    Pending::Parse {
                        id,
                        name,
                        sql,
                        ts: start,
                        ..
                    } => {
                        self.parse_left(id, &name);
                        let shown = Shown::Sql(&sql);
                        self.record(shown, None, error, Some(1), ts, Some(start), true)
                    }
                    Pending::Bind { bind, ts: start } => {
                        let shown = match bind.sql.as_deref() {
                            Some(sql) => Shown::Sql(sql),
                            None => Shown::Unknown,
                        };
                        self.record(shown, None, error, Some(1), ts, Some(start), true)
                    }
                    _ => self.record(Shown::Nothing, None, error, Some(1), ts, None, true),
                };
                out.push(record);
                self.group_exec = true;
                while self.pending.front().is_some_and(|p| !p.ends_group()) {
                    let p = self.pop().expect("checked");
                    self.retire(p, None, ts, false);
                }
                if !matches!(self.pending.front(), Some(Pending::Sync)) {
                    return false; // a Query without a Sync before it
                }
            }
            _ => return false,
        }
        true
    }

    /// The record of an answered Execute: its statement's SQL (EXECUTE
    /// when unknown); its values only under that SQL, once confirmed, and
    /// for a statement confirmed in an earlier exchange only when the
    /// CommandComplete names the same command.
    fn exec_record(
        &mut self,
        exec: Exec,
        tag: Option<String>,
        error: Option<PgError>,
        ts: u64,
    ) -> L7Message {
        self.group_exec = true;
        let Exec {
            bind,
            values,
            ts: start,
        } = exec;
        self.held_values -= values.as_ref().map_or(0, |v| v.0.len());
        let confirmed = bind
            .parse
            .as_ref()
            .is_none_or(|ok| ok.load(Ordering::Relaxed));
        let values = values.filter(|_| {
            confirmed
                && error.is_none()
                && (!bind.reused || tag_matches(tag.as_deref(), bind.sql.as_deref()))
        });
        let shown = match bind.sql.as_deref() {
            Some(sql) => Shown::Sql(sql),
            None => Shown::Unknown,
        };
        let status = Some(error.is_some() as u32);
        self.record(shown, values, error, status, ts, Some(start), true)
    }

    /// One exchange's record, at `ts` (latency from `start`). Values only
    /// when `trusted` and the connection's answers are matched. An error
    /// adds its SQLSTATE and severity, never its text ([`PgError`]).
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        shown: Shown<'_>,
        values: Option<Values>,
        error: Option<PgError>,
        status: Option<u32>,
        ts: u64,
        start: Option<u64>,
        trusted: bool,
    ) -> L7Message {
        let trusted = trusted && !self.untrusted && !self.in_doubt;
        let mut msg = L7Message::new(Protocol::Postgres, Direction::Ingress, ts);
        msg.method = Some("QUERY".into());
        msg.latency_ns = start.map(|s| ts.saturating_sub(s));
        let values = values.filter(|_| trusted).map(Values::take);
        match shown {
            Shown::Sql(sql) => {
                let (verb, text, bound) = super::export_statement(sql.to_string(), values);
                msg.method = verb.or(msg.method);
                msg.payload_text = Some(text);
                msg.request_text = bound;
            }
            Shown::Unknown | Shown::Nothing => {
                if matches!(shown, Shown::Unknown) {
                    msg.method = Some("EXECUTE".into());
                    msg.payload_text = Some("EXECUTE".into());
                }
                if let Some(mut v) = values {
                    zeroize::Zeroize::zeroize(&mut v);
                }
            }
        }
        if let Some(err) = error {
            if let Some(code) = err.sqlstate {
                msg.headers.push(("sqlstate".into(), code));
            }
            if let Some(sev) = err.severity {
                msg.headers.push(("severity".into(), sev.into()));
            }
        }
        msg.status = status;
        msg
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

    fn current_state(&self) -> &'static str {
        match self.state {
            State::WaitingForStartup => "waiting_for_startup",
            State::InAuth => "in_auth",
            State::Ready => "ready",
            State::Encrypted => "encrypted",
        }
    }
}

/// Whether SQL may create, redefine or destroy prepared statements:
/// it names PREPARE, DEALLOCATE or DISCARD as a word, in any case,
/// anywhere (comments and string literals included, so a dynamic
/// `EXECUTE 'DEALLOCATE s'` counts). Words are runs of ASCII letters and
/// digits: any other byte separates, which errs toward forgetting.
fn may_redefine_statements(sql: &str) -> bool {
    sql.as_bytes()
        .split(|b| !b.is_ascii_alphanumeric())
        .any(|w| {
            [&b"PREPARE"[..], b"DEALLOCATE", b"DISCARD"]
                .iter()
                .any(|k| w.eq_ignore_ascii_case(k))
        })
}

/// Whether a CommandComplete tag names the command of `sql` (its first
/// keyword: `INSERT 0 1` for an INSERT). No tag (an error) or no known
/// keyword is no match.
fn tag_matches(tag: Option<&str>, sql: Option<&str>) -> bool {
    let (Some(tag), Some(verb)) = (tag, sql.and_then(super::secrets::sql_verb)) else {
        return false;
    };
    tag.split(' ')
        .next()
        .is_some_and(|w| w.eq_ignore_ascii_case(verb))
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

/// What an ErrorResponse exports: its SQLSTATE and severity, nothing
/// else. The message, detail, hint, context and the schema, table,
/// column, type and constraint names can echo a bound value or a row
/// (`invalid input syntax for type integer: "hunter2"`), and which
/// statement an error answers is only as sure as the pairing, so no text
/// field is ever read out. SQLSTATE is five characters from a fixed
/// alphabet; the severity is one of a fixed set.
#[derive(Debug, Clone, PartialEq)]
struct PgError {
    sqlstate: Option<String>,
    severity: Option<&'static str>,
}

const SEVERITIES: &[&str] = &[
    "ERROR", "FATAL", "PANIC", "WARNING", "NOTICE", "DEBUG", "INFO", "LOG",
];

fn parse_error_response(data: &[u8]) -> PgError {
    // ErrorResponse: series of type(1) + string\0, terminated by \0
    let mut err = PgError {
        sqlstate: None,
        severity: None,
    };
    let mut i = 0;
    while i < data.len() && data[i] != 0 {
        let field_type = data[i];
        i += 1;
        let end = data[i..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data.len() - i);
        let value = &data[i..i + end];
        match field_type {
            b'C' if value.len() == 5
                && value
                    .iter()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()) =>
            {
                err.sqlstate = Some(String::from_utf8_lossy(value).into_owned());
            }
            // 'V' is never localised; 'S' may be, and is kept only when it
            // is one of the fixed English words.
            b'V' | b'S' => {
                if let Some(sev) = SEVERITIES.iter().find(|s| s.as_bytes() == value)
                    && (field_type == b'V' || err.severity.is_none())
                {
                    err.severity = Some(sev);
                }
            }
            _ => {}
        }
        i += end + 1;
    }
    err
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
            // Lost server bytes (ring drops, or a result packet past
            // `max_packet_bytes`): the answers among them are unknown, so
            // the queue is in doubt until a ReadyForQuery that can be
            // attributed (`ready_in_doubt`), found by its bytes.
            (Direction::Ingress, State::Ready) => {
                self.server_buf.clear();
                self.framing_lost = true;
                self.untrusted = true;
                self.enter_doubt();
                Some(ParseResult::NeedMoreData)
            }
            (_, State::Encrypted) => Some(ParseResult::NeedMoreData),
            _ => None,
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Postgres
    }
    /// The stream was not seen from its first byte: bytes that look like a
    /// StartupMessage may be the inside of a message, and answers to
    /// messages sent before capture may still come.
    fn joined_late(&mut self) {
        self.untrusted = true;
    }

    /// Over TLS this parser latches as for a late join (its ruling;
    /// [`ProtocolParser::tls_unproven_start`]).
    fn tls_unproven_start(&mut self) {
        self.joined_late();
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
        // Found by its bytes, the ReadyForQuery re-establishes the framing
        // and closes the query (without status: its bytes may have been
        // row data). From lost server bytes on the connection is
        // untrusted: records go on, never with bound values.
        match p.feed(&tail, Direction::Ingress, 2000) {
            ParseResult::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
                assert_eq!(msgs[0].status, None);
            }
            other => panic!("expected the query's message after resync, got {other:?}"),
        }
        assert!(p.untrusted);
        p.feed(
            &extended_cycle(Some(("", "SELECT $1")), "", &["v"]),
            Direction::Egress,
            3000,
        );
        let ParseResult::Messages(msgs) = p.feed(&insert_done(), Direction::Ingress, 3500) else {
            panic!("expected a record");
        };
        assert_eq!(
            (msgs[0].latency_ns, msgs[0].request_text.as_deref()),
            (Some(500), None)
        );
        assert_eq!(p.state, State::Ready);
    }

    /// The ReadyForQuery was in the lost bytes and the client sent its
    /// next query: the next ReadyForQuery may answer either, so it is not
    /// attributed. The older query is reported without status, and the
    /// queue stays in doubt (no error text) until a ReadyForQuery arrives
    /// with one query pending.
    #[test]
    fn test_gap_swallowing_ready_for_query_is_not_guessed() {
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
        p.feed(
            &make_frontend_msg(b'Q', b"UPDATE t SET a = 1\0"),
            Direction::Egress,
            3000,
        );
        let mut resp = make_backend_msg(b'E', b"SERROR\0Mboom hunter2\0\0");
        resp.extend_from_slice(&make_backend_msg(b'Z', b"I"));
        let ParseResult::Messages(msgs) = p.feed(&resp, Direction::Ingress, 3500) else {
            panic!("the older query is reported");
        };
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert_eq!(msgs[0].method.as_deref(), Some("SELECT"));
        assert_eq!(msgs[0].status, None);
        assert!(p.untrusted);
        p.feed(
            &make_frontend_msg(b'Q', b"SELECT 2\0"),
            Direction::Egress,
            4000,
        );
        let out = format!("{:?}", p.feed(&resp, Direction::Ingress, 4500));
        assert!(!out.contains("hunter2") && !out.contains("boom"), "{out}");
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

    /// Codex R8 #2: messages the server has not answered are retained;
    /// a client pipelining Binds and Executes of a large statement must
    /// not grow memory without bound (queue capped, SQL shared, not
    /// copied, bound values capped in bytes).
    #[test]
    fn test_unanswered_binds_stay_bounded() {
        let mut p = setup_ready_parser();
        let sql = format!("SELECT {}", "x".repeat(4096));
        p.feed(
            &extended_cycle(Some(("s1", &sql)), "s1", &[]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        let value = "v".repeat(4096);
        for _ in 0..MAX_PENDING {
            let mut pair = make_bind("s1", &[&value]);
            pair.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
            p.feed(&pair, Direction::Egress, 3);
            assert!(
                p.held_values <= MAX_HELD_VALUES,
                "{} bytes held",
                p.held_values
            );
        }
        assert!(
            p.pending.len() <= MAX_PENDING,
            "{} pending",
            p.pending.len()
        );
        assert!(
            p.held_values <= MAX_HELD_VALUES,
            "{} bytes held",
            p.held_values
        );
        let copies = p
            .pending
            .iter()
            .filter(|e| matches!(e, Pending::Execute(x) if x.bind.sql.is_some()))
            .count();
        let shared = p.prepared.get("s1").map_or(0, |s| Arc::strong_count(s) - 1);
        assert!(copies <= shared, "{copies} SQL copies, {shared} shared");
        // Past the cap the connection's answers are not matched any more.
        assert!(p.untrusted);
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
        // Reported (EXECUTE, SQL unknown), without its values.
        match p.feed(&insert_done(), Direction::Ingress, 2) {
            ParseResult::Messages(m) => {
                assert_eq!(m.len(), 1, "{m:?}");
                assert_eq!(m[0].method.as_deref(), Some("EXECUTE"));
                assert_eq!(m[0].request_text, None);
            }
            other => panic!("expected the EXECUTE, got {other:?}"),
        }

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

    /// Parse (unnamed or named), Bind with `params`, Execute; no Sync.
    fn pbe(name: &str, sql: &str, params: &[&str]) -> Vec<u8> {
        let mut out = extended_cycle(Some((name, sql)), name, params);
        out.truncate(out.len() - 5); // drop the Sync
        out
    }

    fn sync() -> Vec<u8> {
        make_frontend_msg(b'S', b"")
    }

    fn error(msg: &str) -> Vec<u8> {
        make_backend_msg(b'E', format!("SERROR\0C22P02\0M{msg}\0\0").as_bytes())
    }

    fn records(r: ParseResult) -> Vec<L7Message> {
        match r {
            ParseResult::Messages(m) => m,
            ParseResult::NeedMoreData => vec![],
            other => panic!("{other:?}"),
        }
    }

    /// Review HIGH-1: several statements under one Sync are answered by
    /// one ReadyForQuery. Each Execute is paired with its own answer, so
    /// the next group's error is reported under its own (credential)
    /// statement, never under the earlier group's SQL.
    #[test]
    fn test_statements_under_one_sync_pair_with_their_own_answers() {
        let mut p = setup_ready_parser();
        let mut g1 = pbe("", "SELECT $1::int", &["1"]);
        g1.extend(pbe("", "SELECT $1::int + 1", &["2"]));
        g1.extend(sync());
        p.feed(&g1, Direction::Egress, 1);
        let mut r1 = Vec::new();
        for _ in 0..2 {
            r1.extend(make_backend_msg(b'1', b""));
            r1.extend(make_backend_msg(b'2', b""));
            r1.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        }
        r1.extend(make_backend_msg(b'Z', b"I"));
        let m1 = records(p.feed(&r1, Direction::Ingress, 2));
        assert_eq!(m1.len(), 2, "{m1:?}");
        assert_eq!(m1[0].request_text.as_deref(), Some("1"));
        assert_eq!(m1[1].payload_text.as_deref(), Some("SELECT $1::int + 1"));
        assert_eq!(m1[1].request_text.as_deref(), Some("2"));

        let mut g2 = pbe(
            "",
            "UPDATE users SET password = $1::int WHERE id = 1",
            &["hunter2"],
        );
        g2.extend(sync());
        p.feed(&g2, Direction::Egress, 3);
        let mut r2 = make_backend_msg(b'1', b"");
        r2.extend(error("invalid input syntax for type integer: \"hunter2\""));
        r2.extend(make_backend_msg(b'Z', b"I"));
        let m2 = records(p.feed(&r2, Direction::Ingress, 4));
        let out = format!("{m2:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m2.len(), 1, "{out}");
        assert_eq!(m2[0].method.as_deref(), Some("UPDATE"));
        assert_eq!(m2[0].status, Some(1));
    }

    /// JDBC executeBatch: one statement Parsed once, then Bind/Execute per
    /// row, one Sync. Every row is its own record with its own values.
    #[test]
    fn test_batch_under_one_sync() {
        let mut p = setup_ready_parser();
        let sql = "INSERT INTO users (email) VALUES ($1)";
        let mut batch = pbe("S_1", sql, &["a@x.io"]);
        for v in ["b@x.io", "c@x.io"] {
            batch.extend(make_bind("S_1", &[v]));
            batch.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        }
        batch.extend(sync());
        p.feed(&batch, Direction::Egress, 1);
        let mut r = make_backend_msg(b'1', b"");
        for _ in 0..3 {
            r.extend(make_backend_msg(b'2', b""));
            r.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        }
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        let values: Vec<_> = m.iter().map(|m| m.request_text.as_deref()).collect();
        assert_eq!(values, [Some("a@x.io"), Some("b@x.io"), Some("c@x.io")]);
    }

    /// An error mid-batch: the failing statement gets the error, the
    /// statements after it never ran (not reported), the earlier ones keep
    /// their own answers, and the next group is paired correctly.
    #[test]
    fn test_error_mid_batch() {
        let mut p = setup_ready_parser();
        let mut batch = pbe("", "INSERT INTO t (a) VALUES ($1)", &["one"]);
        batch.extend(pbe("", "INSERT INTO t (n) VALUES ($1::int)", &["two"]));
        batch.extend(pbe("", "INSERT INTO t (a) VALUES ($1)", &["three"]));
        batch.extend(sync());
        p.feed(&batch, Direction::Egress, 1);
        let mut r = make_backend_msg(b'1', b"");
        r.extend(make_backend_msg(b'2', b""));
        r.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        r.extend(make_backend_msg(b'1', b""));
        r.extend(error("invalid input syntax for type integer: \"two\""));
        r.extend(make_backend_msg(b'Z', b"E"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(
            (m[0].status, m[0].request_text.as_deref()),
            (Some(0), Some("one"))
        );
        assert_eq!(m[1].status, Some(1));
        assert_eq!(m[1].request_text, None);
        assert_eq!(
            m[1].payload_text.as_deref(),
            Some("INSERT INTO t (n) VALUES ($1::int)")
        );
        assert!(m[1].headers.contains(&("sqlstate".into(), "22P02".into())));
        assert!(!format!("{m:?}").contains("invalid input"));
        p.feed(
            &extended_cycle(Some(("", "SELECT $1")), "", &["four"]),
            Direction::Egress,
            3,
        );
        let m = records(p.feed(&insert_done(), Direction::Ingress, 4));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].request_text.as_deref(), Some("four"));
    }

    /// Describe (statement and portal), Close and Flush inside a group are
    /// answered (or not, for Flush) in order without disturbing the pairing.
    #[test]
    fn test_describe_close_flush_inside_a_group() {
        let mut p = setup_ready_parser();
        let mut body = b"s\0SELECT $1::text\0".to_vec();
        body.extend_from_slice(&0i16.to_be_bytes());
        let mut c = make_frontend_msg(b'P', &body);
        c.extend(make_frontend_msg(b'D', b"Ss\0"));
        c.extend(make_frontend_msg(b'H', b""));
        c.extend(make_bind("s", &["x1"]));
        c.extend(make_frontend_msg(b'D', b"P\0"));
        c.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        c.extend(make_frontend_msg(b'C', b"Ss\0"));
        c.extend(sync());
        p.feed(&c, Direction::Egress, 1);
        let mut r = make_backend_msg(b'1', b"");
        r.extend(make_backend_msg(b't', &[0, 1, 0, 0, 0, 25]));
        r.extend(make_backend_msg(
            b'T',
            &[
                0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
            ],
        ));
        r.extend(make_backend_msg(b'2', b""));
        r.extend(make_backend_msg(
            b'T',
            &[
                0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
            ],
        ));
        r.extend(make_backend_msg(b'D', &[0, 1, 0, 0, 0, 2, b'x', b'1']));
        r.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        r.extend(make_backend_msg(b'3', b""));
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].request_text.as_deref(), Some("x1"));
        assert!(!p.in_doubt);
        // Closed: forgotten.
        assert!(!p.prepared.contains_key("s"));
    }

    /// A simple Query between extended groups is its own group.
    #[test]
    fn test_simple_query_between_groups() {
        let mut p = setup_ready_parser();
        let mut c = extended_cycle(Some(("", "SELECT $1")), "", &["v1"]);
        c.extend(make_frontend_msg(b'Q', b"SELECT 2\0"));
        c.extend(extended_cycle(Some(("", "SELECT $1")), "", &["v3"]));
        p.feed(&c, Direction::Egress, 1);
        let mut r = insert_done();
        r.extend(error("division by zero"));
        r.extend(make_backend_msg(b'Z', b"I"));
        r.extend(insert_done());
        let m = records(p.feed(&r, Direction::Ingress, 2));
        assert_eq!(m.len(), 3, "{m:?}");
        assert_eq!(m[0].request_text.as_deref(), Some("v1"));
        assert_eq!(
            (m[1].status, m[1].payload_text.as_deref()),
            (Some(1), Some("SELECT 2"))
        );
        assert!(!format!("{m:?}").contains("division"));
        assert_eq!(m[2].request_text.as_deref(), Some("v3"));
    }

    /// Server bytes lost mid-group: the answered statements keep their
    /// records; the rest are reported without values or status, and the
    /// names Parsed in the group are forgotten. A ReadyForQuery found by
    /// its bytes may be row data, so the connection is untrusted from then
    /// on (records, no bound values).
    #[test]
    fn test_lost_server_bytes_inside_a_group() {
        let mut p = setup_ready_parser();
        let mut c = pbe("a", "SELECT $1::text", &["v1"]);
        c.extend(pbe("b", "SELECT $1::text || 'x'", &["v2"]));
        c.extend(sync());
        p.feed(&c, Direction::Egress, 1);
        let mut r = make_backend_msg(b'1', b"");
        r.extend(make_backend_msg(b'2', b""));
        r.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        assert_eq!(m[0].request_text.as_deref(), Some("v1"));
        assert!(p.skip(Direction::Ingress, 40, 3).is_some());
        let mut tail = vec![9u8; 7];
        tail.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&tail, Direction::Ingress, 4));
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!((m[0].request_text.as_deref(), m[0].status), (None, None));
        assert!(p.untrusted, "framing was lost");
        assert!(p.prepared.contains_key("a") && !p.prepared.contains_key("b"));
        // Reused `a`: records go on, never with values.
        let mut done = make_backend_msg(b'2', b"");
        done.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        done.extend(make_backend_msg(b'Z', b"I"));
        for (v, t) in [("v3", 5), ("v4", 7)] {
            p.feed(&extended_cycle(None, "a", &[v]), Direction::Egress, t);
            let m = records(p.feed(&done, Direction::Ingress, t + 1));
            assert_eq!((m.len(), m[0].request_text.as_deref()), (1, None));
        }
    }

    /// An answer that matches nothing pending: doubt, no error text, until
    /// an attributable ReadyForQuery.
    #[test]
    fn test_unexpected_answer_withholds_until_attributable() {
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("", "SELECT $1")), "", &["v1"]),
            Direction::Egress,
            1,
        );
        // A BindComplete where a ParseComplete is due.
        let mut r = make_backend_msg(b'2', b"");
        r.extend(error("bad \"v1\""));
        r.extend(make_backend_msg(b'Z', b"I"));
        let out = format!("{:?}", p.feed(&r, Direction::Ingress, 2));
        assert!(!out.contains("v1"), "{out}");
        assert!(!p.in_doubt);
    }

    /// Review HIGH-2: a statement whose SQL is not known (prepared before
    /// capture): its error text is withheld, it may quote a bound value.
    #[test]
    fn test_unknown_statement_error_text_is_withheld() {
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(None, "s", &["hunter2"]),
            Direction::Egress,
            1,
        );
        let mut r = error("invalid input syntax for type integer: \"hunter2\"");
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        let out = format!("{m:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].method.as_deref(), Some("EXECUTE"));
        assert_eq!(m[0].status, Some(1));
    }

    /// Review LOW: a reused statement's values need a matching
    /// CommandComplete whatever started the group (here a Parse of the
    /// unnamed statement).
    #[test]
    fn test_reused_statement_tag_check_in_a_parse_started_group() {
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(
                Some(("s", "INSERT INTO users (email) VALUES ($1)")),
                "s",
                &["a@x.io"],
            ),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        let mut c = pbe("", "SELECT 1", &[]);
        c.extend(make_bind("s", &["s7Kf2v9LmQ8z"]));
        c.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        c.extend(sync());
        p.feed(&c, Direction::Egress, 3);
        let mut r = make_backend_msg(b'1', b"");
        r.extend(make_backend_msg(b'2', b""));
        r.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        r.extend(make_backend_msg(b'2', b""));
        // Redefined unseen to an UPDATE: the tag does not match.
        r.extend(make_backend_msg(b'C', b"UPDATE 1\0"));
        r.extend(make_backend_msg(b'Z', b"I"));
        let out = format!("{:?}", p.feed(&r, Direction::Ingress, 4));
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// Bind of `statement` into `portal`, text-format parameters.
    fn bind_portal(portal: &str, statement: &str, params: &[&str]) -> Vec<u8> {
        let mut b = format!("{portal}\0{statement}\0").into_bytes();
        b.extend_from_slice(&0i16.to_be_bytes());
        b.extend_from_slice(&(params.len() as i16).to_be_bytes());
        for v in params {
            b.extend_from_slice(&(v.len() as i32).to_be_bytes());
            b.extend_from_slice(v.as_bytes());
        }
        b.extend_from_slice(&0i16.to_be_bytes());
        make_frontend_msg(b'B', &b)
    }

    fn execute(portal: &str) -> Vec<u8> {
        let mut b = format!("{portal}\0").into_bytes();
        b.extend_from_slice(&0i32.to_be_bytes());
        make_frontend_msg(b'E', &b)
    }

    fn parse_msg(name: &str, sql: &str) -> Vec<u8> {
        let mut body = format!("{name}\0{sql}\0").into_bytes();
        body.extend_from_slice(&0i16.to_be_bytes());
        make_frontend_msg(b'P', &body)
    }

    /// A parser with `s` (benign) and `t` (a credential statement)
    /// confirmed.
    fn with_s_and_t() -> PostgresParser {
        let mut p = setup_ready_parser();
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1::text")), "s", &["x"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        p.feed(
            &extended_cycle(
                Some(("t", "UPDATE users SET password = $1::int WHERE id = 1")),
                "t",
                &["1"],
            ),
            Direction::Egress,
            3,
        );
        let mut r = make_backend_msg(b'1', b"");
        r.extend(make_backend_msg(b'2', b""));
        r.extend(make_backend_msg(b'C', b"UPDATE 1\0"));
        r.extend(make_backend_msg(b'Z', b"I"));
        p.feed(&r, Direction::Ingress, 4);
        assert!(p.prepared.contains_key("s") && p.prepared.contains_key("t"));
        p
    }

    /// The reviewer's exact input: group 2 answered `1 2 E Z`.
    #[test]
    fn test_review_high_1_exact_input() {
        let mut p = setup_ready_parser();
        let mut g1 = pbe("", "SELECT $1::int", &["1"]);
        g1.extend(pbe("", "SELECT $1::int + 1", &["2"]));
        g1.extend(sync());
        p.feed(&g1, Direction::Egress, 1);
        let mut r1 = Vec::new();
        for _ in 0..2 {
            r1.extend(make_backend_msg(b'1', b""));
            r1.extend(make_backend_msg(b'2', b""));
            r1.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        }
        r1.extend(make_backend_msg(b'Z', b"I"));
        p.feed(&r1, Direction::Ingress, 2);
        let mut g2 = pbe(
            "",
            "UPDATE users SET password = $1::int WHERE id = 1",
            &["hunter2"],
        );
        g2.extend(sync());
        p.feed(&g2, Direction::Egress, 3);
        let mut r2 = make_backend_msg(b'1', b"");
        r2.extend(make_backend_msg(b'2', b""));
        r2.extend(error("invalid input syntax for type integer: \"hunter2\""));
        r2.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r2, Direction::Ingress, 4));
        let out = format!("{m:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m.len(), 1, "{out}");
        assert_eq!(m[0].method.as_deref(), Some("UPDATE"));
    }

    /// A failed Parse is reported under its own SQL, not a later Parse's.
    #[test]
    fn test_failed_parse_keeps_its_own_sql() {
        let mut p = setup_ready_parser();
        let mut c = parse_msg("a", "UPDATE users SET password = 'hunter2' WHER id = 1");
        c.extend(parse_msg("b", "SELECT 1"));
        c.extend(sync());
        p.feed(&c, Direction::Egress, 1);
        let mut r = error("syntax error at or near \"WHER\": 'hunter2'");
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        let out = format!("{m:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m.len(), 1, "{out}");
        assert_eq!(m[0].method.as_deref(), Some("UPDATE"));
        assert!(!p.prepared.contains_key("a") && !p.prepared.contains_key("b"));
    }

    /// A failed Parse's error is not handed to a later Execute of another
    /// statement.
    #[test]
    fn test_failed_parse_error_not_handed_to_another_statement() {
        let mut p = with_s_and_t();
        let mut c = parse_msg("x", "UPDATE users SET password = $1 WHER id = 1");
        c.extend(make_bind("s", &["hunter2"]));
        c.extend(execute(""));
        c.extend(sync());
        p.feed(&c, Direction::Egress, 5);
        let mut r = error("syntax error near \"hunter2\"");
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 6));
        let out = format!("{m:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m.len(), 1, "{out}");
        assert_eq!(m[0].method.as_deref(), Some("UPDATE"));
    }

    /// A failed Bind is reported under its own statement, not under an
    /// earlier portal's.
    #[test]
    fn test_failed_bind_keeps_its_own_statement() {
        let mut p = with_s_and_t();
        let mut c = bind_portal("p1", "s", &["ok"]);
        c.extend(bind_portal("p2", "t", &["hunter2"]));
        c.extend(execute("p1"));
        c.extend(execute("p2"));
        c.extend(sync());
        p.feed(&c, Direction::Egress, 5);
        let mut r = make_backend_msg(b'2', b"");
        r.extend(error("invalid input syntax for type integer: \"hunter2\""));
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 6));
        let out = format!("{m:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m.len(), 1, "{out}");
        assert_eq!(m[0].method.as_deref(), Some("UPDATE"));
        assert_eq!(m[0].status, Some(1));
    }

    /// An error answering the Sync (at commit) has no statement of its
    /// own: its text is withheld, and a Parse-only group's record keeps
    /// its own status.
    #[test]
    fn test_sync_error_is_not_shown_under_the_parse() {
        let mut p = setup_ready_parser();
        let mut c = parse_msg("a", "SELECT 1");
        c.extend(sync());
        p.feed(&c, Direction::Egress, 1);
        let mut r = make_backend_msg(b'1', b"");
        r.extend(error("duplicate key value: (email)=(jane@x.io)"));
        r.extend(make_backend_msg(b'Z', b"I"));
        let m = records(p.feed(&r, Direction::Ingress, 2));
        let out = format!("{m:?}");
        assert!(!out.contains("jane@x.io"), "{out}");
        assert_eq!(m.len(), 2, "{out}");
        assert_eq!(
            (m[0].payload_text.as_deref(), m[0].status),
            (Some("SELECT 1"), Some(0))
        );
        assert_eq!(m[1].status, Some(1));
    }

    /// A failed Execute of a reused statement (which may have been
    /// redefined unseen) withholds its error text.
    #[test]
    fn test_reused_statement_error_text_is_withheld() {
        let mut p = with_s_and_t();
        p.feed(
            &extended_cycle(None, "s", &["hunter2"]),
            Direction::Egress,
            5,
        );
        let mut r = make_backend_msg(b'2', b"");
        r.extend(error("invalid input: \"hunter2\""));
        r.extend(make_backend_msg(b'Z', b"I"));
        let out = format!("{:?}", p.feed(&r, Direction::Ingress, 6));
        assert!(!out.contains("hunter2"), "{out}");
    }

    /// Final review HIGH-1: a FunctionCall (PQfn, `lo_*`, JDBC fastpath)
    /// is answered by FunctionCallResponse and ReadyForQuery. It is a
    /// group of its own, so the answers after it stay paired.
    #[test]
    fn test_function_call_is_a_group() {
        let mut p = setup_ready_parser();
        let mut call = 952u32.to_be_bytes().to_vec(); // lo_open
        call.extend_from_slice(&0i16.to_be_bytes());
        call.extend_from_slice(&0i16.to_be_bytes());
        call.extend_from_slice(&0i16.to_be_bytes());
        let mut c = make_frontend_msg(b'F', &call);
        c.extend(make_frontend_msg(b'Q', b"SELECT 1\0"));
        c.extend(pbe(
            "",
            "UPDATE users SET password = $1::int WHERE id = 1",
            &["hunter2"],
        ));
        c.extend(sync());
        c.extend(extended_cycle(Some(("", "SELECT $1")), "", &["v4"]));
        p.feed(&c, Direction::Egress, 1);
        let mut r = make_backend_msg(b'V', &[0, 0, 0, 4, 0, 0, 0, 1]);
        r.extend(make_backend_msg(b'Z', b"I"));
        r.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        r.extend(make_backend_msg(b'Z', b"I"));
        r.extend(make_backend_msg(b'1', b""));
        r.extend(make_backend_msg(b'2', b""));
        r.extend(error("invalid input syntax for type integer: \"hunter2\""));
        r.extend(make_backend_msg(b'Z', b"I"));
        r.extend(insert_done());
        let m = records(p.feed(&r, Direction::Ingress, 2));
        let out = format!("{m:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert_eq!(m.len(), 3, "{out}");
        assert_eq!(
            (m[0].payload_text.as_deref(), m[0].status),
            (Some("SELECT 1"), Some(0))
        );
        assert_eq!(
            (m[1].method.as_deref(), m[1].status),
            (Some("UPDATE"), Some(1))
        );
        assert_eq!(m[2].request_text.as_deref(), Some("v4"));
        assert!(!p.in_doubt && !p.untrusted);
    }

    /// A client message the queue does not model may draw answers it
    /// cannot place: the connection's answers are no longer trusted.
    #[test]
    fn test_unmodelled_client_message_untrusts_the_connection() {
        let mut p = setup_ready_parser();
        p.feed(&make_frontend_msg(b'p', b"x\0"), Direction::Egress, 1);
        assert!(p.untrusted);
    }

    /// Final review HIGH-2: a connection joined mid-stream whose first
    /// byte is 0 looks like a StartupMessage. The connection manager says
    /// the stream was not seen from its start (`joined_late`): it is
    /// untrusted for life, whatever its bytes parse as.
    #[test]
    fn test_joined_late_untrusts_even_a_startup_lookalike() {
        let mut p = PostgresParser::new();
        p.joined_late();
        p.feed(&make_startup_msg(), Direction::Egress, 0);
        p.feed(&make_backend_msg(b'Z', b"I"), Direction::Ingress, 0);
        assert_eq!(p.state, State::Ready);
        p.feed(
            &extended_cycle(Some(("s", "SELECT $1")), "s", &["hunter2"]),
            Direction::Egress,
            1,
        );
        let out = format!("{:?}", p.feed(&insert_done(), Direction::Ingress, 2));
        assert!(!out.contains("hunter2"), "{out}");
        assert!(p.untrusted && p.prepared.is_empty());
    }

    /// Final review HIGH-3: pipelining, lost server bytes, and a row that
    /// holds a ReadyForQuery's bytes. The byte search may stop on the
    /// fake one, so the connection is untrusted from the loss on: no bound
    /// value, and no error text ever, whatever the pairing.
    #[test]
    fn test_fake_ready_for_query_in_a_row_after_lost_bytes() {
        let mut p = setup_ready_parser();
        let mut c = make_frontend_msg(b'Q', b"SELECT note FROM users\0");
        c.extend(pbe(
            "",
            "UPDATE users SET password = $1::int WHERE id = 1",
            &["hunter2"],
        ));
        c.extend(sync());
        c.extend(extended_cycle(Some(("", "SELECT $1")), "", &["v3"]));
        p.feed(&c, Direction::Egress, 1);
        p.feed(
            &make_backend_msg(b'T', &[0, 1, b'n', 0]),
            Direction::Ingress,
            2,
        );
        assert!(p.skip(Direction::Ingress, 9000, 3).is_some());
        // The tail of a row whose text holds `Z\0\0\0\x05I`, the row's end,
        // the Query's real ReadyForQuery, then the next groups' answers.
        let mut r = b"..Z\0\0\0\x05I..".to_vec();
        r.extend(make_backend_msg(b'D', &[0, 1, 0, 0, 0, 1, b'x']));
        r.extend(make_backend_msg(b'C', b"SELECT 2\0"));
        r.extend(make_backend_msg(b'Z', b"I"));
        r.extend(make_backend_msg(b'1', b""));
        r.extend(make_backend_msg(b'2', b""));
        r.extend(error("invalid input syntax for type integer: \"hunter2\""));
        r.extend(make_backend_msg(b'Z', b"I"));
        r.extend(insert_done());
        let out = format!("{:?}", p.feed(&r, Direction::Ingress, 4));
        assert!(!out.contains("hunter2") && !out.contains("v3"), "{out}");
        assert!(p.untrusted);
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

        // A lost response: the group's Parses may or may not have been
        // committed, so both names are forgotten, and from then on the
        // connection is untrusted: no Parse is learned.
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
    /// (PREPARE / DEALLOCATE: every confirmed statement is forgotten), and
    /// any Query ends the unnamed one.
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

    /// SQL that names PREPARE, DEALLOCATE or DISCARD as a word, in any
    /// case and anywhere (comments and literals included), may redefine
    /// statements; other SQL, and longer words containing them, may not.
    #[test]
    fn test_may_redefine_statements() {
        for sql in [
            "PREPARE s2(text) AS SELECT $1",
            "DEALLOCATE s",
            "DEALLOCATE ALL",
            "DISCARD ALL",
            "dEaLlOcAtE s",
            "discard plans",
            "SELECT 1 /* deallocate s */",
            "SELECT 1 -- PREPARE\n",
            "SELECT 'prepare'",
            "SELECT f($$DEALLOCATE s$$)",
            "DO $x$BEGIN EXECUTE 'deallocate s'; END$x$",
            "SELECT x_prepare_y",
        ] {
            assert!(may_redefine_statements(sql), "{sql}");
        }
        for sql in [
            "SELECT 1",
            "SELECT prepared_at, discarded FROM t",
            "INSERT INTO users (note) VALUES ('preparation')",
            "UPDATE t SET deallocated = true",
        ] {
            assert!(!may_redefine_statements(sql), "{sql}");
        }
    }

    /// A simple Query always forgets the unnamed statement; it forgets the
    /// named ones only when its SQL may redefine statements. The same SQL
    /// sent through Parse (the extended protocol) forgets them too.
    #[test]
    fn test_statement_redefining_sql_forgets_named_statements() {
        // `s` (named) and the unnamed statement, both confirmed.
        let confirmed = || {
            let mut p = setup_ready_parser();
            p.feed(
                &extended_cycle(Some(("s", "SELECT $1::text")), "s", &["x"]),
                Direction::Egress,
                1,
            );
            p.feed(&insert_done(), Direction::Ingress, 2);
            p.feed(
                &extended_cycle(Some(("", "SELECT $1::int")), "", &["1"]),
                Direction::Egress,
                3,
            );
            p.feed(&insert_done(), Direction::Ingress, 4);
            assert!(p.prepared.contains_key("s") && p.prepared.contains_key(""));
            p
        };
        let simple = |p: &mut PostgresParser, sql: &str| {
            p.feed(
                &make_frontend_msg(b'Q', format!("{sql}\0").as_bytes()),
                Direction::Egress,
                5,
            );
            let mut r = make_backend_msg(b'C', b"OK\0");
            r.extend(make_backend_msg(b'Z', b"I"));
            p.feed(&r, Direction::Ingress, 6);
        };
        let extended = |p: &mut PostgresParser, sql: &str| {
            p.feed(
                &extended_cycle(Some(("", sql)), "", &[]),
                Direction::Egress,
                5,
            );
            p.feed(&insert_done(), Direction::Ingress, 6);
        };
        let forgetting = [
            "PREPARE s2(text) AS INSERT INTO users(password) VALUES ($1)",
            "DEALLOCATE s",
            "Deallocate ALL",
            "DISCARD ALL",
            "SELECT 1 /* DEALLOCATE */",
            "SELECT 'prepare'",
        ];
        for sql in forgetting {
            let mut p = confirmed();
            simple(&mut p, sql);
            assert!(p.prepared.is_empty(), "simple {sql}: {:?}", p.prepared);

            let mut p = confirmed();
            extended(&mut p, sql);
            assert!(!p.prepared.contains_key("s"), "extended {sql}");
        }
        // Plain SQL: the named statement stays; a simple Query still ends
        // the unnamed one.
        let mut p = confirmed();
        simple(&mut p, "SELECT id FROM users WHERE note = 'x'");
        assert!(p.prepared.contains_key("s"), "{:?}", p.prepared);
        assert!(!p.prepared.contains_key(""), "{:?}", p.prepared);
        let mut p = confirmed();
        extended(&mut p, "SELECT prepared_at FROM t");
        assert!(p.prepared.contains_key("s"), "{:?}", p.prepared);

        // The closed hole: Parse("", "DEALLOCATE s"), then a Bind of `s`
        // (which the client may have re-PREPAREd) exports no values.
        let mut p = confirmed();
        extended(&mut p, "DEALLOCATE s");
        p.feed(
            &extended_cycle(None, "s", &["s7Kf2v9LmQ8z"]),
            Direction::Egress,
            7,
        );
        let mut done = make_backend_msg(b'2', b"");
        done.extend(make_backend_msg(b'C', b"SELECT 1\0"));
        done.extend(make_backend_msg(b'Z', b"I"));
        let out = format!("{:?}", p.feed(&done, Direction::Ingress, 8));
        assert!(!out.contains("s7Kf"), "{out}");
    }

    /// A statement confirmed in an earlier cycle may have been redefined
    /// by a server-side function (dynamic PREPARE / DEALLOCATE, which the
    /// agent cannot see): its values are exported only when the server's
    /// CommandComplete names the command of the SQL it was confirmed with.
    #[test]
    fn test_reused_statement_values_need_a_matching_command_tag() {
        let run = |answer: Vec<u8>| -> Option<String> {
            let mut p = setup_ready_parser();
            let sql = "INSERT INTO users (email) VALUES ($1)";
            p.feed(
                &extended_cycle(Some(("s", sql)), "s", &["a@x.io"]),
                Direction::Egress,
                1,
            );
            p.feed(&insert_done(), Direction::Ingress, 2);
            p.feed(
                &extended_cycle(None, "s", &["s7Kf2v9LmQ8z"]),
                Direction::Egress,
                3,
            );
            match p.feed(&answer, Direction::Ingress, 4) {
                ParseResult::Messages(m) => m[0].request_text.clone(),
                other => panic!("{other:?}"),
            }
        };
        let answer = |tag: Option<&[u8]>| {
            let mut r = make_backend_msg(b'2', b"");
            match tag {
                Some(t) => r.extend(make_backend_msg(b'C', t)),
                None => r.extend(make_backend_msg(b'E', b"SERROR\0Mfailed\0\0")),
            }
            r.extend(make_backend_msg(b'Z', b"I"));
            r
        };
        assert_eq!(
            run(answer(Some(b"INSERT 0 1\0"))).as_deref(),
            Some("s7Kf2v9LmQ8z")
        );
        // Redefined to another command (PREPARE takes only SELECT, INSERT,
        // UPDATE, DELETE, MERGE and VALUES): UPDATE users SET password = $1.
        assert_eq!(run(answer(Some(b"UPDATE 1\0"))), None);
        // No tag (an error): unverified, withheld.
        assert_eq!(run(answer(None)), None);
    }

    /// A Bind/Execute cycle of a statement whose SQL the agent does not
    /// know (forgotten, or prepared before capture) is still one exchange:
    /// it is exported without SQL or bound values, never dropped, and its
    /// answer is not paired with the next query.
    #[test]
    fn test_bind_of_unknown_statement_is_exported_without_sql() {
        let mut p = setup_ready_parser();
        let sql = "INSERT INTO users (id, email, note) VALUES ($1, $2, $3)";
        p.feed(
            &extended_cycle(Some(("_pg3_0", sql)), "_pg3_0", &["1", "a@x.io", "t1"]),
            Direction::Egress,
            1,
        );
        p.feed(&insert_done(), Direction::Ingress, 2);
        // DISCARD ALL in a simple Query: every statement is forgotten.
        p.feed(
            &make_frontend_msg(b'Q', b"DISCARD ALL\0"),
            Direction::Egress,
            3,
        );
        let mut r = make_backend_msg(b'C', b"DISCARD ALL\0");
        r.extend(make_backend_msg(b'Z', b"I"));
        p.feed(&r, Direction::Ingress, 4);
        // The driver reuses the statement: Bind/Execute/Sync only.
        p.feed(
            &extended_cycle(None, "_pg3_0", &["2", "b@x.io", "t2"]),
            Direction::Egress,
            5,
        );
        let mut done = make_backend_msg(b'2', b"");
        done.extend(make_backend_msg(b'C', b"INSERT 0 1\0"));
        done.extend(make_backend_msg(b'Z', b"I"));
        let ParseResult::Messages(msgs) = p.feed(&done, Direction::Ingress, 9) else {
            panic!("the Bind cycle must be exported");
        };
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert_eq!(msgs[0].request_text, None, "{msgs:?}");
        assert_eq!(msgs[0].method.as_deref(), Some("EXECUTE"), "{msgs:?}");
        assert_eq!(msgs[0].payload_text.as_deref(), Some("EXECUTE"), "{msgs:?}");
        assert_eq!(msgs[0].latency_ns, Some(4), "{msgs:?}");
        assert_eq!(msgs[0].status, Some(0));
        // The next query gets its own answer.
        p.feed(
            &make_frontend_msg(b'Q', b"SELECT 2\0"),
            Direction::Egress,
            10,
        );
        let mut r = make_backend_msg(b'E', b"SERROR\0Mboom\0\0");
        r.extend(make_backend_msg(b'Z', b"I"));
        let ParseResult::Messages(msgs) = p.feed(&r, Direction::Ingress, 11) else {
            panic!("expected the SELECT");
        };
        assert_eq!(msgs[0].payload_text.as_deref(), Some("SELECT 2"));
        assert_eq!(msgs[0].status, Some(1));
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
        let mut client = make_frontend_msg(b'P', &parse_payload);
        client.extend(make_bind("stmt", &["1"]));
        client.extend(make_frontend_msg(b'D', b"P\0"));
        client.extend(make_frontend_msg(b'E', b"\0\0\0\0\0"));
        client.extend(make_frontend_msg(b'S', b""));
        p.feed(&client, Direction::Egress, 1000);

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
        for (query, shown) in [
            (
                &b"ALTER ROLE app PASSWORD 'pg-s3cret' BAD\0"[..],
                "ALTER <statement withheld>",
            ),
            (b"SELECT 1\0", "SELECT 1"),
        ] {
            let mut p = setup_ready_parser();
            p.feed(&make_frontend_msg(b'Q', query), Direction::Egress, 1000);
            let mut response = make_backend_msg(
                b'E',
                b"SERROR\0VERROR\0C42601\0Mnear \"PASSWORD 'pg-s3cret' BAD\"\0Dd\0Hh\0\0",
            );
            response.extend_from_slice(&make_backend_msg(b'Z', b"I"));
            let ParseResult::Messages(msgs) = p.feed(&response, Direction::Ingress, 2000) else {
                panic!("expected a message");
            };
            let out = format!("{msgs:?}");
            assert!(!out.contains("near"), "{out}");
            assert_eq!(msgs[0].payload_text.as_deref(), Some(shown));
            assert_eq!(
                msgs[0].headers,
                vec![
                    ("sqlstate".to_string(), "42601".to_string()),
                    ("severity".to_string(), "ERROR".to_string())
                ]
            );
        }
    }

    /// Only a well-formed SQLSTATE and a known severity are read out of an
    /// ErrorResponse; every text field is dropped.
    #[test]
    fn test_error_response_exports_only_code_and_severity() {
        let e = parse_error_response(
            b"SFEHLER\0VERROR\0C22P02\0Mhunter2\0Dhunter2\0tusers\0ccol\0nk\0\0",
        );
        assert_eq!(
            e,
            PgError {
                sqlstate: Some("22P02".into()),
                severity: Some("ERROR")
            }
        );
        let e = parse_error_response(b"Shunter2\0Chunter2\0\0");
        assert_eq!(
            e,
            PgError {
                sqlstate: None,
                severity: None
            }
        );
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
