//! What may reach the parsers and every sink: `pid_filter`,
//! `sampling_mode = "connection_sample"` and `"head_only"`, on the TC
//! backend. On cgroup_skb the kernel decides all of them and this gate is a
//! pass-through ([`GateConfig::from_config`]).
//!
//! Each worker runs every event through its gate first, before the raw dump,
//! logging, parsing, PII scanning, the service graph and the exports, so an
//! event the gate drops (or the part of it the gate cuts) reaches none of
//! them. A connection's events always go to the same worker, so the gate's
//! per-connection state is per worker.
//!
//! - `pid_filter`: TLS and socket events carry the process that produced
//!   them and are filtered in the kernel already (`PID_FILTER`); they are
//!   checked again here. TC packets run in softirq with no process: they
//!   pass only once a socket event (connect / accept) from a listed process
//!   has named the connection's owner. Until then they are held, briefly and
//!   within fixed bounds, because a server's accept() returns after the
//!   client's first bytes may already be on the wire; a connection whose
//!   owner is not seen in time is dropped and counted.
//! - `connection_sample`: a connection is in or out for its whole life, from
//!   a keyed hash (SipHash, random key per agent start) of its connection
//!   key, so which connections are kept cannot be predicted or steered.
//! - `head_only`: only the first N bytes of each direction of a connection
//!   pass. TCP is cut at the stream offset counted from the SYN, which the
//!   kernel delivers in this mode; a TCP connection whose SYN was not seen
//!   (open before the agent started, or forgotten) passes no bytes at all.
//!   TLS and UDP count from the first byte seen; having no start marker,
//!   their state is never forgotten (not when idle, not when the table is
//!   full), so a count never restarts. A full table admits no new state:
//!   new connections then pass nothing.

// The workers that use it are Linux-only; the logic is tested everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use fxhash::{FxHashMap, FxHashSet};
use panopticon_common::{
    DataEvent, EventType, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN,
};

use crate::config::{AgentConfig, CaptureBackend, SamplingMode};
use crate::event_loop::{EventStats, sender_endpoint};
use crate::protocol::fsm::Endpoint;

const IP_PROTO_TCP: u8 = 6;

/// Most TC events held per connection while its owner is unknown.
pub const HOLD_MAX_EVENTS: usize = 8;
/// Most TC events held per worker (each a ~4 KB copy).
pub const HOLD_MAX_TOTAL: usize = 256;
/// How long held events wait for their connection's owner.
pub const HOLD_TIMEOUT_NS: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Process the event (possibly cut).
    Process,
    /// Discard it; counted.
    Drop,
    /// Kept by the gate until its connection's owner is known
    /// ([`CaptureGate::release`]).
    Hold,
}

/// The settings every worker's gate shares, from the config.
#[derive(Debug, Clone, Default)]
pub struct GateConfig {
    pids: Option<Arc<FxHashSet<u32>>>,
    /// Keyed hashes below this are sampled in; None = no sampling.
    sample_threshold: Option<u64>,
    head_bytes: Option<u64>,
}

impl GateConfig {
    /// For live capture. On the cgroup_skb backend the kernel has made
    /// every scope decision (DESIGN §8): the gate is a pass-through (no pid
    /// check, holds, sampling or head cut) and TC SYN events stay off.
    pub fn from_config(config: &AgentConfig) -> Self {
        if config.capture_backend == CaptureBackend::CgroupSkb {
            return Self::default();
        }
        Self::user_space(config)
    }

    /// The user-space rules (TC semantics) whatever the backend: for events
    /// no kernel scope decided, such as a replayed recording. They err
    /// toward drop.
    pub fn user_space(config: &AgentConfig) -> Self {
        Self {
            pids: config
                .pid_filter
                .as_ref()
                .map(|p| Arc::new(p.iter().copied().collect())),
            // A rate of 1 keeps everything: exactly `full`.
            sample_threshold: (config.sampling_mode == SamplingMode::ConnectionSample
                && config.sample_rate < 1.0)
                .then(|| sample_threshold(config.sample_rate)),
            head_bytes: match config.sampling_mode {
                SamplingMode::HeadOnly { max_bytes } => Some(max_bytes),
                _ => None,
            },
        }
    }

    /// Whether TC must also deliver SYN segments (head_only counts TCP
    /// offsets from them).
    pub fn wants_syn(&self) -> bool {
        self.head_bytes.is_some()
    }
}

/// `rate` of the u64 range: hashes below it are sampled in. 0 for 0.
fn sample_threshold(rate: f64) -> u64 {
    // Saturating cast; rate < 1 here, so the product is < 2^64.
    (rate * 18_446_744_073_709_551_616.0) as u64
}

/// Keyed, uniform hash of a connection key: SipHash under a key drawn once
/// per agent start. The keys themselves are not uniform enough to compare
/// against a threshold (TC flow cookies are FNV-1a of the 5-tuple).
fn sample_hash(key: u64) -> u64 {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    KEY.get_or_init(RandomState::new).hash_one(key)
}

/// Whether the connection with this key is sampled in.
fn sampled_in(threshold: u64, key: u64) -> bool {
    sample_hash(key) < threshold
}

struct Held {
    first_ns: u64,
    events: Vec<Box<DataEvent>>,
}

/// One direction of a connection under head_only.
#[derive(Debug, Clone, Copy)]
struct Side {
    who: Endpoint,
    /// TCP: the sequence number of stream offset `sent`.
    next_seq: u32,
    /// Bytes of this direction seen so far (highest stream offset).
    sent: u64,
}

struct Head {
    last_ns: u64,
    /// TCP (counted from the SYN) rather than TLS / UDP (from first sight).
    tcp: bool,
    sides: [Option<Side>; 2],
}

impl Head {
    fn side(&mut self, who: Endpoint) -> Option<&mut Side> {
        self.sides.iter_mut().flatten().find(|s| s.who == who)
    }

    /// The sender's side, added if there is room.
    fn side_or_new(&mut self, who: Endpoint, side: Side) -> Option<&mut Side> {
        let at = self
            .sides
            .iter()
            .position(|s| s.is_some_and(|s| s.who == who))
            .or_else(|| self.sides.iter().position(Option::is_none))?;
        Some(self.sides[at].get_or_insert(side))
    }
}

/// Insert `key` (last seen at `ts`), clearing the map first if it is full.
/// True if the key was new.
fn insert_bounded<V>(map: &mut FxHashMap<u64, V>, cap: usize, key: u64, value: V) -> bool {
    if map.len() >= cap && !map.contains_key(&key) {
        map.clear();
    }
    map.insert(key, value).is_none()
}

/// One worker's gate.
pub struct CaptureGate {
    cfg: GateConfig,
    cap: usize,
    held: FxHashMap<u64, Held>,
    held_total: usize,
    /// Connections whose owner was not found in time → last seen.
    denied: FxHashMap<u64, u64>,
    /// Sampled-out connections → last seen (for counting them once).
    sampled_out: FxHashMap<u64, u64>,
    heads: FxHashMap<u64, Head>,
}

impl CaptureGate {
    /// `cap` bounds each per-connection table.
    pub fn new(cfg: GateConfig, cap: usize) -> Self {
        Self {
            cfg,
            cap: cap.max(1),
            held: FxHashMap::default(),
            held_total: 0,
            denied: FxHashMap::default(),
            sampled_out: FxHashMap::default(),
            heads: FxHashMap::default(),
        }
    }

    /// Whether events of process `pid` may be captured.
    pub fn pid_allowed(&self, pid: u32) -> bool {
        self.cfg.pids.as_ref().is_none_or(|p| p.contains(&pid))
    }

    fn owner_listed(&self, owners: &[Option<u32>; 2]) -> bool {
        self.cfg
            .pids
            .as_ref()
            .is_none_or(|p| owners.iter().flatten().any(|pid| p.contains(pid)))
    }

    /// Decide what happens to `event` of connection `key`. `owners` are the
    /// local processes (client, server) known to own the connection. Under
    /// head_only, cuts the event's payload in place.
    pub fn admit(
        &mut self,
        event: &mut DataEvent,
        key: u64,
        owners: [Option<u32>; 2],
        stats: &EventStats,
    ) -> Verdict {
        if let Some(threshold) = self.cfg.sample_threshold
            && !sampled_in(threshold, key)
        {
            stats.sampled_out_events.fetch_add(1, Ordering::Relaxed);
            if insert_bounded(&mut self.sampled_out, self.cap, key, event.timestamp_ns) {
                stats
                    .sampled_out_connections
                    .fetch_add(1, Ordering::Relaxed);
            }
            return Verdict::Drop;
        }
        if self.cfg.pids.is_some() {
            if event.event_type == EventType::TcPacket {
                if !self.owner_listed(&owners) {
                    return self.hold(event, key, stats);
                }
            } else if !self.pid_allowed(event.pid) {
                stats
                    .pid_filter_dropped_events
                    .fetch_add(1, Ordering::Relaxed);
                return Verdict::Drop;
            }
        }
        self.cut_head(event, key, stats)
    }

    fn hold(&mut self, event: &DataEvent, key: u64, stats: &EventStats) -> Verdict {
        let ts = event.timestamp_ns;
        if let Some(last) = self.denied.get_mut(&key) {
            *last = ts;
            stats
                .pid_filter_dropped_events
                .fetch_add(1, Ordering::Relaxed);
            return Verdict::Drop;
        }
        let full = self.held_total >= HOLD_MAX_TOTAL;
        let held = self.held.entry(key).or_insert_with(|| Held {
            first_ns: ts,
            events: Vec::new(),
        });
        if full || held.events.len() >= HOLD_MAX_EVENTS {
            stats
                .pid_filter_dropped_events
                .fetch_add(1, Ordering::Relaxed);
            self.deny(key, ts, stats);
            return Verdict::Drop;
        }
        held.events.push(Box::new(*event));
        self.held_total += 1;
        Verdict::Hold
    }

    /// Give up on connection `key`: drop what is held, drop what follows.
    fn deny(&mut self, key: u64, ts: u64, stats: &EventStats) {
        if let Some(held) = self.held.remove(&key) {
            self.held_total -= held.events.len();
            stats
                .pid_filter_dropped_events
                .fetch_add(held.events.len() as u64, Ordering::Relaxed);
        }
        insert_bounded(&mut self.denied, self.cap, key, ts);
        stats
            .pid_filter_unknown_owner_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    /// After an owner event of connection `key`: its held packets, oldest
    /// first, if a listed process now owns it. Run each through
    /// [`cut_head`](Self::cut_head) before processing it.
    pub fn release(&mut self, key: u64, owners: [Option<u32>; 2]) -> Vec<Box<DataEvent>> {
        if !self.held.contains_key(&key) || !self.owner_listed(&owners) {
            return Vec::new();
        }
        let held = self.held.remove(&key).map(|h| h.events).unwrap_or_default();
        self.held_total -= held.len();
        held
    }

    /// Whether any events are held.
    pub fn has_held(&self) -> bool {
        !self.held.is_empty()
    }

    /// Drop held connections whose owner did not show up in time.
    pub fn expire_held(&mut self, now_ns: u64, stats: &EventStats) {
        let expired: Vec<(u64, u64)> = self
            .held
            .iter()
            .filter(|(_, h)| now_ns.saturating_sub(h.first_ns) > HOLD_TIMEOUT_NS)
            .map(|(&k, h)| (k, h.first_ns))
            .collect();
        for (key, ts) in expired {
            self.deny(key, ts, stats);
        }
    }

    /// Forget connections idle for longer than `idle_ns`.
    pub fn sweep(&mut self, now_ns: u64, idle_ns: u64, stats: &EventStats) {
        self.expire_held(now_ns, stats);
        let live = |last: u64| now_ns.saturating_sub(last) <= idle_ns;
        self.denied.retain(|_, last| live(*last));
        self.sampled_out.retain(|_, last| live(*last));
        // Only TCP head state may go when idle: a TCP segment without state
        // passes nothing. TLS and UDP have no start marker, so forgetting
        // one would restart its count: they are kept until restart.
        self.heads.retain(|_, h| !h.tcp || live(h.last_ns));
    }

    /// A TCP connection closed (FIN both ways, RST): its head_only state
    /// goes, and a segment that follows passes nothing. (TLS and UDP
    /// connections have no close the agent sees.)
    pub fn forget(&mut self, key: u64) {
        self.heads.remove(&key);
    }

    /// Add head_only state for `key`. Fails closed when the table is full:
    /// nothing is evicted (that would restart a TLS / UDP count), the new
    /// connection gets no state and passes nothing.
    fn insert_head(&mut self, key: u64, tcp: bool, ts: u64) {
        if self.heads.len() < self.cap {
            let head = Head {
                last_ns: ts,
                tcp,
                sides: [None; 2],
            };
            self.heads.insert(key, head);
        }
    }

    /// head_only: cut `event` to the bytes before its direction's limit.
    pub fn cut_head(&mut self, event: &mut DataEvent, key: u64, stats: &EventStats) -> Verdict {
        let Some(limit) = self.cfg.head_bytes else {
            return Verdict::Process;
        };
        let tcp = event.event_type == EventType::TcPacket && event.ip_proto == IP_PROTO_TCP;
        // Bytes this event stands for (captured or not).
        let len = event.orig_len as u64;
        if !tcp && len == 0 {
            return Verdict::Process; // socket events: nothing to cut
        }
        let ts = event.timestamp_ns;
        let who = sender_endpoint(event);
        let syn = tcp && event.tcp_flags & TCP_FLAG_SYN != 0;
        if syn {
            // A connection (re)starting: a SYN without ACK opens a new one,
            // and each side's stream begins after its SYN.
            if event.tcp_flags & TCP_FLAG_ACK == 0 {
                self.heads.remove(&key);
            }
            if !self.heads.contains_key(&key) {
                self.insert_head(key, true, ts);
            }
            if let Some(head) = self.heads.get_mut(&key) {
                let start = Side {
                    who,
                    next_seq: event.tcp_seq.wrapping_add(1),
                    sent: 0,
                };
                if let Some(side) = head.side_or_new(who, start) {
                    *side = start;
                }
            }
        } else if !tcp && !self.heads.contains_key(&key) {
            self.insert_head(key, false, ts);
        }

        // Stream offset of the event's first byte; None when unknown (TCP
        // without its SYN, or before it), which passes nothing.
        let start = self.heads.get_mut(&key).and_then(|head| {
            head.last_ns = ts;
            let side = if tcp {
                head.side(who)?
            } else {
                head.side_or_new(
                    who,
                    Side {
                        who,
                        next_seq: 0,
                        sent: 0,
                    },
                )?
            };
            if tcp {
                let data_seq = event.tcp_seq.wrapping_add(syn as u32);
                let diff = data_seq.wrapping_sub(side.next_seq) as i32 as i64;
                let start = u64::try_from(side.sent as i64 + diff).ok()?;
                let end = start + len;
                if end > side.sent {
                    side.sent = end;
                    side.next_seq = data_seq.wrapping_add(len as u32);
                }
                Some(start)
            } else {
                let start = side.sent;
                side.sent += len;
                Some(start)
            }
        });
        let keep = start.map_or(0, |s| limit.saturating_sub(s).min(len));
        if keep == len {
            return Verdict::Process;
        }
        stats.head_only_cut_events.fetch_add(1, Ordering::Relaxed);
        if keep == 0 && event.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST) == 0 {
            return Verdict::Drop;
        }
        // Keep the head; a FIN / RST past it still closes the connection.
        event.payload_len = event.payload_len.min(keep as u32);
        event.orig_len = keep as u32;
        Verdict::Process
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panopticon_common::Direction;

    fn event(kind: EventType, payload: &[u8]) -> DataEvent {
        // SAFETY: all-zero is a valid DataEvent.
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        e.event_type = kind;
        e.direction = Direction::Egress;
        e.payload[..payload.len()].copy_from_slice(payload);
        e.payload_len = payload.len() as u32;
        e.orig_len = payload.len() as u32;
        e
    }

    fn tcp(src: Endpoint, seq: u32, flags: u8, payload: &[u8]) -> DataEvent {
        let mut e = event(EventType::TcPacket, payload);
        e.ip_proto = IP_PROTO_TCP;
        (e.src_addr, e.src_port) = src;
        e.tcp_seq = seq;
        e.tcp_flags = flags;
        e
    }

    fn config(toml: &str) -> GateConfig {
        GateConfig::from_config(&crate::config::load_config_from_str(toml).unwrap())
    }

    fn gate(toml: &str) -> CaptureGate {
        CaptureGate::new(config(toml), 1024)
    }

    /// Keys spread like real ones: distinct, otherwise arbitrary.
    fn keys(n: usize) -> impl Iterator<Item = u64> {
        let s = RandomState::new();
        (0..n as u64).map(move |i| s.hash_one(i))
    }

    #[test]
    fn sampling_is_uniform_and_stable_per_connection() {
        const N: usize = 100_000;
        for rate in [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99] {
            let t = sample_threshold(rate);
            let kept = keys(N).filter(|&k| sampled_in(t, k)).count();
            let frac = kept as f64 / N as f64;
            assert!((frac - rate).abs() < 0.01, "rate {rate}: kept {frac}");
            // Sequential keys too (nearby 5-tuples give nearby inputs).
            let kept = (0..N as u64).filter(|&k| sampled_in(t, k)).count();
            let frac = kept as f64 / N as f64;
            assert!(
                (frac - rate).abs() < 0.01,
                "rate {rate}, sequential: {frac}"
            );
            // The same key always gets the same decision.
            for k in keys(1000) {
                let first = sampled_in(t, k);
                assert!((0..10).all(|_| sampled_in(t, k) == first));
            }
        }
        assert_eq!(sample_threshold(0.0), 0);
        assert!(keys(N).all(|k| !sampled_in(sample_threshold(0.0), k)));
    }

    #[test]
    fn connection_sample_drops_whole_connections_and_counts_them() {
        let stats = EventStats::new();
        let mut half = gate("sampling_mode = \"connection_sample\"\nsample_rate = 0.5\n");
        let mut kept = 0;
        for key in keys(1000) {
            let verdicts: Vec<Verdict> = (0..5)
                .map(|_| half.admit(&mut event(EventType::TlsData, b"x"), key, [None; 2], &stats))
                .collect();
            assert!(verdicts.windows(2).all(|w| w[0] == w[1]), "{verdicts:?}");
            kept += (verdicts[0] == Verdict::Process) as usize;
        }
        let out = 1000 - kept as u64;
        assert!((400..600).contains(&kept), "{kept}");
        assert_eq!(stats.sampled_out_connections.load(Ordering::Relaxed), out);
        assert_eq!(stats.sampled_out_events.load(Ordering::Relaxed), out * 5);

        // 0 keeps nothing; 1 is exactly full (no sampling at all).
        let mut none = gate("sampling_mode = \"connection_sample\"\nsample_rate = 0.0\n");
        assert!(keys(1000).all(|k| none.admit(
            &mut event(EventType::TlsData, b"x"),
            k,
            [None; 2],
            &stats
        ) == Verdict::Drop));
        let all = config("sampling_mode = \"connection_sample\"\nsample_rate = 1.0\n");
        assert!(all.sample_threshold.is_none() && all.head_bytes.is_none());
        assert!(all.pids.is_none());
    }

    #[test]
    fn pid_filter_checks_processes_and_tc_owners() {
        let stats = EventStats::new();
        let mut g = gate("pid_filter = [100]\n");
        let mut tls = event(EventType::TlsData, b"GET /");
        tls.pid = 100;
        assert_eq!(g.admit(&mut tls, 1, [None; 2], &stats), Verdict::Process);
        tls.pid = 101;
        assert_eq!(g.admit(&mut tls, 1, [None; 2], &stats), Verdict::Drop);
        assert_eq!(stats.pid_filter_dropped_events.load(Ordering::Relaxed), 1);

        // TC with a listed owner (either end) passes at once.
        let pkt = || tcp((1, 1000), 1, 0, b"GET /");
        assert_eq!(
            g.admit(&mut pkt(), 7, [Some(5), Some(100)], &stats),
            Verdict::Process
        );
        // Unknown owner: held until a listed owner shows up, then released in order.
        for i in 0..3 {
            let mut p = pkt();
            p.tcp_seq = i;
            assert_eq!(g.admit(&mut p, 8, [Some(5), None], &stats), Verdict::Hold);
        }
        assert!(g.release(8, [Some(5), None]).is_empty(), "unlisted owner");
        let released = g.release(8, [Some(5), Some(100)]);
        assert_eq!(
            released.iter().map(|e| e.tcp_seq).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert!(!g.has_held());
    }

    #[test]
    fn pid_filter_drops_connections_whose_owner_never_shows() {
        let stats = EventStats::new();
        let mut g = gate("pid_filter = [100]\n");
        let mut pkt = tcp((1, 1000), 1, 0, b"x");
        pkt.timestamp_ns = 10;
        for _ in 0..HOLD_MAX_EVENTS {
            assert_eq!(g.admit(&mut pkt, 9, [None; 2], &stats), Verdict::Hold);
        }
        // Over the per-connection bound: everything of it is dropped...
        assert_eq!(g.admit(&mut pkt, 9, [None; 2], &stats), Verdict::Drop);
        assert_eq!(g.admit(&mut pkt, 9, [None; 2], &stats), Verdict::Drop);
        assert!(g.release(9, [Some(100), None]).is_empty());
        let dropped = stats.pid_filter_dropped_events.load(Ordering::Relaxed);
        assert_eq!(dropped, HOLD_MAX_EVENTS as u64 + 2);
        // ...unless its listed owner is known by then.
        assert_eq!(
            g.admit(&mut pkt, 9, [Some(100), None], &stats),
            Verdict::Process
        );

        // Timed out.
        assert_eq!(g.admit(&mut pkt, 10, [None; 2], &stats), Verdict::Hold);
        g.expire_held(10 + HOLD_TIMEOUT_NS, &stats);
        assert!(g.has_held());
        g.expire_held(11 + HOLD_TIMEOUT_NS, &stats);
        assert!(!g.has_held());
        assert_eq!(
            stats
                .pid_filter_unknown_owner_connections
                .load(Ordering::Relaxed),
            2
        );
        // The worker-wide bound.
        for key in 0..HOLD_MAX_TOTAL as u64 {
            assert_eq!(
                g.admit(&mut pkt, 1000 + key, [None; 2], &stats),
                Verdict::Hold
            );
        }
        assert_eq!(g.admit(&mut pkt, 5000, [None; 2], &stats), Verdict::Drop);
    }

    #[test]
    fn cgroup_skb_gate_is_a_pass_through() {
        // Every user-space rule set, on both backends.
        for rules in [
            "pid_filter = [100]\n",
            "sampling_mode = \"connection_sample\"\nsample_rate = 0.0\n",
            "sampling_mode = \"head_only\"\nhead_only_bytes = 1\n",
        ] {
            let stats = EventStats::new();
            let cg = config(&format!("{rules}[capture]\nbackend = \"cgroup_skb\"\n"));
            assert!(!cg.wants_syn(), "{rules}");
            let mut g = CaptureGate::new(cg, 1024);
            let mut tls = event(EventType::TlsData, b"GET / HTTP/1.1");
            tls.pid = 101;
            let mut close = event(EventType::SockClose, b"");
            close.socket_cookie = 9;
            // No SYN seen, no owner known, unlisted pid: all pass unchanged.
            for (key, mut e) in [(1, tcp((1, 1000), 5, 0, b"abcdef")), (2, tls), (9, close)] {
                let before = e;
                assert_eq!(g.admit(&mut e, key, [None; 2], &stats), Verdict::Process);
                assert_eq!(e.payload_bytes(), before.payload_bytes(), "{rules}");
                assert_eq!(e.orig_len, before.orig_len);
            }
            assert!(!g.has_held());
            for c in [
                &stats.pid_filter_dropped_events,
                &stats.sampled_out_events,
                &stats.head_only_cut_events,
            ] {
                assert_eq!(c.load(Ordering::Relaxed), 0, "{rules}");
            }

            // The same rules on TC still filter.
            let mut tc = gate(rules);
            let mut p = tcp((1, 1000), 5, 0, b"abcdef");
            assert_ne!(tc.admit(&mut p, 1, [None; 2], &stats), Verdict::Process);
        }
        assert!(config("sampling_mode = \"head_only\"\nhead_only_bytes = 1\n").wants_syn());
    }

    fn head(g: &mut CaptureGate, e: &mut DataEvent, key: u64) -> (Verdict, Vec<u8>) {
        let stats = EventStats::new();
        let v = g.admit(e, key, [None; 2], &stats);
        (v, e.payload_bytes().to_vec())
    }

    #[test]
    fn head_only_cuts_tcp_at_the_stream_offset() {
        let mut g = gate("sampling_mode = \"head_only\"\nhead_only_bytes = 10\n");
        let (c, s) = ((1, 40000), (2, 80));
        // Data before the SYN was seen: nothing passes.
        assert_eq!(
            head(&mut g, &mut tcp(c, 1001, 0, b"abc"), 1).0,
            Verdict::Drop
        );
        head(&mut g, &mut tcp(c, 1000, TCP_FLAG_SYN, b""), 1);
        head(
            &mut g,
            &mut tcp(s, 5000, TCP_FLAG_SYN | TCP_FLAG_ACK, b""),
            1,
        );
        let ack = TCP_FLAG_ACK;
        assert_eq!(head(&mut g, &mut tcp(c, 1001, ack, b"0123"), 1).1, b"0123");
        // Straddles the limit: cut at offset 10.
        let mut e = tcp(c, 1005, ack, b"456789abcd");
        assert_eq!(
            head(&mut g, &mut e, 1),
            (Verdict::Process, b"456789".to_vec())
        );
        assert_eq!(e.orig_len, 6);
        // A retransmission of head bytes is cut the same way.
        assert_eq!(
            head(&mut g, &mut tcp(c, 1005, ack, b"456789abcd"), 1).1,
            b"456789"
        );
        // Past the limit: dropped, but a FIN still gets through, empty.
        assert_eq!(
            head(&mut g, &mut tcp(c, 1015, ack, b"efgh"), 1).0,
            Verdict::Drop
        );
        let (v, p) = head(&mut g, &mut tcp(c, 1019, ack | TCP_FLAG_FIN, b"ij"), 1);
        assert_eq!((v, p.as_slice()), (Verdict::Process, &b""[..]));
        // The other direction has its own 10 bytes.
        let (v, p) = head(&mut g, &mut tcp(s, 5001, ack, b"HTTP/1.1 200 OK"), 1);
        assert_eq!((v, p.as_slice()), (Verdict::Process, &b"HTTP/1.1 2"[..]));
        // Sequence wraparound inside the head.
        head(&mut g, &mut tcp(c, u32::MAX - 1, TCP_FLAG_SYN, b""), 2);
        assert_eq!(
            head(&mut g, &mut tcp(c, u32::MAX, ack, b"01234"), 2).1,
            b"01234"
        );
        assert_eq!(
            head(&mut g, &mut tcp(c, 4, ack, b"56789xyz"), 2).1,
            b"56789"
        );
        // A forgotten connection passes nothing more.
        g.forget(1);
        assert_eq!(
            head(&mut g, &mut tcp(c, 1001, ack, b"0123"), 1).0,
            Verdict::Drop
        );
        // A new SYN on the same key starts a new connection.
        head(&mut g, &mut tcp(c, 7000, TCP_FLAG_SYN, b""), 1);
        assert_eq!(
            head(&mut g, &mut tcp(c, 7001, ack, b"0123456789AB"), 1).1,
            b"0123456789"
        );
    }

    fn tls(dir: Direction, p: &[u8]) -> DataEvent {
        let mut e = event(EventType::TlsData, p);
        e.direction = dir;
        e
    }

    #[test]
    fn head_only_idle_connections_never_restart_their_count() {
        let stats = EventStats::new();
        let mut g = gate("sampling_mode = \"head_only\"\nhead_only_bytes = 4\n");
        let (c, ack) = ((1, 40000), TCP_FLAG_ACK);
        // TLS: the head is used up, then the connection goes idle.
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"abcdef"), 1).1,
            b"abcd"
        );
        // Half a head used on another, then idle too.
        assert_eq!(head(&mut g, &mut tls(Direction::Egress, b"ab"), 2).1, b"ab");
        // TCP, idle as well.
        head(&mut g, &mut tcp(c, 100, TCP_FLAG_SYN, b""), 3);
        assert_eq!(head(&mut g, &mut tcp(c, 101, ack, b"ab"), 3).1, b"ab");
        let idle = 30_000_000_000;
        g.sweep(idle * 10, idle, &stats);
        // No restart: the cut one stays cut, the other keeps its count.
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"x"), 1).0,
            Verdict::Drop
        );
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"cdef"), 2).1,
            b"cd"
        );
        // TCP state went, so the connection passes nothing (fail closed).
        assert_eq!(
            head(&mut g, &mut tcp(c, 103, ack, b"c"), 3).0,
            Verdict::Drop
        );
    }

    #[test]
    fn head_only_full_table_fails_closed_without_evicting() {
        let mut g = CaptureGate::new(
            config("sampling_mode = \"head_only\"\nhead_only_bytes = 4\n"),
            2,
        );
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"abcdef"), 1).1,
            b"abcd"
        );
        assert_eq!(head(&mut g, &mut tls(Direction::Egress, b"ab"), 2).1, b"ab");
        // Full: a new connection gets no state and passes nothing...
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"new"), 3).0,
            Verdict::Drop
        );
        let (c, ack) = ((1, 40000), TCP_FLAG_ACK);
        head(&mut g, &mut tcp(c, 100, TCP_FLAG_SYN, b""), 4);
        assert_eq!(
            head(&mut g, &mut tcp(c, 101, ack, b"ab"), 4).0,
            Verdict::Drop
        );
        // ...and the existing ones were not evicted to make room.
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"x"), 1).0,
            Verdict::Drop
        );
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"cdef"), 2).1,
            b"cd"
        );
        // Space freed by a close is usable again.
        g.forget(2);
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"wxyz!"), 5).1,
            b"wxyz"
        );
    }

    #[test]
    fn head_only_cuts_tls_per_direction() {
        let stats = EventStats::new();
        let mut g = gate("sampling_mode = \"head_only\"\nhead_only_bytes = 6\n");
        let tls = |dir, p: &[u8]| {
            let mut e = event(EventType::TlsData, p);
            e.direction = dir;
            e
        };
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"GET"), 3).1,
            b"GET"
        );
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b" /x HTTP"), 3).1,
            b" /x"
        );
        assert_eq!(
            head(&mut g, &mut tls(Direction::Egress, b"more"), 3).0,
            Verdict::Drop
        );
        assert_eq!(
            head(&mut g, &mut tls(Direction::Ingress, b"HTTP/1.1"), 3).1,
            b"HTTP/1"
        );
        // A captured prefix of a larger write: the uncaptured rest counts too.
        let mut big = tls(Direction::Egress, b"ab");
        big.orig_len = 100;
        assert_eq!(head(&mut g, &mut big, 4).1, b"ab");
        assert_eq!(big.orig_len, 6);
        assert_eq!(
            g.admit(&mut tls(Direction::Egress, b"c"), 4, [None; 2], &stats),
            Verdict::Drop
        );
        assert_eq!(stats.head_only_cut_events.load(Ordering::Relaxed), 1);
        // Socket events carry no data and pass.
        let mut sock = event(EventType::SockAccept, b"");
        assert_eq!(head(&mut g, &mut sock, 5).0, Verdict::Process);
    }
}
