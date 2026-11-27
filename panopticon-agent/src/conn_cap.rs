//! Per-connection packet cap (`raise_packet_cap`, the kernel's `CONN_CAP`
//! map, sock_capture.rs `raised_cap`).
//!
//! The kernel captures at most `max_packet_bytes` of one TCP packet (16 KiB
//! by default); GSO/GRO packets reach 64 KiB. Every parser accounts for a
//! cut that falls inside one message of known length, but a cut that
//! crosses a message boundary loses frame sync, and the parser then
//! exports only closed-set values for the rest of the connection
//! (`ConnectionFsmManager::skip_from` latches it). Whether a large packet
//! is one message or several depends on the protocol:
//!
//! - AMQP: a delivery is three frames or more (method, header, body), and
//!   one packet carries several deliveries: a cut crosses frames.
//! - HTTP/2 and gRPC: frames are at most 16 KiB by default
//!   (`SETTINGS_MAX_FRAME_SIZE`), so a packet over 16 KiB is several frames.
//! - Kafka: one frame per request or response, but up to five requests in
//!   flight per connection: a packet can end one response and start the next.
//! - PostgreSQL, MySQL, Redis and DNS over TCP: a lost client byte (and,
//!   for PostgreSQL and Redis, a lost server byte) latches the connection
//!   whatever its position.
//! - HTTP/1.1: one response at a time (pipelining is rare), whose large
//!   packets are body bytes of known length or a chunk's data: the cut is
//!   accounted and the parser stays in sync. Not raised: HTTP/1.1 carries
//!   most bulk traffic, and raising its packets is the global cost
//!   (BENCHMARKS.md, "Large packets") this avoids.
//!
//! So when a connection's first packet is detected as one of the raised
//! protocols, its socket cookie is written to `CONN_CAP` with
//! [`CONN_CAP_RAISED`] (64 KiB). The kernel reads the map only for a packet
//! over `max_packet_bytes`, after the scope verdict, and deletes the entry
//! when the socket closes (its TCP_CLOSE callback). A packet that arrives
//! before the entry is written is cut at `max_packet_bytes` as before
//! (counted, `truncated_before_raise`).
//!
//! The map writes run on one thread of their own ([`CapWriter`]), fed by a
//! bounded queue: a worker never makes the syscall, nor waits for a lock
//! another worker holds. A raise the queue has no room for is counted as a
//! failed write, like one the map refuses.
//!
//! The map is an LRU hash of [`MAX_CONN_CAP`] entries, which would make
//! room for a new entry by dropping an old one, silently returning a live
//! connection to `max_packet_bytes`. So user space keeps the entries it
//! wrote within [`CONN_CAP_LIVE_MAX`] (three quarters of the map: an LRU
//! hash can evict before it is full, its free lists being per CPU), and
//! refuses a raise past that (counted, `conn_cap_refused`) instead of
//! letting the kernel drop one. It gives an entry back when the connection
//! ends: its close record, or the worker's idle and capacity evictions
//! ([`ConnCap::sweep`]), which also cover sockets the kernel never sees
//! close (one with no socket state, such as a socket that predates the
//! agent in unscoped `full`).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use panopticon_common::{CONN_CAP_RAISED, MAX_CONN_CAP};

use crate::event_loop::EventStats;
use crate::protocol::Protocol;

/// Whether a connection of `proto` gets the raised cap (module docs).
pub fn raises(proto: Protocol) -> bool {
    match proto {
        Protocol::Amqp
        | Protocol::Kafka
        | Protocol::Http2
        | Protocol::Grpc
        | Protocol::Postgres
        | Protocol::Mysql
        | Protocol::Redis
        | Protocol::Dns => true,
        Protocol::Http1 | Protocol::Unknown => false,
    }
}

/// Entries user space keeps in `CONN_CAP` at most (module docs).
pub const CONN_CAP_LIVE_MAX: usize = MAX_CONN_CAP as usize * 3 / 4;

/// Map writes waiting for the writer thread.
const QUEUE: usize = 4096;

/// Not written yet (a [`ConnCap`] entry's write time).
const PENDING: u64 = u64::MAX;

/// The kernel's `CONN_CAP` map (an aya map on Linux, a fake in tests).
pub trait CapStore: Send {
    fn insert(&mut self, cookie: u64, cap: u32) -> anyhow::Result<()>;
    fn remove(&mut self, cookie: u64) -> anyhow::Result<()>;
}

#[cfg(target_os = "linux")]
impl CapStore for aya::maps::HashMap<aya::maps::MapData, u64, u32> {
    fn insert(&mut self, cookie: u64, cap: u32) -> anyhow::Result<()> {
        Ok(aya::maps::HashMap::insert(self, cookie, cap, 0)?)
    }
    fn remove(&mut self, cookie: u64) -> anyhow::Result<()> {
        Ok(aya::maps::HashMap::remove(self, &cookie)?)
    }
}

enum Op {
    /// Raise `cookie`; on success store the time (CLOCK_MONOTONIC) in the
    /// cell, so records the kernel emitted before it count as cut before
    /// the raise.
    Insert(u64, Arc<AtomicU64>),
    Remove(u64),
    /// Tests: answered once every earlier operation is done.
    #[cfg(test)]
    Flush(SyncSender<()>),
}

/// The map and its writer thread, shared by every capture pipeline of the
/// agent (the map is taken from the loaded object once). The thread starts
/// with the first pipeline ([`ConnCap::new`]) and ends when the last
/// pipeline lets go of it.
pub struct CapWriter {
    store: Mutex<Option<Box<dyn CapStore>>>,
    tx: OnceLock<Option<SyncSender<Op>>>,
    /// Entries user space has written and not given back, every pipeline
    /// together (at most [`CONN_CAP_LIVE_MAX`]).
    live: AtomicUsize,
}

pub type SharedStore = Arc<CapWriter>;

impl CapWriter {
    // Built by the Linux loader (`take_conn_cap`) and by tests.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(store: Box<dyn CapStore>) -> SharedStore {
        Arc::new(Self {
            store: Mutex::new(Some(store)),
            tx: OnceLock::new(),
            live: AtomicUsize::new(0),
        })
    }

    fn sender(&self, stats: &Arc<EventStats>) -> Option<&SyncSender<Op>> {
        self.tx
            .get_or_init(|| {
                let store = self.store.lock().unwrap_or_else(|e| e.into_inner()).take()?;
                let (tx, rx) = sync_channel(QUEUE);
                let stats = Arc::clone(stats);
                std::thread::Builder::new()
                    .name("conn-cap".into())
                    .spawn(move || write_loop(store, rx, &stats))
                    .map_err(|e| tracing::warn!(error = %e, "conn-cap writer thread: raise_packet_cap off"))
                    .ok()?;
                Some(tx)
            })
            .as_ref()
    }

    /// Room for one more entry: taken (true), or the limit is reached.
    fn reserve(&self) -> bool {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < CONN_CAP_LIVE_MAX).then_some(n + 1)
            })
            .is_ok()
    }

    fn release(&self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

fn write_loop(mut store: Box<dyn CapStore>, rx: Receiver<Op>, stats: &EventStats) {
    for op in rx {
        match op {
            Op::Insert(cookie, at) => match store.insert(cookie, CONN_CAP_RAISED) {
                Ok(()) => at.store(crate::util::monotonic_now_ns(), Ordering::Release),
                // Never raised: its cut records are plain cuts, not the race.
                Err(_) => {
                    at.store(0, Ordering::Release);
                    stats.conn_cap_write_failed.fetch_add(1, Ordering::Relaxed);
                }
            },
            // A failed delete leaves the entry to the kernel's close, or
            // to the LRU (user space no longer counts it).
            Op::Remove(cookie) => {
                let _ = store.remove(cookie);
            }
            #[cfg(test)]
            Op::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// One raised connection: when its entry was written ([`PENDING`] until
/// then, 0 if the map refused it), and the worker that owns it (for
/// [`ConnCap::sweep`]). A refused entry stays counted until its
/// connection ends, like a written one.
struct Raised {
    at: Arc<AtomicU64>,
    worker: usize,
}

/// One capture pipeline's raised connections.
pub struct ConnCap {
    writer: SharedStore,
    raised: DashMap<u64, Raised>,
    stats: Arc<EventStats>,
}

impl ConnCap {
    pub fn new(writer: SharedStore, stats: Arc<EventStats>) -> Self {
        // Start the writer thread now, not at the first raise.
        let _ = writer.sender(&stats);
        Self {
            writer,
            raised: DashMap::new(),
            stats,
        }
    }

    /// A new connection keyed by kernel socket cookie `cookie`, owned by
    /// worker `worker`, was detected as `proto` from a TCP packet: raise
    /// its cap if the protocol needs it. Queued at once for the writer
    /// thread, so that the packets after the first are captured whole.
    pub fn on_detect(&self, cookie: u64, proto: Protocol, worker: usize) {
        if !raises(proto)
            || cookie == 0
            || cookie & panopticon_common::TLS_KEY_BIT != 0
            || self.raised.contains_key(&cookie)
        {
            return;
        }
        let Some(tx) = self.writer.sender(&self.stats) else {
            self.stats
                .conn_cap_write_failed
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if !self.writer.reserve() {
            self.stats.conn_cap_refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let at = Arc::new(AtomicU64::new(PENDING));
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            tx.try_send(Op::Insert(cookie, Arc::clone(&at)))
        {
            self.writer.release();
            self.stats
                .conn_cap_write_failed
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.raised.insert(cookie, Raised { at, worker });
        self.stats.conn_cap_raised.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP record of connection `cookie`, emitted by the kernel at
    /// `timestamp_ns`, had bytes past the capture cap. On a raised
    /// connection, one emitted before the entry was written is the race
    /// (the first large packet beat user space).
    pub fn on_truncated(&self, cookie: u64, timestamp_ns: u64) {
        if let Some(r) = self.raised.get(&cookie)
            && timestamp_ns < r.at.load(Ordering::Acquire)
        {
            self.stats
                .conn_cap_truncated_before_raise
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The connection ended: drop its entry (the kernel deletes it at TCP
    /// close too; this covers an entry written after that close, and a
    /// socket the kernel does not see close).
    pub fn on_close(&self, cookie: u64) {
        if self.raised.remove(&cookie).is_some() {
            self.give_back(cookie);
        }
    }

    /// Worker `worker`'s sweep: drop the entries of its connections that
    /// it no longer tracks (`tracked` false: evicted idle or at capacity),
    /// as [`ConnCap::on_close`] does.
    pub fn sweep(&self, worker: usize, tracked: impl Fn(u64) -> bool) {
        let mut gone = Vec::new();
        self.raised.retain(|&cookie, r| {
            let keep = r.worker != worker || tracked(cookie);
            if !keep {
                gone.push(cookie);
            }
            keep
        });
        for cookie in gone {
            self.give_back(cookie);
        }
    }

    fn give_back(&self, cookie: u64) {
        self.writer.release();
        if let Some(tx) = self.writer.sender(&self.stats) {
            let _ = tx.try_send(Op::Remove(cookie));
        }
    }

    #[cfg(test)]
    pub(crate) fn is_raised(&self, cookie: u64) -> bool {
        self.raised.contains_key(&cookie)
    }

    /// Tests: wait until the writer thread has done every queued write.
    #[cfg(test)]
    pub(crate) fn flush(&self) {
        let (tx, rx) = sync_channel(1);
        if let Some(w) = self.writer.sender(&self.stats) {
            w.send(Op::Flush(tx)).unwrap();
            rx.recv().unwrap();
        }
    }

    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        self.writer.live.load(Ordering::Acquire)
    }
}

/// Tests: a `ConnCap` over an in-memory map (and whether writes fail).
#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    #[derive(Default)]
    pub(crate) struct Fake {
        pub map: std::collections::HashMap<u64, u32>,
        pub fail: bool,
    }

    struct Handle(Arc<Mutex<Fake>>);

    impl CapStore for Handle {
        fn insert(&mut self, cookie: u64, cap: u32) -> anyhow::Result<()> {
            let mut f = self.0.lock().unwrap();
            anyhow::ensure!(!f.fail, "map full");
            f.map.insert(cookie, cap);
            Ok(())
        }
        fn remove(&mut self, cookie: u64) -> anyhow::Result<()> {
            self.0.lock().unwrap().map.remove(&cookie);
            Ok(())
        }
    }

    pub(crate) fn conn_cap() -> (ConnCap, Arc<Mutex<Fake>>, Arc<EventStats>) {
        let fake = Arc::new(Mutex::new(Fake::default()));
        let store = CapWriter::new(Box::new(Handle(Arc::clone(&fake))));
        let stats = Arc::new(EventStats::new());
        (ConnCap::new(store, Arc::clone(&stats)), fake, stats)
    }
}

#[cfg(test)]
mod tests {
    use super::fake::conn_cap;
    use super::*;

    #[test]
    fn policy_raises_every_protocol_but_http1() {
        use Protocol::*;
        for p in [Amqp, Kafka, Http2, Grpc, Postgres, Mysql, Redis, Dns] {
            assert!(raises(p), "{p}");
        }
        assert!(!raises(Http1));
        assert!(!raises(Unknown));
    }

    #[test]
    fn detect_writes_the_raised_cap_for_raised_protocols_only() {
        let (c, fake, stats) = conn_cap();
        c.on_detect(7, Protocol::Amqp, 0);
        c.on_detect(7, Protocol::Amqp, 0); // detected again: written once
        c.on_detect(8, Protocol::Http1, 0);
        // A TLS key (bit 63) and an unkeyed record are never socket cookies.
        c.on_detect(panopticon_common::TLS_KEY_BIT | 9, Protocol::Kafka, 0);
        c.on_detect(0, Protocol::Kafka, 0);
        c.flush();
        let map = fake.lock().unwrap().map.clone();
        assert_eq!(map, [(7, CONN_CAP_RAISED)].into_iter().collect());
        assert_eq!(CONN_CAP_RAISED, 65_536);
        assert_eq!(stats.conn_cap_raised.load(Ordering::Relaxed), 1);
        assert!(c.is_raised(7) && !c.is_raised(8));
        assert_eq!(c.live(), 1);
    }

    #[test]
    fn a_failed_write_is_counted_and_its_cuts_are_not_the_race() {
        let (c, fake, stats) = conn_cap();
        fake.lock().unwrap().fail = true;
        c.on_detect(7, Protocol::Amqp, 0);
        c.flush();
        assert_eq!(stats.conn_cap_write_failed.load(Ordering::Relaxed), 1);
        assert!(fake.lock().unwrap().map.is_empty());
        c.on_truncated(7, crate::util::monotonic_now_ns());
        assert_eq!(
            stats
                .conn_cap_truncated_before_raise
                .load(Ordering::Relaxed),
            0
        );
        // Counted until the connection ends, then given back.
        assert_eq!(c.live(), 1);
        c.on_close(7);
        assert_eq!(c.live(), 0);
    }

    #[test]
    fn truncation_before_the_write_is_the_race() {
        let (c, _, stats) = conn_cap();
        let before = crate::util::monotonic_now_ns();
        c.on_detect(7, Protocol::Amqp, 0);
        c.flush();
        let after = crate::util::monotonic_now_ns() + 1;
        c.on_truncated(7, before); // emitted before the entry existed
        c.on_truncated(7, after); // after: cut at 64 KiB (kernel-counted)
        c.on_truncated(8, before); // not raised
        assert_eq!(
            stats
                .conn_cap_truncated_before_raise
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn close_deletes_only_what_this_pipeline_wrote() {
        let (c, fake, _) = conn_cap();
        c.on_detect(7, Protocol::Redis, 0);
        c.flush();
        fake.lock().unwrap().map.insert(99, CONN_CAP_RAISED); // another pipeline's
        c.on_close(7);
        c.on_close(99);
        c.on_close(7); // twice: nothing more
        c.flush();
        let map = fake.lock().unwrap().map.clone();
        assert_eq!(map, [(99, CONN_CAP_RAISED)].into_iter().collect());
        assert!(!c.is_raised(7));
        assert_eq!(c.live(), 0);
    }

    #[test]
    fn the_live_limit_refuses_instead_of_letting_the_kernel_evict() {
        let (c, fake, stats) = conn_cap();
        for cookie in 1..=CONN_CAP_LIVE_MAX as u64 + 5 {
            c.on_detect(cookie, Protocol::Kafka, 0);
            if cookie % 1024 == 0 {
                c.flush(); // the queue is bounded: let the writer keep up
            }
        }
        c.flush();
        assert_eq!(c.live(), CONN_CAP_LIVE_MAX);
        assert!(CONN_CAP_LIVE_MAX < MAX_CONN_CAP as usize);
        assert_eq!(stats.conn_cap_refused.load(Ordering::Relaxed), 5);
        assert_eq!(fake.lock().unwrap().map.len(), CONN_CAP_LIVE_MAX);
        // One ends: there is room for one more.
        c.on_close(1);
        c.on_detect(1_000_000, Protocol::Kafka, 0);
        c.flush();
        assert!(c.is_raised(1_000_000));
        assert_eq!(stats.conn_cap_refused.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn a_full_queue_is_a_failed_write_not_a_wait() {
        // A store that blocks until released: the queue fills behind it.
        struct Slow(std::sync::mpsc::Receiver<()>);
        impl CapStore for Slow {
            fn insert(&mut self, _: u64, _: u32) -> anyhow::Result<()> {
                let _ = self.0.recv();
                Ok(())
            }
            fn remove(&mut self, _: u64) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let (go, wait) = std::sync::mpsc::channel();
        let stats = Arc::new(EventStats::new());
        let c = ConnCap::new(CapWriter::new(Box::new(Slow(wait))), Arc::clone(&stats));
        for cookie in 1..=QUEUE as u64 + 10 {
            c.on_detect(cookie, Protocol::Redis, 0);
        }
        let failed = stats.conn_cap_write_failed.load(Ordering::Relaxed);
        assert!((9..=10).contains(&failed), "{failed}");
        assert_eq!(c.live() as u64, QUEUE as u64 + 10 - failed);
        drop(go); // the writer drains
        c.flush();
    }

    #[test]
    fn sweep_gives_back_a_workers_untracked_connections() {
        let (c, fake, _) = conn_cap();
        c.on_detect(1, Protocol::Postgres, 0);
        c.on_detect(2, Protocol::Postgres, 0);
        c.on_detect(3, Protocol::Postgres, 1); // another worker's
        c.flush();
        c.sweep(0, |cookie| cookie == 2); // 1 was evicted
        c.flush();
        assert!(!c.is_raised(1) && c.is_raised(2) && c.is_raised(3));
        let mut keys: Vec<_> = fake.lock().unwrap().map.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![2, 3]);
        assert_eq!(c.live(), 2);
    }
}
