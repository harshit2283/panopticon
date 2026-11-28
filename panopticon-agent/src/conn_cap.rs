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
//! wrote within [`CONN_CAP_LIVE_MAX`] (three quarters of the map), and
//! refuses a raise past that (counted, `conn_cap_refused`) instead of
//! letting the kernel drop one. An LRU hash can evict before it is full:
//! each CPU that inserts keeps up to 128 free entries of its own, so the
//! writer thread is pinned to one CPU (only it inserts), which leaves the
//! margin far above what one CPU can strand.
//!
//! The entries are owned by the writer ([`CapWriter`]), shared by every
//! capture pipeline, not by one pipeline: a narrowing replaces the
//! pipeline, and the new one re-detects the same connections; it adopts
//! their entries instead of writing and counting them again. An entry is
//! given back when its connection ends: its close record (any pipeline),
//! or its owning worker's idle and capacity evictions
//! ([`ConnCap::sweep`]), which also cover sockets the kernel never sees
//! close (one with no socket state, such as a socket that predates the
//! agent in unscoped `full`); an entry a dropped pipeline owned and no
//! pipeline adopts within the idle timeout is given back by any sweep.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
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
    /// the raise; 0 if the map refused it.
    Insert(u64, Arc<AtomicU64>),
    Remove(u64),
    /// Tests: answered once every earlier operation is done.
    #[cfg(test)]
    Flush(SyncSender<()>),
}

/// One entry user space keeps in the map: when it was written ([`PENDING`]
/// until then, 0 if the map refused it), the pipeline and worker that own
/// it, and since when no live pipeline does.
struct Owned {
    at: Arc<AtomicU64>,
    pipeline: u64,
    worker: usize,
    orphaned: Option<Instant>,
}

/// The map, its writer thread and the entries user space keeps in it,
/// shared by every capture pipeline of the agent (the map is taken from the
/// loaded object once). The thread starts with the first pipeline
/// ([`ConnCap::new`]) and ends when the last pipeline lets go of it.
pub struct CapWriter {
    store: Mutex<Option<Box<dyn CapStore>>>,
    tx: OnceLock<Option<SyncSender<Op>>>,
    owned: DashMap<u64, Owned>,
    /// Entries reserved: those in `owned`, and one being added
    /// (at most [`CONN_CAP_LIVE_MAX`]).
    live: AtomicUsize,
    /// Deletes the queue had no room for: still counted in `live`, sent
    /// again at the next sweep.
    retry: Mutex<Vec<u64>>,
    next_pipeline: AtomicU64,
}

pub type SharedStore = Arc<CapWriter>;

impl CapWriter {
    // Built by the Linux loader (`take_conn_cap`) and by tests.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(store: Box<dyn CapStore>) -> SharedStore {
        Arc::new(Self {
            store: Mutex::new(Some(store)),
            tx: OnceLock::new(),
            owned: DashMap::new(),
            live: AtomicUsize::new(0),
            retry: Mutex::new(Vec::new()),
            next_pipeline: AtomicU64::new(1),
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

    /// Delete `cookie`'s entry (already out of `owned`): its count is
    /// released once the delete is queued.
    fn give_back(&self, cookie: u64, stats: &Arc<EventStats>) {
        match self.sender(stats).map(|tx| tx.try_send(Op::Remove(cookie))) {
            Some(Err(TrySendError::Full(_))) => {
                self.retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(cookie);
            }
            _ => self.release(),
        }
    }

    /// Queue the deletes that found the queue full before.
    fn drain_retry(&self, stats: &Arc<EventStats>) {
        let pending = std::mem::take(&mut *self.retry.lock().unwrap_or_else(|e| e.into_inner()));
        for cookie in pending {
            self.give_back(cookie, stats);
        }
    }
}

/// The writer thread. Only it inserts into the map, and it stays on one
/// CPU (module docs).
fn write_loop(mut store: Box<dyn CapStore>, rx: Receiver<Op>, stats: &EventStats) {
    pin_to_current_cpu();
    for op in rx {
        match op {
            Op::Insert(cookie, at) => match store.insert(cookie, CONN_CAP_RAISED) {
                Ok(()) => {
                    at.store(crate::util::monotonic_now_ns(), Ordering::Release);
                    stats.conn_cap_raised.fetch_add(1, Ordering::Relaxed);
                }
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

#[cfg(target_os = "linux")]
fn pin_to_current_cpu() {
    // SAFETY: sched_getcpu has no arguments; the set is a zeroed
    // cpu_set_t of the size passed, for the calling thread (pid 0).
    unsafe {
        let cpu = libc::sched_getcpu();
        if cpu < 0 {
            return;
        }
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            tracing::debug!("conn-cap writer: CPU pinning failed");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_to_current_cpu() {}

/// One capture pipeline's view of the raised connections: it raises, adopts
/// and gives back entries of [`CapWriter`] under its own id.
pub struct ConnCap {
    writer: SharedStore,
    pipeline: u64,
    stats: Arc<EventStats>,
}

impl ConnCap {
    pub fn new(writer: SharedStore, stats: Arc<EventStats>) -> Self {
        // Start the writer thread now, not at the first raise.
        let _ = writer.sender(&stats);
        let pipeline = writer.next_pipeline.fetch_add(1, Ordering::Relaxed);
        Self {
            writer,
            pipeline,
            stats,
        }
    }

    /// A new connection keyed by kernel socket cookie `cookie`, owned by
    /// worker `worker`, was detected as `proto` from a TCP packet: raise
    /// its cap if the protocol needs it (queued at once for the writer
    /// thread, so that the packets after the first are captured whole), or
    /// adopt its entry if one is kept already (a pipeline before this one
    /// raised it).
    pub fn on_detect(&self, cookie: u64, proto: Protocol, worker: usize) {
        if !raises(proto) || cookie == 0 || cookie & panopticon_common::TLS_KEY_BIT != 0 {
            return;
        }
        match self.writer.owned.entry(cookie) {
            MapEntry::Occupied(mut e) => {
                let o = e.get_mut();
                o.pipeline = self.pipeline;
                o.worker = worker;
                o.orphaned = None;
            }
            MapEntry::Vacant(v) => {
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
                if tx.try_send(Op::Insert(cookie, Arc::clone(&at))).is_err() {
                    self.writer.release();
                    self.stats
                        .conn_cap_write_failed
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                v.insert(Owned {
                    at,
                    pipeline: self.pipeline,
                    worker,
                    orphaned: None,
                });
            }
        }
    }

    /// A TCP record of connection `cookie`, emitted by the kernel at
    /// `timestamp_ns`, had bytes past the capture cap. On a raised
    /// connection, one emitted before the entry was written is the race
    /// (the first large packet beat user space).
    pub fn on_truncated(&self, cookie: u64, timestamp_ns: u64) {
        if let Some(o) = self.writer.owned.get(&cookie)
            && timestamp_ns < o.at.load(Ordering::Acquire)
        {
            self.stats
                .conn_cap_truncated_before_raise
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The connection ended (its close record, in whichever pipeline):
    /// drop its entry (the kernel deletes it at TCP close too; this covers
    /// an entry written after that close, and a socket the kernel does not
    /// see close).
    pub fn on_close(&self, cookie: u64) {
        if self.writer.owned.remove(&cookie).is_some() {
            self.writer.give_back(cookie, &self.stats);
        }
    }

    /// Worker `worker`'s sweep: give back the entries of its connections
    /// that it no longer tracks (`tracked` false: evicted idle or at
    /// capacity), and entries no live pipeline has adopted for
    /// `orphan_ttl` (the idle timeout); then queue the deletes a full
    /// queue held back.
    pub fn sweep(&self, worker: usize, tracked: impl Fn(u64) -> bool, orphan_ttl: Duration) {
        let mut gone = Vec::new();
        self.writer.owned.retain(|&cookie, o| {
            let mine = o.pipeline == self.pipeline && o.worker == worker;
            let keep = if mine {
                tracked(cookie)
            } else {
                o.orphaned.is_none_or(|t| t.elapsed() <= orphan_ttl)
            };
            if !keep {
                gone.push(cookie);
            }
            keep
        });
        for cookie in gone {
            self.writer.give_back(cookie, &self.stats);
        }
        self.writer.drain_retry(&self.stats);
    }

    #[cfg(test)]
    pub(crate) fn is_raised(&self, cookie: u64) -> bool {
        self.writer.owned.contains_key(&cookie)
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

/// A pipeline replaced (a narrowing) or stopped: its entries stay in the
/// map, for the next pipeline to adopt when it re-detects their
/// connections, or for a sweep to give back after the idle timeout.
impl Drop for ConnCap {
    fn drop(&mut self) {
        let now = Instant::now();
        for mut o in self.writer.owned.iter_mut() {
            if o.pipeline == self.pipeline {
                o.orphaned = Some(now);
            }
        }
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
        assert_eq!(
            stats.conn_cap_raised.load(Ordering::Relaxed),
            0,
            "raised or failed, not both"
        );
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
    fn a_new_pipeline_adopts_the_entries_of_the_one_it_replaced() {
        let (old, fake, stats) = conn_cap();
        let writer = Arc::clone(&old.writer);
        for cookie in 1..=3 {
            old.on_detect(cookie, Protocol::Kafka, 0);
        }
        old.flush();
        assert_eq!(old.live(), 3);
        drop(old); // a narrowing replaces the pipeline
        let new = ConnCap::new(Arc::clone(&writer), Arc::clone(&stats));
        // Its workers re-detect the same live connections mid-stream.
        for cookie in 1..=3 {
            new.on_detect(cookie, Protocol::Kafka, 1);
        }
        new.flush();
        assert_eq!(new.live(), 3, "adopted, not counted again");
        assert_eq!(
            stats.conn_cap_raised.load(Ordering::Relaxed),
            3,
            "written once"
        );
        assert_eq!(fake.lock().unwrap().map.len(), 3);
        // Adopted: the new pipeline's worker owns them now.
        new.sweep(1, |cookie| cookie != 2, Duration::from_secs(60));
        new.flush();
        assert!(!new.is_raised(2) && new.is_raised(1));
        assert_eq!(new.live(), 2);
    }

    #[test]
    fn entries_no_pipeline_adopts_are_given_back_after_the_idle_timeout() {
        let (old, fake, stats) = conn_cap();
        let writer = Arc::clone(&old.writer);
        old.on_detect(7, Protocol::Amqp, 0);
        old.flush();
        drop(old);
        let new = ConnCap::new(writer, stats);
        new.sweep(0, |_| true, Duration::from_secs(60));
        assert!(new.is_raised(7), "within the timeout: kept for adoption");
        std::thread::sleep(Duration::from_millis(5));
        new.sweep(0, |_| true, Duration::from_millis(1));
        new.flush();
        assert!(!new.is_raised(7));
        assert_eq!(new.live(), 0);
        assert!(fake.lock().unwrap().map.is_empty());
    }

    #[test]
    fn a_delete_the_queue_cannot_take_stays_counted_and_is_sent_again() {
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
        // Fill the queue behind a blocked insert.
        let mut cookie = 0;
        while stats.conn_cap_write_failed.load(Ordering::Relaxed) == 0 {
            cookie += 1;
            c.on_detect(cookie, Protocol::Redis, 0);
        }
        let live = c.live();
        c.on_close(1); // its delete finds the queue full
        assert_eq!(c.live(), live, "still counted");
        drop(go);
        c.flush();
        c.sweep(0, |_| true, Duration::from_secs(60));
        c.flush();
        assert_eq!(c.live(), live - 1, "sent again, then released");
    }

    #[test]
    fn sweep_gives_back_a_workers_untracked_connections() {
        let (c, fake, _) = conn_cap();
        c.on_detect(1, Protocol::Postgres, 0);
        c.on_detect(2, Protocol::Postgres, 0);
        c.on_detect(3, Protocol::Postgres, 1); // another worker's
        c.flush();
        c.sweep(0, |cookie| cookie == 2, Duration::from_secs(60)); // 1 was evicted
        c.flush();
        assert!(!c.is_raised(1) && c.is_raised(2) && c.is_raised(3));
        let mut keys: Vec<_> = fake.lock().unwrap().map.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![2, 3]);
        assert_eq!(c.live(), 2);
    }
}
