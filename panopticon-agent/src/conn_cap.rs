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
//! when the socket closes; the map is an LRU hash of [`MAX_CONN_CAP`]
//! entries. A packet that arrives before the entry is written is cut at
//! `max_packet_bytes` as before (counted, `truncated_before_raise`).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

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

/// The map, shared by every capture pipeline of the agent (it is taken
/// from the loaded object once).
pub type SharedStore = Arc<Mutex<Box<dyn CapStore>>>;

/// One capture pipeline's raised connections: what it wrote to the map,
/// and when (CLOCK_MONOTONIC, the clock of `DataEvent::timestamp_ns`).
pub struct ConnCap {
    store: SharedStore,
    raised: DashMap<u64, u64>,
    stats: Arc<EventStats>,
}

impl ConnCap {
    pub fn new(store: SharedStore, stats: Arc<EventStats>) -> Self {
        Self {
            store,
            raised: DashMap::new(),
            stats,
        }
    }

    /// A new connection keyed by kernel socket cookie `cookie` was
    /// detected as `proto` from a TCP packet: raise its cap if the
    /// protocol needs it. Written at once, by the worker, so that the
    /// packets after the first are captured whole.
    pub fn on_detect(&self, cookie: u64, proto: Protocol) {
        if !raises(proto) || cookie == 0 || cookie & panopticon_common::TLS_KEY_BIT != 0 {
            return;
        }
        let written = self
            .store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cookie, CONN_CAP_RAISED);
        if written.is_err() {
            self.stats
                .conn_cap_write_failed
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        // The tracking set is bounded like the kernel's LRU: past it, it
        // starts over (the kernel deletes its own entries at close).
        if self.raised.len() >= MAX_CONN_CAP as usize {
            self.raised.clear();
        }
        self.raised.insert(cookie, crate::util::monotonic_now_ns());
        self.stats.conn_cap_raised.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP record of connection `cookie`, emitted by the kernel at
    /// `timestamp_ns`, had bytes past the capture cap. On a raised
    /// connection, one emitted before the entry was written is the race
    /// (the first large packet beat user space).
    pub fn on_truncated(&self, cookie: u64, timestamp_ns: u64) {
        if let Some(at) = self.raised.get(&cookie)
            && timestamp_ns < *at
        {
            self.stats
                .conn_cap_truncated_before_raise
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The connection ended: drop its entry (the kernel deletes it at TCP
    /// close too; this covers an entry written after that close).
    pub fn on_close(&self, cookie: u64) {
        if self.raised.remove(&cookie).is_some() {
            let _ = self
                .store
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(cookie);
        }
    }

    #[cfg(test)]
    pub(crate) fn is_raised(&self, cookie: u64) -> bool {
        self.raised.contains_key(&cookie)
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
        let store: SharedStore = Arc::new(Mutex::new(Box::new(Handle(Arc::clone(&fake)))));
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
        c.on_detect(7, Protocol::Amqp);
        c.on_detect(8, Protocol::Http1);
        // A TLS key (bit 63) and an unkeyed record are never socket cookies.
        c.on_detect(panopticon_common::TLS_KEY_BIT | 9, Protocol::Kafka);
        c.on_detect(0, Protocol::Kafka);
        let map = fake.lock().unwrap().map.clone();
        assert_eq!(map, [(7, CONN_CAP_RAISED)].into_iter().collect());
        assert_eq!(CONN_CAP_RAISED, 65_536);
        assert_eq!(stats.conn_cap_raised.load(Ordering::Relaxed), 1);
        assert!(c.is_raised(7) && !c.is_raised(8));
    }

    #[test]
    fn a_failed_write_is_counted_and_not_tracked() {
        let (c, fake, stats) = conn_cap();
        fake.lock().unwrap().fail = true;
        c.on_detect(7, Protocol::Amqp);
        assert_eq!(stats.conn_cap_write_failed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.conn_cap_raised.load(Ordering::Relaxed), 0);
        assert!(!c.is_raised(7));
    }

    #[test]
    fn truncation_before_the_write_is_the_race() {
        let (c, _, stats) = conn_cap();
        let before = crate::util::monotonic_now_ns();
        c.on_detect(7, Protocol::Amqp);
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
        c.on_detect(7, Protocol::Redis);
        fake.lock().unwrap().map.insert(99, CONN_CAP_RAISED); // another pipeline's
        c.on_close(7);
        c.on_close(99);
        c.on_close(7); // twice: nothing more
        let map = fake.lock().unwrap().map.clone();
        assert_eq!(map, [(99, CONN_CAP_RAISED)].into_iter().collect());
        assert!(!c.is_raised(7));
    }
}
