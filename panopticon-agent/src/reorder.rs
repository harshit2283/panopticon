//! A small reorder window in front of each worker's TCP sequence check.
//!
//! cgroup_skb ingress runs before the socket lock, so two CPUs can run the
//! capture for one socket at once, and the chunk records of two large
//! packets (sock_capture.rs `emit`) reach the ring interleaved: A0 B0 A1 B1.
//! Taken in arrival order, B0 opens a gap (its bytes are ahead of the next
//! expected one), the parser skips the gap, and A1, now behind, is dropped
//! as a retransmission: nothing was lost in the kernel, yet the parser lost
//! bytes and may withhold fields for the rest of the connection.
//!
//! So a TCP record whose bytes start past the connection's next expected
//! byte is held, with every later record of that connection (both
//! directions, in arrival order: the parser of one connection sees both,
//! and must not see a later request before an earlier response). Held
//! records leave the window, still through the normal sequence check, as
//! soon as the front one is in order or a record of the same side fills
//! the hole. The window is bounded in time ([`HOLD_TIME`]), bytes per
//! connection ([`HOLD_BYTES_PER_CONN`]) and records per worker
//! ([`HOLD_RECORDS`]); a hole wider than one packet ([`HOLD_MAX_GAP`]) is
//! not held at all. Past any bound the records go on in arrival order and
//! the hole is a gap, as before (fail closed), counted in
//! `tcp_reorder_gaps`.
//!
//! Serialising the capture per socket in the kernel instead is not
//! possible: a `bpf_spin_lock` may not be held across helper calls, and
//! each chunk is a `bpf_ringbuf_reserve` / `bpf_skb_load_bytes` /
//! `bpf_ringbuf_submit`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use panopticon_common::DataEvent;

use crate::event_loop::{EventStats, sender_endpoint, tcp_segment};
use crate::protocol::fsm::{ConnectionFsmManager, SegmentVerdict};

/// How long a hole may stay open before it is taken as a loss. Interleaved
/// chunks are written to the ring within microseconds of each other.
pub(crate) const HOLD_TIME: Duration = Duration::from_millis(5);
/// Wire bytes (`orig_len`) held per connection: two packets at the 64 KiB
/// maximum of `max_packet_bytes`.
pub(crate) const HOLD_BYTES_PER_CONN: u64 = 128 << 10;
/// Records held per worker, each a copy of one record (about 4.2 KB).
pub(crate) const HOLD_RECORDS: usize = 1024;
/// A hole wider than one packet's chunks is not an interleave.
pub(crate) const HOLD_MAX_GAP: u32 = 64 << 10;

struct Held {
    event: Box<DataEvent>,
    since: Instant,
}

#[derive(Default)]
struct Queue {
    held: VecDeque<Held>,
    bytes: u64,
}

#[derive(Default)]
pub(crate) struct ReorderWindow {
    conns: HashMap<u64, Queue>,
    records: usize,
}

/// The hole `event`'s bytes would leave before them, if it is a TCP
/// record of a tracked connection that is ahead of the next expected byte.
fn hole(m: &ConnectionFsmManager, cookie: u64, event: &DataEvent) -> Option<u32> {
    let seg = tcp_segment(event)?;
    match m.peek_segment(cookie, sender_endpoint(event), event.direction, seg)? {
        SegmentVerdict::Accept { gap, .. } if gap > 0 => Some(gap),
        _ => None,
    }
}

impl ReorderWindow {
    pub(crate) fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// When the oldest held record's hole is to be taken as a loss.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.conns
            .values()
            .filter_map(|q| q.held.front())
            .map(|h| h.since + HOLD_TIME)
            .min()
    }

    /// An arriving record of connection `cookie`. `process` runs every
    /// record that leaves the window (this one included), in the order the
    /// parsers are to see them.
    pub(crate) fn offer(
        &mut self,
        m: &ConnectionFsmManager,
        cookie: u64,
        event: &DataEvent,
        now: Instant,
        stats: &EventStats,
        process: &mut impl FnMut(&DataEvent),
    ) {
        let queued = self.conns.contains_key(&cookie);
        if !queued {
            match hole(m, cookie, event) {
                Some(gap) if gap <= HOLD_MAX_GAP && self.records < HOLD_RECORDS => {}
                Some(_) => {
                    stats.tcp_reorder_gaps.fetch_add(1, Ordering::Relaxed);
                    return process(event);
                }
                None => return process(event),
            }
        }
        let bytes = self.conns.get(&cookie).map_or(0, |q| q.bytes);
        if bytes + event.orig_len as u64 > HOLD_BYTES_PER_CONN || self.records >= HOLD_RECORDS {
            // Window full: what is held goes on with its hole, then this.
            self.flush(m, cookie, stats, process);
            return process(event);
        }
        let q = self.conns.entry(cookie).or_default();
        q.bytes += event.orig_len as u64;
        q.held.push_back(Held {
            event: Box::new(*event),
            since: now,
        });
        self.records += 1;
        stats.tcp_reorder_held.fetch_add(1, Ordering::Relaxed);
        self.drain(m, cookie, process);
    }

    /// Release what is in order: the front while it is, or a record of
    /// the front's side that fills (part of) its hole.
    fn drain(
        &mut self,
        m: &ConnectionFsmManager,
        cookie: u64,
        process: &mut impl FnMut(&DataEvent),
    ) {
        loop {
            let Some(q) = self.conns.get(&cookie) else {
                return;
            };
            let Some(front) = q.held.front() else {
                self.conns.remove(&cookie);
                return;
            };
            let next = if hole(m, cookie, &front.event).is_none() {
                Some(0)
            } else {
                let side = sender_endpoint(&front.event);
                q.held.iter().position(|h| {
                    sender_endpoint(&h.event) == side && hole(m, cookie, &h.event).is_none()
                })
            };
            let Some(i) = next else {
                return;
            };
            let event = self.take(cookie, i);
            process(&event);
        }
    }

    fn take(&mut self, cookie: u64, i: usize) -> Box<DataEvent> {
        let q = self.conns.get_mut(&cookie).expect("queued connection");
        let h = q.held.remove(i).expect("held record");
        q.bytes -= h.event.orig_len as u64;
        self.records -= 1;
        if q.held.is_empty() {
            self.conns.remove(&cookie);
        }
        h.event
    }

    /// Release everything held for `cookie` in arrival order, holes and
    /// all (the connection is closing, or its window is full).
    pub(crate) fn flush(
        &mut self,
        m: &ConnectionFsmManager,
        cookie: u64,
        stats: &EventStats,
        process: &mut impl FnMut(&DataEvent),
    ) {
        while self.conns.contains_key(&cookie) {
            let event = self.take(cookie, 0);
            if hole(m, cookie, &event).is_some() {
                stats.tcp_reorder_gaps.fetch_add(1, Ordering::Relaxed);
            }
            process(&event);
            self.drain(m, cookie, process);
        }
    }

    /// Take the holes older than [`HOLD_TIME`] as losses: their front
    /// record goes on with its gap, and whatever is then in order follows.
    pub(crate) fn expire(
        &mut self,
        m: &ConnectionFsmManager,
        now: Instant,
        stats: &EventStats,
        process: &mut impl FnMut(u64, &DataEvent),
    ) {
        let due: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, q)| q.held.front().is_some_and(|h| now >= h.since + HOLD_TIME))
            .map(|(&c, _)| c)
            .collect();
        for cookie in due {
            let mut p = |e: &DataEvent| process(cookie, e);
            while self
                .conns
                .get(&cookie)
                .and_then(|q| q.held.front())
                .is_some_and(|h| now >= h.since + HOLD_TIME)
            {
                let event = self.take(cookie, 0);
                if hole(m, cookie, &event).is_some() {
                    stats.tcp_reorder_gaps.fetch_add(1, Ordering::Relaxed);
                }
                p(&event);
                self.drain(m, cookie, &mut p);
            }
        }
    }

    /// Release everything (the worker is stopping).
    pub(crate) fn flush_all(
        &mut self,
        m: &ConnectionFsmManager,
        stats: &EventStats,
        process: &mut impl FnMut(u64, &DataEvent),
    ) {
        let cookies: Vec<u64> = self.conns.keys().copied().collect();
        for cookie in cookies {
            self.flush(m, cookie, stats, &mut |e: &DataEvent| process(cookie, e));
        }
    }
}
