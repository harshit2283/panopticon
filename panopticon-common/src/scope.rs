//! Pure capture-scope arithmetic shared by the eBPF programs and the agent.
//!
//! Every function here errs toward capturing less: an input it cannot trust
//! yields "capture nothing", never a guess.

/// A socket is initialised only when its stored `init_cookie` is its own
/// cookie. A child cloned from a listener (`BPF_F_CLONE`) carries the
/// listener's cookie, so it reads as uninitialised until its own
/// ESTABLISHED callback publishes. Cookie 0 is never valid.
#[inline(always)]
pub fn is_initialised(init_cookie: u64, cookie: u64) -> bool {
    init_cookie != 0 && init_cookie == cookie
}

/// Stream offset of the first byte of a segment, from an unlocked read of
/// a socket's kernel counters, or `None` if the read was torn.
///
/// * `count`: `bytes_received` (or `bytes_acked`).
/// * `count_base`: what `count` includes besides stream bytes: 0 for
///   `bytes_received`, our SYN for `bytes_acked` (1 active, 0 passive).
/// * `nxt1`, `nxt2`: `rcv_nxt` (or `snd_una`) read before and after `count`.
/// * `seq_base`: the stream origin (ISN + 1), derived under the socket lock
///   at ESTABLISHED as `nxt - (u32)(count - count_base)`, so bytes moved
///   before that callback (TCP Fast Open) keep their positions.
/// * `seq`: the segment's sequence number.
///
/// The kernel moves the counter and the sequence together under the socket
/// lock, so for every coherent pair `(u32)(count - count_base) ==
/// nxt - seq_base`. A torn pair breaks that identity unless the two differ
/// by a multiple of 4 GiB, which cannot arrive between two loads.
#[inline(always)]
pub fn stream_offset(
    count: u64,
    count_base: u64,
    nxt1: u32,
    nxt2: u32,
    seq_base: u32,
    seq: u32,
) -> Option<i64> {
    if nxt1 != nxt2 || count < count_base {
        return None;
    }
    let done = count - count_base;
    if done as u32 != nxt1.wrapping_sub(seq_base) || done > i64::MAX as u64 {
        return None;
    }
    Some(done as i64 + seq.wrapping_sub(nxt1) as i32 as i64)
}

/// How many bytes, from the start of a segment at `off` with `len` bytes,
/// fall inside the head `[0, n)`. Segments starting before 0 or at/after
/// `n` give 0.
#[inline(always)]
pub fn head_take(off: i64, len: u32, n: u64) -> u32 {
    if off < 0 || off as u64 >= n {
        return 0;
    }
    let room = n - off as u64;
    if (len as u64) < room {
        len
    } else {
        room as u32
    }
}

/// Bytes a sender may copy after atomically reserving `len` bytes of an
/// `n`-byte budget whose previous total was `prev` (the value a
/// fetch-and-add returned).
#[inline(always)]
pub fn reserved_take(prev: u64, len: u32, n: u64) -> u32 {
    if prev >= n {
        return 0;
    }
    let room = n - prev;
    if (len as u64) < room {
        len
    } else {
        room as u32
    }
}

/// `true` if a socket's draw is in a sample whose threshold is
/// `rate * 2^32` (computed in user space; rate 1 is `full`, never sampled).
#[inline(always)]
pub fn in_sample(draw: u32, threshold: u32) -> bool {
    draw < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_SEQ: u32 = 0xFFFF_FF00; // near the wrap on purpose

    fn seq_at(done: u64) -> u32 {
        BASE_SEQ.wrapping_add(done as u32)
    }

    #[test]
    fn initialised_only_with_own_nonzero_cookie() {
        assert!(is_initialised(42, 42));
        assert!(!is_initialised(41, 42)); // cloned from a listener
        assert!(!is_initialised(0, 0));
        assert!(!is_initialised(0, 42));
    }

    #[test]
    fn coherent_in_order_segment_is_at_count() {
        for done in [0u64, 1, 4095, 1 << 32, (5 << 32) + 17] {
            let n = seq_at(done);
            assert_eq!(
                stream_offset(done + 1, 1, n, n, BASE_SEQ, n),
                Some(done as i64)
            );
        }
    }

    #[test]
    fn out_of_order_and_retransmitted_segments_keep_their_position() {
        let done = 10_000u64;
        let n = seq_at(done);
        let ahead = n.wrapping_add(500);
        let behind = n.wrapping_sub(3000);
        assert_eq!(stream_offset(done, 0, n, n, BASE_SEQ, ahead), Some(10_500));
        assert_eq!(stream_offset(done, 0, n, n, BASE_SEQ, behind), Some(7_000));
    }

    #[test]
    fn torn_reads_are_rejected() {
        let n_old = seq_at(1000);
        let n_new = seq_at(1500);
        // old count with new seq, and new count with old seq
        assert_eq!(stream_offset(1000, 0, n_new, n_new, BASE_SEQ, n_new), None);
        assert_eq!(stream_offset(1500, 0, n_old, n_old, BASE_SEQ, n_old), None);
        // seq moved between the two loads
        assert_eq!(stream_offset(1000, 0, n_old, n_new, BASE_SEQ, n_old), None);
        // counter below its base
        assert_eq!(stream_offset(0, 1, n_old, n_old, BASE_SEQ, n_old), None);
    }

    #[test]
    fn past_four_gib_never_maps_back_into_the_head() {
        // A 32-bit offset would wrap to 100 here; the u64 count keeps it far past N.
        let done = (1u64 << 32) + 100;
        let n = seq_at(done);
        let off = stream_offset(done, 0, n, n, BASE_SEQ, n).unwrap();
        assert_eq!(head_take(off, 1000, 4096), 0);
    }

    #[test]
    fn head_take_cuts_at_n() {
        assert_eq!(head_take(0, 100, 4096), 100);
        assert_eq!(head_take(4000, 200, 4096), 96); // crossing segment
        assert_eq!(head_take(4096, 10, 4096), 0);
        assert_eq!(head_take(-1, 10, 4096), 0);
        assert_eq!(head_take(0, u32::MAX, 1 << 40), u32::MAX);
    }

    #[test]
    fn reservations_never_exceed_the_budget() {
        // Concurrent fetch-and-adds hand out disjoint ranges.
        let n = 4096u64;
        let mut total = 0u64;
        let mut copied = 0u64;
        for len in [1000u32, 3000, 500, 200, 9000] {
            copied += reserved_take(total, len, n) as u64;
            total += len as u64;
        }
        assert_eq!(copied, n);
        assert_eq!(reserved_take(u64::MAX, 1, n), 0);
    }

    #[test]
    fn sample_threshold_is_strict() {
        assert!(!in_sample(0, 0)); // rate 0 takes nothing
        assert!(in_sample(0, 1));
        assert!(!in_sample(u32::MAX, u32::MAX));
    }
}
