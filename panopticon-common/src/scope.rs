//! Pure capture-scope arithmetic shared by the eBPF programs and the agent.
//!
//! Every function here errs toward capturing less: an input it cannot trust
//! yields "capture nothing", never a guess.

/// Per-socket scope state, kept in a `BPF_MAP_TYPE_SK_STORAGE` map created
/// with `BPF_F_CLONE`, so an accepted child starts with a copy of its
/// listener's value. Fields marked "reset" are rewritten by the child's own
/// ESTABLISHED callback before `init_cookie` is published. The acceptor
/// fields are written only by the accept hook, on the accepted socket, and
/// `accept_cookie` names that socket: a passive ESTABLISHED never clears
/// them (the accept can come first), and a child carrying another socket's
/// acceptor (a clone) is never initialised.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SockState {
    /// This socket's cookie once initialised; written last.
    pub init_cookie: u64,
    /// One aligned 64-bit store: `(scope_gen << 8) | verdict`. 0 = stale. Reset.
    pub verdict_word: u64,
    /// UDP `head_only` budgets, reserved with fetch-and-add.
    pub udp_sent: u64,
    pub udp_rcvd: u64,
    /// Creator tgid (`cgroup/sock_create`), or the listener's on a child.
    pub owner_tgid: u32,
    /// Tgid that `accept()`ed this socket; written after `accept_cookie`.
    pub acceptor_tgid: u32,
    /// `CONFIG_PID_EPOCH` that `pid_bits` were computed under.
    pub pid_epoch: u32,
    /// `bpf_get_prandom_u32()` drawn at initialisation. Redrawn per child.
    pub sample: u32,
    /// Stream origins (ISN + 1), derived at ESTABLISHED. Reset.
    pub rcv_base: u32,
    pub snd_base: u32,
    /// `OWNER_LISTED` | `ACCEPTOR_LISTED`. `ACCEPTOR_LISTED` only with
    /// `acceptor_tgid`, both from the accept hook.
    pub pid_bits: u8,
    /// `FLAG_*` bits.
    pub flags: u8,
    /// Our SYN's count in `bytes_acked`: 1 active, 0 passive. Reset.
    pub syn_adj: u8,
    /// 1 once a packet record of this socket was emitted (sock_capture.rs
    /// `mark_emitted`); `on_tcp_close` sends a close record only then, and
    /// only while the socket is authorised.
    /// A plain store, never a read-modify-write of `flags` (FLAG_KTLS is set
    /// concurrently, unlocked). Sticky; a child may inherit 1 from its
    /// listener (BPF_F_CLONE), which only costs it a close record.
    pub emitted: u8,
    /// 1 once a data packet of this socket was seen on a local path
    /// ([`local_packet`]), whatever `capture_loopback` was then. Sticky, a
    /// plain store like `emitted`: while loopback capture is off, every
    /// packet of the socket is dropped and its close record suppressed
    /// (DESIGN §3.7). A child may inherit 1 from its listener (clone), which
    /// only drops more.
    pub local: u8,
    /// Cookie of the socket the accept hook wrote `acceptor_tgid` and
    /// `ACCEPTOR_LISTED` on; written first. 0 = never accepted.
    pub accept_cookie: u64,
}

pub const OWNER_LISTED: u8 = 1 << 0;
pub const ACCEPTOR_LISTED: u8 = 1 << 1;

/// Stream origins are valid (`head_only` may use them). Reset per child.
pub const FLAG_BASELINE: u8 = 1 << 0;
pub const FLAG_ROLE_CLIENT: u8 = 1 << 1;
pub const FLAG_ROLE_SERVER: u8 = 1 << 2;
/// Sticky, never cleared: a kernel TLS key was (or may have been) installed
/// on the socket (a `SOL_TLS` setsockopt, DESIGN §3.5).
pub const FLAG_KTLS: u8 = 1 << 5;
/// Sticky: TCP repair was used, so the stream history is unknown.
pub const FLAG_REPAIRED: u8 = 1 << 6;
/// Sticky: the socket went through `TCP_CLOSE` and may be reconnected.
pub const FLAG_REUSED: u8 = 1 << 7;
/// Flags a child's ESTABLISHED reset keeps.
pub const FLAGS_STICKY: u8 = FLAG_KTLS | FLAG_REPAIRED | FLAG_REUSED;

pub const VERDICT_IN: u8 = 1;
pub const VERDICT_OUT_PID: u8 = 2;
pub const VERDICT_OUT_CGROUP: u8 = 3;
pub const VERDICT_OUT_SAMPLE: u8 = 4;
/// `pid_filter` only, and no owner or acceptor recorded under this epoch.
pub const VERDICT_OUT_NO_OWNER: u8 = 5;

// `CONFIG_SCOPE_MODE` bits. 0 is unscoped `full`: capture as before, no
// socket state needed. Any bit set is a restricted mode.
/// `pid_filter` is a selector.
pub const SCOPE_SEL_PID: u64 = 1 << 0;
/// `cgroup_filter` / `pod_filter` is a selector (`CGROUP_ALLOW`).
pub const SCOPE_SEL_CGROUP: u64 = 1 << 1;
/// `sampling_mode = "connection_sample"`.
pub const SCOPE_SAMPLE: u64 = 1 << 2;
/// `sampling_mode = "head_only"`.
pub const SCOPE_HEAD: u64 = 1 << 3;

/// Unscoped `full`: the only mode that captures sockets without state,
/// kTLS payload, and TLS plaintext from every process.
#[inline(always)]
pub fn is_unscoped_full(mode: u64) -> bool {
    mode == 0
}

/// Only `full` (scoped or not) exports TLS plaintext (DESIGN §3.5).
#[inline(always)]
pub fn tls_mode_allowed(mode: u64) -> bool {
    mode & (SCOPE_SAMPLE | SCOPE_HEAD) == 0
}

// `SCOPE_DROPS` indices (DESIGN §5). `ring_full` stays `KERNEL_DROPS`.
pub const DROP_NOT_ELIGIBLE: u32 = 0;
pub const DROP_UNINIT: u32 = 1;
pub const DROP_NO_OWNER: u32 = 2;
pub const DROP_OUT_OF_SCOPE: u32 = 3;
pub const DROP_SAMPLED_OUT: u32 = 4;
pub const DROP_NO_BASELINE: u32 = 5;
pub const DROP_HEAD_CUT: u32 = 6;
pub const DROP_HEAD_INCOHERENT: u32 = 7;
pub const DROP_TLS_MODE: u32 = 8;
pub const DROP_TLS_OUT_OF_SCOPE: u32 = 9;
pub const DROP_KTLS_PAYLOAD: u32 = 10;
/// `capture_loopback = false`: a data packet on a node-local path
/// ([`local_packet`]). Packets only: TLS plaintext is scoped by process.
pub const DROP_LOOPBACK: u32 = 11;
pub const SCOPE_DROP_REASONS: u32 = 12;
/// Metric label of each `DROP_*` index.
pub const SCOPE_DROP_NAMES: [&str; SCOPE_DROP_REASONS as usize] = [
    "not_eligible",
    "uninit",
    "no_owner",
    "out_of_scope",
    "sampled_out",
    "no_baseline",
    "head_cut",
    "head_incoherent",
    "tls_mode",
    "tls_out_of_scope",
    "ktls_payload",
    "loopback",
];

/// The loopback device's ifindex in every network namespace
/// (`LOOPBACK_IFINDEX`; `loopback_net_init` registers `lo` first and
/// checks it got 1). A packet whose device (`__sk_buff.ifindex`) is 1 is
/// node-local: TC on the node's NIC never saw it.
pub const LOOPBACK_IFINDEX: u32 = 1;

/// `NETDEV_OFFS` indices: where the capture hook finds the device's
/// `IFF_L3MDEV_MASTER` bit (DESIGN §3.7), written by the loader from the
/// kernel's BTF before the capture hooks attach.
/// `sk_buff.dev` byte offset.
pub const NETDEV_SKB_DEV: u32 = 0;
/// Byte offset in `net_device` of the `priv_flags` byte holding the bit.
pub const NETDEV_L3M_BYTE: u32 = 1;
/// The bit's mask within that byte; 0 means not written (fails closed).
pub const NETDEV_L3M_MASK: u32 = 2;
pub const NETDEV_OFFS_LEN: u32 = 3;

/// Whether a data packet travels a node-local path (DESIGN §3.7), from
/// what the cgroup hook sees, never from addresses:
/// * its device is `lo` (`ifindex`, either direction);
/// * its device is a VRF master (`vrf`: the packet's own device has
///   `IFF_L3MDEV_MASTER` in `priv_flags`, read at the hook; an unreadable
///   device counts as one: fails closed). VRF local delivery
///   leaves and arrives on the master, bound or not; so does a VRF's remote
///   ingress, which is dropped with it. A socket is excluded from its first
///   packet seen on a master on (sticky); a one-way sender whose packets
///   all leave by a slave is never seen on the master and is captured;
/// * the socket already had a local packet (`SockState::local`).
#[inline(always)]
pub fn local_packet(ifindex: u32, vrf: bool, sticky: bool) -> bool {
    ifindex == LOOPBACK_IFINDEX || vrf || sticky
}

/// `DataEvent::role`.
pub const ROLE_UNKNOWN: u8 = 0;
pub const ROLE_CLIENT: u8 = 1;
pub const ROLE_SERVER: u8 = 2;

/// `DataEvent::stream_off` when no offset was computed.
pub const STREAM_OFF_UNKNOWN: u64 = u64::MAX;

/// The event role from `SockState::flags`.
#[inline(always)]
pub fn role_of(flags: u8) -> u8 {
    if flags & FLAG_ROLE_CLIENT != 0 {
        ROLE_CLIENT
    } else if flags & FLAG_ROLE_SERVER != 0 {
        ROLE_SERVER
    } else {
        ROLE_UNKNOWN
    }
}

/// `pid_filter` inputs of one socket, judged under the current epoch: a
/// different epoch means nothing recorded counts (`no_owner`).
/// `creator` is the listener rule (`pid_filter_listener`,
/// `CONFIG_PID_CREATOR_RULE`): under the acceptor rule (false) a passive
/// socket (`FLAG_ROLE_SERVER`) is selected only by `ACCEPTOR_LISTED`; the
/// `OWNER_LISTED` it cloned from its listener does not count. Under the
/// creator rule either bit selects it. Other sockets (client, UDP) are
/// selected by either bit under both rules.
/// Returns `(listed, owner_known)`.
#[inline(always)]
pub fn pid_inputs(s: &SockState, epoch: u32, creator: bool) -> (bool, bool) {
    if s.pid_epoch != epoch {
        return (false, false);
    }
    let owner = if creator || s.flags & FLAG_ROLE_SERVER == 0 {
        OWNER_LISTED
    } else {
        0
    };
    (
        s.pid_bits & (owner | ACCEPTOR_LISTED) != 0,
        s.owner_tgid != 0 || s.acceptor_tgid != 0,
    )
}

/// Whether a verdict may be cached (DESIGN §3.1). An OUT verdict under
/// `pid_filter` of a server socket not yet accepted (`acceptor_tgid` read
/// as 0, before the other pid inputs) is not: the accept hook can still add
/// `ACCEPTOR_LISTED`, and a word cached after the hook reset it would keep
/// the connection OUT for its life. Every other input is final once the
/// socket is initialised.
#[inline(always)]
pub fn verdict_cacheable(v: u8, mode: u64, flags: u8, acceptor_tgid: u32) -> bool {
    v == VERDICT_IN
        || mode & SCOPE_SEL_PID == 0
        || flags & FLAG_ROLE_SERVER == 0
        || acceptor_tgid != 0
}

/// The scope verdict of an initialised socket in restricted `mode`.
/// Selectors combine as a union; sampling applies after scope.
#[inline(always)]
pub fn verdict(
    mode: u64,
    pid_listed: bool,
    pid_owner_known: bool,
    cgroup_in: bool,
    sampled_in: bool,
) -> u8 {
    let pid_sel = mode & SCOPE_SEL_PID != 0;
    let cg_sel = mode & SCOPE_SEL_CGROUP != 0;
    if (pid_sel || cg_sel) && !((pid_sel && pid_listed) || (cg_sel && cgroup_in)) {
        return if cg_sel {
            VERDICT_OUT_CGROUP
        } else if pid_owner_known {
            VERDICT_OUT_PID
        } else {
            VERDICT_OUT_NO_OWNER
        };
    }
    if mode & SCOPE_SAMPLE != 0 && !sampled_in {
        return VERDICT_OUT_SAMPLE;
    }
    VERDICT_IN
}

/// The `SCOPE_DROPS` index for an OUT verdict.
#[inline(always)]
pub fn drop_reason(verdict: u8) -> u32 {
    match verdict {
        VERDICT_OUT_SAMPLE => DROP_SAMPLED_OUT,
        VERDICT_OUT_NO_OWNER => DROP_NO_OWNER,
        _ => DROP_OUT_OF_SCOPE,
    }
}

/// Pack a verdict with the scope generation it was computed under.
#[inline(always)]
pub fn verdict_word(generation: u32, verdict: u8) -> u64 {
    ((generation as u64) << 8) | verdict as u64
}

/// The cached verdict, if `word` was computed under generation `gen`.
#[inline(always)]
pub fn cached_verdict(word: u64, generation: u32) -> Option<u8> {
    if word == 0 || (word >> 8) != generation as u64 {
        return None;
    }
    Some(word as u8)
}

/// A socket is initialised only when its stored `init_cookie` is its own
/// cookie. A child cloned from a listener (`BPF_F_CLONE`) carries the
/// listener's cookie, so it reads as uninitialised until its own
/// ESTABLISHED callback publishes. Cookie 0 is never valid.
#[inline(always)]
pub fn is_initialised(init_cookie: u64, cookie: u64) -> bool {
    init_cookie != 0 && init_cookie == cookie
}

/// TLS address learning (DESIGN §3.5): whether one read of a socket's
/// state (`init_cookie`, `flags`, `verdict_word`, and `CONFIG_SCOPE_GEN` as
/// `gen_now`) shows the socket in scope under generation `g1`. The kernel
/// evaluates it before reading the socket's tuple and again after: the tuple
/// is the in-scope socket's only if both hold. A disconnect in between sets
/// `REUSED` and clears `init_cookie` for good; a selector change moves the
/// generation; an accept clears the verdict.
#[inline(always)]
pub fn tls_addr_in_scope(
    cookie: u64,
    g1: u32,
    init_cookie: u64,
    flags: u8,
    word: u64,
    gen_now: u32,
) -> bool {
    is_initialised(init_cookie, cookie)
        && flags & FLAG_REUSED == 0
        && cached_verdict(word, g1) == Some(VERDICT_IN)
        && gen_now == g1
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
/// `rate * 2^32` ([`sample_threshold`]). u64, so rate 1 (2^32) takes every draw.
#[inline(always)]
pub fn in_sample(draw: u32, threshold: u64) -> bool {
    (draw as u64) < threshold
}

/// `CONFIG_SAMPLE_THRESHOLD` for `sample_rate`: `rate * 2^32`, clamped to
/// `[0, 2^32]`; NaN gives 0 (sample nothing).
pub fn sample_threshold(rate: f64) -> u64 {
    const FULL: f64 = (1u64 << 32) as f64;
    if rate.is_nan() || rate <= 0.0 {
        return 0;
    }
    if rate >= 1.0 {
        return 1 << 32;
    }
    (rate * FULL) as u64
}

/// UDP `head_only` pre-check (DESIGN §3.3): once the budget counter holds
/// `n` or more, a datagram reserves nothing, so the counter never wraps.
#[inline(always)]
pub fn udp_should_reserve(counter: u64, n: u64) -> bool {
    counter < n
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_SEQ: u32 = 0xFFFF_FF00; // near the wrap on purpose

    fn seq_at(done: u64) -> u32 {
        BASE_SEQ.wrapping_add(done as u32)
    }

    #[test]
    fn sock_state_layout_is_stable() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<SockState>(), 72);
        assert_eq!(align_of::<SockState>(), 8);
        assert_eq!(offset_of!(SockState, verdict_word) % 8, 0);
        assert_eq!(offset_of!(SockState, pid_bits), 56);
        assert_eq!(offset_of!(SockState, local), 60);
        assert_eq!(offset_of!(SockState, accept_cookie), 64);
    }

    #[test]
    fn verdict_word_is_valid_only_for_its_generation() {
        let w = verdict_word(7, VERDICT_IN);
        assert_eq!(cached_verdict(w, 7), Some(VERDICT_IN));
        assert_eq!(cached_verdict(w, 8), None); // older writer: stale
        assert_eq!(cached_verdict(0, 0), None); // reset
        assert_eq!(
            cached_verdict(verdict_word(u32::MAX, VERDICT_OUT_SAMPLE), u32::MAX),
            Some(VERDICT_OUT_SAMPLE)
        );
    }

    #[test]
    fn tls_addr_needs_the_same_in_scope_socket_throughout() {
        let w = verdict_word(3, VERDICT_IN);
        assert!(tls_addr_in_scope(42, 3, 42, 0, w, 3));
        // before the read: not initialised, a listener's clone, no verdict
        assert!(!tls_addr_in_scope(42, 3, 0, 0, w, 3));
        assert!(!tls_addr_in_scope(42, 3, 41, 0, w, 3));
        assert!(!tls_addr_in_scope(42, 3, 42, 0, 0, 3));
        assert!(!tls_addr_in_scope(
            42,
            3,
            42,
            0,
            verdict_word(3, VERDICT_OUT_PID),
            3
        ));
        // stale verdict (older generation)
        assert!(!tls_addr_in_scope(
            42,
            3,
            42,
            0,
            verdict_word(2, VERDICT_IN),
            3
        ));
        // after the read: disconnected (REUSED, init cleared), or REUSED
        // alone, or the generation moved, or the verdict was cleared
        assert!(!tls_addr_in_scope(42, 3, 0, FLAG_REUSED, w, 3));
        assert!(!tls_addr_in_scope(42, 3, 42, FLAG_REUSED, w, 3));
        assert!(!tls_addr_in_scope(42, 3, 42, 0, w, 4));
        assert!(!tls_addr_in_scope(42, 3, 42, 0, 0, 3));
        // other sticky flags do not matter for an address
        assert!(tls_addr_in_scope(
            42,
            3,
            42,
            FLAG_KTLS | FLAG_BASELINE,
            w,
            3
        ));
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
        assert!(!in_sample(u32::MAX, u32::MAX as u64));
        assert!(in_sample(u32::MAX, sample_threshold(1.0))); // rate 1 takes all
    }

    #[test]
    fn sample_threshold_clamps() {
        assert_eq!(sample_threshold(0.0), 0);
        assert_eq!(sample_threshold(-1.0), 0);
        assert_eq!(sample_threshold(f64::NAN), 0);
        assert_eq!(sample_threshold(0.5), 1 << 31);
        assert_eq!(sample_threshold(1.0), 1 << 32);
        assert_eq!(sample_threshold(7.0), 1 << 32);
    }

    #[test]
    fn udp_pre_check_stops_the_counter_near_n() {
        // Every CPU passes the pre-check at most once more after the counter
        // crosses N, so it ends below N + one datagram per CPU, far from wrap.
        let n = 4096u64;
        let mut counter = 0u64;
        let mut copied = 0u64;
        for _ in 0..10_000 {
            let len = 65_507u32; // largest UDP payload
            if udp_should_reserve(counter, n) {
                copied += reserved_take(counter, len, n) as u64;
                counter += len as u64;
            }
        }
        assert_eq!(copied, n);
        assert!(counter < n + 65_507);
        assert!(!udp_should_reserve(u64::MAX, n));
    }

    #[test]
    fn modes() {
        assert!(is_unscoped_full(0));
        assert!(!is_unscoped_full(SCOPE_SEL_PID));
        assert!(tls_mode_allowed(SCOPE_SEL_PID | SCOPE_SEL_CGROUP));
        assert!(!tls_mode_allowed(SCOPE_SAMPLE));
        assert!(!tls_mode_allowed(SCOPE_HEAD | SCOPE_SEL_PID));
    }

    #[test]
    fn pid_inputs_need_the_current_epoch() {
        let mut s = SockState {
            pid_epoch: 7,
            pid_bits: OWNER_LISTED,
            owner_tgid: 42,
            ..Default::default()
        };
        for creator in [false, true] {
            s.pid_bits = OWNER_LISTED;
            s.owner_tgid = 42;
            s.acceptor_tgid = 0;
            assert_eq!(pid_inputs(&s, 7, creator), (true, true));
            assert_eq!(pid_inputs(&s, 8, creator), (false, false)); // other start: no_owner
            s.pid_bits = 0;
            assert_eq!(pid_inputs(&s, 7, creator), (false, true));
            s.owner_tgid = 0;
            assert_eq!(pid_inputs(&s, 7, creator), (false, false));
            s.acceptor_tgid = 9;
            s.pid_bits = ACCEPTOR_LISTED;
            assert_eq!(pid_inputs(&s, 7, creator), (true, true));
        }
    }

    #[test]
    fn listener_rule_decides_whether_the_creator_selects_children() {
        // An accepted child: listener created by a listed process (cloned
        // OWNER_LISTED), accepted by an unlisted one.
        let child = SockState {
            pid_epoch: 7,
            pid_bits: OWNER_LISTED,
            owner_tgid: 42,
            acceptor_tgid: 43,
            flags: FLAG_ROLE_SERVER | FLAG_BASELINE,
            ..Default::default()
        };
        assert_eq!(pid_inputs(&child, 7, true), (true, true), "creator rule");
        assert_eq!(pid_inputs(&child, 7, false), (false, true), "acceptor rule");
        let v = |c| {
            let (listed, known) = pid_inputs(&child, 7, c);
            verdict(SCOPE_SEL_PID, listed, known, false, true)
        };
        assert_eq!(v(true), VERDICT_IN);
        assert_eq!(v(false), VERDICT_OUT_PID);
        // Not yet accepted, acceptor rule: OUT, and not cached (the accept
        // can still list it).
        let early = SockState {
            acceptor_tgid: 0,
            ..child
        };
        assert_eq!(pid_inputs(&early, 7, false), (false, true));
        assert!(!verdict_cacheable(
            VERDICT_OUT_PID,
            SCOPE_SEL_PID,
            early.flags,
            0
        ));
        // A listed acceptor selects it under both rules.
        let acc = SockState {
            pid_bits: OWNER_LISTED | ACCEPTOR_LISTED,
            ..child
        };
        assert_eq!(pid_inputs(&acc, 7, false), (true, true));
        let acc_only = SockState {
            pid_bits: ACCEPTOR_LISTED,
            ..child
        };
        assert_eq!(pid_inputs(&acc_only, 7, true), (true, true));
        // Client and UDP sockets: the creator selects them under both rules.
        for flags in [FLAG_ROLE_CLIENT | FLAG_BASELINE, FLAG_BASELINE] {
            let s = SockState {
                flags,
                acceptor_tgid: 0,
                ..child
            };
            assert_eq!(pid_inputs(&s, 7, false), (true, true));
        }
    }

    #[test]
    fn loopback_rules() {
        assert_eq!(SCOPE_DROP_NAMES[DROP_LOOPBACK as usize], "loopback");
        assert!(local_packet(1, false, false));
        // A VRF master, either direction.
        assert!(local_packet(9, true, false));
        // A veth or NIC packet.
        assert!(!local_packet(4, false, false));
        // Sticky: once local, every packet of the socket.
        assert!(local_packet(4, false, true));
    }

    #[test]
    fn out_before_accept_is_not_cached() {
        let pid = SCOPE_SEL_PID;
        let srv = FLAG_ROLE_SERVER;
        // A server child not yet accepted: OUT may turn IN at accept.
        assert!(!verdict_cacheable(VERDICT_OUT_NO_OWNER, pid, srv, 0));
        assert!(!verdict_cacheable(
            VERDICT_OUT_PID,
            pid | SCOPE_SEL_CGROUP,
            srv,
            0
        ));
        assert!(!verdict_cacheable(
            VERDICT_OUT_SAMPLE,
            pid | SCOPE_SAMPLE,
            srv,
            0
        ));
        // Final inputs: accepted, a client, no pid selector, or IN.
        assert!(verdict_cacheable(VERDICT_OUT_PID, pid, srv, 9));
        assert!(verdict_cacheable(VERDICT_OUT_PID, pid, FLAG_ROLE_CLIENT, 0));
        assert!(verdict_cacheable(
            VERDICT_OUT_CGROUP,
            SCOPE_SEL_CGROUP,
            srv,
            0
        ));
        assert!(verdict_cacheable(VERDICT_IN, pid, srv, 0));
    }

    #[test]
    fn verdict_is_a_union_then_a_sample() {
        let pid = SCOPE_SEL_PID;
        let cg = SCOPE_SEL_CGROUP;
        assert_eq!(verdict(pid, true, true, false, false), VERDICT_IN);
        assert_eq!(verdict(pid, false, true, true, true), VERDICT_OUT_PID);
        assert_eq!(verdict(pid, false, false, true, true), VERDICT_OUT_NO_OWNER);
        assert_eq!(verdict(cg, true, true, false, true), VERDICT_OUT_CGROUP);
        assert_eq!(verdict(cg, false, false, true, true), VERDICT_IN);
        assert_eq!(verdict(pid | cg, false, false, true, true), VERDICT_IN);
        assert_eq!(verdict(pid | cg, true, true, false, true), VERDICT_IN);
        assert_eq!(
            verdict(pid | cg, false, false, false, true),
            VERDICT_OUT_CGROUP
        );
        // Sampling applies only after scope.
        let s = SCOPE_SAMPLE;
        assert_eq!(verdict(s, false, false, false, false), VERDICT_OUT_SAMPLE);
        assert_eq!(verdict(s, false, false, false, true), VERDICT_IN);
        assert_eq!(verdict(pid | s, false, true, false, true), VERDICT_OUT_PID);
        assert_eq!(
            verdict(pid | s, true, true, false, false),
            VERDICT_OUT_SAMPLE
        );
        // head_only alone selects everything (the cut is separate).
        assert_eq!(verdict(SCOPE_HEAD, false, false, false, false), VERDICT_IN);
    }

    #[test]
    fn drop_reasons_cover_every_out_verdict() {
        assert_eq!(drop_reason(VERDICT_OUT_PID), DROP_OUT_OF_SCOPE);
        assert_eq!(drop_reason(VERDICT_OUT_CGROUP), DROP_OUT_OF_SCOPE);
        assert_eq!(drop_reason(VERDICT_OUT_SAMPLE), DROP_SAMPLED_OUT);
        assert_eq!(drop_reason(VERDICT_OUT_NO_OWNER), DROP_NO_OWNER);
        assert_eq!(SCOPE_DROP_NAMES[DROP_KTLS_PAYLOAD as usize], "ktls_payload");
        assert_eq!(SCOPE_DROP_NAMES.len(), SCOPE_DROP_REASONS as usize);
    }

    #[test]
    fn roles() {
        assert_eq!(role_of(FLAG_ROLE_CLIENT | FLAG_BASELINE), ROLE_CLIENT);
        assert_eq!(role_of(FLAG_ROLE_SERVER | FLAG_KTLS), ROLE_SERVER);
        assert_eq!(role_of(FLAG_REUSED), ROLE_UNKNOWN);
    }
}
