//! Capture scope from kernel socket state (the cgroup_skb backend).
//!
//! `cgroup_skb` ingress/egress on the cgroup v2 root capture each socket's
//! packets and decide scope from that socket's `SockState`, kept in the
//! `SOCK_STATE` sk_storage map. The writers of that state are kernel events
//! only: `cgroup/sock_create` (creator, UDP initialisation), `sockops`
//! (TCP initialisation at ESTABLISHED, revocation at TCP_CLOSE), fexit
//! `inet_csk_accept` (acceptor, on the child only) and fentry
//! `sock_common_setsockopt` (sticky KTLS at kTLS key install). Every rule errs toward not capturing: a socket whose state
//! is missing, not its own, or not computable is dropped and counted in
//! `SCOPE_DROPS`, except in unscoped `full` mode, which captures every socket.
//!
//! Every program here returns "allow" (1) on every path: a cgroup program
//! returning 0 would drop the packet or fail the `socket()` call.

use core::ffi::c_void;
use core::ptr::{null_mut, read_volatile, write_volatile};

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_CLONE, BPF_F_NO_PREALLOC, bpf_map_type::BPF_MAP_TYPE_SK_STORAGE},
    helpers::bpf_probe_read_kernel,
    helpers::generated::{
        bpf_get_current_ancestor_cgroup_id, bpf_get_current_pid_tgid, bpf_get_prandom_u32,
        bpf_get_socket_cookie, bpf_ktime_get_ns,
        bpf_probe_read_kernel as bpf_probe_read_kernel_raw, bpf_sk_ancestor_cgroup_id,
        bpf_sk_cgroup_id, bpf_sk_fullsock, bpf_sk_storage_delete, bpf_sk_storage_get,
        bpf_skb_load_bytes, bpf_sock_ops_cb_flags_set, bpf_tcp_sock,
    },
    macros::{cgroup_skb, cgroup_sock, fentry, fexit, map, sock_ops},
    maps::ProgramArray,
    programs::{FEntryContext, FExitContext, SkBuffContext, SockContext, SockOpsContext},
};
use panopticon_common::{
    CONFIG_CAPTURE_ENABLED, CONFIG_CAPTURE_LOOPBACK, CONFIG_HEAD_BYTES, CONFIG_MAX_PAYLOAD,
    CONFIG_PENDING_BUDGET, CONFIG_PENDING_HOLD, CONFIG_PENDING_OVERFLOW, CONFIG_PENDING_SEED,
    CONFIG_PENDING_SHARE, CONFIG_PID_CREATOR_RULE, CONFIG_PID_EPOCH, CONFIG_SAMPLE_THRESHOLD,
    CONFIG_SCOPE_ARMED, CONFIG_SCOPE_GEN, CONFIG_SCOPE_MODE, CONN_CAP_CUT, CONN_CAP_USED,
    DATA_EVENT_HEADER_LEN, DataEvent, Direction, EventType, MAX_PAYLOAD_SIZE,
    PENDING_CTL_OVERFLOW_USED, PENDING_CTL_USED, PENDING_HOLD_BYTES, PENDING_LISTENER_BUCKETS,
    TlsLibrary, pending_listener_bucket,
    scope::{
        ACCEPTOR_LISTED, DROP_HEAD_CUT, DROP_HEAD_INCOHERENT, DROP_KTLS_PAYLOAD, DROP_LOOPBACK,
        DROP_NO_BASELINE, DROP_NOT_ELIGIBLE, DROP_OUT_OF_SCOPE, DROP_PENDING_ACCEPT,
        DROP_PENDING_DISCARDED, DROP_PENDING_OVERFLOW, DROP_PENDING_RACE, DROP_UNINIT,
        FLAG_BASELINE, FLAG_KTLS, FLAG_REPAIRED, FLAG_REUSED, FLAG_ROLE_CLIENT, FLAG_ROLE_SERVER,
        FLAGS_STICKY, NETDEV_L3M_BYTE, NETDEV_L3M_MASK, NETDEV_SKB_DEV, OWNER_LISTED, SCOPE_HEAD,
        SCOPE_SAMPLE, SCOPE_SEL_CGROUP, STREAM_OFF_UNKNOWN, SockState, VERDICT_IN, cached_verdict,
        drop_reason, head_take, in_sample, is_initialised, is_unscoped_full, local_packet,
        pending_accept, pid_inputs, reserved_take, role_of, skb_stamp, stream_offset,
        tls_addr_in_scope, udp_should_reserve, verdict, verdict_cacheable, verdict_word,
    },
};

use crate::maps::{
    CGROUP_ALLOW, CONFIG, CONN_CAP, CONN_CAP_STATS, IPV6_DROPS, NETDEV_OFFS, PENDING_CTL,
    PENDING_LISTENERS, PID_FILTER, SizedEvent, count_kernel_drop, count_scope_drop, shard_for,
    shard_output, shard_reserve_as, shard_submit_flags_for,
};

// ── SOCK_STATE: BTF sk_storage map with BPF_F_CLONE ────────────────────────
//
// Aya's `SkStorage` is typed to `SockAddrContext` and its flags are fixed to
// BPF_F_NO_PREALLOC, and `btf_map_def!` is crate-private, so the BTF map
// definition is written out here (same layout aya and libbpf parse).
// BPF_F_CLONE: an accepted child starts with a copy of its listener's value
// (owner, OWNER_LISTED, cgroup is the socket's own); every per-connection
// field is reset by the child's own ESTABLISHED callback.

#[repr(C)]
pub struct SockStateMap {
    r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE as usize],
    key: *const i32,
    value: *const SockState,
    max_entries: *const [i32; 0],
    map_flags: *const [i32; (BPF_F_NO_PREALLOC | BPF_F_CLONE) as usize],
}

unsafe impl Sync for SockStateMap {}

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "SOCK_STATE")]
pub static SOCK_STATE: SockStateMap = SockStateMap {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_flags: core::ptr::null(),
};

const SK_STORAGE_GET_F_CREATE: u64 = 1;

/// The socket's state, or null. State is created only for sockets created
/// while this agent runs: by `cgroup/sock_create`, and for a child of a
/// listener without state (one that predates the agent, §3.1) by its
/// PASSIVE_ESTABLISHED or its accept, whichever runs first. User space never
/// writes state. A socket that itself predates the agent is never
/// initialised (§2.1).
#[inline(always)]
fn state_of(sk: *mut c_void, create: bool) -> *mut SockState {
    let flags = if create { SK_STORAGE_GET_F_CREATE } else { 0 };
    unsafe {
        bpf_sk_storage_get(
            &SOCK_STATE as *const SockStateMap as *mut c_void,
            sk,
            null_mut(),
            flags,
        ) as *mut SockState
    }
}

/// The socket's state, created if absent. The accept hook and a passive
/// ESTABLISHED can race to create a child's state; the loser's create
/// fails (it exists), so it looks the winner's up.
#[inline(always)]
fn state_or_create(sk: *mut c_void) -> *mut SockState {
    let st = state_of(sk, true);
    if st.is_null() {
        state_of(sk, false)
    } else {
        st
    }
}

// ── Volatile field access ──────────────────────────────────────────────────
//
// Publication (§2.2): writers store every field, then `init_cookie`; readers
// load `init_cookie`, then fields. x86-64 keeps stores and loads in program
// order, so only the compiler must not reorder them: every access to shared
// state is volatile, and volatile accesses keep their order.

macro_rules! rd {
    ($st:expr, $f:ident) => {{
        #[allow(unused_unsafe)]
        let v = unsafe { read_volatile(&raw const (*$st).$f) };
        v
    }};
}
macro_rules! wr {
    ($st:expr, $f:ident, $v:expr) => {{
        let v = $v;
        #[allow(unused_unsafe)]
        unsafe {
            write_volatile(&raw mut (*$st).$f, v)
        }
    }};
}

// ── PENDING: the pre-accept hold (DESIGN §3.1) ─────────────────────────────
//
// Under `pid_filter` with the acceptor rule, a server socket's acceptor is
// unknown until accept() returns it, so bytes it receives before then
// cannot be scoped when they arrive (`scope::pending_accept`). They are held
// here, in the socket's own storage, and decided at accept: sent if the
// acceptor is listed (under the generation and mode they were held under),
// discarded otherwise. Nothing held leaves the kernel unless its acceptor
// is listed. No BPF_F_CLONE: a listener never holds, and a child must not
// start with a copy.
//
// Protocol, on one socket's value:
// * a holder (`hold_packet`, in `scope_skb_hold`) takes ticket
//   `fetch_add(tickets, 1)`; tickets 0 and 1 own slots 0 and 1, each
//   written once; a ticket >= PENDING_SLOTS is an overflow, one >=
//   PENDING_CLOSED means the slots were already closed;
// * the creator that wins `fetch_add(charged, 1) == 0` keeps the budget
//   bytes it took for the value; any other gives them back;
// * a closer (the release at accept, the discard at TCP_CLOSE, or a holder
//   that finds the socket accepted or closed under it) first wins
//   `fetch_add(closed, 1) == 0`; it closes the tickets with
//   `fetch_add(tickets, PENDING_CLOSED)`, which also tells it how many
//   slots were handed out (`count`), and goes through them in order;
// * per slot, the writer adds SLOT_WRITTEN to `state` once the record is
//   whole and the release adds SLOT_REACHED when it gets there: whoever
//   adds second sees the other's add. A release that reaches a slot still
//   being written stops; that slot's writer then sends (or discards) its
//   record and goes on with the rest. So records leave in ticket order,
//   none is lost to the race, and the last one through frees the value
//   and gives its bytes back to the budget (exactly once: one path reaches
//   the end);
// * `SockState::held`: 1 before a value is created, 2 once the socket was
//   accepted or closed and its value (if any) freed. Written 2 by whoever
//   frees the value, or by the accept, close or destroy that finds no
//   value (`held` 0, or 1 when every hold failed). An in-scope packet looks
//   for a waiting value while it is 1; a holder that finds 2 holds nothing
//   (`scope_skb_hold` hands the packet back to the capture hook, which now
//   finds it accepted). A holder that read 1 before such a 2 can still
//   create a value after it: it then finds the socket accepted or closed
//   after its write and releases the value itself (`hold_packet`).

/// Slots per socket: the bytes of the first two packets received before
/// accept() (a request line and its headers, normally one).
const PENDING_SLOTS: u64 = 2;
/// Added to `tickets` by the closer: every later ticket reads as closed.
const PENDING_CLOSED: u64 = 1 << 32;

#[repr(C)]
pub struct PendingSlot {
    /// SLOT_WRITTEN | SLOT_REACHED, by fetch-and-add (see above).
    state: u64,
    /// `CONFIG_SCOPE_MODE` the packet was held under.
    mode: u64,
    /// The record as it would have been sent, `acceptor_tgid` 0.
    rec: SizedEvent<MAX_PAYLOAD_SIZE>,
}

#[repr(C)]
pub struct Pending {
    tickets: u64,
    closed: u64,
    charged: u64,
    /// Slots handed out, written by the closer before it reaches any.
    count: u64,
    slots: [PendingSlot; PENDING_SLOTS as usize],
}

const SLOT_WRITTEN: u64 = 1;
const SLOT_REACHED: u64 = 2;

/// Budget bytes one socket's hold takes: what the kernel allocates for it.
/// The value (8,440 bytes) plus the storage element's header is a
/// 16 KiB kmalloc object, freed after an RCU grace period. The socket's
/// optmem is charged the element's size (value and header), which fits
/// under the default `optmem_max` (20,480 before 6.9) beside SOCK_STATE.
const PENDING_BYTES: u64 = PENDING_HOLD_BYTES;
const _: () = assert!(
    core::mem::size_of::<Pending>() + 256 <= PENDING_BYTES as usize
        && core::mem::size_of::<Pending>() > 8 << 10
);

#[repr(C)]
pub struct PendingMap {
    r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE as usize],
    key: *const i32,
    value: *const Pending,
    max_entries: *const [i32; 0],
    map_flags: *const [i32; BPF_F_NO_PREALLOC as usize],
}

unsafe impl Sync for PendingMap {}

#[unsafe(link_section = ".maps")]
#[unsafe(export_name = "PENDING")]
pub static PENDING: PendingMap = PendingMap {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_flags: core::ptr::null(),
};

#[inline(always)]
fn pending_of(sk: *mut c_void, create: bool) -> *mut Pending {
    let flags = if create { SK_STORAGE_GET_F_CREATE } else { 0 };
    unsafe {
        bpf_sk_storage_get(
            &PENDING as *const PendingMap as *mut c_void,
            sk,
            null_mut(),
            flags,
        ) as *mut Pending
    }
}

#[inline(always)]
fn pending_ctl(index: u32) -> *mut u64 {
    match PENDING_CTL.get_ptr_mut(index) {
        Some(p) => p,
        None => null_mut(),
    }
}

/// Take one hold's bytes from the budget, charged to listener counter
/// `bucket`; false (nothing taken) if the budget is spent, or the
/// listener's share is and so is the overflow pool ([`share_take`]).
#[inline(always)]
fn budget_take(bucket: u32) -> bool {
    let used = pending_ctl(PENDING_CTL_USED);
    let limit = pending_ctl(CONFIG_PENDING_BUDGET);
    if used.is_null() || limit.is_null() {
        return false;
    }
    let prev = unsafe { fetch_add_u64(used, PENDING_BYTES) };
    if prev.saturating_add(PENDING_BYTES) > unsafe { read_volatile(limit) } {
        unsafe { fetch_add_u64(used, PENDING_BYTES.wrapping_neg()) };
        return false;
    }
    if !share_take(bucket) {
        unsafe { fetch_add_u64(used, PENDING_BYTES.wrapping_neg()) };
        return false;
    }
    true
}

/// Give back what [`budget_take`] took for `bucket`.
#[inline(always)]
fn budget_give(bucket: u32) {
    share_give(bucket);
    let used = pending_ctl(PENDING_CTL_USED);
    if !used.is_null() {
        unsafe { fetch_add_u64(used, PENDING_BYTES.wrapping_neg()) };
    }
}

/// The listener counter of `bucket` (masked, so every verifier bounds it).
#[inline(always)]
fn listener_counter(bucket: u32) -> *mut u64 {
    match PENDING_LISTENERS.get_ptr_mut(bucket & (PENDING_LISTENER_BUCKETS - 1)) {
        Some(p) => p,
        None => null_mut(),
    }
}

/// The per-listener share (DESIGN §3.1): one hold's bytes on listener
/// counter `bucket`. A listener may always take its share
/// (`CONFIG_PENDING_SHARE`) while the budget lasts; past it, a hold also
/// takes from the overflow pool (`CONFIG_PENDING_OVERFLOW`) all listeners
/// share. So no listener, an unlisted one that never accepts included,
/// takes more than its share and the pool, and the rest of the budget is
/// left to the shares of the others.
///
/// `PENDING_CTL_OVERFLOW_USED` is the sum over counters of what each holds
/// past its share, once no take or give is in flight: a counter's
/// fetch-and-adds fall in one order, and each moves the pool by one hold
/// exactly when that counter's excess changed (at or past its share before
/// an add, past it before a subtract; the share is whole holds), whatever
/// order the pool's own adds land in, failed takes and their undo
/// included. In flight it can read high (a failed take not yet undone),
/// low (a counter added to, the pool not yet) or wrapped below 0 (a
/// subtract before its add, which `saturating_add` refuses): every pool
/// admission checks its own add against the limit, so none of this admits
/// past it once settled, and under contention it can only refuse a take
/// that would have fit (best effort, as `used` is when failed takes on
/// many CPUs inflate it briefly).
#[inline(always)]
fn share_take(bucket: u32) -> bool {
    let c = listener_counter(bucket);
    let pool = pending_ctl(PENDING_CTL_OVERFLOW_USED);
    let share = pending_ctl(CONFIG_PENDING_SHARE);
    let pool_limit = pending_ctl(CONFIG_PENDING_OVERFLOW);
    if c.is_null() || pool.is_null() || share.is_null() || pool_limit.is_null() {
        return false;
    }
    let share = unsafe { read_volatile(share) };
    let prev = unsafe { fetch_add_u64(c, PENDING_BYTES) };
    if prev < share {
        return true;
    }
    let was = unsafe { fetch_add_u64(pool, PENDING_BYTES) };
    if was.saturating_add(PENDING_BYTES) <= unsafe { read_volatile(pool_limit) } {
        return true;
    }
    share_give(bucket);
    false
}

/// Give back one hold's bytes on listener counter `bucket` ([`share_take`]).
#[inline(always)]
fn share_give(bucket: u32) {
    let c = listener_counter(bucket);
    let pool = pending_ctl(PENDING_CTL_OVERFLOW_USED);
    let share = pending_ctl(CONFIG_PENDING_SHARE);
    if c.is_null() || pool.is_null() || share.is_null() {
        return;
    }
    let share = unsafe { read_volatile(share) };
    let prev = unsafe { fetch_add_u64(c, PENDING_BYTES.wrapping_neg()) };
    if prev > share {
        unsafe { fetch_add_u64(pool, PENDING_BYTES.wrapping_neg()) };
    }
}

/// The socket's hold, created (and its bytes taken from the budget,
/// charged to listener counter `bucket`) if it has none; null if the
/// budget or the listener's share is spent ([`budget_take`]) or the
/// storage cannot be created (the socket's optmem). A create that loses a
/// race to another CPU's create gets null back (`-EEXIST` under the
/// storage lock) or the winner's value; either way only the first to win
/// `charged` keeps the bytes it took. Every holder of one socket charges
/// the same counter (`SockState::hold_bucket`).
#[inline(always)]
fn pending_get_or_create(sk: *mut c_void, bucket: u32) -> *mut Pending {
    let p = pending_of(sk, false);
    if !p.is_null() {
        return p;
    }
    if !budget_take(bucket) {
        return null_mut();
    }
    let p = pending_of(sk, true);
    if p.is_null() {
        budget_give(bucket);
        return pending_of(sk, false);
    }
    if unsafe { fetch_add_u64(&raw mut (*p).charged, 1) } != 0 {
        budget_give(bucket);
    }
    p
}

/// Free a hold and give its bytes back (to the counter its holders
/// charged, `SockState::hold_bucket`), then mark the socket done
/// (`held` 2). Exactly once per value: only the release that went through
/// every slot calls it. A holder still writing into the value writes
/// freed-under-RCU memory nobody reads (it cannot be: its slot was
/// reached, so it would have sent it first).
#[inline(always)]
fn pending_free(sk: *mut c_void, st: *mut SockState) {
    unsafe {
        bpf_sk_storage_delete(&PENDING as *const PendingMap as *mut c_void, sk);
    }
    budget_give(u32::from(rd!(st, hold_bucket)));
    wr!(st, held, HELD_DONE);
}

/// A full memory barrier (a locked add of 0, BPF_ADD | BPF_FETCH): orders
/// a store that ends a socket's pre-accept life (the acceptor, REUSED)
/// before the lookup of its hold. x86-64 may otherwise satisfy that load
/// before the store is visible, and a holder doing the mirror image
/// (create, fetch-and-add, load) could miss it too, leaving a hold that
/// nobody releases.
#[inline(always)]
fn pending_fence() {
    let used = pending_ctl(PENDING_CTL_USED);
    if !used.is_null() {
        unsafe { fetch_add_u64(used, 0) };
    }
}

/// Whether a held record may be sent now, from the socket's state, and its
/// acceptor:
/// * the acceptor is listed (ACCEPTOR_LISTED under the current epoch, the
///   accept hook's write), so its verdict is now IN, as `pending_accept`
///   required of every other input when the packet was held;
/// * the socket is still the initialised, not reused, non-kTLS socket the
///   packet was held on.
///
/// The per-record checks are in [`release_slot`].
#[inline(always)]
fn release_gate(st: *mut SockState, cookie: u64) -> (bool, u32) {
    let tgid = rd!(st, acceptor_tgid);
    let epoch = cfg(CONFIG_PID_EPOCH) as u32;
    let flags = rd!(st, flags);
    let ok = tgid != 0
        && rd!(st, pid_epoch) == epoch
        && rd!(st, pid_bits) & ACCEPTOR_LISTED != 0
        && is_initialised(rd!(st, init_cookie), cookie)
        && flags & (FLAG_KTLS | FLAG_REUSED) == 0;
    (ok, tgid)
}

/// Send one written slot's record, stamped with its acceptor, or discard
/// it. Sent only if the gate holds ([`release_gate`]) and
/// * capture is on: `CONFIG_CAPTURE_ENABLED`, the gate of the packet path
///   (`try_skb`) the record came from, and armed (the accept hook runs only
///   armed). In a restricted mode that is what `tls_capture_on` tests too,
///   so either would do; neither alone is enough, as a disarm or a
///   narrowing can come between the hold and the accept:
/// * the scope is what it was when the packet was held: the same
///   `CONFIG_SCOPE_GEN` as the record's stamp (any selector change, a
///   listener-rule or loopback change, bumps it) and the same
///   `CONFIG_SCOPE_MODE` (the fatal stop changes the mode without a bump,
///   after clearing `CONFIG_CAPTURE_ENABLED`).
#[inline(always)]
fn release_slot(slot: *mut PendingSlot, st: *mut SockState, ok: bool, tgid: u32, shard: u32) {
    let event = unsafe { &raw mut (*slot).rec } as *mut DataEvent;
    let stamp = unsafe { read_volatile(&raw const (*event).scope_gen) };
    let len = unsafe { read_volatile(&raw const (*event).payload_len) };
    let send = ok
        && cfg(CONFIG_CAPTURE_ENABLED) != 0
        && scope_gen() == stamp
        && scope_mode() == unsafe { read_volatile(&raw const (*slot).mode) }
        && len != 0
        && len <= MAX_PAYLOAD_SIZE as u32;
    if !send {
        count_scope_drop(DROP_PENDING_DISCARDED);
        return;
    }
    unsafe { write_volatile(&raw mut (*event).acceptor_tgid, tgid) };
    mark_emitted(st);
    // [1, MAX_PAYLOAD_SIZE] in a form every verifier bounds (as in
    // `emit_sized`): LLVM drops a plain range check it has proven, so a
    // volatile read hides the value; the mask changes nothing at runtime.
    let opaque = unsafe { read_volatile(&len) };
    let len = (opaque.wrapping_sub(1) & (MAX_PAYLOAD_SIZE as u32 - 1)) + 1;
    let size = DATA_EVENT_HEADER_LEN as u64 + len as u64;
    if shard_output(shard, event as *const c_void, size) != 0 {
        count_kernel_drop();
    }
}

/// Go through the closed slots from `start` (see the protocol above): a
/// written slot is sent or discarded ([`release_slot`]); at a slot still
/// being written, stop (its writer goes on from there). `own`: the caller
/// is the writer of slot `start`, which the release already reached. Past
/// the last slot, free the value.
#[inline(always)]
fn release_from(
    sk: *mut c_void,
    st: *mut SockState,
    p: *mut Pending,
    cookie: u64,
    start: u64,
    own: bool,
) {
    let n = unsafe { read_volatile(&raw const (*p).count) };
    let (ok, tgid) = release_gate(st, cookie);
    let shard = shard_for(cookie);
    for i in 0..PENDING_SLOTS {
        if i < start {
            continue;
        }
        if i >= n {
            break;
        }
        // A bound every verifier sees: LLVM starts the loop at `start`, and
        // the index derived from it is otherwise unbounded below.
        let idx = unsafe { read_volatile(&i) } & (PENDING_SLOTS - 1);
        let slot = unsafe { &raw mut (*p).slots[idx as usize] };
        if !(own && i == start) {
            let was = unsafe { fetch_add_u64(&raw mut (*slot).state, SLOT_REACHED) };
            if was & SLOT_WRITTEN == 0 {
                return; // its writer goes on
            }
        }
        release_slot(slot, st, ok, tgid, shard);
    }
    pending_free(sk, st);
}

/// Close the socket's hold `p` and release it ([`release_from`]), unless
/// another closer has it.
#[inline(always)]
fn close_and_release(sk: *mut c_void, st: *mut SockState, p: *mut Pending, cookie: u64) {
    if unsafe { fetch_add_u64(&raw mut (*p).closed, 1) } != 0 {
        return;
    }
    let t = unsafe { fetch_add_u64(&raw mut (*p).tickets, PENDING_CLOSED) };
    let n = if t < PENDING_SLOTS { t } else { PENDING_SLOTS };
    unsafe { write_volatile(&raw mut (*p).count, n) };
    release_from(sk, st, p, cookie, 0, false);
}

/// The end of a socket's pre-accept life (its accept, or TCP_CLOSE), after
/// the store that ends it and a fence: release its hold if it has one.
/// `held` 0: nothing was held, and nothing will be (2). 1 and no value:
/// every hold failed (the budget, the share or option memory), or a holder
/// is creating one now; done (2) all the same, so later packets skip the
/// lookup for the hold. A holder creating one then finds this socket
/// accepted or closed and releases it itself (`hold_packet`, after its
/// write). A later packet of the connection that races that holder on
/// another CPU can leave first (as it could before: its lookup could come
/// before the holder's create); both records carry their stream offsets,
/// and user space's reorder window puts them back in order
/// (`reorder.rs`, `tcp_reorder_held`).
#[inline(always)]
fn pending_end(sk: *mut c_void, st: *mut SockState, cookie: u64) {
    match rd!(st, held) {
        0 => wr!(st, held, HELD_DONE),
        HELD_MAYBE => {
            let p = pending_of(sk, false);
            if p.is_null() {
                wr!(st, held, HELD_DONE);
            } else {
                close_and_release(sk, st, p, cookie);
            }
        }
        _ => {}
    }
}

/// `SockState::held` values.
const HELD_MAYBE: u8 = 1;
const HELD_DONE: u8 = 2;

// ── Config ─────────────────────────────────────────────────────────────────

#[inline(always)]
fn cfg(index: u32) -> u64 {
    match CONFIG.get_ptr(index) {
        Some(p) => unsafe { read_volatile(p) },
        None => 0,
    }
}

/// CONFIG_SCOPE_GEN, freshly loaded each call (the g1/g2 protocol, §3).
#[inline(always)]
pub(crate) fn scope_gen() -> u32 {
    cfg(CONFIG_SCOPE_GEN) as u32
}

#[inline(always)]
pub(crate) fn scope_mode() -> u64 {
    cfg(CONFIG_SCOPE_MODE)
}

/// Startup is complete (CONFIG_SCOPE_ARMED). Until then the writers below
/// create and publish nothing: a socket created or established during
/// startup is treated exactly like one that predates the agent. That closes
/// every window in which a dependency of initialised state was not yet in
/// place: the capture hooks and UDP budgets (a UDP socket could otherwise
/// move bytes before accounting starts), the kTLS key-install marker (a
/// socket could install kTLS keys unmarked), and the exit cleanup and PID_FILTER (pid
/// bits computed from an incomplete list).
#[inline(always)]
pub(crate) fn armed() -> bool {
    cfg(CONFIG_SCOPE_ARMED) != 0
}

/// Whether the TLS probes may collect anything (DESIGN §3.5, §7): checked
/// first by every TLS entry, return, address-recording and emission path.
///
/// * `CONFIG_CAPTURE_ENABLED`, in every mode: the user's
///   `capture_enabled = false`, and the fatal stop (`scope_select.rs`
///   `AyaAllow::disarm`). The loader writes it from `capture_enabled`
///   (default true) before any program is attached, as the
///   packet path already honours it.
/// * `CONFIG_SCOPE_ARMED`, in restricted modes only: until arming, the TLS
///   scope inputs (`PID_FILTER`) and the socket state the address check
///   reads are incomplete, and the fatal stop clears it. Unscoped full
///   mode is never armed, so it does not apply
///   there. The fatal stop also leaves the mode restricted, so a stopped
///   agent fails both conditions.
#[inline(always)]
pub(crate) fn tls_capture_on() -> bool {
    cfg(CONFIG_CAPTURE_ENABLED) != 0 && (is_unscoped_full(scope_mode()) || armed())
}

/// `capture_loopback` (`CONFIG_CAPTURE_LOOPBACK`, DESIGN §3.7): packets
/// and close records only. A reader whose result is stamped into an event
/// reads the generation first.
#[inline(always)]
pub(crate) fn capture_loopback() -> bool {
    cfg(CONFIG_CAPTURE_LOOPBACK) != 0
}

#[inline(always)]
fn current_tgid() -> u32 {
    (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32
}

#[inline(always)]
fn pid_listed(tgid: u32) -> bool {
    unsafe { PID_FILTER.get(&tgid) }.is_some()
}

/// Ancestor levels checked against CGROUP_ALLOW (§3.2).
const CGROUP_LEVELS: i32 = 16;

/// Whether an ancestor (levels 1..16) of the socket's cgroup is selected.
#[inline(always)]
fn sk_cgroup_selected(sk: *mut c_void) -> bool {
    for level in 1..=CGROUP_LEVELS {
        let id = unsafe { bpf_sk_ancestor_cgroup_id(sk, level) };
        if id == 0 {
            return false;
        }
        if unsafe { CGROUP_ALLOW.get(&id) }.is_some() {
            return true;
        }
    }
    false
}

/// Whether an ancestor (levels 1..16) of the current task's cgroup is
/// selected (TLS uprobes, §3.5).
#[inline(always)]
pub(crate) fn current_cgroup_selected() -> bool {
    for level in 1..=CGROUP_LEVELS {
        let id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if id == 0 {
            return false;
        }
        if unsafe { CGROUP_ALLOW.get(&id) }.is_some() {
            return true;
        }
    }
    false
}

/// TLS plaintext scope at the library call (§3.5): the generation the call
/// is in scope under, or the `SCOPE_DROPS` reason to drop it with. Stateless:
/// nothing is carried between calls. Only meaningful in a restricted mode.
#[inline(always)]
pub(crate) fn tls_call_scope(mode: u64, tgid: u32) -> Result<u32, u32> {
    use panopticon_common::scope::{DROP_TLS_MODE, DROP_TLS_OUT_OF_SCOPE, SCOPE_SEL_PID};
    if !panopticon_common::scope::tls_mode_allowed(mode) {
        return Err(DROP_TLS_MODE);
    }
    let g1 = scope_gen();
    let selected = (mode & SCOPE_SEL_PID != 0 && pid_listed(tgid))
        || (mode & SCOPE_SEL_CGROUP != 0 && current_cgroup_selected());
    let g2 = scope_gen();
    if g1 != g2 || !selected {
        return Err(DROP_TLS_OUT_OF_SCOPE);
    }
    Ok(g1)
}

/// TLS address learning in a restricted mode (§3.5, §2.1): `sk`'s cookie,
/// the generation it was checked under, and its tuple, only if `sk` itself is in scope under the current generation
/// for the whole time its tuple is read. Uses the capture path's own state:
/// the socket's `SOCK_STATE` entry, initialised with its own cookie, not
/// REUSED, and an IN verdict cached for `CONFIG_SCOPE_GEN`, checked before
/// the tuple read and again after it (`tls_addr_in_scope`). fentry runs
/// before the socket lock, so another thread may disconnect and reconnect
/// the socket meanwhile; that sets REUSED for good and fails the second
/// check. The verdict is not computed here (the socket cgroup helper is
/// not available to tracing programs): a stale or missing cache gives no
/// address. `sk` must be a BTF `struct sock *` (fentry arg).
#[inline(always)]
pub(crate) fn sock_addr_checked(sk: *mut c_void) -> Option<(u64, u32, (u32, u32, u16, u16))> {
    let st = state_of(sk, false);
    if st.is_null() {
        return None;
    }
    let cookie = unsafe { bpf_get_socket_cookie(sk) };
    let g1 = scope_gen();
    let before = tls_addr_in_scope(
        cookie,
        g1,
        rd!(st, init_cookie),
        rd!(st, flags),
        rd!(st, verdict_word),
        g1,
    );
    if !before {
        return None;
    }
    let tuple = read_sock_tuple(sk as *const u8).ok()?;
    let after = tls_addr_in_scope(
        cookie,
        g1,
        rd!(st, init_cookie),
        rd!(st, flags),
        rd!(st, verdict_word),
        scope_gen(),
    );
    if !after {
        return None;
    }
    Some((cookie, g1, tuple))
}

// ── Socket creation ────────────────────────────────────────────────────────

const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

/// `cgroup/sock_create`: record the creator, and initialise UDP sockets
/// (they have had no traffic yet, so the budget baseline is exact).
#[cgroup_sock(sock_create)]
pub fn scope_sock_create(ctx: SockContext) -> i32 {
    try_sock_create(&ctx);
    1
}

#[inline(always)]
fn try_sock_create(ctx: &SockContext) {
    let sk = ctx.sock;
    let (ty, proto) = unsafe { ((*sk).type_, (*sk).protocol) };
    let udp = ty == SOCK_DGRAM && proto == IPPROTO_UDP;
    if !(udp || ty == SOCK_STREAM && proto == IPPROTO_TCP) || !armed() {
        return;
    }
    let st = state_of(sk as *mut c_void, true);
    if st.is_null() {
        return;
    }
    let tgid = current_tgid();
    wr!(st, owner_tgid, tgid);
    wr!(st, pid_epoch, cfg(CONFIG_PID_EPOCH) as u32);
    wr!(
        st,
        pid_bits,
        if pid_listed(tgid) { OWNER_LISTED } else { 0 }
    );
    if udp {
        wr!(st, sample, unsafe { bpf_get_prandom_u32() });
        wr!(st, udp_sent, 0);
        wr!(st, udp_rcvd, 0);
        wr!(st, verdict_word, 0);
        wr!(st, flags, FLAG_BASELINE);
        let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
        wr!(st, init_cookie, cookie); // published last
    }
}

// ── sockops: TCP initialisation and revocation ─────────────────────────────

const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_STATE_CB: u32 = 10;
const BPF_SOCK_OPS_STATE_CB_FLAG: u32 = 1 << 2;
const TCP_CLOSE: u32 = 7;

#[sock_ops]
pub fn scope_sockops(ctx: SockOpsContext) -> u32 {
    match ctx.op() {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => on_established(&ctx, true),
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => on_established(&ctx, false),
        BPF_SOCK_OPS_STATE_CB if ctx.arg(1) == TCP_CLOSE => on_tcp_close(&ctx),
        _ => {}
    }
    1
}

/// ESTABLISHED (§2.1, §3.3): reset every per-connection field, derive the
/// stream origins under the socket lock, and publish `init_cookie` last.
/// A socket that was ever closed (REUSED) is never initialised again.
#[inline(always)]
fn on_established(ctx: &SockOpsContext, active: bool) {
    let ops = ctx.ops;
    let sk = unsafe { (*ops).__bindgen_anon_2.sk };
    if sk.is_null() || !armed() {
        return;
    }
    // Why this is safe after arming, whenever the socket was created: a TCP
    // socket created during startup has no state (sock_create was
    // disarmed), so as an active socket it stays uninitialised; a child is
    // a new socket and reaches here only after arming, when the capture
    // hooks and the kTLS key-install marker are live. The origins are
    // derived here from the kernel counters, not from anything seen
    // earlier, and kTLS keys can only be installed on an established socket
    // (they need the tls ULP, which needs ESTABLISHED), i.e. after this
    // point, when the marker is already live.
    //
    // A child of a listener without state (one that predates the agent)
    // has nothing to clone: it is a new socket, so it gets fresh
    // state here or in its accept, whichever runs first. Its owner is
    // unknown (epoch 0 never matches), so pid_filter selects it by its
    // acceptor only: under the acceptor rule its bytes before accept() are
    // held (`hold_packet`), under the creator rule dropped (no_owner,
    // §3.1). An active socket without state predates the agent and stays
    // uninitialised.
    let st = if active {
        state_of(sk as *mut c_void, false)
    } else {
        state_or_create(sk as *mut c_void)
    };
    if st.is_null() {
        return;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ops as *mut c_void) };
    // The accept hook can run before this callback: the child is queued for
    // accept() before tcp_child_process runs it, and accept does not take
    // the child's lock. So a passive callback never clears the acceptor; it
    // writes no field the accept hook writes. Acceptor fields are this
    // socket's only if `accept_cookie` is its cookie (written before
    // `acceptor_tgid`, so read after it); otherwise they were cloned from a
    // listener that was itself once accepted, and the child is never
    // initialised. An active socket is never returned by accept, so its
    // acceptor fields (from an earlier accepted life) are cleared.
    if !active && rd!(st, acceptor_tgid) != 0 && rd!(st, accept_cookie) != cookie {
        return;
    }
    let old_flags = rd!(st, flags);
    if old_flags & FLAG_REUSED != 0 {
        return;
    }
    // Revocation at TCP_CLOSE needs STATE_CB; without it, no publication.
    let cb = unsafe { (*ops).bpf_sock_ops_cb_flags };
    if unsafe { bpf_sock_ops_cb_flags_set(ops, (cb | BPF_SOCK_OPS_STATE_CB_FLAG) as i32) } != 0 {
        return;
    }
    let (rcv_nxt, bytes_received, snd_una, bytes_acked) = unsafe {
        (
            (*ops).rcv_nxt,
            (*ops).bytes_received,
            (*ops).snd_una,
            (*ops).bytes_acked,
        )
    };
    let syn_adj: u8 = if active { 1 } else { 0 };
    // A repair-mode connect runs ACTIVE_ESTABLISHED with no SYN-ACK; its
    // stream history is unknown, so it never gets a baseline (§3.3).
    let repaired = active && unsafe { (*ops).skb_len == 0 && (*ops).skb_tcp_flags == 0 };
    let mut flags = old_flags & FLAGS_STICKY;
    if repaired {
        flags |= FLAG_REPAIRED;
    }
    flags |= if active {
        FLAG_ROLE_CLIENT
    } else {
        FLAG_ROLE_SERVER
    };
    if flags & FLAG_REPAIRED == 0 && bytes_acked >= syn_adj as u64 {
        flags |= FLAG_BASELINE;
    }
    let rcv_base = rcv_nxt.wrapping_sub(bytes_received as u32);
    let snd_base = snd_una.wrapping_sub(bytes_acked.wrapping_sub(syn_adj as u64) as u32);

    if active {
        wr!(st, acceptor_tgid, 0);
        wr!(st, pid_bits, rd!(st, pid_bits) & OWNER_LISTED);
    }
    wr!(st, sample, unsafe { bpf_get_prandom_u32() });
    wr!(st, rcv_base, rcv_base);
    wr!(st, snd_base, snd_base);
    wr!(st, syn_adj, syn_adj);
    wr!(st, udp_sent, 0);
    wr!(st, udp_rcvd, 0);
    wr!(st, verdict_word, 0);
    wr!(st, flags, flags);
    wr!(st, init_cookie, cookie); // published last
}

/// Any transition to TCP_CLOSE (close, `connect(AF_UNSPEC)`): revoke
/// initialisation for good, then tell user space the socket ended, if it
/// may hold state for it and the socket is authorised now. Only packet
/// records create per-socket state in user space on this backend, so a
/// socket none was emitted for (`SockState::emitted`) gets no close record.
/// Authorised: unscoped `full`, or initialised with an IN verdict cached for
/// the current generation (`tls_addr_in_scope`, the test the TLS address
/// path uses), read before the revocation. The record carries that
/// generation, so user space applies its admission floor to it as to any
/// record; a socket narrowed out never sends one (narrowing replaces the
/// pipeline, which drops its state). The record is the header only
/// (96 bytes, `SizedEvent<0>`).
#[inline(always)]
fn on_tcp_close(ctx: &SockOpsContext) {
    let ops = ctx.ops;
    let sk = unsafe { (*ops).__bindgen_anon_2.sk };
    if sk.is_null() {
        return;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ops as *mut c_void) };
    // A raised packet cap ends with its socket (cookies are never reused),
    // whether or not the socket has state: user space raises a connection
    // it sees in unscoped full mode, a socket that predates the agent
    // included, and another program may have asked for this callback.
    let _ = CONN_CAP.remove(&cookie);
    let st = state_of(sk as *mut c_void, false);
    if st.is_null() {
        return;
    }
    let g1 = scope_gen();
    // Capture on (and armed outside unscoped full): a completed disarm or
    // `capture_enabled = false` leaves generation and verdicts as they were,
    // so the scope check alone would still authorise a close.
    // Loopback off (§3.7): a socket that ever had a local packet sends no
    // close (it carries the tuple), by its sticky flag, never its addresses.
    let authorised = rd!(st, emitted) != 0
        && tls_capture_on()
        && (capture_loopback() || rd!(st, local) == 0)
        && (is_unscoped_full(scope_mode())
            || tls_addr_in_scope(
                cookie,
                g1,
                rd!(st, init_cookie),
                rd!(st, flags),
                rd!(st, verdict_word),
                g1,
            ));
    wr!(st, init_cookie, 0);
    wr!(st, flags, rd!(st, flags) | FLAG_REUSED);
    // A socket closed (an RST, or its listener closed) before accept():
    // what it held never leaves the kernel. The fence orders the REUSED
    // store before the lookup; a holder creating its value meanwhile
    // checks REUSED after its own (`hold_packet`), so one of the two sees
    // the other.
    pending_fence();
    pending_end(sk as *mut c_void, st, cookie);
    if !authorised {
        return;
    }

    let shard = shard_for(cookie);
    let Some(mut entry) = shard_reserve_as::<SizedEvent<0>>(shard) else {
        count_kernel_drop();
        return;
    };
    // Header fields only: they all lie in the reserved record.
    let event = entry.as_mut_ptr() as *mut DataEvent;
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).socket_cookie = cookie;
        (*event).event_type = EventType::SockClose;
        (*event).direction = Direction::Egress;
        (*event).pid = 0;
        (*event).tgid = 0;
        (*event).src_addr = u32::from_be((*ops).local_ip4);
        (*event).dst_addr = u32::from_be((*ops).remote_ip4);
        (*event).src_port = (*ops).local_port as u16;
        (*event).dst_port = u32::from_be((*ops).remote_port) as u16;
        (*event).ip_proto = IPPROTO_TCP as u8;
        (*event).tls_library = TlsLibrary::None;
        (*event).payload_len = 0;
        (*event).orig_len = 0;
        (*event).tcp_flags = 0;
        (*event).tcp_seq = 0;
        (*event).tcp_ack = 0;
        crate::maps::clear_scope_fields(event);
        (*event).scope_gen = g1;
        (*event).owner_tgid = rd!(st, owner_tgid);
        (*event).acceptor_tgid = rd!(st, acceptor_tgid);
        (*event).role = role_of(rd!(st, flags));
    }
    // A selector changed, or capture stopped, while the record was built:
    // send nothing.
    if scope_gen() != g1 || !tls_capture_on() {
        entry.discard(0);
        return;
    }
    entry.submit(shard_submit_flags_for::<SizedEvent<0>>(shard));
}

// ── VRF masters (§3.7) ─────────────────────────────────────────────────────

/// Whether the packet's device is a VRF master (`IFF_L3MDEV_MASTER` in its
/// `priv_flags`), read from the `sk_buff` itself: the hook's context is the
/// kernel's `struct sk_buff`, and `skb->dev` is the output device on egress
/// and the VRF master on VRF ingress. No inventory, so nothing to keep in
/// sync with device creation or deletion. Unwritten offsets (mask 0), a
/// failed read or no device count as a master (fails closed: dropped while
/// loopback is off).
///
/// Branch-free on purpose: both reads always run and every failure is folded
/// in arithmetically, so the verifier sees one path. Early returns here
/// multiplied the states of `try_skb` past the 1M-instruction limit on 5.15
/// and 4.18.
#[inline(always)]
fn on_vrf_master(skb: *const u8) -> bool {
    let off = |i| NETDEV_OFFS.get(i).copied().unwrap_or(0);
    let (dev_off, byte_off, mask) = (
        off(NETDEV_SKB_DEV),
        off(NETDEV_L3M_BYTE),
        off(NETDEV_L3M_MASK),
    );
    let mut dev: u64 = 0;
    let mut b: u8 = 0;
    // A failed read zeroes its destination and returns a negative errno.
    let r1 = unsafe {
        bpf_probe_read_kernel_raw(
            &mut dev as *mut u64 as *mut c_void,
            8,
            skb.wrapping_add(dev_off as usize) as *const c_void,
        )
    };
    let r2 = unsafe {
        bpf_probe_read_kernel_raw(
            &mut b as *mut u8 as *mut c_void,
            1,
            (dev as usize).wrapping_add(byte_off as usize) as *const c_void,
        )
    };
    let failed = ((r1 | r2) as u64) >> 63;
    let null = !(dev | dev.wrapping_neg()) >> 63;
    let unwritten = u64::from(mask.wrapping_sub(1) >> 31); // mask 0 (masks are 1..=128)
    let hit = u64::from(((u32::from(b) & mask) + 255) >> 8);
    (failed | null | unwritten | hit) != 0
}

// ── accept: the acceptor, on the child only ────────────────────────────────

/// `inet_csk_accept(sk, flags, err, kern)` before 6.10 (and RHEL 8): the
/// returned child is the fifth context slot. Exactly one of the two
/// variants loads on a kernel; the loader picks it.
#[fexit(function = "inet_csk_accept")]
pub fn scope_accept4(ctx: FExitContext) -> i32 {
    on_accept(ctx.arg(4));
    0
}

/// `inet_csk_accept(sk, struct proto_accept_arg *arg)` from 6.10 (and RHEL 9).
#[fexit(function = "inet_csk_accept")]
pub fn scope_accept2(ctx: FExitContext) -> i32 {
    on_accept(ctx.arg(2));
    0
}

/// Record the acceptor on the returned child. The listener is never
/// written (no backfill, §3.1). The child may not be established yet (it is
/// queued for accept() before its PASSIVE_ESTABLISHED callback runs), and a
/// child of a listener without state may have no state yet: it is created
/// here then. A child that already carries another socket's acceptor (a
/// clone of a listener that was itself once accepted) is left untouched:
/// rewriting its `accept_cookie` first would let a concurrent passive
/// ESTABLISHED adopt the cloned acceptor bits and a reader cache IN from
/// them before the new bits land. Untouched, it is never initialised (the
/// passive ESTABLISHED refuses it too). Write order otherwise:
/// `accept_cookie` (claims the fields for this socket), the bits,
/// `acceptor_tgid` (readers that see it see the bits), then clear the
/// verdict so the next packet recomputes it. Then the bytes held before
/// accept() are released or discarded (`pending_end`). Not before
/// arming, when PID_FILTER may be incomplete.
#[inline(always)]
fn on_accept(child: *mut c_void) {
    if child.is_null() || !armed() {
        return;
    }
    let st = state_or_create(child);
    if st.is_null() {
        return;
    }
    let cookie = unsafe { bpf_get_socket_cookie(child) };
    if rd!(st, acceptor_tgid) != 0 && rd!(st, accept_cookie) != cookie {
        // Never initialised, so it never held; discarded all the same
        // (the gate fails: not initialised).
        pending_end(child, st, cookie);
        return;
    }
    let tgid = current_tgid();
    let epoch = cfg(CONFIG_PID_EPOCH) as u32;
    // Bits from another epoch mean nothing; never let this write revive
    // them. Only the owner bit is kept: an acceptor bit not written for
    // this socket is a clone's.
    let mut bits = if rd!(st, pid_epoch) == epoch {
        rd!(st, pid_bits) & OWNER_LISTED
    } else {
        0
    };
    if pid_listed(tgid) {
        bits |= ACCEPTOR_LISTED;
    }
    wr!(st, accept_cookie, cookie);
    wr!(st, pid_bits, bits);
    wr!(st, pid_epoch, epoch);
    wr!(st, acceptor_tgid, tgid);
    wr!(st, verdict_word, 0);
    // The pre-accept hold. The fence orders the acceptor store before the
    // lookup (see `pending_fence`); `held` is read after it.
    pending_fence();
    pending_end(child, st, cookie);
}

// ── destroy: the hold's backstop ───────────────────────────────────────────

/// fentry `tcp_v4_destroy_sock`, every TCP socket's `sk_prot->destroy`
/// (IPv6 sockets call it too): the backstop of the pre-accept hold. A hold
/// ends at accept() or at TCP_CLOSE (`on_tcp_close`, a STATE_CB callback
/// `on_established` asked for). Another sockops program can rewrite the
/// socket's callback flags without STATE_CB, and a socket closed before
/// accept() then ends with its hold still charged to the budget, for the
/// agent's life. Here a hold still waiting (`held` 1) is ended as TCP_CLOSE
/// would end it: the socket is revoked (REUSED), so the release discards
/// every slot, and the bytes go back to the budget. Any `held` but 2 goes
/// through it, 0 included: a first holder may be on its way (past its
/// verdict, `held` not yet 1), and after the REUSED store and the fence
/// it either finds REUSED after its write and releases its own value, or
/// its value is there for `pending_end` to find (the order of
/// `on_tcp_close`). Optional (the loader attaches it with the hold where
/// it loads); a socket whose hold already ended (`held` 2) costs one
/// storage lookup.
#[fentry(function = "tcp_v4_destroy_sock")]
pub fn scope_tcp_destroy(ctx: FEntryContext) -> i32 {
    on_destroy(ctx.arg(0));
    0
}

#[inline(always)]
fn on_destroy(sk: *mut c_void) {
    if sk.is_null() {
        return;
    }
    let st = state_of(sk, false);
    if st.is_null() || rd!(st, held) == HELD_DONE {
        return;
    }
    wr!(st, init_cookie, 0);
    wr!(st, flags, rd!(st, flags) | FLAG_REUSED);
    pending_fence();
    let cookie = unsafe { bpf_get_socket_cookie(sk) };
    pending_end(sk, st, cookie);
}

// ── kTLS key install: sticky KTLS ──────────────────────────────────────────

const SOL_TLS: i32 = 282;

/// Every `SOL_TLS` setsockopt on a TCP socket, and so every kTLS key install
/// (`TLS_TX`, `TLS_RX`), reaches the socket's `sk_prot->setsockopt` through
/// `sock_common_setsockopt`, and before 5.9 for 32-bit callers through
/// `compat_sock_common_setsockopt`: the native and compat syscalls, io_uring
/// and the TLS handshake agent alike (§3.5). Marked on entry, before any key
/// exists, whatever the option and the result. A ULP attached without keys
/// (OpenSSL 3.0 does that on every socket) leaves the payload as the
/// application wrote it, so it is not marked (except `scope_set_ulp`).
///
/// `sk` is read from the `struct socket *` argument at a fixed offset, one
/// variant per layout: 24 since 5.3, 32 before (RHEL 8). The verifier types
/// the load from BTF, so a variant whose offset is not `sk` passes
/// `bpf_sk_storage_get` a non-socket and does not load; the loader takes
/// the variant that does.
#[inline(always)]
fn mark_sol_tls(ctx: &FEntryContext, sk_off: usize) {
    let level: i32 = ctx.arg(1);
    if level != SOL_TLS {
        return;
    }
    let sock: *const u8 = ctx.arg(0);
    let sk = unsafe { *(sock.add(sk_off) as *const *mut c_void) };
    mark_ktls(sk);
}

#[inline(always)]
fn mark_ktls(sk: *mut c_void) {
    if sk.is_null() {
        return;
    }
    let st = state_of(sk, false);
    if !st.is_null() {
        wr!(st, flags, rd!(st, flags) | FLAG_KTLS);
    }
}

#[fentry(function = "sock_common_setsockopt")]
pub fn scope_sol_tls(ctx: FEntryContext) -> i32 {
    mark_sol_tls(&ctx, 24);
    0
}

#[fentry(function = "sock_common_setsockopt")]
pub fn scope_sol_tls_wq(ctx: FEntryContext) -> i32 {
    mark_sol_tls(&ctx, 32);
    0
}

#[fentry(function = "compat_sock_common_setsockopt")]
pub fn scope_sol_tls_compat(ctx: FEntryContext) -> i32 {
    mark_sol_tls(&ctx, 24);
    0
}

#[fentry(function = "compat_sock_common_setsockopt")]
pub fn scope_sol_tls_compat_wq(ctx: FEntryContext) -> i32 {
    mark_sol_tls(&ctx, 32);
    0
}

/// Where `sock_common_setsockopt` cannot be traced (5.9 to 6.0: it takes
/// `sockptr_t` by value, which trampolines support from 6.1), the same mark
/// from the two places `__sys_setsockopt` passes before it calls
/// `sock->ops->setsockopt`, the only caller of a TCP socket's
/// `sock_common_setsockopt` on those kernels apart from SMC (see
/// `scope_set_ulp`): the LSM hook, for every caller (native and compat),
/// and the return of the cgroup setsockopt filter, which may rewrite the
/// level after the LSM hook (it runs only when a cgroup setsockopt program
/// is attached, never for compat callers, before `ops->setsockopt`).
#[fentry(function = "security_socket_setsockopt")]
pub fn scope_sol_tls_lsm(ctx: FEntryContext) -> i32 {
    mark_sol_tls(&ctx, 24);
    0
}

/// `__cgroup_bpf_run_filter_setsockopt(sk, int *level, ...)`: the level the
/// kernel goes on with. The `int *` is read from the argument array with a
/// probe read (5.15's verifier loads only struct pointers from it).
/// Unreadable counts as `SOL_TLS`.
#[fexit(function = "__cgroup_bpf_run_filter_setsockopt")]
pub fn scope_sol_tls_cgroup(ctx: FExitContext) -> i32 {
    let args = ctx.as_ptr() as *const *const i32;
    let level = unsafe { bpf_probe_read_kernel(args.add(1)) }
        .and_then(|p| unsafe { bpf_probe_read_kernel(p) })
        .unwrap_or(SOL_TLS);
    if level == SOL_TLS {
        mark_ktls(ctx.arg(0));
    }
    0
}

/// SMC calls its TCP socket's `ops->setsockopt` directly, past the LSM hook,
/// and before 5.14 passes `TCP_ULP` through to it. So where the LSM hook
/// marks (5.9 to 6.0) on a kernel older than 5.14, a ULP attach marks too,
/// on entry, whatever the ULP and the result (the rule before key-install
/// marking). Every way of attaching a ULP reaches `tcp_set_ulp`.
#[fentry(function = "tcp_set_ulp")]
pub fn scope_set_ulp(ctx: FEntryContext) -> i32 {
    mark_ktls(ctx.arg(0));
    0
}

// ── Packet capture ─────────────────────────────────────────────────────────

#[cgroup_skb(ingress)]
pub fn scope_skb_ingress(ctx: SkBuffContext) -> i32 {
    let _ = try_skb::<false>(&ctx, Direction::Ingress);
    1
}

#[cgroup_skb(egress)]
pub fn scope_skb_egress(ctx: SkBuffContext) -> i32 {
    let _ = try_skb::<false>(&ctx, Direction::Egress);
    1
}

/// TCP states in which a socket's payload is eligible: everything except
/// SYN_SENT (2), SYN_RECV (3), CLOSE (7) and LISTEN (10).
#[inline(always)]
fn tcp_state_eligible(state: u32) -> bool {
    !matches!(state, 2 | 3 | 7 | 10)
}

/// What one packet carries, parsed from its IPv4 and L4 headers.
struct Packet {
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    payload_off: u32,
    payload_len: u32,
}

const ETH_P_IP_BE: u32 = (0x0800u16).to_be() as u32;

/// Order per packet (§3): eligibility, loopback, initialisation, (UDP head
/// reservation), verdict, kTLS, head cut, copy and emit. `HOLD`: the same
/// steps in `scope_skb_hold`, for a packet the capture hook found to be held
/// (`scope::pending_accept`), ending in the hold instead of the emit.
#[inline(always)]
fn try_skb<const HOLD: bool>(ctx: &SkBuffContext, direction: Direction) -> Result<(), ()> {
    if cfg(CONFIG_CAPTURE_ENABLED) == 0 {
        return Ok(());
    }
    let skb = ctx.skb.skb;
    // ── eligibility
    let sk = unsafe { (*skb).__bindgen_anon_2.sk };
    if sk.is_null() {
        return drop(DROP_NOT_ELIGIBLE);
    }
    let sk = unsafe { bpf_sk_fullsock(sk) };
    if sk.is_null() {
        return drop(DROP_NOT_ELIGIBLE);
    }
    let (ty, proto) = unsafe { ((*sk).type_, (*sk).protocol) };
    let udp = ty == SOCK_DGRAM && proto == IPPROTO_UDP;
    let mut tp = null_mut();
    if ty == SOCK_STREAM && proto == IPPROTO_TCP {
        tp = unsafe { bpf_tcp_sock(sk) };
        if tp.is_null() || !tcp_state_eligible(unsafe { (*sk).state }) {
            return drop(DROP_NOT_ELIGIBLE);
        }
    } else if !udp {
        return drop(DROP_NOT_ELIGIBLE);
    }
    if HOLD && udp {
        return hold_reenter(ctx); // never held: only TCP servers are
    }
    if unsafe { (*skb).protocol } != ETH_P_IP_BE {
        // IPv6 is not captured yet.
        if let Some(counter) = IPV6_DROPS.get_ptr_mut(0) {
            unsafe { *counter += 1 };
        }
        return Ok(());
    }
    let pkt = parse(ctx, udp)?;
    if pkt.payload_len == 0 {
        return Ok(()); // no data; the socket's end comes from STATE_CB
    }
    // ── loopback (§3.7): a data packet on a node-local path (`lo` in any
    // namespace: 127/8, the host's or the pod's own address; a VRF master,
    // local delivery included; a socket already marked; IPv6, ::1
    // included, is not captured, above). The socket is marked whatever the setting, so
    // turning capture off later drops it whole and suppresses its close.
    // The generation is read before the setting and the socket's mark, and
    // every event is stamped `g0` (unscoped and restricted alike), so a
    // packet whose loopback decision predates a narrowing (the setting
    // turned off, or another packet marking the socket meanwhile) is refused
    // at the ring read.
    let sk = sk as *mut c_void;
    let st = state_of(sk, false);
    let g0 = scope_gen();
    let marked = !st.is_null() && rd!(st, local) != 0;
    let ifindex = unsafe { (*skb).ifindex };
    let vrf = on_vrf_master(skb as *const u8);
    let lo = local_packet(ifindex, vrf, marked);
    if lo && !marked && !st.is_null() {
        wr!(st, local, 1);
    }
    // The decision is valid for `g0` only: the setting and the socket's
    // `local` flag (set by a concurrent packet) can change after it, so the
    // event is stamped `g0`, below.
    if lo && !capture_loopback() {
        return drop(DROP_LOOPBACK);
    }
    let mode = scope_mode();

    // ── initialisation
    let cookie = unsafe { bpf_get_socket_cookie(skb as *mut c_void) };
    let initialised = !st.is_null() && is_initialised(rd!(st, init_cookie), cookie);
    // Both modes end in the one `emit` below: a second inlined copy of the
    // chunk loop doubled the verifier's work.
    let (hdr_st, take, stream_off, stamp) = if is_unscoped_full(mode) {
        if HOLD {
            return hold_reenter(ctx); // the mode changed since
        }
        let mut off = STREAM_OFF_UNKNOWN;
        if initialised && !udp && rd!(st, flags) & FLAG_BASELINE != 0 {
            if let Some(o) = tcp_offset(tp, st, direction, pkt.seq) {
                off = position(o);
            }
        }
        let hdr_st = if initialised { st } else { null_mut() };
        (hdr_st, pkt.payload_len, off, g0)
    } else if !initialised {
        return drop(DROP_UNINIT);
    } else {
        match restricted::<HOLD>(st, sk, tp, mode, direction, udp, &pkt, g0) {
            Ok(v) => v,
            Err(DROP_PENDING_ACCEPT) if !HOLD && direction == Direction::Ingress => {
                return hold_tail_call(ctx);
            }
            Err(DROP_HOLD_REENTER) if HOLD => return hold_reenter(ctx),
            Err(reason) => return drop(reason),
        }
    };
    if HOLD {
        // One record's worth is held (the rest is counted in its
        // `orig_len`, like a head cut).
        let take = take.min(MAX_PAYLOAD_SIZE as u32);
        let h = header(
            sk, hdr_st, cookie, direction, udp, &pkt, take, stream_off, stamp,
        );
        return match hold_packet(ctx, sk, st, cookie, mode, &h) {
            Some(r) => drop(r),
            // Closed before it was ever accepted: nothing to decide again
            // (the capture hook would find it pending and come back).
            None if rd!(st, acceptor_tgid) == 0 => drop(DROP_PENDING_DISCARDED),
            None => hold_reenter(ctx),
        };
    }
    mark_emitted(st);
    let mut cap = packet_cap();
    if take > cap && !udp {
        cap = raised_cap(cookie, cap, take);
    }
    let take = take.min(cap);
    let h = header(
        sk, hdr_st, cookie, direction, udp, &pkt, take, stream_off, stamp,
    );
    emit(ctx, &h)
}

/// Slot 0: `scope_skb_hold`; slot 1: `scope_skb_ingress`. Inserted by the
/// loader before the capture hooks attach. Empty, a tail call fails and the
/// packet is dropped (`pending_overflow` into the hold, `pending_race` back).
#[map]
pub static HOLD_PROG: ProgramArray = ProgramArray::with_max_entries(2, 0);

/// `scope_verdict` in the hold program: the packet is no longer to be held
/// (accepted, or closed, since the capture hook's verdict).
const DROP_HOLD_REENTER: u32 = u32::MAX - 1;

/// Hand a packet the hold program will not hold back to the capture hook
/// (`HOLD_PROG` slot 1), which decides it again: the socket was accepted
/// (or closed) since the hook's verdict, so it is sent or dropped as any
/// other packet, never held again (the acceptor is written).
#[inline(always)]
fn hold_reenter(ctx: &SkBuffContext) -> Result<(), ()> {
    let _ = unsafe { HOLD_PROG.tail_call(ctx, 1) };
    drop(DROP_PENDING_RACE)
}

/// Hand a packet to be held to `scope_skb_hold`, which runs the packet's
/// steps again and holds it. A tail call, not inline: with the hold inlined,
/// `scope_skb_ingress` passed the verifier's 1M-instruction limit on 4.18.
/// Nothing is passed: the hold program decides from the socket's state
/// again, and holds only if that decision is still "held".
#[inline(always)]
fn hold_tail_call(ctx: &SkBuffContext) -> Result<(), ()> {
    let _ = unsafe { HOLD_PROG.tail_call(ctx, 0) };
    drop(DROP_PENDING_OVERFLOW)
}

/// The hold of one ingress packet, tail-called by `scope_skb_ingress`
/// (`hold_tail_call`), never attached: a cgroup_skb ingress program, so
/// the kernel accepts it in `HOLD_PROG`.
#[cgroup_skb(ingress)]
pub fn scope_skb_hold(ctx: SkBuffContext) -> i32 {
    let _ = try_skb::<true>(&ctx, Direction::Ingress);
    1
}

/// Hold a pre-accept packet ([`pending_accept`]) in the socket's `PENDING`
/// value until accept() decides it (`pending_end`): its record, built
/// exactly as `emit` would send it (`acceptor_tgid` 0, stamped with the
/// generation of its verdict), in a slot of its own. Not sent, and nothing
/// of it leaves the kernel unless the release finds the acceptor listed.
/// None: not held, the socket was accepted or closed meanwhile (hand the
/// packet back, `hold_reenter`); Some(reason): dropped; Some(u32::MAX):
/// held (a counter index that does not exist).
#[inline(always)]
fn hold_packet(
    ctx: &SkBuffContext,
    sk: *mut c_void,
    st: *mut SockState,
    cookie: u64,
    mode: u64,
    h: &Hdr,
) -> Option<u32> {
    match rd!(st, held) {
        HELD_DONE => return None,
        0 => wr!(st, held, HELD_MAYBE), // before the value exists
        _ => {}
    }
    // The listener: this server socket's local address and port (an
    // ingress packet's destination). Written before the budget is charged,
    // the same value by every holder of the socket.
    let bucket = pending_listener_bucket(
        cfg_pending(CONFIG_PENDING_SEED) as u32,
        h.dst_addr,
        h.dst_port,
    );
    wr!(st, hold_bucket, bucket as u16);
    let p = pending_get_or_create(sk, bucket);
    if p.is_null() {
        return Some(DROP_PENDING_OVERFLOW);
    }
    let t = unsafe { fetch_add_u64(&raw mut (*p).tickets, 1) };
    if t >= PENDING_CLOSED {
        return None;
    }
    if t >= PENDING_SLOTS {
        return Some(DROP_PENDING_OVERFLOW);
    }
    // Bounded where it is used (see `release_from`): LLVM drops a mask it
    // has proven, and a fetch-and-add result spilled to the stack is
    // unbounded to older verifiers.
    let t = unsafe { read_volatile(&t) } & (PENDING_SLOTS - 1);
    let slot = unsafe { &raw mut (*p).slots[t as usize] };
    let rec = unsafe { &raw mut (*slot).rec };
    let event = rec as *mut DataEvent;
    unsafe {
        write_header(event, h, 0, h.payload_len, true);
        write_volatile(&raw mut (*slot).mode, mode);
        // [1, MAX_PAYLOAD_SIZE], as in `emit_sized`. The value was zeroed
        // when created and each slot is written once, so the slack is zero.
        let want = read_volatile(&h.take);
        let len = (want.wrapping_sub(1) & (MAX_PAYLOAD_SIZE as u32 - 1)) + 1;
        let ret = bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            h.payload_off,
            (&raw mut (*rec).payload) as *mut c_void,
            len,
        );
        (*event).payload_len = if ret == 0 { len } else { 0 };
    }
    // Written. A release that already reached this slot stopped here: go
    // on with it from this slot.
    if unsafe { fetch_add_u64(&raw mut (*slot).state, SLOT_WRITTEN) } & SLOT_REACHED != 0 {
        release_from(sk, st, p, cookie, t, true);
        return Some(u32::MAX);
    }
    // The accept (or a close) may have run since this packet's verdict and
    // missed the value: the fetch-and-adds above are full barriers, so
    // either the closer's lookup sees the value or this sees its store.
    // Then this holder closes and releases it.
    if rd!(st, acceptor_tgid) != 0 || rd!(st, flags) & FLAG_REUSED != 0 {
        close_and_release(sk, st, p, cookie);
    }
    Some(u32::MAX)
}

/// `max_packet_bytes` (`CONFIG_MAX_PAYLOAD`): payload bytes captured of
/// one packet, at most MAX_SKB_CHUNKS records. Unwritten (0) reads as one
/// record, MAX_PAYLOAD_SIZE. What is cut is counted in the last record's
/// `orig_len`, like a head-only cut.
#[inline(always)]
fn packet_cap() -> u32 {
    match cfg(CONFIG_MAX_PAYLOAD) {
        0 => MAX_PAYLOAD_SIZE as u32,
        n => n.min((MAX_SKB_CHUNKS * MAX_PAYLOAD_SIZE) as u64) as u32,
    }
}

/// The cap of a TCP packet of `take` bytes over `max_packet_bytes` (`cap`):
/// the connection's own cap in `CONN_CAP` if user space raised it (a
/// protocol whose parser loses frame sync on a cut packet), clamped as
/// [`packet_cap`] clamps, and never below `cap`. Read only after the scope
/// verdict, so it raises capture of an in-scope socket and nothing else.
/// Counted: packets captured past `cap` (`CONN_CAP_USED`), and those still
/// cut at the raised cap (`CONN_CAP_CUT`).
#[inline(always)]
fn raised_cap(cookie: u64, cap: u32, take: u32) -> u32 {
    let Some(v) = (unsafe { CONN_CAP.get(&cookie) }) else {
        return cap;
    };
    let raised = (*v).min((MAX_SKB_CHUNKS * MAX_PAYLOAD_SIZE) as u32);
    if raised <= cap {
        return cap;
    }
    conn_cap_count(CONN_CAP_USED);
    if take > raised {
        conn_cap_count(CONN_CAP_CUT);
    }
    raised
}

#[inline(always)]
fn conn_cap_count(index: u32) {
    if let Some(n) = CONN_CAP_STATS.get_ptr_mut(index) {
        unsafe { *n += 1 };
    }
}

/// The restricted-mode steps of [`try_skb`] for an initialised socket:
/// (UDP head reservation), verdict, kTLS, head cut. The socket state for
/// the header, the bytes to capture, the stream offset and the generation
/// stamp, or the `SCOPE_DROPS` reason to drop the packet with.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn restricted<const HOLD: bool>(
    st: *mut SockState,
    sk: *mut c_void,
    tp: *mut aya_ebpf::bindings::bpf_tcp_sock,
    mode: u64,
    direction: Direction,
    udp: bool,
    pkt: &Packet,
    g0: u32,
) -> Result<(*mut SockState, u32, u64, u32), u32> {
    let flags = rd!(st, flags);
    let head = mode & SCOPE_HEAD != 0;
    let n = cfg(CONFIG_HEAD_BYTES);

    // ── UDP head budget: reserved before the verdict, whatever it is (§3.3)
    let mut take = pkt.payload_len;
    let mut off = STREAM_OFF_UNKNOWN;
    if udp && head {
        if flags & FLAG_BASELINE == 0 {
            return Err(DROP_NO_BASELINE);
        }
        let counter = match direction {
            Direction::Egress => unsafe { &raw mut (*st).udp_sent },
            Direction::Ingress => unsafe { &raw mut (*st).udp_rcvd },
        };
        take = 0;
        if udp_should_reserve(unsafe { read_volatile(counter) }, n) {
            let prev = unsafe { fetch_add_u64(counter, pkt.payload_len as u64) };
            take = reserved_take(prev, pkt.payload_len, n);
            off = prev;
        }
    }

    // ── verdict (cached per generation)
    let g = scope_verdict::<HOLD>(st, sk, mode, direction == Direction::Ingress)?;
    // In scope: a packet held before accept() is sent by the release at
    // accept(). One arriving while a hold is still waiting would go first,
    // out of order: dropped (rare: it raced the accept hook).
    if !HOLD && rd!(st, held) == HELD_MAYBE && !pending_of(sk, false).is_null() {
        return Err(DROP_PENDING_RACE);
    }
    // The verdict is of generation `g` >= `g0`, but the loopback decision
    // above is of `g0`: the event is stamped `g0` (`scope::skb_stamp`), so
    // any narrowing since `g0` refuses it at the ring read, whatever `lo` was.
    let stamp = skb_stamp(g0, g);

    // ── kTLS: the payload may be plaintext at this hook (§3.5). After the
    // verdict, so an in-scope kTLS socket has its IN verdict cached (its TLS
    // calls get their address, `sock_addr_checked`); before every emit, so
    // none of its payload leaves outside unscoped full.
    if flags & FLAG_KTLS != 0 {
        return Err(DROP_KTLS_PAYLOAD);
    }

    // ── TCP stream offset (every mode), then the head cut
    let tcp_off = if !udp && flags & FLAG_BASELINE != 0 {
        tcp_offset(tp, st, direction, pkt.seq)
    } else {
        None
    };
    if let Some(o) = tcp_off {
        off = position(o);
    }
    if head {
        if !udp {
            if flags & FLAG_BASELINE == 0 {
                return Err(DROP_NO_BASELINE);
            }
            let Some(o) = tcp_off else {
                return Err(DROP_HEAD_INCOHERENT);
            };
            take = head_take(o, pkt.payload_len, n);
        }
        if take == 0 {
            return Err(DROP_HEAD_CUT);
        }
    }
    Ok((st, take, off, stamp))
}

/// `DataEvent::stream_off` for an offset: a segment from before the origin
/// has no position.
#[inline(always)]
fn position(off: i64) -> u64 {
    if off < 0 {
        STREAM_OFF_UNKNOWN
    } else {
        off as u64
    }
}

#[inline(always)]
fn drop(reason: u32) -> Result<(), ()> {
    count_scope_drop(reason);
    Ok(())
}

/// The cached verdict, or a fresh one under the g1/g2 protocol (§3).
/// Ok(generation) if in scope, Err(drop reason) otherwise. An OUT verdict
/// that is only "not accepted yet" ([`pending_accept`], an ingress packet,
/// the hold on) is Err(DROP_PENDING_ACCEPT): the capture hook hands the
/// packet to the hold program. There (`HOLD`) that verdict, computed again,
/// is the only one that is Ok; any other, IN included (accepted since), is
/// an Err.
#[inline(always)]
fn scope_verdict<const HOLD: bool>(
    st: *mut SockState,
    sk: *mut c_void,
    mode: u64,
    ingress: bool,
) -> Result<u32, u32> {
    let g1 = scope_gen();
    let word = rd!(st, verdict_word);
    let v = match cached_verdict(word, g1) {
        Some(v) => v,
        None => {
            let epoch = cfg(CONFIG_PID_EPOCH) as u32;
            // acceptor_tgid first: the accept hook writes it after the bits.
            let acceptor_tgid = rd!(st, acceptor_tgid);
            let flags = rd!(st, flags);
            let inputs = SockState {
                acceptor_tgid,
                pid_epoch: rd!(st, pid_epoch),
                pid_bits: rd!(st, pid_bits),
                owner_tgid: rd!(st, owner_tgid),
                flags,
                ..SockState::default()
            };
            // The listener rule, read after g1 like every input (§3.1).
            let creator = cfg(CONFIG_PID_CREATOR_RULE) != 0;
            let (listed, owner_known) = pid_inputs(&inputs, epoch, creator);
            let cgroup_in = mode & SCOPE_SEL_CGROUP != 0 && sk_cgroup_selected(sk);
            let sampled_in = mode & SCOPE_SAMPLE == 0
                || in_sample(rd!(st, sample), cfg(CONFIG_SAMPLE_THRESHOLD));
            let v = verdict(mode, listed, owner_known, cgroup_in, sampled_in);
            if scope_gen() != g1 {
                // A selector changed while computing: apply OUT to this
                // packet, never IN, and cache nothing.
                return Err(if v == VERDICT_IN {
                    DROP_OUT_OF_SCOPE
                } else {
                    drop_reason(v)
                });
            }
            // Not cached either way (`verdict_cacheable`: a server not yet
            // accepted).
            if ingress
                && v != VERDICT_IN
                && hold_on()
                && pending_accept(mode, flags, acceptor_tgid, cgroup_in, sampled_in, creator)
            {
                return if HOLD {
                    Ok(g1)
                } else {
                    Err(DROP_PENDING_ACCEPT)
                };
            }
            if verdict_cacheable(v, mode, flags, acceptor_tgid) {
                wr!(st, verdict_word, verdict_word(g1, v));
            }
            v
        }
    };
    if HOLD {
        // Accepted (or closed) since the capture hook's verdict: decided
        // again there.
        return Err(DROP_HOLD_REENTER);
    }
    if v == VERDICT_IN {
        Ok(g1)
    } else {
        Err(drop_reason(v))
    }
}

/// `CONFIG_PENDING_HOLD`: the accept hook that releases holds is attached.
#[inline(always)]
fn hold_on() -> bool {
    cfg_pending(CONFIG_PENDING_HOLD) != 0
}

/// A `PENDING_CTL` setting (0 if unreadable).
#[inline(always)]
fn cfg_pending(index: u32) -> u64 {
    let p = pending_ctl(index);
    if p.is_null() {
        0
    } else {
        unsafe { read_volatile(p) }
    }
}

/// Stream offset of a TCP segment from an unlocked, self-validating read of
/// the socket's counters (§3.3); one retry on a torn read.
#[inline(always)]
fn tcp_offset(
    tp: *mut aya_ebpf::bindings::bpf_tcp_sock,
    st: *mut SockState,
    direction: Direction,
    seq: u32,
) -> Option<i64> {
    for _ in 0..2 {
        let off = unsafe {
            match direction {
                Direction::Ingress => {
                    let r1 = read_volatile(&raw const (*tp).rcv_nxt);
                    let b = read_volatile(&raw const (*tp).bytes_received);
                    let r2 = read_volatile(&raw const (*tp).rcv_nxt);
                    stream_offset(b, 0, r1, r2, rd!(st, rcv_base), seq)
                }
                Direction::Egress => {
                    let u1 = read_volatile(&raw const (*tp).snd_una);
                    let b = read_volatile(&raw const (*tp).bytes_acked);
                    let u2 = read_volatile(&raw const (*tp).snd_una);
                    stream_offset(b, rd!(st, syn_adj) as u64, u1, u2, rd!(st, snd_base), seq)
                }
            }
        };
        if off.is_some() {
            return off;
        }
    }
    None
}

/// `__sync_fetch_and_add` with the old value (BPF_ADD | BPF_FETCH). Written
/// as one instruction so the rest of the object keeps its codegen (Rust's
/// atomic would need `-mcpu=v3` for the whole object).
#[inline(always)]
unsafe fn fetch_add_u64(p: *mut u64, v: u64) -> u64 {
    let mut r = v;
    unsafe {
        core::arch::asm!(
            "{r} = atomic_fetch_add((u64 *)({p} + 0), {r})",
            r = inout(reg) r,
            p = in(reg) p,
            options(nostack),
        );
    }
    r
}

const IPV4_HDR_MIN_LEN: u32 = 20;
const TCP_HDR_MIN_LEN: u32 = 20;
const UDP_HDR_LEN: u32 = 8;

/// Parse the IPv4 and TCP/UDP headers. A cgroup_skb's data starts at the
/// network header (no Ethernet header).
#[inline(always)]
fn parse(ctx: &SkBuffContext, udp: bool) -> Result<Packet, ()> {
    let skb = &ctx.skb;
    let vihl: u8 = skb.load(0).map_err(|_| ())?;
    let ihl = ((vihl & 0x0F) as u32) * 4;
    if ihl < IPV4_HDR_MIN_LEN {
        return Err(());
    }
    let frag: u16 = u16::from_be(skb.load(6).map_err(|_| ())?);
    if frag & 0x1FFF != 0 {
        return Err(()); // a non-first fragment has no L4 header
    }
    let src_addr = u32::from_be(skb.load(12).map_err(|_| ())?);
    let dst_addr = u32::from_be(skb.load(16).map_err(|_| ())?);
    let l4 = ihl as usize;
    let src_port = u16::from_be(skb.load(l4).map_err(|_| ())?);
    let dst_port = u16::from_be(skb.load(l4 + 2).map_err(|_| ())?);
    let (payload_off, seq, ack, tcp_flags) = if udp {
        (ihl + UDP_HDR_LEN, 0, 0, 0)
    } else {
        let seq = u32::from_be(skb.load(l4 + 4).map_err(|_| ())?);
        let ack = u32::from_be(skb.load(l4 + 8).map_err(|_| ())?);
        let doff: u8 = skb.load(l4 + 12).map_err(|_| ())?;
        let flags: u8 = skb.load(l4 + 13).map_err(|_| ())?;
        let thl = ((doff >> 4) as u32) * 4;
        if thl < TCP_HDR_MIN_LEN {
            return Err(());
        }
        (ihl + thl, seq, ack, flags)
    };
    // skb->len, not tot_len: GSO and BIG TCP packets can exceed (or zero) it.
    let payload_len = ctx.len().saturating_sub(payload_off);
    Ok(Packet {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        seq,
        ack,
        tcp_flags,
        payload_off,
        payload_len,
    })
}

/// A packet record's header fields and what to copy, for [`emit`]: plain
/// values only (no pointers), so [`header`] can launder them in one copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct Hdr {
    cookie: u64,
    /// The packet's first payload byte's stream offset, or STREAM_OFF_UNKNOWN.
    stream_off: u64,
    cgroup_id: u64,
    src_addr: u32,
    dst_addr: u32,
    seq: u32,
    ack: u32,
    payload_off: u32,
    /// Payload bytes on the wire.
    payload_len: u32,
    /// Payload bytes to capture (<= payload_len).
    take: u32,
    scope_gen: u32,
    owner_tgid: u32,
    acceptor_tgid: u32,
    /// A `Direction` (repr(u32)).
    direction: u32,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    ip_proto: u8,
    role: u8,
    /// Written (zero) like every other byte: the verifier refuses a copy
    /// that reads uninitialised stack.
    _pad: [u8; 5],
}

const _: () = assert!(core::mem::size_of::<Hdr>() == 80);

/// The record header for a packet, laundered through a helper copy: the
/// verifier sees helper-written bytes as unknown on every path, so the many
/// paths through `try_skb` (constants on some, map values on others) reach
/// the chunk loop in [`emit`] as one state instead of each walking it
/// again (the loop put scope_skb_ingress past the 1M-instruction limit on
/// 5.15). The copy is from this program's own stack and cannot fault; its
/// result is not checked, so no branch is added (the TLS header does the
/// same, tls_probes.rs `tls_header`).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn header(
    sk: *mut c_void,
    st: *mut SockState,
    cookie: u64,
    direction: Direction,
    udp: bool,
    pkt: &Packet,
    take: u32,
    stream_off: u64,
    scope_gen: u32,
) -> Hdr {
    let (owner_tgid, acceptor_tgid, role) = if st.is_null() {
        (0, 0, 0)
    } else {
        (
            rd!(st, owner_tgid),
            rd!(st, acceptor_tgid),
            role_of(rd!(st, flags)),
        )
    };
    let a = Hdr {
        cookie,
        stream_off,
        cgroup_id: unsafe { bpf_sk_cgroup_id(sk) },
        src_addr: pkt.src_addr,
        dst_addr: pkt.dst_addr,
        seq: pkt.seq,
        ack: pkt.ack,
        payload_off: pkt.payload_off,
        payload_len: pkt.payload_len,
        take,
        scope_gen,
        owner_tgid,
        acceptor_tgid,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        tcp_flags: pkt.tcp_flags,
        ip_proto: if udp { IPPROTO_UDP } else { IPPROTO_TCP } as u8,
        direction: direction as u32,
        role,
        _pad: [0; 5],
    };
    let mut h = a;
    unsafe {
        bpf_probe_read_kernel_raw(
            &raw mut h as *mut c_void,
            core::mem::size_of::<Hdr>() as u32,
            &raw const a as *const c_void,
        );
    }
    h
}

/// Mark `st`'s socket as having had a packet record emitted, so its close
/// is sent (`on_tcp_close`). Set before the record is reserved.
#[inline(always)]
fn mark_emitted(st: *mut SockState) {
    if !st.is_null() && rd!(st, emitted) == 0 {
        wr!(st, emitted, 1);
    }
}

/// Send a packet's first `take` payload bytes to the socket's ring shard.
///
/// A TCP packet whose `take` exceeds MAX_PAYLOAD_SIZE (a GSO/TSO or GRO
/// super-packet) is sent as consecutive chunk records ([`emit_full_chunk`],
/// then [`emit_last`]), at most MAX_SKB_CHUNKS in all, so parsers see the
/// stream contiguously instead of one 4 KiB window and a skipped tail that
/// loses frame boundaries. Each chunk carries its own stream position:
/// `tcp_seq` and a known `stream_off` advanced by the chunk's offset in the
/// packet, `orig_len` the chunk's bytes on the wire, so the chunks'
/// `orig_len` sum to the packet's and user space accounts every byte
/// exactly. The last chunk's `orig_len` also counts whatever is left
/// uncaptured (past MAX_SKB_CHUNKS, or past a head-only cut), and it alone
/// carries FIN / RST. Every chunk goes to the same shard, in order; two
/// CPUs capturing one socket at once (ingress runs before the socket lock)
/// can interleave two packets' chunks there, and user space puts them back
/// in stream order (panopticon-agent `reorder.rs`). If a
/// chunk cannot be reserved the rest of the packet is not sent: user space
/// sees the missing bytes as a gap at the connection's next record, as for
/// any ring drop. A UDP datagram stays one record (one datagram is one
/// message to the parsers), as does a packet carrying RST: user space
/// accepts an RST only at the next expected sequence number, and that
/// check must see the packet's own `tcp_seq`, not a later chunk's (an RST
/// at a wrong sequence number would otherwise pass it on its last chunk).
/// Both are cut at MAX_PAYLOAD_SIZE, the rest counted in `orig_len`.
///
/// Every record is reserved in the ring, never built in a shared per-CPU
/// buffer: egress runs in process context, where a softirq or (on a
/// preemptible kernel) another task on the CPU can run these programs again
/// mid-event; with nothing shared between runs, nesting cannot mix two
/// sockets' bytes. Scope was decided once for the whole packet, before
/// this: every chunk carries the same generation stamp.
#[inline(always)]
fn emit(ctx: &SkBuffContext, h: &Hdr) -> Result<(), ()> {
    use panopticon_common::TCP_FLAG_RST;
    let mut off = 0u32;
    if h.ip_proto != IPPROTO_UDP as u8 && h.tcp_flags & TCP_FLAG_RST == 0 {
        for _ in 0..MAX_SKB_CHUNKS - 1 {
            if h.take <= off + MAX_PAYLOAD_SIZE as u32 {
                break;
            }
            if !emit_full_chunk(ctx, h, off) {
                return Ok(());
            }
            off += MAX_PAYLOAD_SIZE as u32;
        }
    }
    emit_last(ctx, h, off)
}

/// Packets are sent as at most this many records (64 KiB: the default
/// GSO/TSO/GRO maximum), fewer if `max_packet_bytes` ([`packet_cap`]) is
/// lower. Bytes past them are counted, not captured (the last record's
/// `orig_len`). The verifier walks every chunk.
const MAX_SKB_CHUNKS: usize = 16;

// Older kernels' `bpf_skb_load_bytes` fails any offset over 0xffff (the
// check `skb_zero` relies on): the last chunk's offset, after the largest
// IPv4 and TCP headers (60 bytes each), must stay under it.
const _: () = assert!((MAX_SKB_CHUNKS - 1) * MAX_PAYLOAD_SIZE + 60 + 60 <= 0xffff);

/// Header fields of the record for payload bytes from `off`, with
/// `orig_len` bytes on the wire. Only the last record carries FIN / RST.
#[inline(always)]
unsafe fn write_header(event: *mut DataEvent, h: &Hdr, off: u32, orig_len: u32, last: bool) {
    use panopticon_common::{TCP_FLAG_FIN, TCP_FLAG_RST};
    // A known offset (< 2^63) advances; STREAM_OFF_UNKNOWN (u64::MAX) stays.
    // Branch-free: the verifier walks this once per chunk.
    let known = (h.stream_off >> 63).wrapping_sub(1);
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).socket_cookie = h.cookie;
        (*event).event_type = EventType::TcPacket;
        // `direction` holds a Direction (repr(u32)) written by `header`:
        // all four bytes are written.
        *(&raw mut (*event).direction as *mut u32) = h.direction;
        (*event).pid = 0;
        (*event).tgid = 0;
        (*event).src_addr = h.src_addr;
        (*event).dst_addr = h.dst_addr;
        (*event).src_port = h.src_port;
        (*event).dst_port = h.dst_port;
        (*event).ip_proto = h.ip_proto;
        (*event).tls_library = TlsLibrary::None;
        (*event).tcp_flags = if last {
            h.tcp_flags
        } else {
            h.tcp_flags & !(TCP_FLAG_FIN | TCP_FLAG_RST)
        };
        (*event).tcp_seq = h.seq.wrapping_add(off);
        (*event).tcp_ack = h.ack;
        (*event).orig_len = orig_len;
        crate::maps::clear_scope_fields(event);
        (*event).cgroup_id = h.cgroup_id;
        (*event).stream_off = h.stream_off.wrapping_add(off as u64 & known);
        (*event).scope_gen = h.scope_gen;
        (*event).owner_tgid = h.owner_tgid;
        (*event).acceptor_tgid = h.acceptor_tgid;
        (*event).role = h.role;
    }
}

/// A full MAX_PAYLOAD_SIZE record for payload bytes `[off, off + 4096)`,
/// not the last. The copy has a constant length and covers the whole
/// payload (a failed load clears it), so every published byte is written
/// without zeroing. False if it could not be reserved (a kernel drop).
#[inline(always)]
fn emit_full_chunk(ctx: &SkBuffContext, h: &Hdr, off: u32) -> bool {
    let shard = shard_for(h.cookie);
    let Some(mut entry) = shard_reserve_as::<SizedEvent<MAX_PAYLOAD_SIZE>>(shard) else {
        count_kernel_drop();
        return false;
    };
    let rec = entry.as_mut_ptr();
    let event = rec as *mut DataEvent;
    unsafe {
        write_header(event, h, off, MAX_PAYLOAD_SIZE as u32, false);
        let ret = bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            h.payload_off.wrapping_add(off),
            (&raw mut (*rec).payload) as *mut c_void,
            MAX_PAYLOAD_SIZE as u32,
        );
        // 4096 on success, 0 on failure (ret < 0), without a branch.
        (*event).payload_len = MAX_PAYLOAD_SIZE as u32 & !((ret >> 63) as u32);
    }
    entry.submit(shard_submit_flags_for::<SizedEvent<MAX_PAYLOAD_SIZE>>(
        shard,
    ));
    true
}

/// The last (or only) record of a packet: payload bytes `[off, take)`,
/// reserved at the smallest power-of-two payload size class (64 to 4,096
/// bytes) that holds them: the header plus the captured bytes rounded up to
/// a power of two (at least 64), where a whole DataEvent is 4,192 bytes.
#[inline(always)]
fn emit_last(ctx: &SkBuffContext, h: &Hdr, off: u32) -> Result<(), ()> {
    match h.take.saturating_sub(off) {
        0..=64 => emit_sized::<64>(ctx, h, off),
        65..=128 => emit_sized::<128>(ctx, h, off),
        129..=256 => emit_sized::<256>(ctx, h, off),
        257..=512 => emit_sized::<512>(ctx, h, off),
        513..=1024 => emit_sized::<1024>(ctx, h, off),
        1025..=2048 => emit_sized::<2048>(ctx, h, off),
        _ => emit_sized::<MAX_PAYLOAD_SIZE>(ctx, h, off),
    }
}

#[inline(always)]
fn emit_sized<const N: usize>(ctx: &SkBuffContext, h: &Hdr, off: u32) -> Result<(), ()> {
    let shard = shard_for(h.cookie);
    let Some(mut entry) = shard_reserve_as::<SizedEvent<N>>(shard) else {
        count_kernel_drop();
        return Ok(());
    };
    let rec = entry.as_mut_ptr();
    // Header fields through the DataEvent layout (all within the record);
    // the payload only through `rec.payload`, N bytes. Its `orig_len` is
    // everything from `off` to the packet's end.
    let event = rec as *mut DataEvent;
    unsafe {
        write_header(event, h, off, h.payload_len.saturating_sub(off), true);
        // The verifier needs the length provably in [1, N]. LLVM knows it
        // is already in range and drops any plain bounds check, so a
        // volatile read hides the value and the mask + 1 gives the verifier
        // [1, N] directly. `take - off` is in [1, N] here (the class was
        // chosen by it, and the largest class is MAX_PAYLOAD_SIZE), so the
        // mask changes nothing at runtime.
        let rest = h.take.saturating_sub(off);
        let want = if rest > N as u32 { N as u32 } else { rest };
        let opaque = read_volatile(&want);
        let len = (opaque.wrapping_sub(1) & (N as u32 - 1)) + 1;
        // Every published byte is written: ring memory is not zeroed and
        // the whole record is mapped into user space, so unwritten slack
        // would show an earlier record. The load covers [0, len), and
        // len > N/2 in every class above 64 (the smallest class that holds
        // `take - off`), so only [N/2, N) is zeroed before it; the 64-byte
        // class is zeroed whole. A failed load clears what it was given (the
        // helper's `err_clear`), and [0, N/2) is zeroed again then.
        let payload = (&raw mut (*rec).payload) as *mut u8;
        let lo = if N == 64 { 0 } else { N / 2 };
        skb_zero(ctx, payload.add(lo), (N - lo) as u32);
        let ret = bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            h.payload_off.wrapping_add(off),
            payload as *mut c_void,
            len,
        );
        (*event).payload_len = if ret == 0 {
            len
        } else {
            skb_zero(ctx, payload, lo as u32);
            0
        };
    }
    entry.submit(shard_submit_flags_for::<SizedEvent<N>>(shard));
    Ok(())
}

/// Zero `n` (constant) bytes at `dst` in one helper call: `bpf_skb_load_bytes`
/// from an offset past any packet (over INT_MAX, and over 0xffff, the
/// check before 5.x) fails and clears its destination (net/core/filter.c
/// `bpf_skb_load_bytes`, `err_clear`, on every supported kernel). A store
/// loop made scope_skb_ingress too large for the verifier. scope_attach
/// checks the published slack is zero on every lab kernel.
#[inline(always)]
fn skb_zero(ctx: &SkBuffContext, dst: *mut u8, n: u32) {
    if n == 0 {
        return;
    }
    unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            0x8000_0000,
            dst as *mut c_void,
            n,
        );
    }
}

const _: () = assert!(MAX_PAYLOAD_SIZE.is_power_of_two() && MAX_PAYLOAD_SIZE > 2048);

/// Reads the IPv4 5-tuple from `struct sock`.
///
/// Linux `struct sock` (via `struct sock_common`) field offsets (x86_64):
/// - `__sk_common.skc_daddr`   (dst IPv4): offset 0   (u32)
/// - `__sk_common.skc_rcv_saddr` (src IPv4): offset 4 (u32)
/// - `__sk_common.skc_dport`  (dst port, network byte order): offset 12 (u16)
/// - `__sk_common.skc_num`    (src port, host byte order): offset 14 (u16)
#[inline(always)]
pub(crate) fn read_sock_tuple(sk: *const u8) -> Result<(u32, u32, u16, u16), ()> {
    // SAFETY: reading from struct sock fields at known offsets.
    // The sock pointer is provided by the kernel and is valid during kprobe execution.
    unsafe {
        let dst_addr: u32 = bpf_probe_read_kernel(sk.add(0) as *const u32).map_err(|_| ())?;
        let src_addr: u32 = bpf_probe_read_kernel(sk.add(4) as *const u32).map_err(|_| ())?;
        let dst_port_be: u16 = bpf_probe_read_kernel(sk.add(12) as *const u16).map_err(|_| ())?;
        let src_port: u16 = bpf_probe_read_kernel(sk.add(14) as *const u16).map_err(|_| ())?;

        let dst_port = u16::from_be(dst_port_be);

        Ok((
            u32::from_be(src_addr),
            u32::from_be(dst_addr),
            src_port,
            dst_port,
        ))
    }
}
