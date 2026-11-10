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
//! `SCOPE_DROPS`, except in unscoped `full` mode, which captures as TC did.
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
        bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_sk_ancestor_cgroup_id, bpf_sk_cgroup_id,
        bpf_sk_fullsock, bpf_sk_storage_get, bpf_skb_load_bytes, bpf_sock_ops_cb_flags_set,
        bpf_tcp_sock,
    },
    macros::{cgroup_skb, cgroup_sock, fentry, fexit, sock_ops},
    programs::{FEntryContext, FExitContext, SkBuffContext, SockContext, SockOpsContext},
};
use panopticon_common::{
    CONFIG_CAPTURE_ENABLED, CONFIG_HEAD_BYTES, CONFIG_PID_EPOCH, CONFIG_SAMPLE_THRESHOLD,
    CONFIG_SCOPE_ARMED, CONFIG_SCOPE_GEN, CONFIG_SCOPE_MODE, DataEvent, Direction, EventType,
    MAX_PAYLOAD_SIZE, TlsLibrary,
    scope::{
        ACCEPTOR_LISTED, DROP_HEAD_CUT, DROP_HEAD_INCOHERENT, DROP_KTLS_PAYLOAD, DROP_NO_BASELINE,
        DROP_NOT_ELIGIBLE, DROP_OUT_OF_SCOPE, DROP_UNINIT, FLAG_BASELINE, FLAG_KTLS, FLAG_REPAIRED,
        FLAG_REUSED, FLAG_ROLE_CLIENT, FLAG_ROLE_SERVER, FLAGS_STICKY, OWNER_LISTED, SCOPE_HEAD,
        SCOPE_SAMPLE, SCOPE_SEL_CGROUP, STREAM_OFF_UNKNOWN, SockState, VERDICT_IN, cached_verdict,
        drop_reason, head_take, in_sample, is_initialised, is_unscoped_full, pid_inputs,
        reserved_take, role_of, stream_offset, tls_addr_in_scope, udp_should_reserve, verdict,
        verdict_cacheable, verdict_word,
    },
};

use crate::maps::{
    CGROUP_ALLOW, CONFIG, IPV6_DROPS, PID_FILTER, SizedEvent, count_kernel_drop, count_scope_drop,
    shard_for, shard_reserve_as, shard_submit_flags_for,
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
/// listener without state (one that predates the agent and was not
/// initialised at arming, §3.1) by its PASSIVE_ESTABLISHED or its accept,
/// whichever runs first. User space writes state only on pre-agent LISTEN
/// sockets, before arming (`scope_loader::init_listeners`). A socket that
/// itself predates the agent is never initialised (§2.1).
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
/// * `CONFIG_CAPTURE_ENABLED`, on every backend and mode: the user's
///   `capture_enabled = false`, and the fatal stop (`scope_select.rs`
///   `AyaAllow::disarm`). The loader writes it from `capture_enabled`
///   (default true) before any program is attached, as the TC and
///   cgroup_skb packet paths already honour it.
/// * `CONFIG_SCOPE_ARMED`, in restricted modes only: until arming, the TLS
///   scope inputs (`PID_FILTER`) and the socket state the address check
///   reads are incomplete, and the fatal stop clears it. Unscoped full
///   mode (the TC backend included) is never armed, so it does not apply
///   there. The fatal stop also leaves the mode restricted, so a stopped
///   agent fails both conditions.
#[inline(always)]
pub(crate) fn tls_capture_on() -> bool {
    cfg(CONFIG_CAPTURE_ENABLED) != 0 && (is_unscoped_full(scope_mode()) || armed())
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
    let tuple = crate::sock_monitor::read_sock_tuple(sk as *const u8).ok()?;
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
    // A child of a listener without state (pre-agent, not initialised at
    // arming) has nothing to clone: it is a new socket, so it gets fresh
    // state here or in its accept, whichever runs first. Its owner is
    // unknown (epoch 0 never matches), so pid_filter selects it only from
    // accept() on (no_owner before, §3.1). An active socket without state
    // predates the agent and stays uninitialised.
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
    let st = state_of(sk as *mut c_void, false);
    if st.is_null() {
        return;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ops as *mut c_void) };
    let g1 = scope_gen();
    let authorised = rd!(st, emitted) != 0
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
    // A selector changed while the record was built: send nothing.
    if scope_gen() != g1 {
        entry.discard(0);
        return;
    }
    entry.submit(shard_submit_flags_for::<SizedEvent<0>>(shard));
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
/// here then. Write order: `accept_cookie` (claims the fields for this
/// socket), the bits, `acceptor_tgid` (readers that see it see the bits),
/// then clear the verdict so the next packet recomputes it. Not before
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
    wr!(st, accept_cookie, unsafe { bpf_get_socket_cookie(child) });
    wr!(st, pid_bits, bits);
    wr!(st, pid_epoch, epoch);
    wr!(st, acceptor_tgid, tgid);
    wr!(st, verdict_word, 0);
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
    let _ = try_skb(&ctx, Direction::Ingress);
    1
}

#[cgroup_skb(egress)]
pub fn scope_skb_egress(ctx: SkBuffContext) -> i32 {
    let _ = try_skb(&ctx, Direction::Egress);
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

/// Order per packet (§3): eligibility, initialisation, (UDP head
/// reservation), verdict, kTLS, head cut, copy and emit.
#[inline(always)]
fn try_skb(ctx: &SkBuffContext, direction: Direction) -> Result<(), ()> {
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
    if unsafe { (*skb).protocol } != ETH_P_IP_BE {
        // IPv6 is not captured yet, as on the TC path.
        if let Some(counter) = IPV6_DROPS.get_ptr_mut(0) {
            unsafe { *counter += 1 };
        }
        return Ok(());
    }
    let pkt = parse(ctx, udp)?;
    if pkt.payload_len == 0 {
        return Ok(()); // no data; the socket's end comes from STATE_CB
    }
    let sk = sk as *mut c_void;
    let mode = scope_mode();
    let st = state_of(sk, false);

    // ── initialisation
    let cookie = unsafe { bpf_get_socket_cookie(skb as *mut c_void) };
    let initialised = !st.is_null() && is_initialised(rd!(st, init_cookie), cookie);
    if is_unscoped_full(mode) {
        let mut off = STREAM_OFF_UNKNOWN;
        if initialised && !udp && rd!(st, flags) & FLAG_BASELINE != 0 {
            if let Some(o) = tcp_offset(tp, st, direction, pkt.seq) {
                off = position(o);
            }
        }
        mark_emitted(st);
        let st = if initialised { st } else { null_mut() };
        return emit(
            ctx,
            &Record {
                sk,
                st,
                cookie,
                direction,
                udp,
                pkt: &pkt,
                take: pkt.payload_len,
                stream_off: off,
                scope_gen: scope_gen(),
            },
        );
    }
    if !initialised {
        return drop(DROP_UNINIT);
    }
    let flags = rd!(st, flags);
    let head = mode & SCOPE_HEAD != 0;
    let n = cfg(CONFIG_HEAD_BYTES);

    // ── UDP head budget: reserved before the verdict, whatever it is (§3.3)
    let mut take = pkt.payload_len;
    let mut off = STREAM_OFF_UNKNOWN;
    if udp && head {
        if flags & FLAG_BASELINE == 0 {
            return drop(DROP_NO_BASELINE);
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
    let g = match scope_verdict(st, sk, mode) {
        Ok(g) => g,
        Err(reason) => return drop(reason),
    };

    // ── kTLS: the payload may be plaintext at this hook (§3.5). After the
    // verdict, so an in-scope kTLS socket has its IN verdict cached (its TLS
    // calls get their address, `sock_addr_checked`); before every emit, so
    // none of its payload leaves outside unscoped full.
    if flags & FLAG_KTLS != 0 {
        return drop(DROP_KTLS_PAYLOAD);
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
                return drop(DROP_NO_BASELINE);
            }
            let Some(o) = tcp_off else {
                return drop(DROP_HEAD_INCOHERENT);
            };
            take = head_take(o, pkt.payload_len, n);
        }
        if take == 0 {
            return drop(DROP_HEAD_CUT);
        }
    }
    mark_emitted(st);
    emit(
        ctx,
        &Record {
            sk,
            st,
            cookie,
            direction,
            udp,
            pkt: &pkt,
            take,
            stream_off: off,
            scope_gen: g,
        },
    )
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
/// Ok(generation) if in scope, Err(drop reason) otherwise.
#[inline(always)]
fn scope_verdict(st: *mut SockState, sk: *mut c_void, mode: u64) -> Result<u32, u32> {
    let g1 = scope_gen();
    let word = rd!(st, verdict_word);
    let v = match cached_verdict(word, g1) {
        Some(v) => v,
        None => {
            let epoch = cfg(CONFIG_PID_EPOCH) as u32;
            // acceptor_tgid first: the accept hook writes it after the bits.
            let acceptor_tgid = rd!(st, acceptor_tgid);
            let inputs = SockState {
                acceptor_tgid,
                pid_epoch: rd!(st, pid_epoch),
                pid_bits: rd!(st, pid_bits),
                owner_tgid: rd!(st, owner_tgid),
                ..SockState::default()
            };
            let (listed, owner_known) = pid_inputs(&inputs, epoch);
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
            if verdict_cacheable(v, mode, rd!(st, flags), acceptor_tgid) {
                wr!(st, verdict_word, verdict_word(g1, v));
            }
            v
        }
    };
    if v == VERDICT_IN {
        Ok(g1)
    } else {
        Err(drop_reason(v))
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

/// A packet record's fields, for [`emit_sized`].
struct Record<'a> {
    sk: *mut c_void,
    st: *mut SockState,
    cookie: u64,
    direction: Direction,
    udp: bool,
    pkt: &'a Packet,
    take: u32,
    stream_off: u64,
    scope_gen: u32,
}

/// Mark `st`'s socket as having had a packet record emitted, so its close
/// is sent (`on_tcp_close`). Set before the record is reserved.
#[inline(always)]
fn mark_emitted(st: *mut SockState) {
    if !st.is_null() && rd!(st, emitted) == 0 {
        wr!(st, emitted, 1);
    }
}

/// Send a packet record with its first `take` payload bytes to the socket's
/// ring shard, reserved at the smallest power-of-two payload size class
/// (64 to 4,096 bytes) that holds them: the header plus the captured bytes
/// rounded up to a power of two (at least 64), where a whole DataEvent is
/// 4,168 bytes.
/// Reserved in the ring, never built in a shared per-CPU buffer: egress
/// runs in process context, where a softirq or (on a preemptible kernel)
/// another task on the CPU can run these programs again mid-event; with
/// nothing shared between runs, nesting cannot mix two sockets' bytes.
#[inline(always)]
fn emit(ctx: &SkBuffContext, r: &Record) -> Result<(), ()> {
    match r.take {
        0..=64 => emit_sized::<64>(ctx, r),
        65..=128 => emit_sized::<128>(ctx, r),
        129..=256 => emit_sized::<256>(ctx, r),
        257..=512 => emit_sized::<512>(ctx, r),
        513..=1024 => emit_sized::<1024>(ctx, r),
        1025..=2048 => emit_sized::<2048>(ctx, r),
        _ => emit_sized::<MAX_PAYLOAD_SIZE>(ctx, r),
    }
}

#[inline(always)]
fn emit_sized<const N: usize>(ctx: &SkBuffContext, r: &Record) -> Result<(), ()> {
    let shard = shard_for(r.cookie);
    let Some(mut entry) = shard_reserve_as::<SizedEvent<N>>(shard) else {
        count_kernel_drop();
        return Ok(());
    };
    let rec = entry.as_mut_ptr();
    // Header fields through the DataEvent layout (all within the record);
    // the payload only through `rec.payload`, N bytes.
    let event = rec as *mut DataEvent;
    let pkt = r.pkt;
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).socket_cookie = r.cookie;
        (*event).event_type = EventType::TcPacket;
        (*event).direction = r.direction;
        (*event).pid = 0;
        (*event).tgid = 0;
        (*event).src_addr = pkt.src_addr;
        (*event).dst_addr = pkt.dst_addr;
        (*event).src_port = pkt.src_port;
        (*event).dst_port = pkt.dst_port;
        (*event).ip_proto = if r.udp { IPPROTO_UDP } else { IPPROTO_TCP } as u8;
        (*event).tls_library = TlsLibrary::None;
        (*event).tcp_flags = pkt.tcp_flags;
        (*event).tcp_seq = pkt.seq;
        (*event).tcp_ack = pkt.ack;
        (*event).orig_len = pkt.payload_len;
        crate::maps::clear_scope_fields(event);
        (*event).cgroup_id = bpf_sk_cgroup_id(r.sk);
        (*event).stream_off = r.stream_off;
        (*event).scope_gen = r.scope_gen;
        let st = r.st;
        if !st.is_null() {
            (*event).owner_tgid = rd!(st, owner_tgid);
            (*event).acceptor_tgid = rd!(st, acceptor_tgid);
            (*event).role = role_of(rd!(st, flags));
        }
        // The verifier needs the length provably in [1, N]; see
        // tc_capture.rs populate_tc_event for why it is laundered. `take`
        // is in [1, N] here (the class was chosen by it, and the largest
        // class is MAX_PAYLOAD_SIZE), so the mask changes nothing at runtime.
        let want = if r.take > N as u32 { N as u32 } else { r.take };
        let opaque = read_volatile(&want);
        let len = (opaque.wrapping_sub(1) & (N as u32 - 1)) + 1;
        // Every published byte is written: ring memory is not zeroed and
        // the whole record is mapped into user space, so unwritten slack
        // would show an earlier record. The load covers [0, len), and
        // len > N/2 in every class above 64 (the smallest class that holds
        // `take`), so only [N/2, N) is zeroed before it; the 64-byte class
        // is zeroed whole. A failed load clears what it was given (the
        // helper's `err_clear`), and [0, N/2) is zeroed again then.
        let payload = (&raw mut (*rec).payload) as *mut u8;
        let lo = if N == 64 { 0 } else { N / 2 };
        skb_zero(ctx, payload.add(lo), (N - lo) as u32);
        let ret = bpf_skb_load_bytes(
            ctx.skb.skb as *const c_void,
            pkt.payload_off,
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
