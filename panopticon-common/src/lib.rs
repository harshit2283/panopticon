#![no_std]

pub mod scope;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum payload bytes captured per event.
pub const MAX_PAYLOAD_SIZE: usize = 4096;

/// Maximum concurrent tracked connections.
pub const MAX_CONNECTIONS: u32 = 65_536;

/// Maximum bytes for process comm name (Linux TASK_COMM_LEN).
pub const MAX_COMM_SIZE: usize = 16;

/// Number of entries in the CONFIG array map.
pub const CONFIG_ENTRIES: u32 = 16;

/// Maximum entries in the PID filter map.
pub const MAX_PID_FILTER: u32 = 4096;

/// Maximum entries in the CGROUP_ALLOW map (selected cgroup ids).
pub const MAX_CGROUP_ALLOW: u32 = 4096;

/// Size of the per-CPU TLS scratch map.
pub const TLS_SCRATCH_SIZE: u32 = 8192;

/// `DataEvent::tcp_flags` bits.
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_ACK: u8 = 0x10;

// Config array indices
pub const CONFIG_CAPTURE_ENABLED: u32 = 0;
pub const CONFIG_MAX_PAYLOAD: u32 = 1;
pub const CONFIG_USE_RINGBUF: u32 = 2;
pub const CONFIG_PID_FILTER_ON: u32 = 3;
// Index 4 was CONFIG_IGNORE_PORT (a port TC skipped); removed, see
// tc_capture.rs try_tc_capture.
/// Active DATA_EVENTS ring shards minus one (a power of two minus one).
/// 0, the default, sends every event to DATA_EVENTS_0.
pub const CONFIG_RING_SHARD_MASK: u32 = 5;
/// Per-boot random key mixed into TC flow cookies ([`tc_flow_cookie`]),
/// so a peer cannot compute another flow's cookie offline.
pub const CONFIG_COOKIE_KEY: u32 = 6;
/// Non-zero: TC also emits payload-less SYN segments (each TCP direction's
/// stream starts after its SYN: head_only counts from it, and parsers that
/// pair replies by order need it). The agent always sets it.
pub const CONFIG_TCP_SYN_EVENTS: u32 = 7;
/// Capture-scope generation (`scope::verdict_word`). User space updates
/// `CGROUP_ALLOW` first, then increments this.
pub const CONFIG_SCOPE_GEN: u32 = 8;
/// Random per agent start; `SockState::pid_bits` are valid only under it.
pub const CONFIG_PID_EPOCH: u32 = 9;
/// `connection_sample` threshold, `sample_rate * 2^32` (`scope::sample_threshold`).
pub const CONFIG_SAMPLE_THRESHOLD: u32 = 10;
/// `head_only_bytes` (N).
pub const CONFIG_HEAD_BYTES: u32 = 11;
/// `scope::SCOPE_*` bits. 0 is unscoped `full`, the legacy behaviour.
pub const CONFIG_SCOPE_MODE: u32 = 12;
/// Non-zero once startup is complete (the loader's last write). While 0 the
/// scope writers publish no initialisation, so a socket created or
/// established during startup stays uninitialised for life.
pub const CONFIG_SCOPE_ARMED: u32 = 13;
/// `capture_loopback`: non-zero captures packets on a node-local path
/// (`scope::DROP_LOOPBACK`). 0, the default and what an unwritten entry
/// reads as, drops them (cgroup_skb backend; TC never sees loopback). TLS
/// plaintext does not read it: it is scoped by process.
pub const CONFIG_CAPTURE_LOOPBACK: u32 = 14;
/// `pid_filter_listener = "creator"`: non-zero lets a listener's listed
/// creator select its accepted children (`scope::pid_inputs`). 0, the
/// default, selects a passive connection by its acceptor only.
pub const CONFIG_PID_CREATOR_RULE: u32 = 15;
const _: () = assert!(CONFIG_PID_CREATOR_RULE < CONFIG_ENTRIES);

/// Bit 63 of a connection key: set for TLS connection keys (user space),
/// clear for TC flow cookies, so the two key spaces never overlap.
pub const TLS_KEY_BIT: u64 = 1 << 63;

/// DATA_EVENTS ring buffer shards declared in the eBPF object
/// (`DATA_EVENTS_0` .. `DATA_EVENTS_15`). User space activates a power-of-two
/// subset at load time, sized from the node's CPU count.
pub const DATA_RING_SHARDS: usize = 16;

// ── Enums ──────────────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    TcPacket = 0,
    TlsData = 1,
    ProcessExec = 2,
    ProcessExit = 3,
    SockConnect = 4,
    SockAccept = 5,
    SockClose = 6,
    UdpSend = 7,
    UdpRecv = 8,
    /// The TLS library freed a connection object (`SSL_free`): the header
    /// only, keyed like that object's `TlsData` events. Its address may be
    /// handed to the next connection.
    TlsClose = 9,
}

impl EventType {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::TcPacket),
            1 => Some(Self::TlsData),
            2 => Some(Self::ProcessExec),
            3 => Some(Self::ProcessExit),
            4 => Some(Self::SockConnect),
            5 => Some(Self::SockAccept),
            6 => Some(Self::SockClose),
            7 => Some(Self::UdpSend),
            8 => Some(Self::UdpRecv),
            9 => Some(Self::TlsClose),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Ingress = 0,
    Egress = 1,
}

impl Direction {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Ingress),
            1 => Some(Self::Egress),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsLibrary {
    None = 0,
    OpenSsl = 1,
    GoTls = 2,
    JavaSsl = 3,
}

impl TlsLibrary {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::OpenSsl),
            2 => Some(Self::GoTls),
            3 => Some(Self::JavaSsl),
            _ => None,
        }
    }
}

// ── Shared Structs ─────────────────────────────────────────────────────────
//
// All structs are #[repr(C)] with fields ordered by descending alignment to
// avoid implicit padding. These layouts are the ABI contract between eBPF
// kernel probes and the user-space agent — do NOT reorder fields without
// updating both sides and the ABI tests.

/// Network data event (TC capture or TLS intercept).
///
/// At 4192 bytes this MUST be allocated via RingBuf reserve in eBPF,
/// never on the 512-byte BPF stack.
/// Manual `Debug` implementation that omits the 4KB payload array
/// to avoid flooding logs when debugging events.
impl core::fmt::Debug for DataEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DataEvent")
            .field("timestamp_ns", &self.timestamp_ns)
            .field("socket_cookie", &self.socket_cookie)
            .field("event_type", &self.event_type)
            .field("direction", &self.direction)
            .field("pid", &self.pid)
            .field("tgid", &self.tgid)
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .field("payload_len", &self.payload_len)
            .field("src_port", &self.src_port)
            .field("dst_port", &self.dst_port)
            .field("ip_proto", &self.ip_proto)
            .field("tcp_flags", &self.tcp_flags)
            .field("tcp_seq", &self.tcp_seq)
            .field("tcp_ack", &self.tcp_ack)
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataEvent {
    // 8-byte aligned fields first
    pub timestamp_ns: u64,
    /// Kernel socket cookie for TC/socket events. For `TlsData` events, which
    /// have no socket in uprobe context, the address of the library's
    /// per-connection object (OpenSSL `SSL*`, Go `*tls.Conn`): unique per live
    /// connection within the process and shared by its reads and writes.
    pub socket_cookie: u64,
    /// cgroup v2 id of the socket (cgroup_skb backend); 0 otherwise.
    pub cgroup_id: u64,
    /// Stream offset of the first captured byte (TCP), or the UDP budget
    /// reservation's start; `scope::STREAM_OFF_UNKNOWN` if not computed.
    pub stream_off: u64,
    // 4-byte aligned fields
    pub event_type: EventType,
    pub direction: Direction,
    pub pid: u32,
    pub tgid: u32,
    pub src_addr: u32,
    pub dst_addr: u32,
    /// Bytes actually copied into `payload` (≤ MAX_PAYLOAD_SIZE).
    pub payload_len: u32,
    /// Original payload length of the packet / TLS buffer. Larger than
    /// `payload_len` when the capture was truncated (e.g. GSO/TSO
    /// super-packets up to 64KB); parsers use the difference to skip the
    /// bytes they never saw instead of silently losing stream sync.
    pub orig_len: u32,
    pub tls_library: TlsLibrary,
    /// TCP sequence number of a TC packet's first byte (SEG.SEQ), and its
    /// acknowledgment number (SEG.ACK, valid with `TCP_FLAG_ACK`); 0 for
    /// other events. User space uses them to drop retransmitted and
    /// out-of-window segments (protocol/fsm.rs `TcpTracker`).
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    /// Socket creator tgid (`SockState::owner_tgid`); 0 if unknown.
    pub owner_tgid: u32,
    /// Tgid that accepted the socket; 0 if none or unknown.
    pub acceptor_tgid: u32,
    /// `CONFIG_SCOPE_GEN` the event's scope verdict was computed under.
    pub scope_gen: u32,
    // 2-byte aligned fields
    pub src_port: u16,
    pub dst_port: u16,
    // 1-byte aligned fields
    pub ip_proto: u8,
    /// TCP flags of a TC packet (FIN, SYN, RST...); 0 for other events.
    pub tcp_flags: u8,
    /// `scope::ROLE_*`.
    pub role: u8,
    pub _pad: [u8; 1],
    // Payload last (largest field)
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

/// Process lifecycle event (exec/exit).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub comm: [u8; MAX_COMM_SIZE],
}

/// Connection tracking info stored in CONN_MAP.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfo {
    pub socket_cookie: u64,
    pub connect_ts: u64,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub pid: u32,
    pub tgid: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad: [u8; 4],
}

// ── Pod Impls (user-space only) ────────────────────────────────────────────

// SAFETY: DataEvent is #[repr(C)], Copy, contains no pointers.
// Explicit `_pad` field is zeroed by producers. Verified by ABI tests.
#[cfg(feature = "user")]
unsafe impl aya::Pod for DataEvent {}

// SAFETY: ProcessEvent is #[repr(C)], Copy, no pointers.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}

// SAFETY: ConnInfo is #[repr(C)], Copy, no pointers.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnInfo {}

// SAFETY: SockState is #[repr(C)], Copy, integers only.
#[cfg(feature = "user")]
unsafe impl aya::Pod for scope::SockState {}

// ── Utility Methods (user-space only) ──────────────────────────────────────

impl DataEvent {
    /// Returns the valid payload slice, clamped to `MAX_PAYLOAD_SIZE`.
    pub fn payload_bytes(&self) -> &[u8] {
        let len = (self.payload_len as usize).min(MAX_PAYLOAD_SIZE);
        &self.payload[..len]
    }

    /// Bytes of the original payload that were not captured (0 if complete).
    pub fn truncated_bytes(&self) -> u32 {
        self.orig_len.saturating_sub(self.payload_len)
    }
}

impl ProcessEvent {
    /// Returns the process comm as a UTF-8 string, truncated at the first
    /// null byte. Returns `"<invalid>"` if the bytes aren't valid UTF-8.
    pub fn comm_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawDataEvent {
    pub timestamp_ns: u64,
    pub socket_cookie: u64,
    pub cgroup_id: u64,
    pub stream_off: u64,
    pub event_type: u32,
    pub direction: u32,
    pub pid: u32,
    pub tgid: u32,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub payload_len: u32,
    pub orig_len: u32,
    pub tls_library: u32,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub owner_tgid: u32,
    pub acceptor_tgid: u32,
    pub scope_gen: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
    /// TCP flags of a TC packet (FIN, SYN, RST...); 0 for other events.
    pub tcp_flags: u8,
    pub role: u8,
    pub _pad: [u8; 1],
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

impl RawDataEvent {
    fn to_data_event(self) -> Option<DataEvent> {
        Some(DataEvent {
            timestamp_ns: self.timestamp_ns,
            socket_cookie: self.socket_cookie,
            cgroup_id: self.cgroup_id,
            stream_off: self.stream_off,
            event_type: EventType::from_u32(self.event_type)?,
            direction: Direction::from_u32(self.direction)?,
            pid: self.pid,
            tgid: self.tgid,
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            payload_len: self.payload_len,
            orig_len: self.orig_len,
            tls_library: TlsLibrary::from_u32(self.tls_library)?,
            tcp_seq: self.tcp_seq,
            tcp_ack: self.tcp_ack,
            owner_tgid: self.owner_tgid,
            acceptor_tgid: self.acceptor_tgid,
            scope_gen: self.scope_gen,
            src_port: self.src_port,
            dst_port: self.dst_port,
            ip_proto: self.ip_proto,
            tcp_flags: self.tcp_flags,
            role: self.role,
            _pad: self._pad,
            payload: self.payload,
        })
    }
}

/// Parse a `DataEvent` from raw bytes and validate enum fields.
///
/// Returns `None` if the byte length is wrong or enum discriminants are invalid.
pub fn parse_data_event_bytes(bytes: &[u8]) -> Option<DataEvent> {
    if bytes.len() != core::mem::size_of::<RawDataEvent>() {
        return None;
    }
    // SAFETY: `RawDataEvent` is plain integer/byte fields with repr(C), and
    // `bytes` length is exactly the struct size.
    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const RawDataEvent) };
    raw.to_data_event()
}

/// Bytes of a DataEvent before its payload. Ring records carry this header
/// plus only `payload_len` payload bytes.
pub const DATA_EVENT_HEADER_LEN: usize = core::mem::offset_of!(DataEvent, payload);

/// The ring shard an event goes to, from its `socket_cookie`.
///
/// Keyed by connection, not by CPU: a connection's packets are produced on
/// whichever CPUs its threads and softirqs run on, so CPU shards would let
/// user space see a response before its request, or a body's packets out of
/// order. With this key every event of one connection (both directions,
/// its SockConnect/SockAccept owner events and its FIN/RST, which all carry
/// the same 5-tuple cookie; or one TLS connection object) lands in the same
/// ring, so the order user space sees per connection is that ring's reserve
/// order, as it was with a single ring. The multiply takes the high bits so
/// that cookies with constant low bits (16-byte aligned SSL* pointers) still
/// spread over the shards.
#[inline(always)]
pub fn ring_shard(socket_cookie: u64, mask: u32) -> u32 {
    ((socket_cookie.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 60) as u32) & mask
}

/// Bidirectional flow cookie for a TC packet's 5-tuple: FNV-1a over the
/// tuple, ordered so both directions get the same cookie, starting from a
/// basis mixed with the per-boot `key` (CONFIG_COOKIE_KEY). Bit 63 is
/// always clear: TLS connection keys (user space) have it set, so a TLS
/// connection object can never alias a TC flow (F18). The socket owner
/// events (sock_monitor.rs) use the same cookie, which keeps a connection's
/// events on one ring shard ([`ring_shard`]).
#[inline(always)]
pub fn tc_flow_cookie(
    key: u64,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
) -> u64 {
    let (a_addr, a_port, b_addr, b_port) = if (src_addr, src_port) <= (dst_addr, dst_port) {
        (src_addr, src_port, dst_addr, dst_port)
    } else {
        (dst_addr, dst_port, src_addr, src_port)
    };

    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET ^ key;
    let bytes: [u8; 13] = [
        (a_addr >> 24) as u8,
        (a_addr >> 16) as u8,
        (a_addr >> 8) as u8,
        a_addr as u8,
        (a_port >> 8) as u8,
        a_port as u8,
        (b_addr >> 24) as u8,
        (b_addr >> 16) as u8,
        (b_addr >> 8) as u8,
        b_addr as u8,
        (b_port >> 8) as u8,
        b_port as u8,
        ip_proto,
    ];

    let mut i = 0;
    while i < 13 {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash & !TLS_KEY_BIT
}

/// Length of the DataEvent record at the start of `bytes` (header plus
/// `payload_len` payload bytes), or `None` if it is truncated or has invalid
/// enum fields. Trailing bytes are allowed: a full fixed-size DataEvent (the
/// PerfEventArray path, capture files) is a record followed by unused payload.
pub fn data_event_record_len(bytes: &[u8]) -> Option<usize> {
    use core::mem::offset_of;
    if bytes.len() < DATA_EVENT_HEADER_LEN {
        return None;
    }
    let field = |off: usize| {
        u32::from_ne_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    EventType::from_u32(field(offset_of!(DataEvent, event_type)))?;
    Direction::from_u32(field(offset_of!(DataEvent, direction)))?;
    TlsLibrary::from_u32(field(offset_of!(DataEvent, tls_library)))?;
    let payload_len = field(offset_of!(DataEvent, payload_len)) as usize;
    if payload_len > MAX_PAYLOAD_SIZE {
        return None;
    }
    let len = DATA_EVENT_HEADER_LEN + payload_len;
    (len <= bytes.len()).then_some(len)
}

/// Copy the DataEvent record at the start of `bytes` into `out`: its header
/// and `payload_len` payload bytes, not the whole 4KB struct. `out.payload`
/// past `payload_len` keeps what it held. Returns false, leaving `out`
/// untouched, if the record is invalid (see [`data_event_record_len`]).
pub fn read_data_event_into(bytes: &[u8], out: &mut DataEvent) -> bool {
    let Some(len) = data_event_record_len(bytes) else {
        return false;
    };
    // SAFETY: len <= size_of::<DataEvent>() (header + at most
    // MAX_PAYLOAD_SIZE), the enum fields were validated above and every
    // other field is plain integers/bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), (out as *mut DataEvent).cast::<u8>(), len);
    }
    true
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::*;

    // ── ABI Size Stability ─────────────────────────────────────────────

    #[test]
    fn test_data_event_size() {
        assert_eq!(
            size_of::<DataEvent>(),
            4192,
            "DataEvent size changed! This breaks kernel↔userspace ABI."
        );
    }

    #[test]
    fn test_process_event_size() {
        assert_eq!(
            size_of::<ProcessEvent>(),
            40,
            "ProcessEvent size changed! This breaks kernel↔userspace ABI."
        );
    }

    #[test]
    fn test_conn_info_size() {
        assert_eq!(
            size_of::<ConnInfo>(),
            40,
            "ConnInfo size changed! This breaks kernel↔userspace ABI."
        );
    }

    // ── Alignment ──────────────────────────────────────────────────────

    #[test]
    fn test_data_event_alignment() {
        assert_eq!(align_of::<DataEvent>(), 8);
    }

    #[test]
    fn test_process_event_alignment() {
        assert_eq!(align_of::<ProcessEvent>(), 8);
    }

    #[test]
    fn test_conn_info_alignment() {
        assert_eq!(align_of::<ConnInfo>(), 8);
    }

    // ── Field Offsets ──────────────────────────────────────────────────

    #[test]
    fn test_data_event_field_offsets() {
        assert_eq!(offset_of!(DataEvent, timestamp_ns), 0);
        assert_eq!(offset_of!(DataEvent, socket_cookie), 8);
        assert_eq!(offset_of!(DataEvent, cgroup_id), 16);
        assert_eq!(offset_of!(DataEvent, stream_off), 24);
        assert_eq!(offset_of!(DataEvent, event_type), 32);
        assert_eq!(offset_of!(DataEvent, direction), 36);
        assert_eq!(offset_of!(DataEvent, pid), 40);
        assert_eq!(offset_of!(DataEvent, tgid), 44);
        assert_eq!(offset_of!(DataEvent, src_addr), 48);
        assert_eq!(offset_of!(DataEvent, dst_addr), 52);
        assert_eq!(offset_of!(DataEvent, payload_len), 56);
        assert_eq!(offset_of!(DataEvent, orig_len), 60);
        assert_eq!(offset_of!(DataEvent, tls_library), 64);
        assert_eq!(offset_of!(DataEvent, tcp_seq), 68);
        assert_eq!(offset_of!(DataEvent, tcp_ack), 72);
        assert_eq!(offset_of!(DataEvent, owner_tgid), 76);
        assert_eq!(offset_of!(DataEvent, acceptor_tgid), 80);
        assert_eq!(offset_of!(DataEvent, scope_gen), 84);
        assert_eq!(offset_of!(DataEvent, src_port), 88);
        assert_eq!(offset_of!(DataEvent, dst_port), 90);
        assert_eq!(offset_of!(DataEvent, ip_proto), 92);
        assert_eq!(offset_of!(DataEvent, tcp_flags), 93);
        assert_eq!(offset_of!(DataEvent, role), 94);
        assert_eq!(offset_of!(DataEvent, _pad), 95);
        assert_eq!(offset_of!(DataEvent, payload), 96);
        assert_eq!(DATA_EVENT_HEADER_LEN, 96);
    }

    #[test]
    fn raw_data_event_mirrors_data_event() {
        use core::mem::offset_of;
        assert_eq!(size_of::<RawDataEvent>(), size_of::<DataEvent>());
        assert_eq!(
            offset_of!(RawDataEvent, payload),
            offset_of!(DataEvent, payload)
        );
        assert_eq!(offset_of!(RawDataEvent, role), offset_of!(DataEvent, role));
        assert_eq!(
            offset_of!(RawDataEvent, scope_gen),
            offset_of!(DataEvent, scope_gen)
        );
        assert_eq!(
            offset_of!(RawDataEvent, event_type),
            offset_of!(DataEvent, event_type)
        );
    }

    #[test]
    fn test_process_event_field_offsets() {
        assert_eq!(offset_of!(ProcessEvent, timestamp_ns), 0);
        assert_eq!(offset_of!(ProcessEvent, event_type), 8);
        assert_eq!(offset_of!(ProcessEvent, pid), 12);
        assert_eq!(offset_of!(ProcessEvent, tgid), 16);
        assert_eq!(offset_of!(ProcessEvent, ppid), 20);
        assert_eq!(offset_of!(ProcessEvent, comm), 24);
    }

    #[test]
    fn test_conn_info_field_offsets() {
        assert_eq!(offset_of!(ConnInfo, socket_cookie), 0);
        assert_eq!(offset_of!(ConnInfo, connect_ts), 8);
        assert_eq!(offset_of!(ConnInfo, src_addr), 16);
        assert_eq!(offset_of!(ConnInfo, dst_addr), 20);
        assert_eq!(offset_of!(ConnInfo, pid), 24);
        assert_eq!(offset_of!(ConnInfo, tgid), 28);
        assert_eq!(offset_of!(ConnInfo, src_port), 32);
        assert_eq!(offset_of!(ConnInfo, dst_port), 34);
        assert_eq!(offset_of!(ConnInfo, _pad), 36);
    }

    // ── Enum Discriminants ─────────────────────────────────────────────

    #[test]
    fn test_event_type_discriminants() {
        assert_eq!(EventType::TcPacket as u32, 0);
        assert_eq!(EventType::TlsData as u32, 1);
        assert_eq!(EventType::ProcessExec as u32, 2);
        assert_eq!(EventType::ProcessExit as u32, 3);
        assert_eq!(EventType::SockConnect as u32, 4);
        assert_eq!(EventType::SockAccept as u32, 5);
        assert_eq!(EventType::SockClose as u32, 6);
        assert_eq!(EventType::UdpSend as u32, 7);
        assert_eq!(EventType::UdpRecv as u32, 8);
        assert_eq!(EventType::TlsClose as u32, 9);
    }

    #[test]
    fn test_direction_discriminants() {
        assert_eq!(Direction::Ingress as u32, 0);
        assert_eq!(Direction::Egress as u32, 1);
    }

    #[test]
    fn test_tls_library_discriminants() {
        assert_eq!(TlsLibrary::None as u32, 0);
        assert_eq!(TlsLibrary::OpenSsl as u32, 1);
        assert_eq!(TlsLibrary::GoTls as u32, 2);
        assert_eq!(TlsLibrary::JavaSsl as u32, 3);
    }

    // ── Zero-Init Safety ───────────────────────────────────────────────

    #[test]
    fn test_data_event_zero_init() {
        // SAFETY: All fields are valid when zero: enums have 0-variants,
        // integers are 0, arrays are zeroed.
        let event: DataEvent = unsafe { core::mem::zeroed() };
        assert_eq!(event.event_type, EventType::TcPacket);
        assert_eq!(event.direction, Direction::Ingress);
        assert_eq!(event.tls_library, TlsLibrary::None);
        assert_eq!(event.payload_len, 0);
    }

    #[test]
    fn test_process_event_zero_init() {
        let event: ProcessEvent = unsafe { core::mem::zeroed() };
        assert_eq!(event.event_type, EventType::TcPacket);
        assert_eq!(event.pid, 0);
    }

    #[test]
    fn test_conn_info_zero_init() {
        let info: ConnInfo = unsafe { core::mem::zeroed() };
        assert_eq!(info.socket_cookie, 0);
        assert_eq!(info.src_port, 0);
    }

    // ── Constant Consistency ───────────────────────────────────────────

    #[test]
    fn test_max_payload_fits_in_data_event() {
        let event: DataEvent = unsafe { core::mem::zeroed() };
        assert_eq!(MAX_PAYLOAD_SIZE, event.payload.len());
    }

    #[test]
    fn test_max_comm_fits_in_process_event() {
        let event: ProcessEvent = unsafe { core::mem::zeroed() };
        assert_eq!(MAX_COMM_SIZE, event.comm.len());
    }

    #[test]
    fn test_config_indices_within_bounds() {
        assert!(CONFIG_CAPTURE_ENABLED < CONFIG_ENTRIES);
        assert!(CONFIG_MAX_PAYLOAD < CONFIG_ENTRIES);
        assert!(CONFIG_USE_RINGBUF < CONFIG_ENTRIES);
        assert!(CONFIG_PID_FILTER_ON < CONFIG_ENTRIES);
        assert!(CONFIG_RING_SHARD_MASK < CONFIG_ENTRIES);
        assert!(CONFIG_COOKIE_KEY < CONFIG_ENTRIES);
        let scope = [
            CONFIG_SCOPE_GEN,
            CONFIG_PID_EPOCH,
            CONFIG_SAMPLE_THRESHOLD,
            CONFIG_HEAD_BYTES,
            CONFIG_SCOPE_MODE,
            CONFIG_SCOPE_ARMED,
            CONFIG_CAPTURE_LOOPBACK,
            CONFIG_PID_CREATOR_RULE,
        ];
        for (i, &idx) in scope.iter().enumerate() {
            assert!(idx < CONFIG_ENTRIES);
            assert!(idx > CONFIG_TCP_SYN_EVENTS, "scope index {idx} reuses one");
            assert!(!scope[..i].contains(&idx), "duplicate index {idx}");
        }
        assert!(DATA_RING_SHARDS.is_power_of_two());
    }

    // ── No Implicit Padding ────────────────────────────────────────────

    #[test]
    fn test_data_event_no_implicit_padding() {
        let expected = 8 + 8 // timestamp_ns, socket_cookie
            + 8 + 8           // cgroup_id, stream_off
            + 4 + 4           // event_type, direction
            + 4 + 4           // pid, tgid
            + 4 + 4           // src_addr, dst_addr
            + 4 + 4           // payload_len, orig_len
            + 4               // tls_library
            + 4 + 4           // tcp_seq, tcp_ack
            + 4 + 4 + 4       // owner_tgid, acceptor_tgid, scope_gen
            + 2 + 2           // src_port, dst_port
            + 1 + 1 + 1 + 1   // ip_proto, tcp_flags, role, _pad
            + MAX_PAYLOAD_SIZE;
        assert_eq!(
            size_of::<DataEvent>(),
            expected,
            "DataEvent has implicit padding — check field ordering"
        );
    }

    #[test]
    fn test_process_event_no_implicit_padding() {
        let expected = 8 + 4 + 4 + 4 + 4 + MAX_COMM_SIZE;
        assert_eq!(
            size_of::<ProcessEvent>(),
            expected,
            "ProcessEvent has implicit padding — check field ordering"
        );
    }

    #[test]
    fn test_conn_info_no_implicit_padding() {
        let expected = 8 + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 4;
        assert_eq!(
            size_of::<ConnInfo>(),
            expected,
            "ConnInfo has implicit padding — check field ordering"
        );
    }
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use core::mem::size_of;

    fn as_bytes(e: &DataEvent) -> &[u8] {
        // SAFETY: DataEvent is repr(C), Copy, with no implicit padding.
        unsafe {
            core::slice::from_raw_parts((e as *const DataEvent).cast(), size_of::<DataEvent>())
        }
    }

    #[test]
    fn ring_shard_stays_in_mask_and_spreads_aligned_pointers() {
        let mut seen = [0u32; DATA_RING_SHARDS];
        for i in 0..4096u64 {
            let ssl_ptr = 0x5555_0000_0000 + i * 0x4a0; // 16-byte aligned, like SSL*
            let s = ring_shard(ssl_ptr, (DATA_RING_SHARDS - 1) as u32);
            seen[s as usize] += 1;
            assert_eq!(ring_shard(ssl_ptr, 0), 0);
            assert!(ring_shard(ssl_ptr, 3) <= 3);
        }
        // Every shard used, none with more than twice its fair share.
        assert!(
            seen.iter()
                .all(|&n| n > 0 && n < 2 * 4096 / DATA_RING_SHARDS as u32),
            "{seen:?}"
        );
    }

    #[test]
    fn tc_flow_cookie_is_symmetric_keyed_and_outside_the_tls_key_space() {
        let (a, b) = (0x0A00_0001, 0x0A00_0002);
        let mut keyed_differs = 0;
        for port in 0..4096u16 {
            let c = tc_flow_cookie(7, a, b, 40000 + port, 80, 6);
            assert_eq!(c, tc_flow_cookie(7, b, a, 80, 40000 + port, 6));
            // F18: a TLS key (bit 63 set) can never equal a TC cookie.
            assert_eq!(c & TLS_KEY_BIT, 0);
            keyed_differs += (c != tc_flow_cookie(8, a, b, 40000 + port, 80, 6)) as u32;
        }
        assert_eq!(keyed_differs, 4096, "the boot key changes every cookie");
    }

    #[test]
    fn record_round_trip_copies_header_and_payload_only() {
        // SAFETY: all-zero is valid for DataEvent.
        let mut e: DataEvent = unsafe { core::mem::zeroed() };
        e.event_type = EventType::TlsData;
        e.direction = Direction::Egress;
        e.tls_library = TlsLibrary::OpenSsl;
        e.socket_cookie = 42;
        e.payload_len = 3;
        e.orig_len = 9;
        e.payload[..3].copy_from_slice(b"abc");
        let bytes = &as_bytes(&e)[..DATA_EVENT_HEADER_LEN + 3];
        assert_eq!(
            data_event_record_len(bytes),
            Some(DATA_EVENT_HEADER_LEN + 3)
        );

        let mut out: DataEvent = unsafe { core::mem::zeroed() };
        out.payload.fill(0xEE);
        assert!(read_data_event_into(bytes, &mut out));
        assert_eq!(out.event_type, EventType::TlsData);
        assert_eq!(out.direction, Direction::Egress);
        assert_eq!((out.socket_cookie, out.orig_len), (42, 9));
        assert_eq!(out.payload_bytes(), b"abc");
        assert_eq!(
            out.payload[3], 0xEE,
            "payload past payload_len is not written"
        );

        // A full fixed-size event is a record followed by unused bytes.
        assert_eq!(
            data_event_record_len(as_bytes(&e)),
            Some(DATA_EVENT_HEADER_LEN + 3)
        );
    }

    #[test]
    fn record_accepts_header_only_and_size_class_records() {
        // cgroup_skb close record: the 96-byte header, nothing after it.
        let mut e: DataEvent = unsafe { core::mem::zeroed() };
        e.event_type = EventType::SockClose;
        e.socket_cookie = 7;
        let bytes = &as_bytes(&e)[..DATA_EVENT_HEADER_LEN];
        assert_eq!(data_event_record_len(bytes), Some(DATA_EVENT_HEADER_LEN));
        let mut out: DataEvent = unsafe { core::mem::zeroed() };
        assert!(read_data_event_into(bytes, &mut out));
        assert_eq!(
            (out.event_type, out.socket_cookie),
            (EventType::SockClose, 7)
        );
        assert!(out.payload_bytes().is_empty());

        // cgroup_skb packet record: reserved at a payload size class (here
        // 64 bytes) larger than what it carries; the rest is not payload.
        e.event_type = EventType::TcPacket;
        e.payload_len = 5;
        e.orig_len = 5;
        e.payload[..5].copy_from_slice(b"hello");
        e.payload[5..64].fill(0xAA);
        let bytes = &as_bytes(&e)[..DATA_EVENT_HEADER_LEN + 64];
        assert_eq!(
            data_event_record_len(bytes),
            Some(DATA_EVENT_HEADER_LEN + 5)
        );
        assert!(read_data_event_into(bytes, &mut out));
        assert_eq!(out.payload_bytes(), b"hello");
        assert_eq!(out.payload[5], 0, "slack past payload_len is not copied");
    }

    #[test]
    fn record_rejects_truncated_oversized_and_invalid() {
        let mut e: DataEvent = unsafe { core::mem::zeroed() };
        e.payload_len = 10;
        assert_eq!(
            data_event_record_len(&as_bytes(&e)[..DATA_EVENT_HEADER_LEN + 9]),
            None
        );
        assert_eq!(
            data_event_record_len(&as_bytes(&e)[..DATA_EVENT_HEADER_LEN - 1]),
            None
        );
        e.payload_len = MAX_PAYLOAD_SIZE as u32 + 1;
        assert_eq!(data_event_record_len(as_bytes(&e)), None);
        let mut bytes = [0u8; DATA_EVENT_HEADER_LEN];
        let at = core::mem::offset_of!(DataEvent, event_type);
        bytes[at..at + 4].copy_from_slice(&9999u32.to_ne_bytes());
        assert_eq!(data_event_record_len(&bytes), None);
        let mut out: DataEvent = unsafe { core::mem::zeroed() };
        out.pid = 7;
        assert!(!read_data_event_into(&bytes, &mut out));
        assert_eq!(out.pid, 7);
    }
}

// User-feature-dependent tests (need aya::Pod and utility methods)
#[cfg(all(test, feature = "user"))]
mod user_tests {
    use super::*;
    use core::mem::size_of;

    // ── Utility Method Tests ───────────────────────────────────────────

    fn make_data_event() -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn test_payload_bytes_empty() {
        let event = make_data_event();
        assert!(event.payload_bytes().is_empty());
    }

    #[test]
    fn test_payload_bytes_partial() {
        let mut event = make_data_event();
        event.payload_len = 100;
        event.payload[..100].fill(0xAB);
        let bytes = event.payload_bytes();
        assert_eq!(bytes.len(), 100);
        assert!(bytes.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_payload_bytes_max() {
        let mut event = make_data_event();
        event.payload_len = MAX_PAYLOAD_SIZE as u32;
        assert_eq!(event.payload_bytes().len(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_payload_bytes_overflow_clamped() {
        let mut event = make_data_event();
        event.payload_len = MAX_PAYLOAD_SIZE as u32 + 999;
        assert_eq!(event.payload_bytes().len(), MAX_PAYLOAD_SIZE);
    }

    fn make_process_event() -> ProcessEvent {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn test_comm_str_normal() {
        let mut event = make_process_event();
        let name = b"nginx";
        event.comm[..name.len()].copy_from_slice(name);
        assert_eq!(event.comm_str(), "nginx");
    }

    #[test]
    fn test_comm_str_full() {
        let mut event = make_process_event();
        event.comm = *b"0123456789abcdef";
        assert_eq!(event.comm_str(), "0123456789abcdef");
    }

    #[test]
    fn test_comm_str_empty() {
        let event = make_process_event();
        assert_eq!(event.comm_str(), "");
    }

    #[test]
    fn test_comm_str_invalid_utf8() {
        let mut event = make_process_event();
        event.comm[0] = 0xFF;
        event.comm[1] = 0xFE;
        assert_eq!(event.comm_str(), "<invalid>");
    }

    #[test]
    fn test_parse_data_event_bytes_round_trip() {
        let mut event = make_data_event();
        event.event_type = EventType::TlsData;
        event.direction = Direction::Egress;
        event.tls_library = TlsLibrary::OpenSsl;
        event.payload_len = 3;
        event.payload[..3].copy_from_slice(b"abc");

        // SAFETY: DataEvent is repr(C), Copy, pointer valid for struct size.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const DataEvent as *const u8,
                size_of::<DataEvent>(),
            )
        };

        let parsed = parse_data_event_bytes(bytes).expect("valid bytes should parse");
        assert_eq!(parsed.event_type, EventType::TlsData);
        assert_eq!(parsed.direction, Direction::Egress);
        assert_eq!(parsed.tls_library, TlsLibrary::OpenSsl);
        assert_eq!(parsed.payload_bytes(), b"abc");
    }

    #[test]
    fn test_parse_data_event_bytes_rejects_invalid_enum() {
        let mut bytes = [0u8; size_of::<DataEvent>()];
        // set event_type to the invalid discriminant 9999
        let at = core::mem::offset_of!(DataEvent, event_type);
        bytes[at..at + 4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(parse_data_event_bytes(&bytes).is_none());
    }
}
