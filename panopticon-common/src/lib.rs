#![no_std]

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

/// Size of the per-CPU TLS scratch map.
pub const TLS_SCRATCH_SIZE: u32 = 8192;

// Config array indices
pub const CONFIG_CAPTURE_ENABLED: u32 = 0;
pub const CONFIG_MAX_PAYLOAD: u32 = 1;
pub const CONFIG_USE_RINGBUF: u32 = 2;
pub const CONFIG_PID_FILTER_ON: u32 = 3;

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
/// At ~4152 bytes this MUST be allocated via RingBuf reserve in eBPF,
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
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataEvent {
    // 8-byte aligned fields first
    pub timestamp_ns: u64,
    pub socket_cookie: u64,
    // 4-byte aligned fields
    pub event_type: EventType,
    pub direction: Direction,
    pub pid: u32,
    pub tgid: u32,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub payload_len: u32,
    pub tls_library: TlsLibrary,
    // 2-byte aligned fields
    pub src_port: u16,
    pub dst_port: u16,
    // 1-byte aligned fields
    pub ip_proto: u8,
    pub _pad: [u8; 3],
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

#[cfg(feature = "user")]
// SAFETY: DataEvent is #[repr(C)], Copy, contains no pointers.
// Explicit `_pad` field is zeroed by producers. Verified by ABI tests.
unsafe impl aya::Pod for DataEvent {}

#[cfg(feature = "user")]
// SAFETY: ProcessEvent is #[repr(C)], Copy, no pointers.
unsafe impl aya::Pod for ProcessEvent {}

#[cfg(feature = "user")]
// SAFETY: ConnInfo is #[repr(C)], Copy, no pointers.
unsafe impl aya::Pod for ConnInfo {}

// ── Utility Methods (user-space only) ──────────────────────────────────────

#[cfg(feature = "user")]
impl DataEvent {
    /// Returns the valid payload slice, clamped to `MAX_PAYLOAD_SIZE`.
    pub fn payload_bytes(&self) -> &[u8] {
        let len = (self.payload_len as usize).min(MAX_PAYLOAD_SIZE);
        &self.payload[..len]
    }
}

#[cfg(feature = "user")]
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

#[cfg(feature = "user")]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawDataEvent {
    pub timestamp_ns: u64,
    pub socket_cookie: u64,
    pub event_type: u32,
    pub direction: u32,
    pub pid: u32,
    pub tgid: u32,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub payload_len: u32,
    pub tls_library: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
    pub _pad: [u8; 3],
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

#[cfg(feature = "user")]
impl RawDataEvent {
    fn to_data_event(self) -> Option<DataEvent> {
        Some(DataEvent {
            timestamp_ns: self.timestamp_ns,
            socket_cookie: self.socket_cookie,
            event_type: EventType::from_u32(self.event_type)?,
            direction: Direction::from_u32(self.direction)?,
            pid: self.pid,
            tgid: self.tgid,
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            payload_len: self.payload_len,
            tls_library: TlsLibrary::from_u32(self.tls_library)?,
            src_port: self.src_port,
            dst_port: self.dst_port,
            ip_proto: self.ip_proto,
            _pad: self._pad,
            payload: self.payload,
        })
    }
}

/// Parse a `DataEvent` from raw bytes and validate enum fields.
///
/// Returns `None` if the byte length is wrong or enum discriminants are invalid.
#[cfg(feature = "user")]
pub fn parse_data_event_bytes(bytes: &[u8]) -> Option<DataEvent> {
    if bytes.len() != core::mem::size_of::<RawDataEvent>() {
        return None;
    }
    // SAFETY: `RawDataEvent` is plain integer/byte fields with repr(C), and
    // `bytes` length is exactly the struct size.
    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const RawDataEvent) };
    raw.to_data_event()
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
            4152,
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
        assert_eq!(offset_of!(DataEvent, event_type), 16);
        assert_eq!(offset_of!(DataEvent, direction), 20);
        assert_eq!(offset_of!(DataEvent, pid), 24);
        assert_eq!(offset_of!(DataEvent, tgid), 28);
        assert_eq!(offset_of!(DataEvent, src_addr), 32);
        assert_eq!(offset_of!(DataEvent, dst_addr), 36);
        assert_eq!(offset_of!(DataEvent, payload_len), 40);
        assert_eq!(offset_of!(DataEvent, tls_library), 44);
        assert_eq!(offset_of!(DataEvent, src_port), 48);
        assert_eq!(offset_of!(DataEvent, dst_port), 50);
        assert_eq!(offset_of!(DataEvent, ip_proto), 52);
        assert_eq!(offset_of!(DataEvent, _pad), 53);
        assert_eq!(offset_of!(DataEvent, payload), 56);
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
    }

    // ── No Implicit Padding ────────────────────────────────────────────

    #[test]
    fn test_data_event_no_implicit_padding() {
        let expected = 8 + 8 // timestamp_ns, socket_cookie
            + 4 + 4           // event_type, direction
            + 4 + 4           // pid, tgid
            + 4 + 4           // src_addr, dst_addr
            + 4 + 4           // payload_len, tls_library
            + 2 + 2           // src_port, dst_port
            + 1 + 3           // ip_proto, _pad
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
        // event_type offset = 16, set to invalid discriminant 9999
        bytes[16..20].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(parse_data_event_bytes(&bytes).is_none());
    }
}
