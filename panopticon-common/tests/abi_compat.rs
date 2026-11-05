//! Cross-verification tests that simulate the kernel→userspace data path
//! by serializing structs to raw bytes and reading them back.

use panopticon_common::{
    ConnInfo, DataEvent, Direction, EventType, MAX_PAYLOAD_SIZE, ProcessEvent, TlsLibrary,
};

/// Helper: view any Copy type as a byte slice.
fn as_bytes<T: Copy>(val: &T) -> &[u8] {
    // SAFETY: T is Copy and #[repr(C)], reading raw bytes is always safe.
    unsafe { core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>()) }
}

/// Helper: read a T from a byte slice.
///
/// # Safety
/// The byte slice must be at least `size_of::<T>()` bytes and properly aligned.
unsafe fn from_bytes<T: Copy>(bytes: &[u8]) -> T {
    assert!(bytes.len() >= core::mem::size_of::<T>());
    // SAFETY: caller guarantees size and alignment.
    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) }
}

#[test]
fn test_data_event_round_trip() {
    let mut event: DataEvent = unsafe { core::mem::zeroed() };
    event.timestamp_ns = 0x1234_5678_9ABC_DEF0;
    event.socket_cookie = 42;
    event.event_type = EventType::TlsData;
    event.direction = Direction::Egress;
    event.pid = 1000;
    event.tgid = 1000;
    event.src_addr = 0x0A000001; // 10.0.0.1
    event.dst_addr = 0x0A000002;
    event.payload_len = 5;
    event.tls_library = TlsLibrary::OpenSsl;
    event.src_port = 8080;
    event.dst_port = 443;
    event.ip_proto = 6; // TCP
    event.tcp_seq = 0xFFFF_FFF0;
    event.tcp_ack = 0x0102_0304;
    event.payload[..5].copy_from_slice(b"hello");

    let bytes = as_bytes(&event);
    assert_eq!(bytes.len(), core::mem::size_of::<DataEvent>());

    let restored: DataEvent = unsafe { from_bytes(bytes) };
    assert_eq!(restored.timestamp_ns, 0x1234_5678_9ABC_DEF0);
    assert_eq!(restored.socket_cookie, 42);
    assert_eq!(restored.event_type, EventType::TlsData);
    assert_eq!(restored.direction, Direction::Egress);
    assert_eq!(restored.pid, 1000);
    assert_eq!(restored.src_addr, 0x0A000001);
    assert_eq!(restored.payload_len, 5);
    assert_eq!(restored.tls_library, TlsLibrary::OpenSsl);
    assert_eq!(restored.src_port, 8080);
    assert_eq!(restored.dst_port, 443);
    assert_eq!(restored.ip_proto, 6);
    assert_eq!(restored.tcp_seq, 0xFFFF_FFF0);
    assert_eq!(restored.tcp_ack, 0x0102_0304);
    assert_eq!(&restored.payload[..5], b"hello");
}

#[test]
fn test_process_event_round_trip() {
    let mut event: ProcessEvent = unsafe { core::mem::zeroed() };
    event.timestamp_ns = 999;
    event.event_type = EventType::ProcessExec;
    event.pid = 42;
    event.tgid = 42;
    event.ppid = 1;
    event.comm[..5].copy_from_slice(b"nginx");

    let bytes = as_bytes(&event);
    let restored: ProcessEvent = unsafe { from_bytes(bytes) };
    assert_eq!(restored.timestamp_ns, 999);
    assert_eq!(restored.event_type, EventType::ProcessExec);
    assert_eq!(restored.pid, 42);
    assert_eq!(restored.ppid, 1);
    assert_eq!(&restored.comm[..5], b"nginx");
}

#[test]
fn test_conn_info_round_trip() {
    let mut info: ConnInfo = unsafe { core::mem::zeroed() };
    info.socket_cookie = 0xDEAD;
    info.connect_ts = 12345;
    info.src_addr = 0x7F000001; // 127.0.0.1
    info.dst_addr = 0xC0A80001; // 192.168.0.1
    info.pid = 100;
    info.src_port = 12345;
    info.dst_port = 80;

    let bytes = as_bytes(&info);
    let restored: ConnInfo = unsafe { from_bytes(bytes) };
    assert_eq!(restored.socket_cookie, 0xDEAD);
    assert_eq!(restored.connect_ts, 12345);
    assert_eq!(restored.src_addr, 0x7F000001);
    assert_eq!(restored.dst_port, 80);
}

#[test]
fn test_data_event_specific_byte_offsets() {
    let mut event: DataEvent = unsafe { core::mem::zeroed() };
    event.src_port = 0x1F90; // 8080
    event.ip_proto = 6;
    event.orig_len = 65_000;
    event.tcp_seq = 0xA1B2_C3D4;
    event.tcp_ack = 0x0506_0708;
    event.cgroup_id = 0x1122_3344_5566_7788;
    event.stream_off = 4095;
    event.owner_tgid = 31;
    event.acceptor_tgid = 32;
    event.scope_gen = 33;
    event.role = 2;

    let bytes = as_bytes(&event);
    let u32_at =
        |o: usize| u32::from_ne_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    let u64_at = |o: usize| u64::from_ne_bytes(bytes[o..o + 8].try_into().unwrap());
    assert_eq!(u64_at(16), 0x1122_3344_5566_7788); // cgroup_id
    assert_eq!(u64_at(24), 4095); // stream_off
    assert_eq!(u32_at(60), 65_000); // orig_len
    assert_eq!(u32_at(68), 0xA1B2_C3D4); // tcp_seq
    assert_eq!(u32_at(72), 0x0506_0708); // tcp_ack
    assert_eq!((u32_at(76), u32_at(80), u32_at(84)), (31, 32, 33)); // owner, acceptor, gen
    // src_port is at offset 88 (2 bytes, native endian)
    let src_port = u16::from_ne_bytes([bytes[88], bytes[89]]);
    assert_eq!(src_port, 0x1F90);
    assert_eq!(bytes[92], 6); // ip_proto
    assert_eq!(bytes[94], 2); // role
}

#[test]
fn test_max_payload_event() {
    let mut event: DataEvent = unsafe { core::mem::zeroed() };
    event.payload_len = MAX_PAYLOAD_SIZE as u32;
    event.payload.fill(0xAA);

    let bytes = as_bytes(&event);
    // Payload starts at offset 96
    assert!(bytes[96..96 + MAX_PAYLOAD_SIZE].iter().all(|&b| b == 0xAA));
}
