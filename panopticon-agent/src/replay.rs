#![allow(dead_code)]
//! Deterministic replay system for captured network events.
//!
//! Provides `CaptureWriter` and `CaptureReader` for serializing/deserializing
//! `DataEvent` captures to a binary file format. This enables:
//! - Offline replay of production traffic for debugging
//! - Deterministic test inputs for parser development
//! - Regression testing against known-good captures
//!
//! ## File Format
//!
//! ```text
//! [Magic: 6 bytes "PNCAP\x01"]
//! [Header: version(u32) | timestamp_ns(u64) | event_count(u64)]
//! [Event 0: length(u32) | DataEvent bytes]
//! [Event 1: length(u32) | DataEvent bytes]
//! ...
//! ```

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::mem;
use std::path::Path;

use panopticon_common::DataEvent;
#[cfg(target_os = "linux")]
use panopticon_common::parse_data_event_bytes;
#[cfg(not(target_os = "linux"))]
use panopticon_common::{Direction, EventType, MAX_PAYLOAD_SIZE, TlsLibrary};

/// Magic bytes identifying a Panopticon capture file.
const MAGIC: &[u8; 6] = b"PNCAP\x01";

/// Current file format version.
const FORMAT_VERSION: u32 = 1;

#[cfg(not(target_os = "linux"))]
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

#[cfg(not(target_os = "linux"))]
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

#[cfg(not(target_os = "linux"))]
fn parse_data_event_bytes(bytes: &[u8]) -> Option<DataEvent> {
    if bytes.len() != mem::size_of::<RawDataEvent>() {
        return None;
    }
    // SAFETY: `RawDataEvent` is repr(C) with plain integer/byte fields, and
    // `bytes` length is checked to exactly match the struct size.
    let raw = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawDataEvent) };
    raw.to_data_event()
}

/// File header metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureHeader {
    pub version: u32,
    /// Nanosecond timestamp of when the capture started.
    pub timestamp_ns: u64,
    /// Total number of events in the file.
    pub event_count: u64,
}

/// Writes `DataEvent`s to a binary capture file.
///
/// Events are written as length-prefixed raw bytes. The header is finalized
/// when the writer is finished (via `finish()` or `Drop`).
pub struct CaptureWriter<W: Write> {
    writer: BufWriter<W>,
    start_timestamp_ns: u64,
    event_count: u64,
}

impl<W: Write> CaptureWriter<W> {
    /// Create a new capture writer. Writes the magic bytes and a placeholder header.
    pub fn new(inner: W, start_timestamp_ns: u64) -> io::Result<Self> {
        let mut writer = BufWriter::new(inner);

        // Write magic
        writer.write_all(MAGIC)?;

        // Write placeholder header (will be updated on finish if seekable)
        writer.write_all(&FORMAT_VERSION.to_le_bytes())?;
        writer.write_all(&start_timestamp_ns.to_le_bytes())?;
        writer.write_all(&0u64.to_le_bytes())?; // event_count placeholder

        Ok(Self {
            writer,
            start_timestamp_ns,
            event_count: 0,
        })
    }

    /// Write a single `DataEvent` to the capture file.
    ///
    /// The event is written as `[u32 length][raw bytes]`.
    pub fn write_event(&mut self, event: &DataEvent) -> io::Result<()> {
        let event_size = mem::size_of::<DataEvent>() as u32;
        self.writer.write_all(&event_size.to_le_bytes())?;

        // SAFETY: DataEvent is #[repr(C)], Copy, and contains no pointers.
        // This is the same guarantee that makes it safe for eBPF ring buffer transfer.
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(event as *const DataEvent as *const u8, event_size as usize)
        };
        self.writer.write_all(bytes)?;

        self.event_count += 1;
        Ok(())
    }

    /// Returns the number of events written so far.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Flush the writer and return the final event count.
    ///
    /// Note: The header event_count field is only accurate if the underlying
    /// writer supports seeking. For non-seekable writers (pipes, network),
    /// the header will contain 0 and consumers should count events while reading.
    pub fn finish(mut self) -> io::Result<u64> {
        self.writer.flush()?;
        Ok(self.event_count)
    }

    /// Consume the writer and return a finalized byte buffer.
    /// This re-writes the header with the correct event count.
    pub fn into_bytes(self) -> io::Result<Vec<u8>>
    where
        W: Into<Vec<u8>>,
    {
        let count = self.event_count;
        let ts = self.start_timestamp_ns;
        let inner = self.writer.into_inner().map_err(|e| e.into_error())?;
        let mut buf: Vec<u8> = inner.into();

        // Patch the event_count in the header (offset: MAGIC + version + timestamp_ns)
        let count_offset = MAGIC.len() + 4 + 8;
        if buf.len() >= count_offset + 8 {
            buf[count_offset..count_offset + 8].copy_from_slice(&count.to_le_bytes());
        }

        // Also ensure timestamp is correct
        let ts_offset = MAGIC.len() + 4;
        if buf.len() >= ts_offset + 8 {
            buf[ts_offset..ts_offset + 8].copy_from_slice(&ts.to_le_bytes());
        }

        Ok(buf)
    }
}

/// Reads `DataEvent`s from a binary capture file.
#[derive(Debug)]
pub struct CaptureReader<R: Read> {
    reader: BufReader<R>,
    header: CaptureHeader,
    events_read: u64,
}

impl<R: Read> CaptureReader<R> {
    /// Open a capture file and read its header.
    pub fn new(inner: R) -> io::Result<Self> {
        let mut reader = BufReader::new(inner);

        // Read and verify magic
        let mut magic = [0u8; 6];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid capture file magic: expected {:?}, got {:?}",
                    MAGIC, magic
                ),
            ));
        }

        // Read header
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        let version = u32::from_le_bytes(version_buf);

        if version != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported capture format version: {} (expected {})",
                    version, FORMAT_VERSION
                ),
            ));
        }

        let mut ts_buf = [0u8; 8];
        reader.read_exact(&mut ts_buf)?;
        let timestamp_ns = u64::from_le_bytes(ts_buf);

        let mut count_buf = [0u8; 8];
        reader.read_exact(&mut count_buf)?;
        let event_count = u64::from_le_bytes(count_buf);

        let header = CaptureHeader {
            version,
            timestamp_ns,
            event_count,
        };

        Ok(Self {
            reader,
            header,
            events_read: 0,
        })
    }

    /// Returns the file header.
    pub fn header(&self) -> &CaptureHeader {
        &self.header
    }

    /// Returns the number of events read so far.
    pub fn events_read(&self) -> u64 {
        self.events_read
    }

    /// Read the next `DataEvent` from the capture file.
    ///
    /// Returns `None` at end of file.
    pub fn read_event(&mut self) -> io::Result<Option<DataEvent>> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let event_len = u32::from_le_bytes(len_buf) as usize;

        let expected_size = mem::size_of::<DataEvent>();
        if event_len != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "event size mismatch: file has {} bytes, expected {}",
                    event_len, expected_size
                ),
            ));
        }

        // Read event bytes
        let mut event_bytes = vec![0u8; event_len];
        self.reader.read_exact(&mut event_bytes)?;

        let event = parse_data_event_bytes(&event_bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DataEvent payload (bad enum discriminant or length)",
            )
        })?;

        self.events_read += 1;
        Ok(Some(event))
    }

    /// Read all remaining events into a Vec.
    pub fn read_all(&mut self) -> io::Result<Vec<DataEvent>> {
        let mut events = Vec::new();
        while let Some(event) = self.read_event()? {
            events.push(event);
        }
        Ok(events)
    }
}

/// Convenience: write events to a file path.
///
/// Patches the header with the correct event count after all events are written.
pub fn write_capture_file(
    path: &Path,
    events: &[DataEvent],
    start_timestamp_ns: u64,
) -> io::Result<u64> {
    use std::io::Seek;

    let file = std::fs::File::create(path)?;
    let mut writer = CaptureWriter::new(file, start_timestamp_ns)?;
    for event in events {
        writer.write_event(event)?;
    }
    let count = writer.event_count;
    let mut inner = writer.writer.into_inner().map_err(|e| e.into_error())?;

    // Seek back to the event_count field in the header and patch it
    let count_offset = (MAGIC.len() + 4 + 8) as u64;
    inner.seek(io::SeekFrom::Start(count_offset))?;
    inner.write_all(&count.to_le_bytes())?;
    inner.flush()?;

    Ok(count)
}

/// Convenience: read all events from a file path.
pub fn read_capture_file(path: &Path) -> io::Result<(CaptureHeader, Vec<DataEvent>)> {
    let file = std::fs::File::open(path)?;
    let mut reader = CaptureReader::new(file)?;
    let header = reader.header().clone();
    let events = reader.read_all()?;
    Ok((header, events))
}

#[cfg(test)]
mod tests {
    use panopticon_common::{Direction, EventType, TlsLibrary};

    use super::*;

    /// Helper: create a DataEvent with specific fields for testing.
    fn make_test_event(
        timestamp_ns: u64,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent (all enums have a 0 variant)
        let mut event: DataEvent = unsafe { std::mem::zeroed() };
        event.timestamp_ns = timestamp_ns;
        event.event_type = EventType::TcPacket;
        event.direction = Direction::Egress;
        event.src_port = src_port;
        event.dst_port = dst_port;
        event.pid = 1234;
        event.tgid = 1234;
        event.src_addr = 0x0100007f; // 127.0.0.1
        event.dst_addr = 0x0200007f; // 127.0.0.2
        event.ip_proto = 6; // TCP
        event.tls_library = TlsLibrary::None;

        let len = payload.len().min(panopticon_common::MAX_PAYLOAD_SIZE);
        event.payload[..len].copy_from_slice(&payload[..len]);
        event.payload_len = len as u32;

        event
    }

    #[test]
    fn test_round_trip_single_event() {
        let event = make_test_event(1_000_000, 54321, 80, b"GET / HTTP/1.1\r\n\r\n");

        let mut buf = Vec::new();
        {
            let mut writer = CaptureWriter::new(&mut buf, 1_000_000).unwrap();
            writer.write_event(&event).unwrap();
            assert_eq!(writer.event_count(), 1);
            writer.finish().unwrap();
        }

        let cursor = io::Cursor::new(&buf);
        let mut reader = CaptureReader::new(cursor).unwrap();
        assert_eq!(reader.header().version, FORMAT_VERSION);
        assert_eq!(reader.header().timestamp_ns, 1_000_000);

        let read_event = reader.read_event().unwrap().unwrap();
        assert_eq!(read_event.timestamp_ns, event.timestamp_ns);
        assert_eq!(read_event.src_port, event.src_port);
        assert_eq!(read_event.dst_port, event.dst_port);
        assert_eq!(read_event.pid, event.pid);
        assert_eq!(read_event.payload_len, event.payload_len);
        assert_eq!(
            &read_event.payload[..read_event.payload_len as usize],
            &event.payload[..event.payload_len as usize]
        );

        // No more events
        assert!(reader.read_event().unwrap().is_none());
    }

    #[test]
    fn test_round_trip_multiple_events() {
        let events = vec![
            make_test_event(1_000, 54321, 80, b"GET /index.html HTTP/1.1\r\n\r\n"),
            make_test_event(2_000, 80, 54321, b"HTTP/1.1 200 OK\r\n\r\n"),
            make_test_event(3_000, 54322, 3306, &[0x03, 0x00, 0x00, 0x00]),
        ];

        let writer = CaptureWriter::new(Vec::new(), 1_000).unwrap();
        let mut writer = writer;
        for event in &events {
            writer.write_event(event).unwrap();
        }
        let buf = writer.into_bytes().unwrap();

        let cursor = io::Cursor::new(&buf);
        let mut reader = CaptureReader::new(cursor).unwrap();
        assert_eq!(reader.header().event_count, 3);

        let read_events = reader.read_all().unwrap();
        assert_eq!(read_events.len(), 3);

        for (original, read) in events.iter().zip(read_events.iter()) {
            assert_eq!(original.timestamp_ns, read.timestamp_ns);
            assert_eq!(original.src_port, read.src_port);
            assert_eq!(original.dst_port, read.dst_port);
            assert_eq!(original.payload_len, read.payload_len);
        }

        assert_eq!(reader.events_read(), 3);
    }

    #[test]
    fn test_empty_capture() {
        let writer = CaptureWriter::new(Vec::new(), 42).unwrap();
        let buf = writer.into_bytes().unwrap();

        let cursor = io::Cursor::new(&buf);
        let mut reader = CaptureReader::new(cursor).unwrap();
        assert_eq!(reader.header().event_count, 0);
        assert_eq!(reader.header().timestamp_ns, 42);

        let events = reader.read_all().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_invalid_magic() {
        let bad_data = b"BADMAGIC_AND_MORE_BYTES_HERE";
        let cursor = io::Cursor::new(bad_data);
        let result = CaptureReader::new(cursor);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid capture file magic"));
    }

    #[test]
    fn test_truncated_header() {
        // Only magic, no header
        let cursor = io::Cursor::new(MAGIC.as_slice());
        let result = CaptureReader::new(cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_preserves_all_fields() {
        let mut event = make_test_event(999_999, 12345, 8080, b"test payload data");
        event.event_type = EventType::TlsData;
        event.direction = Direction::Ingress;
        event.tls_library = TlsLibrary::OpenSsl;
        event.socket_cookie = 0xDEADBEEF;
        event.src_addr = 0x01020304;
        event.dst_addr = 0x05060708;
        event.ip_proto = 17; // UDP

        let writer = CaptureWriter::new(Vec::new(), 0).unwrap();
        let mut writer = writer;
        writer.write_event(&event).unwrap();
        let buf = writer.into_bytes().unwrap();

        let cursor = io::Cursor::new(&buf);
        let mut reader = CaptureReader::new(cursor).unwrap();
        let read = reader.read_event().unwrap().unwrap();

        assert_eq!(read.timestamp_ns, 999_999);
        assert_eq!(read.event_type, EventType::TlsData);
        assert_eq!(read.direction, Direction::Ingress);
        assert_eq!(read.tls_library, TlsLibrary::OpenSsl);
        assert_eq!(read.socket_cookie, 0xDEADBEEF);
        assert_eq!(read.src_addr, 0x01020304);
        assert_eq!(read.dst_addr, 0x05060708);
        assert_eq!(read.src_port, 12345);
        assert_eq!(read.dst_port, 8080);
        assert_eq!(read.ip_proto, 17);
        assert_eq!(read.pid, 1234);
    }

    #[test]
    fn test_large_payload_event() {
        let large_payload = vec![0xAB; panopticon_common::MAX_PAYLOAD_SIZE];
        let event = make_test_event(1, 1, 2, &large_payload);
        assert_eq!(
            event.payload_len as usize,
            panopticon_common::MAX_PAYLOAD_SIZE
        );

        let writer = CaptureWriter::new(Vec::new(), 0).unwrap();
        let mut writer = writer;
        writer.write_event(&event).unwrap();
        let buf = writer.into_bytes().unwrap();

        let cursor = io::Cursor::new(&buf);
        let mut reader = CaptureReader::new(cursor).unwrap();
        let read = reader.read_event().unwrap().unwrap();
        assert_eq!(
            read.payload_len as usize,
            panopticon_common::MAX_PAYLOAD_SIZE
        );
        assert!(read.payload.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_file_round_trip() {
        let dir = std::env::temp_dir().join("panopticon_replay_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_capture.pncap");

        let events = vec![
            make_test_event(100, 54321, 80, b"GET /health HTTP/1.1\r\n\r\n"),
            make_test_event(200, 80, 54321, b"HTTP/1.1 200 OK\r\n\r\nOK"),
        ];

        let count = write_capture_file(&path, &events, 100).unwrap();
        assert_eq!(count, 2);

        let (header, read_events) = read_capture_file(&path).unwrap();
        assert_eq!(header.event_count, 2);
        assert_eq!(header.timestamp_ns, 100);
        assert_eq!(read_events.len(), 2);
        assert_eq!(read_events[0].timestamp_ns, 100);
        assert_eq!(read_events[1].timestamp_ns, 200);

        // Cleanup
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_into_bytes_patches_header() {
        let events = vec![
            make_test_event(1, 1, 2, b"a"),
            make_test_event(2, 3, 4, b"b"),
            make_test_event(3, 5, 6, b"c"),
        ];

        let mut writer = CaptureWriter::new(Vec::new(), 42).unwrap();
        for event in &events {
            writer.write_event(event).unwrap();
        }
        let buf = writer.into_bytes().unwrap();

        // Verify the event_count in the header is patched correctly
        let count_offset = MAGIC.len() + 4 + 8;
        let count = u64::from_le_bytes(buf[count_offset..count_offset + 8].try_into().unwrap());
        assert_eq!(count, 3);
    }
}
