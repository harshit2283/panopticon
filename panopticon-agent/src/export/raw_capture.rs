//! Raw capture: every event the agent processes, **unredacted**, in the PNCAP
//! format (see `replay.rs`), for users who need the bytes themselves — their
//! own PII classifiers, evidence retention, or checking the agent's output.
//!
//! - Written by a dedicated thread so file IO never blocks workers; when the
//!   writer falls behind, events are dropped and counted
//!   (`panopticon_raw_capture_dropped_total`).
//! - The file is created owner-only (0600) and truncated at startup.
//! - Writing stops at `max_bytes` so a forgotten flag cannot fill the disk.
//! - Payloads are the captured bytes: up to 4096 per packet / TLS buffer;
//!   `orig_len` in each record says how large the original was.
//!
//! `decode_to_jsonl` turns a capture into JSON lines (metadata + base64
//! payload); exposed as `panopticon-agent --decode-capture <FILE>`.

use std::fs::{OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use panopticon_common::DataEvent;
use tracing::{error, info, warn};

use crate::replay::{CaptureReader, CaptureWriter};

/// Bytes per record in the file: u32 length prefix + fixed-size DataEvent.
const RECORD_BYTES: u64 = 4 + std::mem::size_of::<DataEvent>() as u64;
/// Magic + version + start timestamp + event count.
const HEADER_BYTES: u64 = 6 + 4 + 8 + 8;
/// How often the writer flushes when idle and checks for shutdown.
const WRITER_TICK: Duration = Duration::from_millis(200);

/// Cloneable sender side, held by every worker.
#[derive(Clone)]
pub struct RawCaptureHandle {
    tx: SyncSender<DataEvent>,
    /// Set by the writer when it stops (size cap or IO error): workers then
    /// skip recording instead of counting every event as a drop.
    stopped: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
}

impl RawCaptureHandle {
    /// Queue an event for the raw capture file. Never blocks.
    pub fn record(&self, event: &DataEvent) {
        if self.stopped.load(Ordering::Relaxed) {
            return;
        }
        match self.tx.try_send(*event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => self.stopped.store(true, Ordering::Relaxed),
        }
    }

    /// Events dropped because the writer could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Ask the writer to drain what is queued, flush and exit.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Open `path` and start the writer thread.
pub fn spawn(
    path: &str,
    max_bytes: u64,
    queue_capacity: usize,
    start_timestamp_ns: u64,
) -> Result<(RawCaptureHandle, JoinHandle<()>)> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open raw capture file {path}"))?;
    // `mode` only applies on creation; tighten a pre-existing file too.
    std::fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict permissions on {path}"))?;
    let writer = CaptureWriter::new(file, start_timestamp_ns)
        .with_context(|| format!("failed to write capture header to {path}"))?;

    let (tx, rx) = sync_channel(queue_capacity);
    let handle = RawCaptureHandle {
        tx,
        stopped: Arc::new(AtomicBool::new(false)),
        shutdown: Arc::new(AtomicBool::new(false)),
        dropped: Arc::new(AtomicU64::new(0)),
    };
    let stopped = Arc::clone(&handle.stopped);
    let shutdown = Arc::clone(&handle.shutdown);
    let path = path.to_string();
    let thread = std::thread::Builder::new()
        .name("raw-capture".into())
        .spawn(move || writer_loop(writer, rx, max_bytes, &path, &stopped, &shutdown))
        .context("failed to spawn raw capture writer thread")?;
    Ok((handle, thread))
}

fn writer_loop<W: Write>(
    mut writer: CaptureWriter<W>,
    rx: Receiver<DataEvent>,
    max_bytes: u64,
    path: &str,
    stopped: &AtomicBool,
    shutdown: &AtomicBool,
) {
    let mut written = HEADER_BYTES;
    let mut write = |writer: &mut CaptureWriter<W>, event: &DataEvent| -> bool {
        if written + RECORD_BYTES > max_bytes {
            warn!(
                path,
                max_bytes, "Raw capture size limit reached — raw capture stopped"
            );
            return false;
        }
        if let Err(e) = writer.write_event(event) {
            error!(path, error = %e, "Raw capture write failed — raw capture stopped");
            return false;
        }
        written += RECORD_BYTES;
        true
    };

    loop {
        match rx.recv_timeout(WRITER_TICK) {
            Ok(event) => {
                if !write(&mut writer, &event) {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = writer.flush();
                if shutdown.load(Ordering::Relaxed) {
                    // Drain whatever is still queued, then exit.
                    while let Ok(event) = rx.try_recv() {
                        if !write(&mut writer, &event) {
                            break;
                        }
                    }
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    stopped.store(true, Ordering::Relaxed);
    match writer.finish() {
        Ok(events) => info!(path, events, bytes = written, "Raw capture closed"),
        Err(e) => error!(path, error = %e, "Raw capture flush failed"),
    }
}

/// Convert a PNCAP capture into JSON lines: one object per event with its
/// metadata and the captured payload as base64. Returns the event count.
///
/// A truncated final record (agent killed mid-write) ends the output with a
/// warning on stderr instead of failing.
pub fn decode_to_jsonl<R: io::Read, W: Write>(input: R, mut out: W) -> Result<u64> {
    let mut reader = CaptureReader::new(input).context("not a Panopticon capture (PNCAP)")?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut count = 0u64;
    loop {
        let event = match reader.read_event() {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                eprintln!("warning: capture ends with a partial record (agent stopped mid-write)");
                break;
            }
            Err(e) => return Err(e).context(format!("invalid record after {count} events")),
        };
        let payload = event.payload_bytes();
        let record = serde_json::json!({
            "timestamp_ns": event.timestamp_ns,
            "event_type": format!("{:?}", event.event_type),
            "direction": format!("{:?}", event.direction),
            // DataEvent.pid holds the process id (tgid), .tgid the thread id.
            "pid": event.pid,
            "tid": event.tgid,
            "src": crate::util::format_ipv4(event.src_addr),
            "src_port": event.src_port,
            "dst": crate::util::format_ipv4(event.dst_addr),
            "dst_port": event.dst_port,
            "ip_proto": event.ip_proto,
            "tls_library": format!("{:?}", event.tls_library),
            "connection_id": event.socket_cookie,
            "payload_len": payload.len(),
            "orig_len": event.orig_len,
            "truncated": event.truncated_bytes() > 0,
            "payload_b64": b64.encode(payload),
        });
        serde_json::to_writer(&mut out, &record)?;
        out.write_all(b"\n")?;
        count += 1;
    }
    out.flush()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use panopticon_common::{Direction, EventType, TlsLibrary};

    fn event(payload: &[u8], orig_len: u32) -> DataEvent {
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        e.timestamp_ns = 42;
        e.event_type = EventType::TcPacket;
        e.direction = Direction::Ingress;
        e.tls_library = TlsLibrary::None;
        e.src_addr = 0x0A000001;
        e.dst_addr = 0x0A000002;
        e.src_port = 5432;
        e.dst_port = 40000;
        e.ip_proto = 6;
        e.payload[..payload.len()].copy_from_slice(payload);
        e.payload_len = payload.len() as u32;
        e.orig_len = orig_len;
        e
    }

    fn tmp_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("panopticon-raw-{name}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn records_round_trip_unredacted_with_0600_permissions() {
        let path = tmp_path("roundtrip");
        let (handle, thread) = spawn(&path, 1 << 20, 64, 7).unwrap();
        handle.record(&event(b"password=hunter2&ssn=123-45-6789", 32));
        handle.record(&event(b"partial", 9000));
        handle.shutdown();
        thread.join().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let mut out = Vec::new();
        let n = decode_to_jsonl(std::fs::File::open(&path).unwrap(), &mut out).unwrap();
        assert_eq!(n, 2);
        let lines: Vec<serde_json::Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD;
        let payload = b64
            .decode(lines[0]["payload_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(payload, b"password=hunter2&ssn=123-45-6789"); // not redacted
        assert_eq!(lines[0]["src"], "10.0.0.1");
        assert_eq!(lines[0]["truncated"], false);
        assert_eq!(lines[1]["orig_len"], 9000);
        assert_eq!(lines[1]["truncated"], true);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn stops_at_size_limit() {
        let path = tmp_path("limit");
        // Room for the header and exactly two records.
        let (handle, thread) = spawn(&path, HEADER_BYTES + 2 * RECORD_BYTES, 64, 0).unwrap();
        for _ in 0..5 {
            handle.record(&event(b"x", 1));
        }
        handle.shutdown();
        thread.join().unwrap();
        let mut out = Vec::new();
        let n = decode_to_jsonl(std::fs::File::open(&path).unwrap(), &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            HEADER_BYTES + 2 * RECORD_BYTES
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn truncated_final_record_is_tolerated() {
        let path = tmp_path("partial");
        let (handle, thread) = spawn(&path, 1 << 20, 64, 0).unwrap();
        handle.record(&event(b"one", 3));
        handle.record(&event(b"two", 3));
        handle.shutdown();
        thread.join().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let cut = &bytes[..bytes.len() - 100]; // second record cut short
        let mut out = Vec::new();
        assert_eq!(decode_to_jsonl(cut, &mut out).unwrap(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn full_queue_counts_drops_without_blocking() {
        let path = tmp_path("drops");
        let (handle, thread) = spawn(&path, 1 << 30, 1, 0).unwrap();
        for _ in 0..10_000 {
            handle.record(&event(b"burst", 5));
        }
        handle.shutdown();
        thread.join().unwrap();
        let mut out = Vec::new();
        let written = decode_to_jsonl(std::fs::File::open(&path).unwrap(), &mut out).unwrap();
        assert_eq!(written + handle.dropped(), 10_000);
        assert!(handle.dropped() > 0);
        std::fs::remove_file(&path).ok();
    }
}
