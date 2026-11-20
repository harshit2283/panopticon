//! Raw capture: every event the agent processes, **unredacted**, in the PNCAP
//! format (see `replay.rs`), for users who need the bytes themselves — their
//! own PII classifiers, evidence retention, or checking the agent's output.
//!
//! - Written by a dedicated thread per capture pipeline so file IO never
//!   blocks workers; when the writer falls behind, events are dropped and
//!   counted (`panopticon_raw_capture_dropped_total`).
//! - The file is created owner-only (0600) and truncated at startup, once
//!   ([`open`]): every pipeline appends whole records to it under its own
//!   gate, so a narrowing never writes a second header or a split record.
//! - Writing stops at `max_bytes` so a forgotten flag cannot fill the disk.
//! - Writing stops, and the file is closed, as soon as a reload tightens
//!   the privacy mode below `full`: events still queued are not written.
//! - Payloads are the captured bytes: up to 4096 per packet / TLS buffer;
//!   `orig_len` in each record says how large the original was.
//!
//! `decode_to_jsonl` turns a capture into JSON lines (metadata + base64
//! payload); exposed as `panopticon-agent --privacy-mode full --decode-capture <FILE>`.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use panopticon_common::DataEvent;
use tracing::{error, info, warn};

use crate::config::{PrivacyGate, PrivacyMode};
use crate::io_gate::{IoGate, RecordFile, Refused};
use crate::replay::{CAPTURE_RECORD_BYTES, CaptureReader, capture_header, encode_capture_record};

/// Bytes per record in the file: u32 length prefix + fixed-size DataEvent.
#[cfg(test)]
const RECORD_BYTES: u64 = CAPTURE_RECORD_BYTES as u64;
/// Magic + version + start timestamp + event count.
#[cfg(test)]
const HEADER_BYTES: u64 = 6 + 4 + 8 + 8;
/// How often the writer checks for shutdown and a tightened mode when idle.
const WRITER_TICK: Duration = Duration::from_millis(200);

/// Cloneable sender side, held by every worker of one pipeline.
#[derive(Clone)]
pub struct RawCaptureHandle {
    tx: SyncSender<DataEvent>,
    /// Set by the writer when it stops (size cap or IO error): workers then
    /// skip recording instead of counting every event as a drop.
    stopped: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    /// The shared file, which counts drops over every pipeline.
    file: Arc<RecordFile>,
}

impl RawCaptureHandle {
    /// Queue an event for the raw capture file. Never blocks.
    pub fn record(&self, event: &DataEvent) {
        if self.stopped.load(Ordering::Relaxed) {
            return;
        }
        // Records are whole DataEvents: zero the payload past payload_len,
        // which holds stale bytes of earlier events in the worker's scratch
        // (other connections', or the part head_only cut, or events the
        // capture gate dropped).
        let mut event = *event;
        let len = (event.payload_len as usize).min(event.payload.len());
        event.payload[len..].fill(0);
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.file.count_dropped(1),
            Err(TrySendError::Disconnected(_)) => self.stopped.store(true, Ordering::Relaxed),
        }
    }

    /// Ask the writer to drain what is queued and exit.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Create the capture file at `path` (fresh, owner-only) with its header.
/// `max_bytes` caps the whole file, header included.
pub fn open(path: &str, max_bytes: u64, start_timestamp_ns: u64) -> Result<Arc<RecordFile>> {
    RecordFile::create(path, &capture_header(start_timestamp_ns), max_bytes, false)
        .with_context(|| format!("raw capture file {path}"))
}

/// Start one pipeline's writer thread on `file`, writing under `gate`, and
/// only while `privacy` is `full`. It logs through `dispatch`.
pub fn spawn(
    file: Arc<RecordFile>,
    gate: Arc<IoGate>,
    queue_capacity: usize,
    privacy: Arc<PrivacyGate>,
    dispatch: tracing::Dispatch,
) -> Result<(RawCaptureHandle, JoinHandle<()>)> {
    let (tx, rx) = sync_channel(queue_capacity);
    let handle = RawCaptureHandle {
        tx,
        stopped: Arc::new(AtomicBool::new(false)),
        shutdown: Arc::new(AtomicBool::new(false)),
        file: Arc::clone(&file),
    };
    let stopped = Arc::clone(&handle.stopped);
    let shutdown = Arc::clone(&handle.shutdown);
    let thread = std::thread::Builder::new()
        .name("raw-capture".into())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                writer_loop(&file, &gate, rx, &stopped, &shutdown, &privacy)
            })
        })
        .context("failed to spawn raw capture writer thread")?;
    Ok((handle, thread))
}

fn writer_loop(
    file: &RecordFile,
    gate: &IoGate,
    rx: Receiver<DataEvent>,
    stopped: &AtomicBool,
    shutdown: &AtomicBool,
    privacy: &PrivacyGate,
) {
    let path = file.path().to_string();
    let mut events = 0u64;
    let mut record = Vec::with_capacity(CAPTURE_RECORD_BYTES);
    // False once this writer must stop.
    let mut write = |event: &DataEvent| -> bool {
        // Checked per record: what was queued under `full` is not written
        // once a reload has tightened the mode.
        if privacy.get() != PrivacyMode::Full {
            warn!(
                path,
                "Privacy mode tightened — raw capture stopped and closed"
            );
            file.close();
            return false;
        }
        record.clear();
        encode_capture_record(event, &mut record);
        match file.write(gate, &record) {
            Ok(()) => {
                events += 1;
                true
            }
            // The size cap (logged by the file), a closed file, or a
            // revoked pipeline: nothing more is written.
            Err(Refused::Full | Refused::Closed | Refused::Revoked) => false,
            Err(Refused::Io(e)) => {
                error!(path, error = %e, "Raw capture write failed — raw capture stopped");
                false
            }
        }
    };

    loop {
        match rx.recv_timeout(WRITER_TICK) {
            Ok(event) => {
                if !write(&event) {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if privacy.get() != PrivacyMode::Full {
                    warn!(
                        path,
                        "Privacy mode tightened — raw capture stopped and closed"
                    );
                    file.close();
                    break;
                }
                if shutdown.load(Ordering::Relaxed) {
                    // Drain whatever is still queued, then exit.
                    while let Ok(event) = rx.try_recv() {
                        if !write(&event) {
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
    if !gate.is_revoked() {
        info!(path, events, "Raw capture writer stopped");
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
            "tcp_seq": event.tcp_seq,
            "tcp_flags": event.tcp_flags,
            // Capture-scope fields (packet events; 0 / u64::MAX otherwise).
            "cgroup_id": event.cgroup_id,
            "stream_off": event.stream_off,
            "owner_tgid": event.owner_tgid,
            "acceptor_tgid": event.acceptor_tgid,
            "scope_gen": event.scope_gen,
            "role": event.role,
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
    use std::os::unix::fs::PermissionsExt;

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

    fn full() -> Arc<PrivacyGate> {
        Arc::new(PrivacyGate::new(PrivacyMode::Full))
    }

    fn spawn(
        path: &str,
        max_bytes: u64,
        queue: usize,
        ts: u64,
        privacy: Arc<PrivacyGate>,
    ) -> Result<(RawCaptureHandle, JoinHandle<()>)> {
        super::spawn(
            open(path, max_bytes, ts)?,
            IoGate::new(),
            queue,
            privacy,
            tracing::Dispatch::default(),
        )
    }

    /// Codex #2: a tighten below `full` stops the writer and closes the
    /// file; events queued afterwards are never written.
    #[test]
    fn tighten_stops_and_closes_the_raw_capture() {
        let path = tmp_path("tighten");
        let gate = full();
        let (handle, thread) = spawn(&path, 1 << 20, 64, 0, Arc::clone(&gate)).unwrap();
        handle.record(&event(b"before", 6));
        std::thread::sleep(Duration::from_millis(300));
        gate.tighten(PrivacyMode::Redacted);
        handle.record(&event(b"ssn=123-45-6789", 15)); // queued after the tighten
        thread.join().unwrap(); // stops on its own, without shutdown()
        let mut out = Vec::new();
        let n = decode_to_jsonl(std::fs::File::open(&path).unwrap(), &mut out).unwrap();
        assert_eq!(n, 1, "only the event written under full");
        let b64 = base64::engine::general_purpose::STANDARD;
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains(&b64.encode(b"ssn=123-45-6789"))
        );
        std::fs::remove_file(&path).ok();
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
        let (handle, thread) = spawn(&path, 1 << 20, 64, 7, full()).unwrap();
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
        assert_eq!(lines[0]["stream_off"], 0); // zeroed test event
        assert_eq!(lines[0]["owner_tgid"], 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bytes_past_payload_len_never_reach_the_file() {
        let path = tmp_path("stale");
        let (handle, thread) = spawn(&path, 1 << 20, 64, 0, full()).unwrap();
        // A reused scratch event: a short payload over an earlier long one.
        let mut e = event(b"ssn=123-45-6789 beyond the cut", 30);
        e.payload_len = 3;
        handle.record(&e);
        handle.shutdown();
        thread.join().unwrap();
        let file = std::fs::read(&path).unwrap();
        assert!(!file.windows(11).any(|w| w == b"123-45-6789"));
        assert!(file.windows(3).any(|w| w == b"ssn"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn stops_at_size_limit() {
        let path = tmp_path("limit");
        // Room for the header and exactly two records.
        let (handle, thread) =
            spawn(&path, HEADER_BYTES + 2 * RECORD_BYTES, 64, 0, full()).unwrap();
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
        let (handle, thread) = spawn(&path, 1 << 20, 64, 0, full()).unwrap();
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

    /// Revision 1 item 4: one header for the whole file; a later pipeline
    /// appends records after a revoked one, which writes nothing more.
    #[test]
    fn pipelines_share_one_file_and_header() {
        let path = tmp_path("shared");
        let file = open(&path, 1 << 20, 0).unwrap();
        let (old_gate, new_gate) = (IoGate::new(), IoGate::new());
        let start = |gate: &Arc<IoGate>| {
            super::spawn(
                Arc::clone(&file),
                Arc::clone(gate),
                64,
                full(),
                tracing::Dispatch::default(),
            )
            .unwrap()
        };
        let (old, old_thread) = start(&old_gate);
        old.record(&event(b"old-written", 11));
        std::thread::sleep(Duration::from_millis(300));
        old_gate.revoke();
        old.record(&event(b"old-after-revoke", 16));
        let (new, new_thread) = start(&new_gate);
        new.record(&event(b"new-written", 11));
        for (h, t) in [(old, old_thread), (new, new_thread)] {
            h.shutdown();
            t.join().unwrap();
        }
        let mut out = Vec::new();
        let n = decode_to_jsonl(std::fs::File::open(&path).unwrap(), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        assert_eq!(n, 2, "{out}");
        assert!(out.contains(&b64.encode(b"old-written")));
        assert!(out.contains(&b64.encode(b"new-written")));
        assert!(!out.contains(&b64.encode(b"old-after-revoke")));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn full_queue_counts_drops_without_blocking() {
        let path = tmp_path("drops");
        let (handle, thread) = spawn(&path, 1 << 30, 1, 0, full()).unwrap();
        for _ in 0..10_000 {
            handle.record(&event(b"burst", 5));
        }
        handle.shutdown();
        thread.join().unwrap();
        let mut out = Vec::new();
        let written = decode_to_jsonl(std::fs::File::open(&path).unwrap(), &mut out).unwrap();
        assert_eq!(written + handle.file.dropped(), 10_000);
        assert!(handle.file.dropped() > 0);
        std::fs::remove_file(&path).ok();
    }
}
