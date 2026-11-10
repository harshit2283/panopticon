//! The capture pipeline's I/O gate (DESIGN §3, narrowing).
//!
//! Each capture pipeline owns one [`IoGate`]. Every write that can carry
//! captured data, or anything derived from it, out of the process goes
//! through that gate at the lowest layer, beneath any buffering:
//!
//! - files: [`RecordFile`], one per output path, shared by every pipeline;
//!   the pipelines' own buffers above it hold whole records only;
//! - sockets: [`GatedIo`] around the TCP stream of the OTLP gRPC channel
//!   and of the external PII client, *beneath* TLS ([`GatedConnector`]),
//!   so bytes that TLS, h2 or tonic buffered are refused when they are
//!   finally written;
//! - logs: [`GatedLog`], the writer of the pipeline's tracing `Dispatch`.
//!
//! A gated write holds the gate's read lock across its check and the I/O.
//! [`IoGate::revoke`] takes the write lock, so it waits for every write in
//! flight, and marks the gate revoked for good: from then on every gated
//! write fails and its bytes are discarded.

use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::instrument::WithSubscriber;

use crate::test_hooks::SOCKET_SENT;

/// Revoked once, for good. See the module docs.
#[derive(Debug, Default)]
pub struct IoGate(RwLock<bool>);

impl IoGate {
    pub fn new() -> Arc<Self> {
        let gate = Arc::default();
        crate::test_hooks::new_gate(&gate);
        gate
    }

    /// The read guard while the gate is open; None once revoked. Hold it
    /// across the check and the I/O.
    pub fn open(&self) -> Option<RwLockReadGuard<'_, bool>> {
        let guard = self.0.read().unwrap_or_else(|e| e.into_inner());
        (!*guard).then_some(guard)
    }

    /// Wait for every gated write in flight, then refuse all writes from
    /// now on. Blocks: call it off the async runtime threads.
    pub fn revoke(&self) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = true;
    }

    pub fn is_revoked(&self) -> bool {
        self.open().is_none()
    }
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "write refused: the capture pipeline was revoked",
    )
}

// ── Files ────────────────────────────────────────────────────────────────

/// Why [`RecordFile::write`] wrote nothing (the records are dropped).
#[derive(Debug)]
pub enum Refused {
    /// The writing pipeline was revoked.
    Revoked,
    /// The file was closed (privacy tightened, size cap, or too many
    /// failed writes).
    Closed,
    /// The records would pass the file's byte cap; the file is now closed.
    Full,
    /// The write failed; the file is unchanged, or it was torn and output
    /// continues in a fresh file.
    Io(io::Error),
}

/// Rotations after torn writes before the output is given up.
const MAX_ROTATIONS: u32 = 8;

struct FileState {
    file: Option<std::fs::File>,
    /// Bytes written so far, over every file (headers included).
    written: u64,
    rotations: u32,
}

/// What a write has to report. Logged only after the file mutex and the
/// gate's read guard are released: a log line goes through a pipeline's
/// gated writer, which takes a gate's read lock, and a second read lock
/// queued behind a waiting `revoke` would never be granted.
enum Diag {
    Full,
    Rotated(String),
    GaveUp,
    RotateFailed(anyhow::Error),
}

/// One output file, opened once and shared by every capture pipeline
/// (Revision 1 item 4). Writes are whole records, serialised by the file
/// mutex, each under the writer's gate: generations never interleave inside
/// a record, and a revoked pipeline's records are dropped whole. A write
/// that fails part way leaves a torn record, so output continues in a fresh
/// file `<path>.<n>` (header written again) and the torn one is left alone.
pub struct RecordFile {
    path: String,
    /// Written at the start of every file (the raw capture's PNCAP header).
    header: Vec<u8>,
    /// Byte cap over the whole output, headers included (`u64::MAX`: none).
    max_bytes: u64,
    state: Mutex<FileState>,
    /// Records the writers dropped because they fell behind (aggregate,
    /// over every pipeline).
    dropped: AtomicU64,
    /// Tests: the next write stops after this many bytes (`u64::MAX`: off).
    #[cfg(test)]
    fail_after: AtomicU64,
    /// Tests: diagnostics logged, and how many of them while the file
    /// mutex or the writer's gate was held.
    #[cfg(test)]
    logged: [AtomicU64; 2],
}

impl RecordFile {
    /// Open `path` owner-only (`append`: keep what it holds; otherwise a
    /// fresh file, see [`crate::export::open_private`]) and write `header`.
    /// A header that does not fit the cap is not written and the output
    /// starts closed.
    pub fn create(path: &str, header: &[u8], max_bytes: u64, append: bool) -> Result<Arc<Self>> {
        let mut file = crate::export::open_private(path, append)?;
        let fits = header.len() as u64 <= max_bytes;
        if fits {
            file.write_all(header)
                .with_context(|| format!("cannot write the header of {path}"))?;
        }
        let f = Arc::new(Self {
            path: path.to_string(),
            header: header.to_vec(),
            max_bytes,
            state: Mutex::new(FileState {
                file: fits.then_some(file),
                written: if fits { header.len() as u64 } else { 0 },
                rotations: 0,
            }),
            dropped: AtomicU64::new(0),
            #[cfg(test)]
            fail_after: AtomicU64::new(u64::MAX),
            #[cfg(test)]
            logged: Default::default(),
        });
        if !fits {
            f.log(Diag::Full, None);
        }
        Ok(f)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Write `records` (complete records only) under `gate`.
    pub fn write(&self, gate: &IoGate, records: &[u8]) -> Result<(), Refused> {
        let (result, diag) = self.write_locked(gate, records);
        if let Some(d) = diag {
            self.log(d, Some(gate));
        }
        result
    }

    /// The write itself, under the file mutex and the gate's read guard;
    /// both are released when it returns.
    fn write_locked(&self, gate: &IoGate, records: &[u8]) -> (Result<(), Refused>, Option<Diag>) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(_open) = gate.open() else {
            return (Err(Refused::Revoked), None);
        };
        if st.file.is_none() {
            return (Err(Refused::Closed), None);
        }
        if st.written.saturating_add(records.len() as u64) > self.max_bytes {
            st.file = None;
            return (Err(Refused::Full), Some(Diag::Full));
        }
        let file = st.file.as_mut().expect("checked above");
        #[cfg(test)]
        let cut = match self.fail_after.swap(u64::MAX, Ordering::Relaxed) {
            u64::MAX => records.len(),
            n => (n as usize).min(records.len()),
        };
        #[cfg(not(test))]
        let cut = records.len();
        let (done, mut result) = write_counted(file, &records[..cut]);
        if result.is_ok() && cut < records.len() {
            result = Err(io::ErrorKind::WriteZero.into());
        }
        st.written += done as u64;
        match result {
            Ok(()) => (Ok(()), None),
            Err(e) if done == 0 => (Err(Refused::Io(e)), None),
            Err(e) => {
                let diag = self.rotate(&mut st);
                (Err(Refused::Io(e)), Some(diag))
            }
        }
    }

    /// After a torn write: continue in `<path>.<n>`, if its header fits.
    fn rotate(&self, st: &mut FileState) -> Diag {
        st.file = None;
        st.rotations += 1;
        if st.rotations > MAX_ROTATIONS {
            return Diag::GaveUp;
        }
        if st.written.saturating_add(self.header.len() as u64) > self.max_bytes {
            return Diag::Full;
        }
        let next = format!("{}.{}", self.path, st.rotations);
        let opened = crate::export::open_private(&next, false).and_then(|mut f| {
            f.write_all(&self.header)?;
            Ok(f)
        });
        match opened {
            Ok(f) => {
                st.written += self.header.len() as u64;
                st.file = Some(f);
                Diag::Rotated(next)
            }
            Err(e) => Diag::RotateFailed(e),
        }
    }

    fn log(&self, d: Diag, _gate: Option<&IoGate>) {
        #[cfg(test)]
        {
            let held =
                self.state.try_lock().is_err() || _gate.is_some_and(|g| g.0.try_write().is_err());
            self.logged[0].fetch_add(1, Ordering::Relaxed);
            self.logged[1].fetch_add(held as u64, Ordering::Relaxed);
        }
        match d {
            Diag::Full => tracing::warn!(
                path = %self.path,
                max_bytes = self.max_bytes,
                "Output size limit reached; output closed"
            ),
            Diag::Rotated(next) => tracing::warn!(
                path = %self.path,
                continued_in = %next,
                "A write failed part way (torn record); output continues in a new file"
            ),
            Diag::GaveUp => {
                tracing::error!(path = %self.path, "Output closed after repeated torn writes")
            }
            Diag::RotateFailed(e) => {
                tracing::error!(path = %self.path, error = %format!("{e:#}"), "Output closed: cannot rotate")
            }
        }
    }

    /// Stop writing and close the file, for every pipeline.
    pub fn close(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).file = None;
    }

    pub fn count_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Tests: the next write stops after `n` bytes, as a full disk would.
    #[cfg(test)]
    pub fn fail_next_write_after(&self, n: u64) {
        self.fail_after.store(n, Ordering::Relaxed);
    }
}

/// `write_all`, reporting how many bytes went out before an error.
fn write_counted(w: &mut impl Write, mut buf: &[u8]) -> (usize, io::Result<()>) {
    let mut done = 0;
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => return (done, Err(io::ErrorKind::WriteZero.into())),
            Ok(n) => {
                done += n;
                buf = &buf[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return (done, Err(e)),
        }
    }
    (done, Ok(()))
}

// ── Sockets ──────────────────────────────────────────────────────────────

/// A stream whose writes, vectored writes, flushes and shutdowns go
/// through the gate (Revision 1 item 1); reads pass. Wraps the raw socket,
/// beneath TLS: `TlsStream<GatedIo<TcpStream>>`, never the reverse.
pub struct GatedIo<T> {
    gate: Arc<IoGate>,
    inner: T,
    /// The test pause point checked before each gated write.
    pause_point: Option<&'static str>,
    /// The peer's port (keys the tests' record of socket writes).
    peer_port: u16,
}

impl<T> GatedIo<T> {
    /// Gate one poll of `op`: `f` runs under the read guard, or is refused.
    fn gated<R>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        op: &'static str,
        f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>>
    where
        T: Unpin,
    {
        let this = self.get_mut();
        if let Some(point) = this.pause_point
            && crate::test_hooks::poll_pause(point, &this.gate, cx).is_pending()
        {
            return Poll::Pending;
        }
        let Some(_open) = this.gate.open() else {
            crate::test_hooks::tap_gate(crate::test_hooks::SOCKET_REFUSED, &this.gate, || {
                format!("{op}\n").into_bytes()
            });
            return Poll::Ready(Err(refused()));
        };
        f(Pin::new(&mut this.inner), cx)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GatedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GatedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let port = self.peer_port;
        let r = self.gated(cx, "write", |io, cx| io.poll_write(cx, buf));
        if let Poll::Ready(Ok(n)) = r {
            crate::test_hooks::tap(SOCKET_SENT, port, &buf[..n]);
        }
        r
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let port = self.peer_port;
        let r = self.gated(cx, "write", |io, cx| io.poll_write_vectored(cx, bufs));
        if let Poll::Ready(Ok(mut n)) = r {
            for b in bufs {
                let k = n.min(b.len());
                crate::test_hooks::tap(SOCKET_SENT, port, &b[..k]);
                n -= k;
            }
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.gated(cx, "flush", |io, cx| io.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.gated(cx, "shutdown", |io, cx| io.poll_shutdown(cx))
    }
}

type GatedTcp = GatedIo<tokio::net::TcpStream>;

/// A connection made by [`GatedConnector`]: TLS, if any, above the gate.
pub enum GatedStream {
    Plain(GatedTcp),
    Tls(Box<tokio_rustls::client::TlsStream<GatedTcp>>),
}

impl AsyncRead for GatedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for GatedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for GatedStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

/// Connects `http://` (and, with TLS configured, `https://`) URIs over a
/// TCP stream wrapped in [`GatedIo`]. Refuses to connect once the gate is
/// revoked.
#[derive(Clone)]
pub struct GatedConnector {
    gate: Arc<IoGate>,
    tls: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    pause_point: Option<&'static str>,
}

impl GatedConnector {
    /// Plain TCP only (`https://` is refused).
    pub fn plain(gate: Arc<IoGate>) -> Self {
        Self {
            gate,
            tls: None,
            pause_point: None,
        }
    }

    /// TCP, or TLS over the gated TCP stream for `https://` (web PKI roots).
    pub fn with_tls(gate: Arc<IoGate>) -> Self {
        let roots = tokio_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            gate,
            tls: Some(Arc::new(config)),
            pause_point: None,
        }
    }

    /// Check test pause point `point` before every gated write.
    pub fn with_pause_point(mut self, point: &'static str) -> Self {
        self.pause_point = Some(point);
        self
    }

    async fn connect(self, uri: http::Uri) -> io::Result<GatedStream> {
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_string());
        if self.gate.is_revoked() {
            return Err(refused());
        }
        let host = uri
            .host()
            .ok_or_else(|| invalid("URI has no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let tls = match uri.scheme_str() {
            Some("http") => None,
            Some("https") => Some(
                self.tls
                    .clone()
                    .ok_or_else(|| invalid("https is not supported for this endpoint"))?,
            ),
            _ => return Err(invalid("URI scheme must be http or https")),
        };
        let port = uri
            .port_u16()
            .unwrap_or(if tls.is_some() { 443 } else { 80 });
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
        tcp.set_nodelay(true)?;
        let io = GatedIo {
            gate: self.gate,
            inner: tcp,
            pause_point: self.pause_point,
            peer_port: port,
        };
        Ok(match tls {
            None => GatedStream::Plain(io),
            Some(config) => {
                let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host)
                    .map_err(|_| invalid("invalid TLS server name"))?;
                let tls = tokio_rustls::TlsConnector::from(config)
                    .connect(name, io)
                    .await?;
                GatedStream::Tls(Box::new(tls))
            }
        })
    }
}

impl tower_service::Service<http::Uri> for GatedConnector {
    type Response = hyper_util::rt::TokioIo<GatedStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.connect(uri).await.map(hyper_util::rt::TokioIo::new) })
    }
}

/// Spawns each future on the Tokio runtime under the pipeline's tracing
/// `Dispatch`: tonic's and hyper's internal connection tasks then log only
/// through the pipeline's gated writer (Revision 1 item 2).
#[derive(Clone)]
pub struct DispatchExecutor(pub tracing::Dispatch);

impl<F> hyper::rt::Executor<F> for DispatchExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut.with_subscriber(self.0.clone()));
    }
}

// ── Logs ─────────────────────────────────────────────────────────────────

/// Where a pipeline's log lines go once past the gate (stdout in the agent).
pub type LogSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

pub fn stdout_sink() -> LogSink {
    Arc::new(|line: &[u8]| {
        let _ = io::stdout().lock().write_all(line);
    })
}

/// The `MakeWriter` of a pipeline's tracing subscriber: each event is
/// buffered whole and written in one piece under the gate, or dropped.
#[derive(Clone)]
pub struct GatedLog {
    gate: Arc<IoGate>,
    sink: LogSink,
}

impl GatedLog {
    pub fn new(gate: Arc<IoGate>, sink: LogSink) -> Self {
        Self { gate, sink }
    }
}

/// One event's formatted bytes, written when dropped.
pub struct GatedLine {
    log: GatedLog,
    buf: Vec<u8>,
}

impl Write for GatedLine {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for GatedLine {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        if let Some(_open) = self.log.gate.open() {
            (self.log.sink)(&self.buf);
        } else {
            let line = std::mem::take(&mut self.buf);
            crate::test_hooks::tap_gate(crate::test_hooks::LOG_REFUSED, &self.log.gate, || line);
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for GatedLog {
    type Writer = GatedLine;

    fn make_writer(&'a self) -> GatedLine {
        GatedLine {
            log: self.clone(),
            buf: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("panopticon-gate-{name}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn record_file_refuses_revoked_writers_and_serialises_records() {
        let path = tmp("records");
        let f = RecordFile::create(&path, b"H", u64::MAX, false).unwrap();
        let (old, new) = (IoGate::new(), IoGate::new());
        f.write(&old, b"old-1\n").unwrap();
        old.revoke();
        assert!(matches!(f.write(&old, b"old-2\n"), Err(Refused::Revoked)));
        f.write(&new, b"new-1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "Hold-1\nnew-1\n");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_file_cap_is_whole_records_and_closes() {
        let path = tmp("cap");
        let f = RecordFile::create(&path, b"HH", 2 + 8, false).unwrap();
        let g = IoGate::new();
        f.write(&g, b"1234").unwrap();
        f.write(&g, b"5678").unwrap();
        assert!(matches!(f.write(&g, b"9"), Err(Refused::Full)));
        assert!(matches!(f.write(&g, b""), Err(Refused::Closed)));
        assert_eq!(std::fs::read(&path).unwrap(), b"HH12345678");
        std::fs::remove_file(&path).ok();
    }

    /// A writer that accepts `room` bytes, then fails.
    struct Short(usize, Vec<u8>);
    impl Write for Short {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::ErrorKind::StorageFull.into());
            }
            let n = b.len().min(self.0);
            self.0 -= n;
            self.1.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn torn_write_is_counted() {
        let mut w = Short(3, Vec::new());
        let (done, r) = write_counted(&mut w, b"abcdef");
        assert_eq!((done, r.is_err()), (3, true));
        let mut w = Short(0, Vec::new());
        assert_eq!(write_counted(&mut w, b"abc").0, 0);
    }

    #[test]
    fn torn_write_rotates_and_a_failed_write_does_not() {
        let path = tmp("torn");
        let f = RecordFile::create(&path, b"H", u64::MAX, false).unwrap();
        let g = IoGate::new();
        f.write(&g, b"rec1\n").unwrap();
        // Nothing written: the file is unchanged, writing goes on in it.
        f.fail_next_write_after(0);
        assert!(matches!(f.write(&g, b"lost\n"), Err(Refused::Io(_))));
        f.write(&g, b"rec2\n").unwrap();
        // Torn: the record is cut, output continues in `<path>.1`.
        f.fail_next_write_after(2);
        assert!(matches!(f.write(&g, b"torn\n"), Err(Refused::Io(_))));
        f.write(&g, b"rec3\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"Hrec1\nrec2\nto");
        let next = format!("{path}.1");
        assert_eq!(std::fs::read(&next).unwrap(), b"Hrec3\n");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&next).ok();
    }

    #[test]
    fn headers_count_against_the_cap() {
        let path = tmp("hdrcap");
        // The header alone does not fit: nothing is written, output closed.
        let f = RecordFile::create(&path, b"HH", 1, false).unwrap();
        assert!(matches!(f.write(&IoGate::new(), b""), Err(Refused::Closed)));
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        // A rotation whose header would pass the cap closes the output.
        let f = RecordFile::create(&path, b"HH", 6, false).unwrap();
        let g = IoGate::new();
        f.write(&g, b"ab").unwrap();
        f.fail_next_write_after(1);
        assert!(f.write(&g, b"cd").is_err());
        assert!(matches!(f.write(&g, b""), Err(Refused::Closed)));
        assert!(!std::path::Path::new(&format!("{path}.1")).exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"HHabc");
        std::fs::remove_file(&path).ok();
    }

    /// A diagnostic logged under the file mutex or the gate's read guard
    /// would go to a gated writer taking that read lock again, which blocks
    /// for good behind a queued `revoke` (Linux's RwLock prefers writers).
    #[test]
    fn diagnostics_are_logged_outside_the_gate_and_file_locks() {
        let path = tmp("diag");
        let file = RecordFile::create(&path, b"H", 1 + 4 + 2, false).unwrap();
        let gate = IoGate::new();
        file.write(&gate, b"ab").unwrap();
        file.fail_next_write_after(1);
        assert!(file.write(&gate, b"cd").is_err()); // torn: rotation logged
        assert!(matches!(file.write(&gate, b"efgh"), Err(Refused::Full)));
        let n = |i: usize| file.logged[i].load(Ordering::Relaxed);
        assert_eq!((n(0), n(1)), (2, 0), "(logged, logged under a lock)");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(format!("{path}.1")).ok();
    }

    #[test]
    fn revoke_waits_for_a_write_in_flight() {
        let gate = IoGate::new();
        let open = gate.open().unwrap();
        let g = Arc::clone(&gate);
        let t = std::thread::spawn(move || g.revoke());
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !t.is_finished(),
            "revoke returned while a write held the gate"
        );
        drop(open);
        t.join().unwrap();
        assert!(gate.open().is_none());
    }

    #[test]
    fn log_lines_are_whole_and_gated() {
        let out = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let o = Arc::clone(&out);
        let gate = IoGate::new();
        let log = GatedLog::new(
            Arc::clone(&gate),
            Arc::new(move |b: &[u8]| o.lock().unwrap().push(b.to_vec())),
        );
        use tracing_subscriber::fmt::MakeWriter;
        let mut w = log.make_writer();
        w.write_all(b"half ").unwrap();
        w.write_all(b"line\n").unwrap();
        drop(w);
        gate.revoke();
        let mut w = log.make_writer();
        w.write_all(b"after\n").unwrap();
        drop(w);
        assert_eq!(*out.lock().unwrap(), vec![b"half line\n".to_vec()]);
    }

    #[tokio::test]
    async fn gated_socket_refuses_writes_flushes_and_shutdown_after_revoke() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let gate = IoGate::new();
        let mut conn = GatedConnector::plain(Arc::clone(&gate));
        let uri: http::Uri = format!("http://{addr}/").parse().unwrap();
        let io = tower_service::Service::call(&mut conn, uri.clone())
            .await
            .unwrap();
        let mut s = io.into_inner();
        let (mut peer, _) = listener.accept().await.unwrap();
        s.write_all(b"before").await.unwrap();
        gate.revoke();
        assert!(s.write_all(b"after").await.is_err());
        assert!(s.flush().await.is_err());
        assert!(s.shutdown().await.is_err());
        drop(s);
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"before");
        // No new connection once revoked; https needs TLS configured.
        assert!(tower_service::Service::call(&mut conn, uri).await.is_err());
        let mut open = GatedConnector::plain(IoGate::new());
        let https: http::Uri = format!("https://{addr}/").parse().unwrap();
        assert!(
            tower_service::Service::call(&mut open, https)
                .await
                .is_err()
        );
    }
}
