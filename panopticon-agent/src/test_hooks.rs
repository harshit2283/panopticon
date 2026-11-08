//! Named pause points for the narrowing tests (DESIGN §10 T-2), compiled in
//! unit tests and with the `scope-test-hooks` feature (lab builds); no-ops
//! otherwise.
//!
//! A hook is armed for one point and one pipeline (its `IoGate`), so tests
//! running in parallel never stop each other's pipelines. The first thread
//! that reaches an armed point stops there until the test releases it.
//!
//! A point inside an async poll ([`poll_pause`]) never blocks its thread:
//! the poll returns `Pending` until the release wakes it. Blocking a Tokio
//! worker there would also hold whatever the caller holds (h2 keeps its
//! stream-state mutex across socket writes), so every other worker that
//! touches the same connection blocks too, until no worker is left to run
//! the timers or the test's own pipeline.

/// A worker, after the admission (generation) check, before it hands an
/// event's results to any sink.
pub const WORKER_BEFORE_SINK: &str = "worker_before_sink";
/// A worker, before it inserts a DNS answer into the cache.
pub const BEFORE_DNS_INSERT: &str = "before_dns_insert";
/// A worker, right after it inserted a DNS answer into the cache.
pub const AFTER_DNS_INSERT: &str = "after_dns_insert";
/// A ring reader, after it admitted an event, before the hand-off.
pub const READER_AFTER_ADMISSION: &str = "reader_after_admission";
/// An OTLP export writing to its socket, before the gate check (async:
/// the write stays pending, as on a socket with a full send buffer).
pub const OTLP_IN_FLIGHT_EXPORT: &str = "otlp_in_flight_export";

#[cfg(any(test, feature = "scope-test-hooks"))]
pub use imp::*;

#[cfg(any(test, feature = "scope-test-hooks"))]
mod imp {
    use std::sync::{Arc, Condvar, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use crate::io_gate::IoGate;

    #[derive(Default)]
    struct Hook {
        /// (reached, released, the waker of a pending poll)
        state: Mutex<(bool, bool, Option<Waker>)>,
        cv: Condvar,
    }

    type Key = (&'static str, usize);

    static HOOKS: Mutex<Vec<(Key, Arc<Hook>)>> = Mutex::new(Vec::new());

    fn key(point: &'static str, gate: &IoGate) -> Key {
        (point, gate as *const IoGate as usize)
    }

    /// Stop here if a test armed `point` for `gate`'s pipeline (once).
    pub fn pause(point: &'static str, gate: &IoGate) {
        let hook = {
            let mut hooks = HOOKS.lock().unwrap_or_else(|e| e.into_inner());
            let Some(i) = hooks.iter().position(|(k, _)| *k == key(point, gate)) else {
                return;
            };
            hooks.swap_remove(i).1
        };
        let mut st = hook.state.lock().unwrap();
        st.0 = true;
        hook.cv.notify_all();
        while !st.1 {
            st = hook.cv.wait(st).unwrap();
        }
    }

    /// Async form of [`pause`]: `Pending` while `point` is armed for
    /// `gate` and not released (every poll that reaches it, until then).
    pub fn poll_pause(point: &'static str, gate: &IoGate, cx: &mut Context<'_>) -> Poll<()> {
        let hook = {
            let hooks = HOOKS.lock().unwrap_or_else(|e| e.into_inner());
            match hooks.iter().find(|(k, _)| *k == key(point, gate)) {
                Some((_, h)) => Arc::clone(h),
                None => return Poll::Ready(()),
            }
        };
        let mut st = hook.state.lock().unwrap();
        if st.1 {
            return Poll::Ready(());
        }
        st.0 = true;
        st.2 = Some(cx.waker().clone());
        hook.cv.notify_all();
        Poll::Pending
    }

    /// An armed point. Dropping it releases a paused thread.
    pub struct Armed {
        key: Key,
        hook: Arc<Hook>,
    }

    pub fn arm(point: &'static str, gate: &IoGate) -> Armed {
        let hook = Arc::new(Hook::default());
        let key = key(point, gate);
        HOOKS.lock().unwrap().push((key, Arc::clone(&hook)));
        Armed { key, hook }
    }

    impl Armed {
        /// Wait (bounded) until a thread is stopped at the point.
        pub fn wait_reached(&self, timeout: Duration) -> bool {
            let st = self.hook.state.lock().unwrap();
            let (st, _) = self
                .hook
                .cv
                .wait_timeout_while(st, timeout, |s| !s.0)
                .unwrap();
            st.0
        }

        pub fn release(&self) {
            let waker = {
                let mut st = self.hook.state.lock().unwrap();
                st.1 = true;
                st.2.take()
            };
            self.hook.cv.notify_all();
            if let Some(w) = waker {
                w.wake();
            }
        }
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            self.release();
            HOOKS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(k, _)| *k != self.key);
        }
    }
}

#[cfg(not(any(test, feature = "scope-test-hooks")))]
#[inline(always)]
pub fn pause(_point: &'static str, _gate: &crate::io_gate::IoGate) {}

#[cfg(not(any(test, feature = "scope-test-hooks")))]
#[inline(always)]
pub fn poll_pause(
    _point: &'static str,
    _gate: &crate::io_gate::IoGate,
    _cx: &mut std::task::Context<'_>,
) -> std::task::Poll<()> {
    std::task::Poll::Ready(())
}
