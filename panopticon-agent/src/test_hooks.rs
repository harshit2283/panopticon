//! Named pause points for the narrowing tests (DESIGN §10 T-2), compiled in
//! unit tests and with the `scope-test-hooks` feature (lab builds); no-ops
//! otherwise.
//!
//! A hook is armed for one point and one pipeline (its `IoGate`), so tests
//! running in parallel never stop each other's pipelines. The first thread
//! that reaches an armed point stops there until the test releases it.

/// A worker, after the admission (generation) check, before it hands an
/// event's results to any sink.
pub const WORKER_BEFORE_SINK: &str = "worker_before_sink";
/// A worker, before it inserts a DNS answer into the cache.
pub const BEFORE_DNS_INSERT: &str = "before_dns_insert";
/// A ring reader, after it admitted an event, before the hand-off.
pub const READER_AFTER_ADMISSION: &str = "reader_after_admission";
/// An OTLP export writing to its socket, before the gate check.
pub const OTLP_IN_FLIGHT_EXPORT: &str = "otlp_in_flight_export";

#[cfg(any(test, feature = "scope-test-hooks"))]
pub use imp::*;

#[cfg(any(test, feature = "scope-test-hooks"))]
mod imp {
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use crate::io_gate::IoGate;

    #[derive(Default)]
    struct Hook {
        /// (reached, released)
        state: Mutex<(bool, bool)>,
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
            self.hook.state.lock().unwrap().1 = true;
            self.hook.cv.notify_all();
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
