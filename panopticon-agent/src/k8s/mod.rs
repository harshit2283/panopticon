#![allow(dead_code)]

//! Kubernetes metadata for endpoint identity.
//!
//! When the agent runs in a pod, it lists (and watches) Pods and Services
//! cluster-wide and keeps an IP → endpoint index, so the service graph and
//! exports can name endpoints after workloads instead of IPs:
//!
//! | IP belongs to | Identity |
//! |---|---|
//! | a pod (not hostNetwork) | `namespace/workload`, e.g. `payments/checkout` |
//! | a Service ClusterIP | `svc:namespace/service`, e.g. `svc:payments/checkout` |
//! | a node (`hostIP`; host-network pods) | `node:name`, e.g. `node:worker-1` |
//!
//! The workload is the pod's controller with ReplicaSets folded into their
//! Deployment and CronJob-created Jobs into their CronJob (see
//! [`model::workload_of`]). Ports are not part of the name: the graph node
//! is the workload, the protocol is on the edge.
//!
//! Failure to reach the API never blocks or crashes the agent: it logs once
//! and identities fall back to DNS names / IPs until the API answers.

pub mod client;
pub mod index;
pub mod model;
pub mod sync;

#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use tracing::{info, warn};

use crate::config::{KubernetesConfig, KubernetesMode};

pub use self::client::{ApiClient, ClusterEnv};
use self::index::Store;
pub use self::index::{EndpointKind, K8sEndpoint, K8sIndex};
pub use self::sync::SyncOptions;

/// Shared Kubernetes metadata: an atomically swapped IP index plus the
/// state the background sync keeps.
pub struct K8sMetadata {
    index: ArcSwap<K8sIndex>,
    store: Mutex<Store>,
    dirty: AtomicBool,
    /// Incremented on every published index.
    generation: AtomicU64,
    synced: AtomicBool,
    /// Per resource (pods, services): listed at least once.
    listed: [AtomicBool; 2],
    failing: [AtomicBool; 2],
    watch_warned: [AtomicBool; 2],
    cap_warned: AtomicBool,
    failures: AtomicU64,
    api_base: String,
}

impl K8sMetadata {
    pub fn new(api_base: &str) -> Arc<Self> {
        Arc::new(Self {
            index: ArcSwap::from_pointee(K8sIndex::default()),
            store: Mutex::new(Store::default()),
            dirty: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            synced: AtomicBool::new(false),
            listed: [AtomicBool::new(false), AtomicBool::new(false)],
            failing: [AtomicBool::new(false), AtomicBool::new(false)],
            watch_warned: [AtomicBool::new(false), AtomicBool::new(false)],
            cap_warned: AtomicBool::new(false),
            failures: AtomicU64::new(0),
            api_base: api_base.to_string(),
        })
    }

    /// Resolve `config.mode` against the environment and, if Kubernetes
    /// identity is on, start the background sync. Returns at once; `None`
    /// means identities stay DNS/IP based. Must be called inside a Tokio
    /// runtime.
    pub fn start(config: &KubernetesConfig) -> Option<Arc<Self>> {
        Self::start_with_env(config, &ClusterEnv::from_process())
    }

    pub fn start_with_env(config: &KubernetesConfig, env: &ClusterEnv) -> Option<Arc<Self>> {
        match config.mode {
            KubernetesMode::Disabled => {
                info!("Kubernetes identity disabled by config");
                return None;
            }
            KubernetesMode::Auto if !env.is_in_cluster() => {
                info!("Not running in a Kubernetes pod; Kubernetes identity off");
                return None;
            }
            _ => {}
        }
        match ApiClient::in_cluster(env) {
            Ok(client) => {
                let meta = Self::new(client.base());
                info!(
                    api = %client.base(),
                    relist_interval_secs = config.relist_interval.as_secs(),
                    watch = config.watch,
                    "Kubernetes identity enabled; syncing pods and services in the background"
                );
                meta.spawn_sync(client, SyncOptions::from_config(config));
                Some(meta)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Kubernetes identity unavailable; endpoints keep DNS/IP names"
                );
                None
            }
        }
    }

    /// Start the background sync with an explicit client (tests use a
    /// plain-HTTP fake API server).
    pub fn spawn_sync(
        self: &Arc<Self>,
        client: ApiClient,
        opts: SyncOptions,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        sync::spawn(self, client, opts)
    }

    /// The endpoint owning `ip`, if known. Lock-free: one atomic load and a
    /// hash probe on an immutable map.
    #[inline]
    pub fn lookup(&self, ip: u32) -> Option<Arc<K8sEndpoint>> {
        self.index.load().lookup(ip).cloned()
    }

    /// The identity string for `ip` (`namespace/workload`, ...), if known.
    #[inline]
    pub fn display(&self, ip: u32) -> Option<Arc<str>> {
        self.index.load().lookup(ip).map(|e| Arc::clone(&e.display))
    }

    /// The current index snapshot.
    pub fn snapshot(&self) -> Arc<K8sIndex> {
        self.index.load_full()
    }

    /// Number of index snapshots published so far.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Whether an index built from both a pod and a service list has been
    /// published.
    pub fn is_synced(&self) -> bool {
        self.synced.load(Ordering::Acquire)
    }

    /// API requests that failed so far.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}
