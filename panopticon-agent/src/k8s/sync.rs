//! Background sync: list + watch pods and services, publish IP index
//! snapshots.
//!
//! One reflector task per resource keeps [`Store`] current (a paginated
//! list, then a watch from the list's resourceVersion until the re-list
//! interval elapses or the watch breaks); a publisher task rebuilds the
//! [`K8sIndex`] at most once per `publish_interval` when something changed
//! and swaps it in. Nothing here ever blocks agent startup or a worker.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::K8sMetadata;
use super::client::{ApiClient, ApiError};
use super::model::{Pod, Service, WatchEvent};
use crate::config::KubernetesConfig;

/// Tunables for the sync loop (tests shrink them).
#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub relist_interval: Duration,
    pub watch: bool,
    /// Longest single watch request (server-side `timeoutSeconds`).
    pub max_watch: Duration,
    /// How often a changed store is turned into a new index.
    pub publish_interval: Duration,
    /// Retry delay cap after failures.
    pub max_backoff: Duration,
    /// Drop a resource's objects when the API has not answered for this
    /// long: with pods churning and IPs reused, old names would become
    /// wrong names.
    pub stale_after: Duration,
}

impl SyncOptions {
    pub fn from_config(cfg: &KubernetesConfig) -> Self {
        Self {
            relist_interval: cfg.relist_interval,
            watch: cfg.watch,
            max_watch: Duration::from_secs(300),
            publish_interval: Duration::from_secs(1),
            max_backoff: cfg.relist_interval.min(Duration::from_secs(60)),
            stale_after: (cfg.relist_interval * 2).max(Duration::from_secs(60)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resource {
    Pods,
    Services,
}

impl Resource {
    fn path(self) -> &'static str {
        match self {
            Resource::Pods => "/api/v1/pods",
            Resource::Services => "/api/v1/services",
        }
    }

    /// Finished pods have released their IPs; don't fetch them at all.
    fn field_selector(self) -> Option<&'static str> {
        match self {
            Resource::Pods => Some("status.phase!=Succeeded,status.phase!=Failed"),
            Resource::Services => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Resource::Pods => "pods",
            Resource::Services => "services",
        }
    }
}

/// Spawn the reflectors and the publisher. Returns immediately.
pub(crate) fn spawn(
    meta: &Arc<K8sMetadata>,
    client: ApiClient,
    opts: SyncOptions,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    for res in [Resource::Pods, Resource::Services] {
        handles.push(tokio::spawn(reflector(
            Arc::clone(meta),
            client.clone(),
            res,
            opts.clone(),
        )));
    }
    handles.push(tokio::spawn(publisher(Arc::clone(meta), opts)));
    handles
}

async fn publisher(meta: Arc<K8sMetadata>, opts: SyncOptions) {
    let mut tick = tokio::time::interval(opts.publish_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        meta.publish_if_dirty();
    }
}

async fn reflector(meta: Arc<K8sMetadata>, client: ApiClient, res: Resource, opts: SyncOptions) {
    let mut backoff = Duration::from_secs(1).min(opts.max_backoff);
    let mut last_ok: Option<Instant> = None;
    loop {
        let listed = match res {
            Resource::Pods => client
                .list_all::<Pod>(res.path(), res.field_selector())
                .await
                .map(|(items, rv)| {
                    meta.replace_pods(&items);
                    (items.len(), rv)
                }),
            Resource::Services => client
                .list_all::<Service>(res.path(), res.field_selector())
                .await
                .map(|(items, rv)| {
                    meta.replace_services(&items);
                    (items.len(), rv)
                }),
        };
        let (count, mut rv) = match listed {
            Ok(v) => v,
            Err(e) => {
                meta.report_failure(res, &e);
                if last_ok.is_some_and(|t| t.elapsed() >= opts.stale_after) {
                    last_ok = None;
                    meta.clear(res);
                    warn!(
                        resource = res.name(),
                        "Kubernetes metadata is stale; dropped it, endpoints use DNS/IP names"
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(opts.max_backoff);
                continue;
            }
        };
        meta.report_success(res);
        last_ok = Some(Instant::now());
        backoff = Duration::from_secs(1).min(opts.max_backoff);
        debug!(resource = res.name(), count, resource_version = %rv, "Kubernetes list complete");

        let relist_at = Instant::now() + opts.relist_interval;
        if !opts.watch || rv.is_empty() {
            tokio::time::sleep_until(relist_at).await;
            continue;
        }
        // Watch until the re-list deadline, resuming from the last
        // resourceVersion each time the server ends a watch.
        let mut watch_backoff = Duration::from_secs(1).min(opts.max_backoff);
        while Instant::now() < relist_at {
            let remaining = relist_at - Instant::now();
            let timeout = remaining.min(opts.max_watch).max(Duration::from_secs(1));
            let started = Instant::now();
            let result = client
                .watch(res.path(), res.field_selector(), &rv, timeout, |ev| {
                    meta.apply_event(res, ev)
                })
                .await;
            match result {
                Ok(new_rv) => {
                    rv = new_rv;
                    last_ok = Some(Instant::now());
                    watch_backoff = Duration::from_secs(1).min(opts.max_backoff);
                    // A server that ends watches immediately must not
                    // make this loop spin.
                    if started.elapsed() < Duration::from_secs(1) {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                Err(ApiError::Gone) => {
                    debug!(resource = res.name(), "Watch expired (410), re-listing");
                    break;
                }
                Err(e) => {
                    debug!(resource = res.name(), error = %e, "Watch failed, re-listing after backoff");
                    meta.note_watch_failure(res, &e);
                    let left = relist_at.saturating_duration_since(Instant::now());
                    tokio::time::sleep(watch_backoff.min(left)).await;
                    watch_backoff = (watch_backoff * 2).min(opts.max_backoff);
                }
            }
        }
    }
}

impl K8sMetadata {
    pub(crate) fn replace_pods(&self, pods: &[Pod]) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.pods.clear();
        for p in pods {
            if let Some(rec) = p.to_record() {
                store.upsert_pod(p.key(), rec);
            }
        }
        drop(store);
        self.listed[Resource::Pods as usize].store(true, Ordering::Release);
        self.dirty.store(true, Ordering::Release);
    }

    pub(crate) fn replace_services(&self, services: &[Service]) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.services.clear();
        for s in services {
            if let Some(rec) = s.to_record() {
                store.upsert_service(s.key(), rec);
            }
        }
        drop(store);
        self.listed[Resource::Services as usize].store(true, Ordering::Release);
        self.dirty.store(true, Ordering::Release);
    }

    pub(crate) fn clear(&self, res: Resource) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        match res {
            Resource::Pods => store.pods.clear(),
            Resource::Services => store.services.clear(),
        }
        drop(store);
        self.dirty.store(true, Ordering::Release);
    }

    pub(crate) fn apply_event(&self, res: Resource, ev: WatchEvent) {
        let deleted = match ev.event_type.as_str() {
            "ADDED" | "MODIFIED" => false,
            "DELETED" => true,
            // BOOKMARK carries only a resourceVersion (handled by the client).
            _ => return,
        };
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        match res {
            Resource::Pods => {
                let Ok(pod) = serde_json::from_value::<Pod>(ev.object) else {
                    return;
                };
                let key = pod.key();
                match pod.to_record().filter(|_| !deleted) {
                    Some(rec) => {
                        store.upsert_pod(key, rec);
                    }
                    None => {
                        store.pods.remove(&key);
                    }
                }
            }
            Resource::Services => {
                let Ok(svc) = serde_json::from_value::<Service>(ev.object) else {
                    return;
                };
                let key = svc.key();
                match svc.to_record().filter(|_| !deleted) {
                    Some(rec) => {
                        store.upsert_service(key, rec);
                    }
                    None => {
                        store.services.remove(&key);
                    }
                }
            }
        }
        drop(store);
        self.dirty.store(true, Ordering::Release);
    }

    /// Rebuild and swap in the index if the store changed.
    pub(crate) fn publish_if_dirty(&self) -> bool {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return false;
        }
        let (index, dropped) = {
            let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
            (store.build_index(), store.dropped)
        };
        let (pods, services, nodes) = (index.pods, index.services, index.nodes);
        self.index.store(Arc::new(index));
        self.generation.fetch_add(1, Ordering::Release);
        // "Synced" once both pods and services have been listed.
        let all_listed = self.listed.iter().all(|l| l.load(Ordering::Acquire));
        if all_listed && !self.synced.swap(true, Ordering::AcqRel) {
            info!(
                pods,
                services,
                nodes,
                "Kubernetes metadata synced; graph endpoints use namespace/workload names"
            );
        } else {
            debug!(pods, services, nodes, "Kubernetes index updated");
        }
        if dropped > 0 && !self.cap_warned.swap(true, Ordering::AcqRel) {
            warn!(
                dropped,
                "Kubernetes object cap reached; some pods/services are not indexed"
            );
        }
        true
    }

    fn report_failure(&self, res: Resource, e: &ApiError) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        if !self.failing[res as usize].swap(true, Ordering::AcqRel) {
            warn!(
                resource = res.name(),
                api = %self.api_base,
                error = %e,
                hint = e.hint().unwrap_or(""),
                "Kubernetes API unavailable; endpoints keep DNS/IP names until it answers \
                 (retrying in the background, further failures logged at debug)"
            );
        } else {
            debug!(resource = res.name(), error = %e, "Kubernetes API request failed");
        }
    }

    fn note_watch_failure(&self, res: Resource, e: &ApiError) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        if !self.watch_warned[res as usize].swap(true, Ordering::AcqRel) {
            warn!(
                resource = res.name(),
                error = %e,
                hint = e.hint().unwrap_or(""),
                "Kubernetes watch failed; falling back to periodic re-lists"
            );
        }
    }

    fn report_success(&self, res: Resource) {
        if self.failing[res as usize].swap(false, Ordering::AcqRel) {
            info!(resource = res.name(), "Kubernetes API reachable again");
        }
    }
}
