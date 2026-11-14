//! The scope publisher (DESIGN §3, narrowing): one serialised task owns
//! every runtime write to `CGROUP_ALLOW`, `CONFIG_SCOPE_GEN` and the scope
//! options (`CONFIG_CAPTURE_LOOPBACK`, `CONFIG_PID_CREATOR_RULE`). It runs
//! whether or not a cgroup selector is set.
//!
//! Inputs, processed in order: a `SIGHUP` reload that changes
//! `cgroup_filter` / `pod_filter`, `capture_loopback` or
//! `pid_filter_listener`, every Kubernetes metadata change (the pods
//! `pod_filter` selects are re-resolved), and the net_cls watch.
//!
//! For each change the target set is resolved and published
//! ([`crate::scope_select::publish`]):
//! - widening only (cgroups added, `capture_loopback` turned on, the
//!   acceptor rule replaced by the creator rule): the publication is all
//!   (it only adds scope; its generation bump makes cached verdicts
//!   recompute);
//! - narrowing (a cgroup removed, `capture_loopback` turned off, the
//!   creator rule replaced by the acceptor rule; a reload that does any of
//!   these, whatever else it widens): the five steps of DESIGN §3 — publish and bump to `g`,
//!   raise the admission floor to `g`, build a new pipeline and switch the
//!   readers to it, revoke the old pipeline's gate, report applied
//!   ([`Scope::narrow`]); the old pipeline is dropped, never flushed;
//! - after a pipeline build failed, every later change (widening or none)
//!   retries the build (Revision 1 item 7).
//!
//! Any runtime publication failure is a fatal capture stop: the kernel is
//! disarmed on every capture path, the current pipeline is revoked, and
//! only then is the stop logged. If disarming fails, [`run`] returns an
//! error and the agent exits (its programs are never pinned, so they
//! detach with it).
//!
//! The publisher task ending any other way (a panic, an error, or its
//! channel closing while the agent runs) is also a fatal stop, run by
//! [`supervise`], after which the agent exits.
//!
//! Startup: the publisher subscribes to Kubernetes changes when it is
//! created, then the agent runs the first reconciliation
//! ([`Publisher::pods_changed`]) before it starts the ring readers or
//! reports ready.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use crate::config::{PodFilter, ScopeOptions};
use crate::k8s::K8sMetadata;
use crate::pipeline::Scope;
use crate::scope_select::{AllowMap, publish, resolve, select_pods};

pub enum ScopeMsg {
    /// A reload with these selectors. The reply comes once the change is
    /// applied; an error means the reload is rejected and nothing changed.
    Reload {
        cgroup_filter: Option<Vec<String>>,
        pod_filter: Option<Vec<PodFilter>>,
        options: ScopeOptions,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// A v1 net_cls/net_prio hierarchy appeared (DESIGN §3.2): the cgroup
    /// selector admits nothing more until a restart.
    Disable(String),
}

/// Runs `f` on the loaded object's maps (Linux: under the eBPF state lock).
pub trait ScopeMaps: Send {
    fn with(&mut self, f: &mut dyn FnMut(&mut dyn AllowMap) -> Result<()>) -> Result<()>;
}

pub struct Publisher<M> {
    maps: M,
    scope: Arc<Scope>,
    root: PathBuf,
    k8s: Option<Arc<K8sMetadata>>,
    node: Option<String>,
    pod_filter: Vec<PodFilter>,
    /// `cgroup_filter` resolved at the last accepted config.
    cgroup_ids: BTreeSet<u64>,
    /// What `CGROUP_ALLOW` holds.
    current: BTreeSet<u64>,
    /// What the scope options in `CONFIG` are.
    options: ScopeOptions,
    /// Set by the net_cls watch: the target stays empty.
    disabled: Option<String>,
    /// After a fatal stop: nothing more is published.
    stopped: bool,
    /// Kubernetes change notifications, subscribed at creation so that no
    /// change after the first reconciliation is missed.
    pods_rx: Option<watch::Receiver<u64>>,
}

impl<M: ScopeMaps> Publisher<M> {
    /// `root` is the cgroup2 attach root; `cgroup_filter` / `pod_filter`
    /// and `options` are the running config's (the loader wrote `options`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mut maps: M,
        scope: Arc<Scope>,
        root: PathBuf,
        k8s: Option<Arc<K8sMetadata>>,
        node: Option<String>,
        cgroup_filter: &[String],
        pod_filter: &[PodFilter],
        options: ScopeOptions,
    ) -> Result<Self> {
        let mut current = BTreeSet::new();
        maps.with(&mut |m| {
            current = m.ids()?;
            Ok(())
        })?;
        Ok(Self {
            pods_rx: k8s.as_ref().map(|m| m.subscribe()),
            cgroup_ids: resolve(&root, cgroup_filter, &[])?.ids,
            maps,
            scope,
            root,
            k8s,
            node,
            pod_filter: pod_filter.to_vec(),
            current,
            options,
            disabled: None,
            stopped: false,
        })
    }

    #[cfg(test)]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// The pods `pod_filter` selects now, resolved to cgroup ids.
    fn pod_ids(&self, filters: &[PodFilter]) -> Result<BTreeSet<u64>> {
        if filters.is_empty() {
            return Ok(BTreeSet::new());
        }
        let Some(meta) = &self.k8s else {
            bail!("pod_filter needs Kubernetes metadata, which is not available");
        };
        let pods = select_pods(&meta.pods(), filters, self.node.as_deref());
        let r = resolve(&self.root, &[], &pods)?;
        if !r.unresolved.is_empty() {
            warn!(
                pods = ?r.unresolved,
                "pod_filter: no cgroup found for these pods on this node; not captured"
            );
        }
        Ok(r.ids)
    }

    /// The set to publish: empty once disabled, or (failing closed) when
    /// the union passes the map's size.
    fn target(&self, cgroup_ids: &BTreeSet<u64>, pod_ids: BTreeSet<u64>) -> BTreeSet<u64> {
        if self.disabled.is_some() {
            return BTreeSet::new();
        }
        let union: BTreeSet<u64> = cgroup_ids.union(&pod_ids).copied().collect();
        if union.len() > panopticon_common::MAX_CGROUP_ALLOW as usize {
            error!(
                cgroups = union.len(),
                "cgroup_filter/pod_filter select more cgroups than CGROUP_ALLOW holds; \
                 nothing is captured by them"
            );
            return BTreeSet::new();
        }
        union
    }

    /// Process one message.
    pub async fn handle(&mut self, msg: ScopeMsg) -> Result<()> {
        match msg {
            ScopeMsg::Reload {
                cgroup_filter,
                pod_filter,
                options,
                reply,
            } => {
                if self.stopped {
                    let _ = reply.send(Err("capture is stopped; restart the agent".into()));
                    return Ok(());
                }
                let pod_filter = pod_filter.unwrap_or_default();
                let resolved = resolve(
                    &self.root,
                    cgroup_filter.as_deref().unwrap_or_default(),
                    &[],
                )
                .and_then(|r| Ok((r.ids, self.pod_ids(&pod_filter)?)));
                let (cgroup_ids, pod_ids) = match resolved {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = reply.send(Err(format!("{e:#}")));
                        return Ok(());
                    }
                };
                let target = self.target(&cgroup_ids, pod_ids);
                self.cgroup_ids = cgroup_ids;
                self.pod_filter = pod_filter;
                let r = self.apply(target, options, "reload").await;
                let _ = reply.send(if self.stopped {
                    Err("scope publication failed; capture stopped".into())
                } else {
                    Ok(())
                });
                r
            }
            ScopeMsg::Disable(why) => {
                if self.disabled.is_none() {
                    self.disabled = Some(why.clone());
                    self.apply(BTreeSet::new(), self.options, "net_cls").await?;
                    error!(
                        reason = %why,
                        "cgroup_filter/pod_filter stopped admitting: the kernel may no longer \
                         record cgroup v2 membership of new sockets; restart to re-check"
                    );
                }
                Ok(())
            }
        }
    }

    /// Kubernetes metadata changed: re-resolve the selected pods.
    pub async fn pods_changed(&mut self) -> Result<()> {
        if self.stopped || self.pod_filter.is_empty() {
            return Ok(());
        }
        let pod_ids = match self.pod_ids(&self.pod_filter) {
            Ok(ids) => ids,
            Err(e) => {
                // Fail closed: the pods are not captured until they resolve.
                error!(error = %format!("{e:#}"), "pod_filter: cannot resolve the selected pods");
                BTreeSet::new()
            }
        };
        let target = self.target(&self.cgroup_ids, pod_ids);
        self.apply(target, self.options, "kubernetes").await
    }

    /// Publish `target` and `options` and run the change (see the module
    /// docs).
    async fn apply(
        &mut self,
        target: BTreeSet<u64>,
        options: ScopeOptions,
        cause: &'static str,
    ) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        let current = self.current.clone();
        let from = self.options;
        let changed = (from != options).then_some(options);
        let mut outcome = None;
        let published = self.maps.with(&mut |m| {
            let diff = publish(m, &current, &target, changed)?;
            outcome = Some((diff, m.generation()?));
            Ok(())
        });
        let (diff, generation) = match (published, outcome) {
            (Ok(()), Some((diff, g))) => match u32::try_from(g) {
                Ok(g) => (diff, g),
                Err(_) => {
                    return self
                        .fatal_stop(format!("scope generation {g} overflows"))
                        .await;
                }
            },
            (Err(e), _) => return self.fatal_stop(format!("{e:#}")).await,
            (Ok(()), None) => unreachable!("publish ran"),
        };
        self.current = target;
        self.options = options;
        if diff.is_narrowing() || from.narrows_to(options) {
            let installed = self.scope.narrow(generation).await;
            // Step 5: report applied.
            info!(
                cause,
                generation,
                removed = diff.removed.len(),
                added = diff.added.len(),
                capture_loopback = options.capture_loopback,
                creator_rule = options.creator_rule,
                pipeline = installed,
                "Scope narrowed: applied (data captured under the wider scope was revoked)"
            );
        } else {
            let installed = self.scope.ensure_installed().await;
            if !diff.added.is_empty() || changed.is_some() {
                info!(
                    cause,
                    generation,
                    added = diff.added.len(),
                    capture_loopback = options.capture_loopback,
                    creator_rule = options.creator_rule,
                    pipeline = installed,
                    "Scope widened: applied"
                );
            }
        }
        Ok(())
    }

    /// Disarm the kernel, revoke the current pipeline, then log. Err only
    /// when disarming failed: the agent must exit.
    async fn fatal_stop(&mut self, why: String) -> Result<()> {
        self.stopped = true;
        let disarmed = stop_capture(&mut self.maps, &self.scope).await;
        match disarmed {
            Ok(()) => {
                error!(
                    reason = %why,
                    "Scope publication failed: capture stopped (kernel disarmed, pipeline \
                     revoked); restart the agent"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    reason = %why,
                    error = %format!("{e:#}"),
                    "Scope publication failed and the kernel could not be disarmed; exiting"
                );
                bail!("scope publication failed ({why}) and disarming failed ({e:#})")
            }
        }
    }
}

/// Disarm the kernel on every capture path, then revoke the current
/// pipeline (for good). Returns the disarm's result.
pub async fn stop_capture<M: ScopeMaps>(maps: &mut M, scope: &Scope) -> Result<()> {
    let disarmed = maps.with(&mut |m| m.disarm());
    scope.stop().await;
    disarmed
}

/// The publisher task, after the first reconciliation (see the module
/// docs). Returns an error only when the agent must exit.
pub async fn run<M: ScopeMaps>(
    mut publisher: Publisher<M>,
    mut rx: mpsc::Receiver<ScopeMsg>,
) -> Result<()> {
    let mut pods = publisher.pods_rx.take();
    loop {
        let pods_changed = async {
            match pods.as_mut() {
                Some(rx) => rx.changed().await.is_ok(),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => publisher.handle(msg).await?,
                None => return Ok(()),
            },
            alive = pods_changed => {
                if alive {
                    publisher.pods_changed().await?;
                } else {
                    pods = None;
                }
            }
        }
    }
}

/// Wait for the publisher task (`task`). It never ends while the agent
/// runs, so any end (an error, a panic, or a return) is a fatal stop:
/// disarm through `maps`, revoke `scope`, then log. Returns the error the
/// agent exits with.
pub async fn supervise<M: ScopeMaps>(
    task: tokio::task::JoinHandle<Result<()>>,
    mut maps: M,
    scope: &Scope,
) -> anyhow::Error {
    let why = match task.await {
        Ok(Ok(())) => anyhow::anyhow!("the scope publisher stopped"),
        Ok(Err(e)) => e,
        Err(e) if e.is_panic() => anyhow::anyhow!("the scope publisher panicked"),
        Err(_) => anyhow::anyhow!("the scope publisher was cancelled"),
    };
    let disarmed = stop_capture(&mut maps, scope).await;
    error!(
        reason = %format!("{why:#}"),
        disarmed = disarmed.is_ok(),
        "Scope publisher ended: capture stopped (pipeline revoked); exiting"
    );
    match disarmed {
        Ok(()) => why,
        Err(e) => why.context(format!("disarming the kernel failed too ({e:#})")),
    }
}

#[cfg(target_os = "linux")]
pub use linux::AyaMaps;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::scope_select::AyaAllow;

    /// The shared eBPF object's maps, locked per call.
    pub struct AyaMaps(pub Arc<std::sync::Mutex<crate::loader::EbpfState>>);

    impl ScopeMaps for AyaMaps {
        fn with(&mut self, f: &mut dyn FnMut(&mut dyn AllowMap) -> Result<()>) -> Result<()> {
            let mut st = self.0.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut AyaAllow(&mut st.ebpf))
        }
    }
}
