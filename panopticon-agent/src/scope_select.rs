//! `cgroup_filter` / `pod_filter` (DESIGN §3.2): resolve the selectors to
//! cgroup v2 ids and publish them to `CGROUP_ALLOW`.
//!
//! A cgroup id is the inode number of its directory. Every unresolved
//! selector selects nothing; nothing here ever falls back to capturing all.
//! Startup only for now: the runtime publisher (pod churn, reload) is a
//! later stage and will call [`publish`] with the previous set.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::warn;

use crate::config::{PodFilter, PodSelect, cgroup_filter_rel};
use crate::k8s::model::PodRecord;

/// Directory levels below the cgroup2 root searched for pod directories.
/// kubelet's own layouts put them at depth 2 (guaranteed) or 3; the slack
/// covers runtimes that nest `kubepods` under another slice.
const POD_SEARCH_DEPTH: usize = 5;
/// How long startup waits for the first Kubernetes sync with `pod_filter`.
pub const POD_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

// ── Pods ───────────────────────────────────────────────────────────────────

/// A pod `pod_filter` selected: `namespace/name` and its uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedPod {
    pub key: String,
    pub uid: String,
}

/// Namespace equal AND (every listed label equal | name equal).
pub fn pod_matches(f: &PodFilter, p: &PodRecord) -> bool {
    *p.namespace == *f.namespace
        && match &f.select {
            PodSelect::Name(n) => *p.name == **n,
            PodSelect::Labels(l) => l.iter().all(|(k, v)| p.labels.get(k) == Some(v)),
        }
}

/// The pods on `node` (every pod when the node is unknown) that any filter
/// matches.
pub fn select_pods(
    pods: &[PodRecord],
    filters: &[PodFilter],
    node: Option<&str>,
) -> Vec<SelectedPod> {
    let mut out: Vec<SelectedPod> = pods
        .iter()
        .filter(|p| node.is_none_or(|n| p.node.as_deref() == Some(n)))
        .filter(|p| filters.iter().any(|f| pod_matches(f, p)))
        .map(|p| SelectedPod {
            key: format!("{}/{}", p.namespace, p.name),
            uid: p.uid.to_ascii_lowercase(),
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// Wait (bounded) for the first Kubernetes sync, then select this node's
/// matching pods. On timeout, start with what is known: pods not seen yet
/// are not captured.
pub async fn startup_pods(
    meta: &crate::k8s::K8sMetadata,
    filters: &[PodFilter],
) -> Vec<SelectedPod> {
    let deadline = tokio::time::Instant::now() + POD_SYNC_TIMEOUT;
    while !meta.is_synced() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if !meta.is_synced() {
        warn!(
            timeout_secs = POD_SYNC_TIMEOUT.as_secs(),
            "pod_filter: no Kubernetes sync yet; starting with the pods known so far, \
             the others are not captured"
        );
    }
    let node = std::env::var("NODE_NAME").ok().filter(|n| !n.is_empty());
    if node.is_none() {
        warn!(
            "pod_filter: NODE_NAME is not set; matching pods on every node (only this node's resolve)"
        );
    }
    select_pods(&meta.pods(), filters, node.as_deref())
}

/// The pod uid a cgroup directory name is for, lowercase with dashes:
/// `pod<uid>` (cgroupfs driver) or `...-pod<uid with _>.slice` (systemd).
fn pod_uid_of(name: &str) -> Option<String> {
    let name = name.strip_suffix(".slice").unwrap_or(name);
    let at = name.rfind("pod")?;
    if at != 0 && !name[..at].ends_with('-') {
        return None;
    }
    let uid = name[at + 3..].replace('_', "-").to_ascii_lowercase();
    let is_uuid = uid.len() == 36
        && uid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    is_uuid.then_some(uid)
}

/// Pod directories below the root, by uid, searched breadth first to
/// [`POD_SEARCH_DEPTH`] (never below a pod directory). `subdirs(rel)` lists
/// the subdirectory names of `rel` (relative to the root; empty is the root).
fn pod_dirs(subdirs: &dyn Fn(&Path) -> Vec<String>) -> HashMap<String, Vec<PathBuf>> {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut level = vec![PathBuf::new()];
    for _ in 0..POD_SEARCH_DEPTH {
        let mut next = Vec::new();
        for dir in &level {
            for name in subdirs(dir) {
                let p = dir.join(&name);
                match pod_uid_of(&name) {
                    Some(uid) => out.entry(uid).or_default().push(p),
                    None => next.push(p),
                }
            }
        }
        level = next;
    }
    out
}

/// The pod's directory: exactly one match. None or several (ambiguous):
/// unresolved.
fn pod_dir<'a>(dirs: &'a HashMap<String, Vec<PathBuf>>, uid: &str) -> Option<&'a Path> {
    match dirs.get(uid).map(Vec::as_slice) {
        Some([one]) => Some(one),
        _ => None,
    }
}

// ── Resolution ─────────────────────────────────────────────────────────────

/// The selected cgroup ids, and the pods that did not resolve (not in the
/// set: they fail closed).
#[derive(Debug, Default)]
pub struct Resolved {
    pub ids: BTreeSet<u64>,
    pub unresolved: Vec<String>,
}

fn real_subdirs(root: &Path) -> impl Fn(&Path) -> Vec<String> + '_ {
    move |rel| {
        let Ok(rd) = std::fs::read_dir(root.join(rel)) else {
            return Vec::new();
        };
        rd.flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }
}

/// Resolve `cgroup_filter` paths and the selected pods under `root` (the
/// attach root). Refuses a missing path, a path on another filesystem, and
/// the root cgroup (id 1) or the attach root itself (§3.2).
pub fn resolve(root: &Path, paths: &[String], pods: &[SelectedPod]) -> Result<Resolved> {
    let root_meta = std::fs::metadata(root)
        .with_context(|| format!("cannot stat the cgroup root {}", root.display()))?;
    let id_of = |rel: &Path, what: &str| -> Result<Option<u64>> {
        let Ok(m) = std::fs::metadata(root.join(rel)) else {
            return Ok(None);
        };
        if !m.is_dir() || m.dev() != root_meta.dev() {
            return Ok(None);
        }
        if m.ino() == 1 || m.ino() == root_meta.ino() {
            bail!(
                "refusing {what}: it resolves to the cgroup root (id {}), which would capture \
                 every process",
                m.ino()
            );
        }
        Ok(Some(m.ino()))
    };
    let mut out = Resolved::default();
    for p in paths {
        let what = format!("cgroup_filter = \"{p}\"");
        let rel = cgroup_filter_rel(p)?;
        match id_of(Path::new(rel), &what)? {
            Some(id) => out.ids.insert(id),
            None => bail!("refusing {what}: no such cgroup under {}", root.display()),
        };
    }
    if !pods.is_empty() {
        let dirs = pod_dirs(&real_subdirs(root));
        for pod in pods {
            let what = format!("pod_filter pod {}", pod.key);
            match pod_dir(&dirs, &pod.uid) {
                Some(rel) => match id_of(rel, &what)? {
                    Some(id) => {
                        out.ids.insert(id);
                    }
                    None => out.unresolved.push(pod.key.clone()),
                },
                None => out.unresolved.push(pod.key.clone()),
            }
        }
    }
    let max = panopticon_common::MAX_CGROUP_ALLOW as usize;
    if out.ids.len() > max {
        bail!(
            "refusing cgroup_filter/pod_filter: {} cgroups selected; at most {max}",
            out.ids.len()
        );
    }
    Ok(out)
}

// ── Publication ────────────────────────────────────────────────────────────

/// `CGROUP_ALLOW` plus the `CONFIG_SCOPE_GEN` bump.
pub trait AllowMap {
    fn insert(&mut self, id: u64) -> Result<()>;
    fn remove(&mut self, id: u64) -> Result<()>;
    fn bump_gen(&mut self) -> Result<()>;
}

/// What a publication changed. Only `added`: widening. Any `removed`:
/// narrowing, which the runtime publisher must follow with the pipeline
/// revocation (DESIGN §3).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AllowDiff {
    pub added: Vec<u64>,
    pub removed: Vec<u64>,
}

impl AllowDiff {
    pub fn is_narrowing(&self) -> bool {
        !self.removed.is_empty()
    }
}

/// Move `CGROUP_ALLOW` from `current` to `new` in the design's order:
/// deletes, then inserts, then one `CONFIG_SCOPE_GEN` increment if anything
/// changed (§3). A failed write still bumps the generation when an earlier
/// write changed the map, so a delete that went through is never hidden
/// behind a verdict cached under the old generation; the error is returned.
pub fn publish(
    map: &mut dyn AllowMap,
    current: &BTreeSet<u64>,
    new: &BTreeSet<u64>,
) -> Result<AllowDiff> {
    let mut diff = AllowDiff::default();
    let mut write = || -> Result<()> {
        for &id in current.difference(new) {
            map.remove(id)?;
            diff.removed.push(id);
        }
        for &id in new.difference(current) {
            map.insert(id)?;
            diff.added.push(id);
        }
        Ok(())
    };
    let r = write();
    if !diff.added.is_empty() || !diff.removed.is_empty() {
        map.bump_gen()?;
    }
    r.map(|()| diff)
}

// ── net_cls / net_prio (cgroup v1) ─────────────────────────────────────────

/// The mount point of a cgroup v1 hierarchy with `net_cls` or `net_prio`
/// in `/proc/self/mountinfo` text, if one is mounted.
pub fn net_cls_v1_mount(mountinfo: &str) -> Option<&str> {
    mountinfo.lines().find_map(|l| {
        let (pre, post) = l.split_once(" - ")?;
        let mut f = post.split_whitespace();
        if f.next()? != "cgroup" {
            return None;
        }
        let opts = f.nth(1)?;
        if !opts.split(',').any(|o| o == "net_cls" || o == "net_prio") {
            return None;
        }
        pre.split_whitespace().nth(4)
    })
}

/// Why the cgroup selector cannot be trusted now: a v1 `net_cls`/`net_prio`
/// hierarchy is mounted, or mountinfo is unreadable (cannot tell).
fn net_cls_problem() -> Option<String> {
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(m) => net_cls_v1_mount(&m)
            .map(|mp| format!("a cgroup v1 net_cls/net_prio hierarchy is mounted at {mp}")),
        Err(e) => Some(format!("cannot read /proc/self/mountinfo ({e})")),
    }
}

// ── Linux: the BPF maps ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use aya::Ebpf;
    use aya::maps::{Array, HashMap as BpfHashMap, MapData, MapError};
    use panopticon_common::CONFIG_SCOPE_GEN;
    use tracing::{error, info};

    /// `CGROUP_ALLOW` and `CONFIG` of a loaded object.
    pub struct AyaAllow<'a>(pub &'a mut Ebpf);

    impl AyaAllow<'_> {
        fn allow(&mut self) -> Result<BpfHashMap<&mut MapData, u64, u8>> {
            Ok(BpfHashMap::try_from(
                self.0
                    .map_mut("CGROUP_ALLOW")
                    .context("CGROUP_ALLOW map not found")?,
            )?)
        }

        /// The ids in `CGROUP_ALLOW` now.
        pub fn ids(&self) -> Result<BTreeSet<u64>> {
            let m: BpfHashMap<&MapData, u64, u8> = BpfHashMap::try_from(
                self.0
                    .map("CGROUP_ALLOW")
                    .context("CGROUP_ALLOW map not found")?,
            )?;
            Ok(m.keys().collect::<Result<_, _>>()?)
        }
    }

    impl AllowMap for AyaAllow<'_> {
        fn insert(&mut self, id: u64) -> Result<()> {
            self.allow()?
                .insert(id, 1, 0)
                .with_context(|| format!("cannot add cgroup {id} to CGROUP_ALLOW"))
        }

        fn remove(&mut self, id: u64) -> Result<()> {
            match self.allow()?.remove(&id) {
                Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
                Err(MapError::SyscallError(e))
                    if e.io_error.raw_os_error() == Some(libc::ENOENT) =>
                {
                    Ok(())
                }
                Err(e) => Err(e).context(format!("cannot remove cgroup {id} from CGROUP_ALLOW")),
            }
        }

        fn bump_gen(&mut self) -> Result<()> {
            let mut cfg: Array<&mut MapData, u64> =
                Array::try_from(self.0.map_mut("CONFIG").context("CONFIG map not found")?)?;
            let g = cfg.get(&CONFIG_SCOPE_GEN, 0)?;
            cfg.set(CONFIG_SCOPE_GEN, g + 1, 0)?;
            Ok(())
        }
    }

    /// Startup, before anything is attached or armed: refuse the selector
    /// while a v1 net_cls/net_prio hierarchy is mounted (§3.2; T-6 has not
    /// cleared any kernel yet), resolve, and publish `CGROUP_ALLOW`.
    pub fn startup_publish(
        ebpf: &mut Ebpf,
        root: &Path,
        paths: &[String],
        pods: &[SelectedPod],
    ) -> Result<()> {
        if let Some(why) = net_cls_problem() {
            bail!(
                "refusing cgroup_filter/pod_filter: {why}; the kernel may not record \
                 cgroup v2 membership of sockets then (DESIGN §3.2)"
            );
        }
        let r = resolve(root, paths, pods)?;
        if !r.unresolved.is_empty() {
            warn!(
                pods = ?r.unresolved,
                "pod_filter: no cgroup found for these pods on this node; not captured"
            );
        }
        let mut map = AyaAllow(ebpf);
        let current = map.ids()?;
        let diff = publish(&mut map, &current, &r.ids)?;
        info!(
            cgroups = r.ids.len(),
            added = diff.added.len(),
            removed = diff.removed.len(),
            "CGROUP_ALLOW published"
        );
        if r.ids.is_empty() {
            warn!("cgroup_filter/pod_filter selected no cgroup: nothing is captured by them");
        }
        Ok(())
    }

    /// Every 10 s, recheck for a v1 net_cls/net_prio hierarchy (§3.2). On
    /// the first sighting the cgroup selector stops admitting: `CGROUP_ALLOW`
    /// is emptied (one generation bump) and stays empty until a restart,
    /// which then refuses. Not a full narrowing: records already admitted
    /// are not revoked (that needs the runtime publisher's pipeline
    /// revocation).
    pub fn spawn_net_cls_watch(state: std::sync::Arc<std::sync::Mutex<crate::loader::EbpfState>>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let Some(why) = net_cls_problem() else {
                    continue;
                };
                let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                let mut map = AyaAllow(&mut st.ebpf);
                let r = map
                    .ids()
                    .and_then(|cur| publish(&mut map, &cur, &BTreeSet::new()));
                let outcome = match &r {
                    Ok(d) => format!("CGROUP_ALLOW emptied ({} removed)", d.removed.len()),
                    Err(e) => format!("emptying CGROUP_ALLOW failed: {e:#}"),
                };
                error!(
                    reason = %why,
                    outcome = %outcome,
                    "cgroup_filter/pod_filter stopped admitting: the kernel may no longer \
                     record cgroup v2 membership of new sockets; restart to re-check"
                );
                return;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const UID: &str = "0f3c1a2b-4d5e-6f70-8192-a3b4c5d6e7f8";
    const UID_: &str = "0f3c1a2b_4d5e_6f70_8192_a3b4c5d6e7f8";

    fn tree(paths: &[&str]) -> impl Fn(&Path) -> Vec<String> {
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        move |dir: &Path| {
            let mut v: Vec<String> = paths
                .iter()
                .flat_map(|p| p.ancestors().collect::<Vec<_>>())
                .filter(|a| a.parent() == Some(dir) && !a.as_os_str().is_empty())
                .map(|a| a.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v.dedup();
            v
        }
    }

    #[test]
    fn pod_dir_search_covers_both_drivers_and_guaranteed_qos() {
        let cases = [
            // systemd, burstable / besteffort / guaranteed (no qos level)
            format!("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice"),
            format!("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{UID_}.slice"),
            format!("kubepods.slice/kubepods-pod{UID_}.slice"),
            // cgroupfs, burstable / guaranteed (directly under kubepods)
            format!("kubepods/burstable/pod{UID}"),
            format!("kubepods/pod{UID}"),
            // another runtime's prefix
            format!(
                "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod{UID_}.slice"
            ),
        ];
        for want in &cases {
            let ctr = format!("{want}/cri-containerd-abc.scope");
            let dirs = pod_dirs(&tree(&[
                want,
                &ctr,
                "system.slice/sshd.service",
                "user.slice",
            ]));
            assert_eq!(pod_dir(&dirs, UID), Some(Path::new(want)), "{want}");
        }
    }

    #[test]
    fn pod_dir_search_not_found_ambiguous_and_too_deep() {
        let other = "kubepods/pod11111111-2222-3333-4444-555555555555";
        let dirs = pod_dirs(&tree(&[other, "system.slice"]));
        assert_eq!(pod_dir(&dirs, UID), None);
        // two directories for one uid: unresolved, never both
        let a = format!("kubepods/pod{UID}");
        let b = format!("kubepods.slice/kubepods-pod{UID_}.slice");
        assert_eq!(pod_dir(&pod_dirs(&tree(&[&a, &b])), UID), None);
        let deep = format!("a/b/c/d/e/pod{UID}");
        assert_eq!(pod_dir(&pod_dirs(&tree(&[&deep])), UID), None);
        // look-alikes
        assert_eq!(pod_uid_of(&format!("xpod{UID}")), None);
        assert_eq!(pod_uid_of("pod1234"), None);
        assert_eq!(pod_uid_of("kubepods-burstable.slice"), None);
    }

    fn rec(ns: &str, name: &str, node: &str, labels: &[(&str, &str)]) -> PodRecord {
        PodRecord {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            uid: Arc::from(UID.to_ascii_uppercase().as_str()),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            workload_kind: "Pod",
            workload_name: Arc::from(name),
            node: Some(Arc::from(node)),
            ips: vec![],
            host_ip: None,
            host_network: false,
            terminating: false,
            created: None,
        }
    }

    #[test]
    fn pod_filter_matching() {
        let labels = |l: &[(&str, &str)]| PodFilter {
            namespace: "pay".into(),
            select: PodSelect::Labels(
                l.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        };
        let p = rec("pay", "co-1", "n1", &[("app", "co"), ("tier", "web")]);
        assert!(pod_matches(&labels(&[("app", "co")]), &p));
        assert!(pod_matches(&labels(&[("app", "co"), ("tier", "web")]), &p));
        assert!(!pod_matches(&labels(&[("app", "co"), ("tier", "db")]), &p));
        assert!(!pod_matches(&labels(&[("zone", "a")]), &p));
        assert!(!pod_matches(
            &labels(&[("app", "co")]),
            &rec("other", "co-1", "n1", &[("app", "co")])
        ));
        let name = |n: &str| PodFilter {
            namespace: "pay".into(),
            select: PodSelect::Name(n.into()),
        };
        assert!(pod_matches(&name("co-1"), &p));
        assert!(!pod_matches(&name("co-2"), &p));

        let pods = [p.clone(), rec("pay", "co-2", "n2", &[("app", "co")])];
        let f = [labels(&[("app", "co")])];
        let local = select_pods(&pods, &f, Some("n1"));
        assert_eq!(
            local,
            [SelectedPod {
                key: "pay/co-1".into(),
                uid: UID.into()
            }]
        );
        assert_eq!(select_pods(&pods, &f, None).len(), 2);
    }

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("panopticon-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    #[test]
    fn resolve_paths_and_pods_to_inodes() {
        let t = temp("resolve");
        let root = &t.0;
        let pod = format!("kubepods/burstable/pod{UID}");
        std::fs::create_dir_all(root.join(&pod).join("ctr")).unwrap();
        std::fs::create_dir_all(root.join("system.slice")).unwrap();
        let ino = |rel: &str| std::fs::metadata(root.join(rel)).unwrap().ino();

        let pods = [
            SelectedPod {
                key: "pay/co-1".into(),
                uid: UID.into(),
            },
            SelectedPod {
                key: "pay/gone".into(),
                uid: "11111111-2222-3333-4444-555555555555".into(),
            },
        ];
        let r = resolve(root, &["/system.slice".into()], &pods).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino("system.slice"), ino(&pod)]));
        assert_eq!(r.unresolved, ["pay/gone"]);

        // A missing path refuses to start and names it.
        let e = resolve(root, &["nope.slice".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("nope.slice") && e.contains("no such cgroup"),
            "{e}"
        );
        // The attach root itself is refused, however it is reached.
        std::os::unix::fs::symlink(".", root.join("self")).unwrap();
        let e = resolve(root, &["self".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("cgroup root"), "{e}");
    }

    #[derive(Default)]
    struct Log(Vec<String>, Option<u64>);
    impl AllowMap for Log {
        fn insert(&mut self, id: u64) -> Result<()> {
            if self.1 == Some(id) {
                bail!("full");
            }
            self.0.push(format!("+{id}"));
            Ok(())
        }
        fn remove(&mut self, id: u64) -> Result<()> {
            self.0.push(format!("-{id}"));
            Ok(())
        }
        fn bump_gen(&mut self) -> Result<()> {
            self.0.push("gen".into());
            Ok(())
        }
    }

    #[test]
    fn publish_writes_the_map_then_bumps_once() {
        let s = |v: &[u64]| v.iter().copied().collect::<BTreeSet<u64>>();
        let mut m = Log::default();
        let d = publish(&mut m, &s(&[1, 2]), &s(&[2, 3, 4])).unwrap();
        assert_eq!(m.0, ["-1", "+3", "+4", "gen"]);
        assert_eq!(
            d,
            AllowDiff {
                added: vec![3, 4],
                removed: vec![1]
            }
        );
        assert!(d.is_narrowing());

        let mut m = Log::default();
        let d = publish(&mut m, &s(&[2]), &s(&[2, 3])).unwrap();
        assert!(!d.is_narrowing());
        assert_eq!(m.0, ["+3", "gen"]);

        // No change: no generation bump.
        let mut m = Log::default();
        assert_eq!(
            publish(&mut m, &s(&[2]), &s(&[2])).unwrap(),
            AllowDiff::default()
        );
        assert!(m.0.is_empty());

        // A failed write after a delete still bumps, then reports the error.
        let mut m = Log(vec![], Some(4));
        assert!(publish(&mut m, &s(&[1]), &s(&[3, 4])).is_err());
        assert_eq!(m.0, ["-1", "+3", "gen"]);
    }

    #[test]
    fn mountinfo_net_cls_detection() {
        let v2 = "25 1 0:22 / /sys/fs/cgroup rw,nosuid shared:4 - cgroup2 cgroup2 rw,nsdelegate\n";
        assert_eq!(net_cls_v1_mount(v2), None);
        let cpu =
            "30 25 0:26 / /sys/fs/cgroup/cpu,cpuacct rw shared:9 - cgroup cgroup rw,cpu,cpuacct\n";
        assert_eq!(net_cls_v1_mount(&format!("{v2}{cpu}")), None);
        let both = "31 25 0:27 / /sys/fs/cgroup/net_cls,net_prio rw shared:10 - cgroup cgroup rw,net_cls,net_prio\n";
        assert_eq!(
            net_cls_v1_mount(&format!("{v2}{cpu}{both}")),
            Some("/sys/fs/cgroup/net_cls,net_prio")
        );
        let prio = "32 25 0:28 / /mnt/prio rw - cgroup none rw,net_prio\n";
        assert_eq!(net_cls_v1_mount(prio), Some("/mnt/prio"));
        // optional fields before the separator; not cgroup v1
        let tmp = "40 1 0:30 / /net_cls rw shared:1 master:2 - tmpfs net_cls rw,net_cls\n";
        assert_eq!(net_cls_v1_mount(tmp), None);
    }
}
