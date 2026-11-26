//! `cgroup_filter` / `pod_filter` (DESIGN §3.2): resolve the selectors to
//! cgroup v2 ids and publish them to `CGROUP_ALLOW`.
//!
//! A cgroup id is the inode number of its directory. Every unresolved
//! selector selects nothing; nothing here ever falls back to capturing all.
//! Startup publishes here ([`startup_publish`]); at runtime the scope
//! publisher (`scope_publisher.rs`) calls [`publish`] with the previous set.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::bail;
use tracing::warn;

use crate::config::{PodFilter, PodSelect, ScopeOptions};
use crate::k8s::model::PodRecord;

/// The QoS levels kubelet puts below its kubepods root (a guaranteed pod
/// sits directly in the root).
const QOS_LEVELS: [&str; 2] = ["burstable", "besteffort"];
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

/// A uid as kubelet spells it in a cgroup name (`_` for `-` under the
/// systemd driver), lowercase with dashes, if it is one.
fn pod_uid(raw: &str) -> Option<String> {
    let uid = raw.replace('_', "-").to_ascii_lowercase();
    let is_uuid = uid.len() == 36
        && uid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    is_uuid.then_some(uid)
}

/// How kubelet names the directories of one level of its hierarchy.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Naming {
    /// cgroupfs driver: `burstable`, `besteffort`, `pod<uid>`.
    Cgroupfs,
    /// systemd driver: a slice's children are named after it, e.g.
    /// `kubepods-burstable.slice` and `kubepods-burstable-pod<uid>.slice`
    /// in `kubepods.slice` (stem `kubepods`).
    Systemd(String),
}

impl Naming {
    /// The uid of a pod directory named `name` at this level.
    fn pod(&self, name: &str) -> Option<String> {
        match self {
            Naming::Cgroupfs => pod_uid(name.strip_prefix("pod")?),
            Naming::Systemd(stem) => pod_uid(
                name.strip_prefix(stem.as_str())?
                    .strip_prefix("-pod")?
                    .strip_suffix(".slice")?,
            ),
        }
    }

    /// The naming below a QoS level directory named `name`, if it is one.
    fn qos(&self, name: &str) -> Option<Naming> {
        match self {
            Naming::Cgroupfs => QOS_LEVELS.contains(&name).then_some(Naming::Cgroupfs),
            Naming::Systemd(stem) => {
                let level = name.strip_prefix(stem.as_str())?.strip_prefix('-')?;
                let level = level.strip_suffix(".slice")?;
                QOS_LEVELS
                    .contains(&level)
                    .then(|| Naming::Systemd(format!("{stem}-{level}")))
            }
        }
    }
}

/// What the owner check says of one directory of the pod search.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Trust {
    /// Owned by the trusted owner (root) and not group- or other-writable;
    /// its identity `(st_dev, st_ino)`.
    Yes(u64, u64),
    /// No longer there (removed since it was listed): skipped, not
    /// reported as untrusted.
    Gone,
    /// There, but not taken, and why (not owned by root, group- or
    /// other-writable, not reachable without a symlink or mount crossing).
    No(String),
}

/// What the pod search reads of the cgroup2 tree. Paths are relative to
/// the root (empty is the root itself).
trait PodTree {
    /// The subdirectory names of `rel` (none when it cannot be read).
    fn subdirs(&self, rel: &Path) -> Vec<String>;
    /// Whether `rel` is a directory owned by the trusted owner (root) that
    /// no group or other user can write to, checked on the directory
    /// itself, never through a symlink.
    fn trust(&self, rel: &Path) -> Trust;
}

/// Pod directories by uid, searched only where kubelet puts them (security
/// scan F5): below a kubepods root at the top of the cgroup2 hierarchy
/// (`kubepods` for the cgroupfs driver, `kubepods.slice` for systemd, or
/// `<name>-kubepods.slice` in a top-level `<name>.slice` when kubelet's
/// cgroup root is `/<name>`, as kind sets it), directly in it (guaranteed
/// QoS) or in its `burstable` / `besteffort` level, named as that driver
/// names them. Every directory on the way and the pod directory itself
/// must be owned by root and writable by root alone: no other user can
/// create one there, while a subtree delegated to a user
/// (`user@<uid>.service`, a rootless container) is neither searched nor
/// trusted. A pod directory is never searched below. A directory that
/// fails the check is skipped and listed, with why, in
/// [`PodSearch::untrusted`]; one removed while the search runs is skipped
/// silently. A pod directory reached twice (a configured root inside a
/// recognised one) is the same directory, told by its identity, and
/// counted once.
///
/// `configured` is the operator's `pod_cgroup_root` (relative to the
/// root, already checked: root-owned and writable by root alone at every
/// level, no symlink or mount crossing), searched the same way besides the recognised roots, named
/// by the driver its last component shows (`….slice`: systemd).
fn pod_dirs(tree: &dyn PodTree, configured: Option<&Path>) -> PodSearch {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut untrusted = Vec::new();
    let mut trusted = |p: &Path| match tree.trust(p) {
        Trust::Yes(dev, ino) => Some((dev, ino)),
        Trust::Gone => None,
        Trust::No(why) => {
            untrusted.push((p.to_path_buf(), why));
            None
        }
    };
    let mut seen_pods = std::collections::HashSet::new();
    let mut roots: Vec<(PathBuf, Naming)> = Vec::new();
    if let Some(root) = configured {
        roots.push((root.to_path_buf(), root_naming(root)));
    }
    for name in tree.subdirs(Path::new("")) {
        match name.as_str() {
            "kubepods" => roots.push((PathBuf::from(&name), Naming::Cgroupfs)),
            "kubepods.slice" => {
                roots.push((PathBuf::from(&name), Naming::Systemd("kubepods".into())))
            }
            _ => {
                // `<name>.slice/<name>-kubepods.slice`: kubelet's cgroup
                // root `/<name>` under the systemd driver.
                let Some(stem) = name.strip_suffix(".slice").filter(|s| !s.contains('-')) else {
                    continue;
                };
                let child = format!("{stem}-kubepods.slice");
                let top = PathBuf::from(&name);
                if tree.subdirs(&top).contains(&child) && trusted(&top).is_some() {
                    roots.push((top.join(child), Naming::Systemd(format!("{stem}-kubepods"))));
                }
            }
        }
    }
    // The configured root may be one of the recognised ones.
    let mut seen = std::collections::HashSet::new();
    roots.retain(|(p, _)| seen.insert(p.clone()));
    let searched: Vec<PathBuf> = roots.iter().map(|(p, _)| p.clone()).collect();
    for (root, naming) in roots {
        if trusted(&root).is_none() {
            continue;
        }
        let mut levels = vec![(root, naming)];
        let mut i = 0;
        while i < levels.len() {
            let (dir, naming) = levels[i].clone();
            let is_root = i == 0;
            i += 1;
            for name in tree.subdirs(&dir) {
                let p = dir.join(&name);
                if let Some(uid) = naming.pod(&name) {
                    if let Some(id) = trusted(&p)
                        && seen_pods.insert(id)
                    {
                        out.entry(uid).or_default().push(p);
                    }
                } else if is_root
                    && let Some(qos) = naming.qos(&name)
                    && trusted(&p).is_some()
                {
                    levels.push((p, qos));
                }
            }
        }
    }
    PodSearch {
        dirs: out,
        untrusted,
        searched,
    }
}

/// What [`pod_dirs`] found.
struct PodSearch {
    /// Pod directories by uid.
    dirs: HashMap<String, Vec<PathBuf>>,
    /// Directories skipped, and why: not owned by root, group- or
    /// other-writable, or not reachable without a symlink or mount
    /// crossing.
    untrusted: Vec<(PathBuf, String)>,
    /// The kubepods roots searched, for the not-found error.
    searched: Vec<PathBuf>,
}

/// The naming of a configured kubepods root, by its last component:
/// `<stem>.slice` is the systemd driver's, anything else cgroupfs's.
fn root_naming(root: &Path) -> Naming {
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.strip_suffix(".slice") {
        Some(stem) if !stem.is_empty() => Naming::Systemd(stem.to_string()),
        _ => Naming::Cgroupfs,
    }
}

/// `panopticon_pod_filter_unresolved_total{reason}`: resolutions of a
/// selected pod that found no cgroup (`not_found`), several (`ambiguous`)
/// or one that could not be used (`unusable`). Numbers only. Every
/// resolution counts, and the selected pods are resolved again on every
/// pod change the Kubernetes watch reports, so a pod that stays
/// unresolved (Pending, say) adds one per re-resolution.
static POD_UNRESOLVED: [std::sync::atomic::AtomicU64; 3] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 3];
/// The reason labels of [`POD_UNRESOLVED`], in its order.
pub const POD_UNRESOLVED_REASONS: [&str; 3] = ["not_found", "ambiguous", "unusable"];

fn count_unresolved(reason: usize) {
    POD_UNRESOLVED[reason].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The [`POD_UNRESOLVED`] counts, in [`POD_UNRESOLVED_REASONS`] order.
pub fn pod_unresolved() -> [u64; 3] {
    POD_UNRESOLVED
        .each_ref()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
}

/// Which unresolved pods were already reported: each pod uid and reason
/// is logged as an error once, then at debug level on every
/// re-resolution, until the uid resolves or leaves the selection.
#[derive(Debug, Default)]
struct ReportOnce(BTreeSet<(String, usize)>);

impl ReportOnce {
    /// Whether `uid` unresolved for `reason` is reported for the first time.
    fn first(&mut self, uid: &str, reason: usize) -> bool {
        self.0.insert((uid.to_owned(), reason))
    }

    /// Forget every uid not in `still`: it resolved or left the selection,
    /// so failing again is news.
    fn keep_only(&mut self, still: &BTreeSet<&str>) {
        self.0.retain(|(uid, _)| still.contains(uid.as_str()));
    }
}

static POD_REPORTED: std::sync::Mutex<ReportOnce> =
    std::sync::Mutex::new(ReportOnce(BTreeSet::new()));

/// Where a pod's uid led.
#[derive(Debug, PartialEq, Eq)]
enum PodDir<'a> {
    /// Exactly one directory: the pod's cgroup.
    One(&'a Path),
    /// No directory (not on this node, or not started yet).
    None,
    /// Several directories for one uid. kubelet makes one per pod, and
    /// only root can make one where the search looks, so this is a node
    /// misconfiguration or interference, never resolved by a guess.
    Several(&'a [PathBuf]),
}

fn pod_dir<'a>(dirs: &'a HashMap<String, Vec<PathBuf>>, uid: &str) -> PodDir<'a> {
    match dirs.get(uid).map(Vec::as_slice) {
        Some([one]) => PodDir::One(one),
        Some([]) | None => PodDir::None,
        Some(several) => PodDir::Several(several),
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

/// Resolve `cgroup_filter` paths and the selected pods under `root` (the
/// attach root). Every path is opened beneath an fd of the root with
/// `openat2(2)`, refusing any symlink and any mount crossing (bind mounts
/// included), and the cgroup id is the opened directory's inode. Refuses: a
/// kernel without openat2 (never falls back to path lookup), a root that is
/// not the one discovered, an unresolvable `cgroup_filter` path, and the
/// root cgroup (id 1) or the attach root itself (§3.2). An unresolvable pod
/// is not selected: one with no directory where kubelet makes it, owned by
/// root ([`pod_dirs`]), or with several; each is counted
/// ([`pod_unresolved`]) and logged as an error the first time for its uid
/// and reason ([`ReportOnce`]), at debug level after that. `pod_root` is
/// `pod_cgroup_root`: refused unless it is a directory reached without a
/// symlink or mount crossing, owned by root and writable by root alone at
/// every level.
///
/// Other targets have no cgroup v2 and no openat2: always refuses.
pub fn resolve(
    root: &Path,
    paths: &[String],
    pods: &[SelectedPod],
    pod_root: Option<&str>,
) -> Result<Resolved> {
    resolve_owned_by(root, paths, pods, pod_root, 0)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve_owned_by(
    _root: &Path,
    _paths: &[String],
    _pods: &[SelectedPod],
    _pod_root: Option<&str>,
    _owner: u32,
) -> Result<Resolved> {
    anyhow::bail!("refusing cgroup_filter/pod_filter: cgroup selection needs Linux")
}

/// [`resolve`], trusting pod directories owned by `owner` (root, 0, except
/// in tests that cannot create root-owned directories).
#[cfg(target_os = "linux")]
pub(crate) fn resolve_owned_by(
    root: &Path,
    paths: &[String],
    pods: &[SelectedPod],
    pod_root: Option<&str>,
    owner: u32,
) -> Result<Resolved> {
    use crate::config::{cgroup_filter_rel, pod_cgroup_root_rel};
    let r = beneath::Root::open(root)?;
    // `pod_cgroup_root`: every level from the cgroup2 root down must be a
    // directory reached without a symlink or mount crossing, owned by root
    // and writable by root alone.
    let configured = match pod_root {
        Some(p) => {
            let rel = Path::new(pod_cgroup_root_rel(p)?);
            let mut at = PathBuf::new();
            for c in rel.components() {
                at.push(c);
                match r.owned_dir(&at, owner) {
                    Ok(_) => {}
                    Err(beneath::NotOwned::Gone(e)) => bail!(
                        "refusing pod_cgroup_root = \"{p}\": no directory {} under {} ({e})",
                        at.display(),
                        root.display()
                    ),
                    Err(beneath::NotOwned::Bad(why)) => bail!(
                        "refusing pod_cgroup_root = \"{p}\": {} is {why}",
                        at.display()
                    ),
                }
            }
            Some(rel.to_path_buf())
        }
        None => None,
    };
    // A pod's directory is opened once: the owner and mode checked and the
    // id taken on the same descriptor. A cgroup_filter path is the
    // operator's own and is not checked.
    let id_of = |rel: &Path, what: &str, pod: bool| -> Result<std::result::Result<u64, String>> {
        let found = if pod {
            r.owned_dir(rel, owner).map_err(|e| e.to_string())
        } else {
            r.dir_stat(rel)
                .map(|(dev, ino, ..)| (dev, ino))
                .map_err(|e| e.to_string())
        };
        let (dev, ino) = match found {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        if dev != r.dev {
            return Ok(Err(
                std::io::Error::from_raw_os_error(libc::EXDEV).to_string()
            ));
        }
        if ino == 1 || ino == r.ino {
            bail!(
                "refusing {what}: it resolves to the cgroup root (id {ino}), which would capture \
                 every process"
            );
        }
        Ok(Ok(ino))
    };
    let mut out = Resolved::default();
    for p in paths {
        let what = format!("cgroup_filter = \"{p}\"");
        let rel = cgroup_filter_rel(p)?;
        match id_of(Path::new(rel), &what, false)? {
            Ok(id) => out.ids.insert(id),
            Err(e) => bail!(
                "refusing {what}: no cgroup directory there under {} reachable without a \
                 symlink or mount crossing ({e})",
                root.display()
            ),
        };
    }
    if !pods.is_empty() {
        let tree = beneath::Owned { root: &r, owner };
        let PodSearch {
            dirs,
            untrusted,
            searched,
        } = pod_dirs(&tree, configured.as_deref());
        if !untrusted.is_empty() {
            warn!(
                dirs = ?untrusted,
                "pod_filter: cgroup directories under the kubepods hierarchy that are not owned \
                 by root, are group- or other-writable, or are not reachable without a symlink \
                 or mount crossing were skipped"
            );
        }
        // Error once per uid and reason, then debug: the selected pods are
        // resolved again on every pod change, and a Pending pod stays
        // unresolved through each.
        macro_rules! report {
            ($first:expr, $($t:tt)*) => {
                if $first { tracing::error!($($t)*) } else { tracing::debug!($($t)*) }
            };
        }
        let mut reported = POD_REPORTED.lock().unwrap_or_else(|e| e.into_inner());
        let mut still = BTreeSet::new();
        // A pod that does not resolve to exactly one root-owned directory
        // stays unselected (fail closed): a guess between candidates could
        // capture another workload, while an unselected pod only loses its
        // own capture.
        for pod in pods {
            let what = format!("pod_filter pod {}", pod.key);
            let reason = match pod_dir(&dirs, &pod.uid) {
                PodDir::One(rel) => match id_of(rel, &what, true)? {
                    Ok(id) => {
                        out.ids.insert(id);
                        continue;
                    }
                    Err(e) => {
                        report!(reported.first(&pod.uid, 2),
                            pod = %pod.key, dir = %rel.display(), error = %e,
                            "pod_filter: the pod's cgroup directory cannot be used; not captured");
                        2
                    }
                },
                PodDir::Several(found) => {
                    report!(reported.first(&pod.uid, 1),
                        pod = %pod.key,
                        uid = %pod.uid,
                        dirs = ?found,
                        "pod_filter: several cgroup directories for one pod uid; the pod is not \
                         captured until exactly one remains"
                    );
                    1
                }
                PodDir::None => {
                    report!(reported.first(&pod.uid, 0),
                        pod = %pod.key,
                        uid = %pod.uid,
                        searched = ?searched,
                        cgroup2_root = %root.display(),
                        "pod_filter: no cgroup directory for this pod in the kubepods roots \
                         searched; the pod is not captured (resolved again when it changes). \
                         If kubelet uses another cgroup root (--cgroup-root), name its kubepods \
                         directory in pod_cgroup_root. Static (mirror) pods are not supported: \
                         kubelet names their cgroup by the manifest's hash, not the API uid"
                    );
                    0
                }
            };
            count_unresolved(reason);
            still.insert(pod.uid.as_str());
            out.unresolved.push(pod.key.clone());
        }
        reported.keep_only(&still);
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

/// Lookups beneath an opened cgroup2 root with `openat2(2)` (Linux 5.6+).
#[cfg(target_os = "linux")]
mod beneath {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use anyhow::{Context, Result, bail};

    /// No `..` out of the root, no symlink, no mount point (bind mounts too).
    const BENEATH: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;

    /// `openat2(dir, path, flags | O_DIRECTORY | O_CLOEXEC, resolve)`; an
    /// empty `path` is `.`.
    fn openat2(
        dir: libc::c_int,
        path: &Path,
        flags: libc::c_int,
        resolve: u64,
    ) -> io::Result<OwnedFd> {
        let path = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: open_how is plain integers, so zero is valid.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (flags | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
        how.resolve = resolve;
        // SAFETY: valid C string; `how` lives across the call, size matches.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir,
                c.as_ptr(),
                &how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel returned a new fd, owned from here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
    }

    /// `(st_dev, st_ino, st_uid, st_mode)` of an open descriptor.
    fn stat(fd: &OwnedFd) -> io::Result<(u64, u64, u32, u32)> {
        // SAFETY: fstat writes into the zeroed struct; fd is open.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            st.st_dev as u64,
            st.st_ino as u64,
            st.st_uid,
            st.st_mode as u32,
        ))
    }

    fn dev_ino(fd: &OwnedFd) -> io::Result<(u64, u64)> {
        stat(fd).map(|(dev, ino, ..)| (dev, ino))
    }

    /// Why [`Root::owned_dir`] did not take a directory.
    #[derive(Debug)]
    pub enum NotOwned {
        /// Not there (`ENOENT`): removed since it was listed, or never made.
        Gone(io::Error),
        /// There, but not taken: why, as "<path> is …" ends.
        Bad(String),
    }

    impl std::fmt::Display for NotOwned {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                NotOwned::Gone(e) => write!(f, "gone ({e})"),
                NotOwned::Bad(why) => f.write_str(why),
            }
        }
    }

    /// The pod search's view of the tree: directories beneath the root,
    /// trusted when owned by `owner` and writable by it alone.
    pub struct Owned<'a> {
        pub root: &'a Root,
        pub owner: u32,
    }

    impl super::PodTree for Owned<'_> {
        fn subdirs(&self, rel: &Path) -> Vec<String> {
            self.root.subdirs(rel)
        }

        fn trust(&self, rel: &Path) -> super::Trust {
            match self.root.owned_dir(rel, self.owner) {
                Ok((dev, ino)) => super::Trust::Yes(dev, ino),
                Err(NotOwned::Gone(_)) => super::Trust::Gone,
                Err(NotOwned::Bad(why)) => super::Trust::No(why),
            }
        }
    }

    /// The opened cgroup2 root.
    pub struct Root {
        fd: OwnedFd,
        pub dev: u64,
        pub ino: u64,
    }

    impl Root {
        /// Open `path`, refusing a kernel without openat2 and a directory
        /// that is not the root that was discovered (a swap since).
        pub fn open(path: &Path) -> Result<Self> {
            let fd = match openat2(libc::AT_FDCWD, path, libc::O_PATH, 0) {
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => bail!(
                    "refusing cgroup_filter/pod_filter: this kernel has no openat2(2) (Linux \
                     5.6+), needed to resolve cgroups without following symlinks or mounts"
                ),
                r => {
                    r.with_context(|| format!("cannot open the cgroup root {}", path.display()))?
                }
            };
            let (dev, ino) = dev_ino(&fd)?;
            let m = std::fs::metadata(path)
                .with_context(|| format!("cannot stat the cgroup root {}", path.display()))?;
            if (m.dev(), m.ino()) != (dev, ino) {
                bail!(
                    "refusing cgroup_filter/pod_filter: the opened cgroup root is not {}",
                    path.display()
                );
            }
            Ok(Self { fd, dev, ino })
        }

        /// `(st_dev, st_ino, st_uid, st_mode)` of the directory `rel`
        /// beneath the root, by fstat on its `O_PATH` descriptor.
        pub fn dir_stat(&self, rel: &Path) -> io::Result<(u64, u64, u32, u32)> {
            stat(&openat2(self.fd.as_raw_fd(), rel, libc::O_PATH, BENEATH)?)
        }

        /// `(st_dev, st_ino)` of the directory `rel` beneath the root if it
        /// is on the root's mount, owned by `owner` (root) and not group-
        /// or other-writable (only its owner can create a directory in
        /// it), all read from one descriptor.
        pub fn owned_dir(&self, rel: &Path, owner: u32) -> Result<(u64, u64), NotOwned> {
            let (dev, ino, uid, mode) = match self.dir_stat(rel) {
                Ok(s) => s,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    return Err(NotOwned::Gone(e));
                }
                Err(e) => {
                    return Err(NotOwned::Bad(format!(
                        "not reachable without a symlink or mount crossing ({e})"
                    )));
                }
            };
            if dev != self.dev {
                return Err(NotOwned::Bad("on another mount".into()));
            }
            if uid != owner {
                return Err(NotOwned::Bad("not owned by root".into()));
            }
            if mode & 0o022 != 0 {
                return Err(NotOwned::Bad(format!(
                    "group- or other-writable (mode {:o})",
                    mode & 0o7777
                )));
            }
            Ok((dev, ino))
        }

        /// Subdirectory names of `rel` beneath the root (symlinks are not
        /// directories here); empty when `rel` cannot be opened or read in
        /// full.
        pub fn subdirs(&self, rel: &Path) -> Vec<String> {
            let Ok(fd) = openat2(self.fd.as_raw_fd(), rel, libc::O_RDONLY, BENEATH) else {
                return Vec::new();
            };
            let raw = fd.into_raw_fd();
            // SAFETY: fdopendir owns `raw` on success, closed here on
            // failure; entries are copied out before closedir.
            unsafe {
                let d = libc::fdopendir(raw);
                if d.is_null() {
                    libc::close(raw);
                    return Vec::new();
                }
                let mut out = Vec::new();
                loop {
                    *libc::__errno_location() = 0;
                    let e = libc::readdir(d);
                    if e.is_null() {
                        if *libc::__errno_location() != 0 {
                            out.clear();
                        }
                        break;
                    }
                    if (*e).d_type != libc::DT_DIR {
                        continue;
                    }
                    let Ok(name) = CStr::from_ptr((*e).d_name.as_ptr()).to_str() else {
                        continue;
                    };
                    if name != "." && name != ".." {
                        out.push(name.to_owned());
                    }
                }
                libc::closedir(d);
                out
            }
        }
    }
}

// ── Publication ────────────────────────────────────────────────────────────

/// `CGROUP_ALLOW` plus the `CONFIG_SCOPE_GEN` bump.
pub trait AllowMap {
    fn insert(&mut self, id: u64) -> Result<()>;
    fn remove(&mut self, id: u64) -> Result<()>;
    fn bump_gen(&mut self) -> Result<()>;
    /// Write `capture_loopback` and `pid_filter_listener` to `CONFIG`
    /// (`CONFIG_CAPTURE_LOOPBACK`, `CONFIG_PID_CREATOR_RULE`).
    fn set_options(&mut self, options: ScopeOptions) -> Result<()>;
    /// The ids in `CGROUP_ALLOW` now.
    fn ids(&mut self) -> Result<BTreeSet<u64>>;
    /// `CONFIG_SCOPE_GEN` now.
    fn generation(&mut self) -> Result<u64>;
    /// Stop capture in the kernel on every path: packets, new socket
    /// state, and TLS plaintext. The fatal stop after a failed runtime
    /// publication.
    fn disarm(&mut self) -> Result<()>;
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

/// Move `CGROUP_ALLOW` from `current` to `new`, and write `options` if
/// given (they changed), in the design's order: deletes, the options, then
/// inserts, then one `CONFIG_SCOPE_GEN` increment if anything changed (§3).
/// The bump invalidates every cached verdict, so a changed listener rule
/// is applied to every socket's next packet. A failed write still bumps the
/// generation when an earlier write changed the map or an option write was
/// attempted, so a change that went through is never hidden behind a
/// verdict cached under the old generation; the error is returned.
pub fn publish(
    map: &mut dyn AllowMap,
    current: &BTreeSet<u64>,
    new: &BTreeSet<u64>,
    options: Option<ScopeOptions>,
) -> Result<AllowDiff> {
    let mut diff = AllowDiff::default();
    let mut wrote_options = false;
    let mut write = || -> Result<()> {
        for &id in current.difference(new) {
            map.remove(id)?;
            diff.removed.push(id);
        }
        if let Some(o) = options {
            wrote_options = true;
            map.set_options(o)?;
        }
        for &id in new.difference(current) {
            map.insert(id)?;
            diff.added.push(id);
        }
        Ok(())
    };
    let r = write();
    if !diff.added.is_empty() || !diff.removed.is_empty() || wrote_options {
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
    use anyhow::Context;
    use aya::Ebpf;
    use aya::maps::{Array, HashMap as BpfHashMap, MapData, MapError};
    use panopticon_common::CONFIG_SCOPE_GEN;
    use tracing::info;

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

        fn config(&mut self) -> Result<Array<&mut MapData, u64>> {
            Ok(Array::try_from(
                self.0.map_mut("CONFIG").context("CONFIG map not found")?,
            )?)
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
            let mut cfg = self.config()?;
            let g = cfg.get(&CONFIG_SCOPE_GEN, 0)?;
            cfg.set(CONFIG_SCOPE_GEN, g + 1, 0)?;
            Ok(())
        }

        fn ids(&mut self) -> Result<BTreeSet<u64>> {
            let m: BpfHashMap<&MapData, u64, u8> = BpfHashMap::try_from(
                self.0
                    .map("CGROUP_ALLOW")
                    .context("CGROUP_ALLOW map not found")?,
            )?;
            Ok(m.keys().collect::<Result<_, _>>()?)
        }

        fn generation(&mut self) -> Result<u64> {
            Ok(self.config()?.get(&CONFIG_SCOPE_GEN, 0)?)
        }

        fn set_options(&mut self, o: ScopeOptions) -> Result<()> {
            use panopticon_common::{CONFIG_CAPTURE_LOOPBACK, CONFIG_PID_CREATOR_RULE};
            let mut cfg = self.config()?;
            cfg.set(CONFIG_CAPTURE_LOOPBACK, o.capture_loopback as u64, 0)?;
            cfg.set(CONFIG_PID_CREATOR_RULE, o.creator_rule as u64, 0)?;
            Ok(())
        }

        /// What the kernel honours (panopticon-ebpf, read at this stage):
        /// `CONFIG_CAPTURE_ENABLED = 0` stops the cgroup_skb packet path
        /// (`sock_capture.rs` `try_skb`, kTLS and UDP included);
        /// `CONFIG_SCOPE_ARMED = 0` stops the socket-state writers; every
        /// TLS probe checks both first and collects nothing
        /// (`sock_capture.rs` `tls_capture_on`). The mode also gains the
        /// sampled/head bits, which drop every TLS call on their own
        /// (`tls_call_scope`, `scope::tls_mode_allowed`), and stays
        /// non-zero (never unscoped `full`), so the armed flag applies.
        fn disarm(&mut self) -> Result<()> {
            use panopticon_common::scope::{SCOPE_HEAD, SCOPE_SAMPLE};
            use panopticon_common::{
                CONFIG_CAPTURE_ENABLED, CONFIG_SCOPE_ARMED, CONFIG_SCOPE_MODE,
            };
            let mut cfg = self.config()?;
            cfg.set(CONFIG_CAPTURE_ENABLED, 0, 0)?;
            let mode = cfg.get(&CONFIG_SCOPE_MODE, 0)?;
            cfg.set(CONFIG_SCOPE_MODE, mode | SCOPE_SAMPLE | SCOPE_HEAD, 0)?;
            cfg.set(CONFIG_SCOPE_ARMED, 0, 0)?;
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
        pod_root: Option<&str>,
    ) -> Result<()> {
        if let Some(why) = net_cls_problem() {
            bail!(
                "refusing cgroup_filter/pod_filter: {why}; the kernel may not record \
                 cgroup v2 membership of sockets then (DESIGN §3.2)"
            );
        }
        let r = resolve(root, paths, pods, pod_root)?;
        if !r.unresolved.is_empty() {
            warn!(
                pods = ?r.unresolved,
                "pod_filter: no cgroup found for these pods on this node; not captured"
            );
        }
        let mut map = AyaAllow(ebpf);
        let current = map.ids()?;
        let diff = publish(&mut map, &current, &r.ids, None)?;
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
    /// the first sighting the cgroup selector stops admitting: the scope
    /// publisher empties `CGROUP_ALLOW` as a narrowing (with the pipeline
    /// revocation) and keeps it empty until a restart, which then refuses.
    pub fn spawn_net_cls_watch(
        publisher: tokio::sync::mpsc::Sender<crate::scope_publisher::ScopeMsg>,
    ) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                if let Some(why) = net_cls_problem() {
                    let _ = publisher
                        .send(crate::scope_publisher::ScopeMsg::Disable(why))
                        .await;
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::sync::Arc;

    const UID: &str = "0f3c1a2b-4d5e-6f70-8192-a3b4c5d6e7f8";
    const UID_: &str = "0f3c1a2b_4d5e_6f70_8192_a3b4c5d6e7f8";

    /// A cgroup2 tree of these directories (and their ancestors), every one
    /// owned by root except those in `untrusted`; those in `gone` are
    /// listed but removed before they are checked. A directory's identity
    /// is its path.
    struct Tree {
        paths: Vec<PathBuf>,
        untrusted: Vec<PathBuf>,
        gone: Vec<PathBuf>,
    }

    impl PodTree for Tree {
        fn subdirs(&self, dir: &Path) -> Vec<String> {
            let mut v: Vec<String> = self
                .paths
                .iter()
                .flat_map(|p| p.ancestors().collect::<Vec<_>>())
                .filter(|a| a.parent() == Some(dir) && !a.as_os_str().is_empty())
                .map(|a| a.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v.dedup();
            v
        }

        fn trust(&self, rel: &Path) -> Trust {
            if self.gone.iter().any(|g| g == rel) {
                Trust::Gone
            } else if self.untrusted.iter().any(|u| u == rel) {
                Trust::No("not owned by root".into())
            } else {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                rel.hash(&mut h);
                Trust::Yes(1, h.finish())
            }
        }
    }

    fn tree(paths: &[&str]) -> Tree {
        owned_tree(paths, &[])
    }

    fn owned_tree(paths: &[&str], untrusted: &[&str]) -> Tree {
        Tree {
            paths: paths.iter().map(PathBuf::from).collect(),
            untrusted: untrusted.iter().map(PathBuf::from).collect(),
            gone: Vec::new(),
        }
    }

    fn found(tree: &Tree, uid: &str) -> Option<PathBuf> {
        match pod_dir(&pod_dirs(tree, None).dirs, uid) {
            PodDir::One(p) => Some(p.to_path_buf()),
            PodDir::None => None,
            PodDir::Several(s) => panic!("several: {s:?}"),
        }
    }

    #[test]
    fn pod_dir_search_covers_both_drivers_and_guaranteed_qos() {
        let cases = [
            // systemd, burstable / besteffort / guaranteed (no qos level)
            format!("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice"),
            format!("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{UID_}.slice"),
            format!("kubepods.slice/kubepods-pod{UID_}.slice"),
            // cgroupfs, burstable / besteffort / guaranteed
            format!("kubepods/burstable/pod{UID}"),
            format!("kubepods/besteffort/pod{UID}"),
            format!("kubepods/pod{UID}"),
            // kubelet's cgroup root `/kubelet` under systemd (kind)
            format!(
                "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod{UID_}.slice"
            ),
            format!("kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod{UID_}.slice"),
        ];
        for want in &cases {
            let ctr = format!("{want}/cri-containerd-abc.scope");
            let t = tree(&[want, &ctr, "system.slice/sshd.service", "user.slice"]);
            assert_eq!(found(&t, UID).as_deref(), Some(Path::new(want)), "{want}");
        }
    }

    /// Security scan F5: only kubelet's own hierarchy is searched. A
    /// directory named for a pod anywhere else (a subtree delegated to a
    /// user, a system service, a container's own cgroup, any depth) is
    /// never taken, and does not make the real one ambiguous.
    #[test]
    fn pod_dir_search_only_in_the_kubepods_hierarchy() {
        let real =
            format!("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice");
        for decoy in [
            format!("user.slice/user-1000.slice/user@1000.service/pod{UID}"),
            format!("user.slice/user-1000.slice/user@1000.service/kubepods-pod{UID_}.slice"),
            format!("user.slice/user-1000.slice/user@1000.service/kubepods/pod{UID}"),
            format!("user.slice/kubepods/pod{UID}"),
            format!("system.slice/pod{UID}"),
            format!("pod{UID}"),
            format!("a/b/c/d/e/pod{UID}"),
            format!("machine.slice/libpod-x.scope/kubepods/pod{UID}"),
            // Below a QoS level or the wrong driver's names.
            format!("kubepods/burstable/x/pod{UID}"),
            format!("kubepods.slice/pod{UID}"),
            format!("kubepods/kubepods-pod{UID_}.slice"),
            format!("kubepods.slice/kubepods-burstable.slice/kubepods-besteffort-pod{UID_}.slice"),
            format!("kubepods.slice/burstable/pod{UID}"),
            // A slice of another name, or nested deeper than kubelet puts it.
            format!("x-y.slice/x-y-kubepods.slice/x-y-kubepods-pod{UID_}.slice"),
            format!("kubelet.slice/kubepods.slice/kubepods-pod{UID_}.slice"),
        ] {
            assert_eq!(found(&tree(&[&decoy]), UID), None, "{decoy}");
            assert_eq!(
                found(&tree(&[&real, &decoy]), UID).as_deref(),
                Some(Path::new(&real)),
                "{decoy}"
            );
        }
        // Inside the pod's own cgroup (a container may be delegated it):
        // never searched below a pod directory.
        for inner in [
            format!("{real}/cri-containerd-abc.scope/pod{UID}"),
            format!("{real}/kubepods-burstable-pod{UID_}.slice"),
        ] {
            assert_eq!(
                found(&tree(&[&inner]), UID).as_deref(),
                Some(Path::new(&real)),
                "{inner}"
            );
        }
    }

    /// Every directory on the way and the pod directory must be owned by
    /// root; one that is not is skipped and reported.
    #[test]
    fn pod_dir_search_requires_root_ownership() {
        let pod = format!("kubepods/burstable/pod{UID}");
        let spod = format!("kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod{UID_}.slice");
        for (paths, untrusted) in [
            (&pod, "kubepods"),
            (&pod, "kubepods/burstable"),
            (&pod, pod.as_str()),
            (&spod, "kubelet.slice"),
            (&spod, "kubelet.slice/kubelet-kubepods.slice"),
            (&spod, spod.as_str()),
        ] {
            let t = owned_tree(&[paths.as_str()], &[untrusted]);
            assert_eq!(found(&t, UID), None, "{untrusted}");
            assert_eq!(
                pod_dirs(&t, None).untrusted,
                [(PathBuf::from(untrusted), "not owned by root".to_string())],
                "{untrusted}"
            );
            assert!(found(&tree(&[paths.as_str()]), UID).is_some());
        }
        // An untrusted duplicate does not hide the real pod.
        let dup = format!("kubepods/pod{UID}");
        let t = owned_tree(&[&pod, &dup], &[&dup]);
        assert_eq!(found(&t, UID).as_deref(), Some(Path::new(&pod)));
        // A directory removed while the search runs is skipped, and not
        // reported as untrusted (it was never seen to be someone else's).
        for gone in ["kubepods", "kubepods/burstable", pod.as_str()] {
            let mut t = tree(&[&pod]);
            t.gone.push(PathBuf::from(gone));
            let s = pod_dirs(&t, None);
            assert!(s.untrusted.is_empty(), "{gone}: {:?}", s.untrusted);
            assert_eq!(pod_dir(&s.dirs, UID), PodDir::None, "{gone}");
        }
    }

    /// `pod_cgroup_root` inside a recognised root (`kubepods/burstable` in
    /// `kubepods`) reaches each of its pod directories twice: the same
    /// directory, by identity, so one pod, not an ambiguous one.
    #[test]
    fn pod_dir_search_with_an_overlapping_configured_root() {
        let pod = format!("kubepods/burstable/pod{UID}");
        let spod =
            format!("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice");
        for (root, pod) in [
            ("kubepods/burstable", &pod),
            ("kubepods", &pod),
            ("kubepods.slice/kubepods-burstable.slice", &spod),
        ] {
            let s = pod_dirs(&tree(&[pod]), Some(Path::new(root)));
            assert_eq!(pod_dir(&s.dirs, UID), PodDir::One(Path::new(pod)), "{root}");
        }
        // Two directories for one uid are still ambiguous.
        let dup = format!("kubepods/pod{UID}");
        let s = pod_dirs(&tree(&[&pod, &dup]), Some(Path::new("kubepods/burstable")));
        assert!(matches!(pod_dir(&s.dirs, UID), PodDir::Several(d) if d.len() == 2));
    }

    /// An unresolved pod is reported once per uid and reason, until it
    /// resolves or leaves the selection.
    #[test]
    fn unresolved_pods_are_reported_once() {
        let mut r = ReportOnce::default();
        assert!(r.first(UID, 0));
        assert!(!r.first(UID, 0));
        assert!(r.first(UID, 1), "another reason is news");
        assert!(r.first(UID2, 0));
        r.keep_only(&BTreeSet::from([UID2]));
        assert!(r.first(UID, 0), "resolved, then unresolved again");
        assert!(!r.first(UID2, 0));
        r.keep_only(&BTreeSet::new());
        assert!(r.0.is_empty());
    }

    /// A kubelet `--cgroup-root` other than `/` (or `/<name>` under
    /// systemd) puts kubepods elsewhere: not searched unless the operator
    /// names it in `pod_cgroup_root`, then searched with the naming its
    /// last component shows, and listed among the roots searched.
    #[test]
    fn pod_dir_search_in_a_configured_kubelet_root() {
        let cases = [
            (
                "custom/kubepods",
                format!("custom/kubepods/burstable/pod{UID}"),
            ),
            ("custom/kubepods", format!("custom/kubepods/pod{UID}")),
            (
                "a.slice/a-b.slice/a-b-kubepods.slice",
                format!(
                    "a.slice/a-b.slice/a-b-kubepods.slice/a-b-kubepods-besteffort.slice/a-b-kubepods-besteffort-pod{UID_}.slice"
                ),
            ),
        ];
        for (root, pod) in &cases {
            let t = tree(&[pod, "kubepods.slice"]);
            assert_eq!(found(&t, UID), None, "{pod} is refused without the option");
            let s = pod_dirs(&t, Some(Path::new(root)));
            assert!(s.searched.contains(&PathBuf::from(root)), "{root}");
            assert!(s.searched.contains(&PathBuf::from("kubepods.slice")));
            match pod_dir(&s.dirs, UID) {
                PodDir::One(p) => assert_eq!(p, Path::new(pod)),
                other => panic!("{pod}: {other:?}"),
            }
        }
        // Configured as one of the recognised roots: searched once.
        let pod = format!("kubepods/pod{UID}");
        let s = pod_dirs(&tree(&[&pod]), Some(Path::new("kubepods")));
        assert_eq!(s.searched, [PathBuf::from("kubepods")]);
        assert!(matches!(pod_dir(&s.dirs, UID), PodDir::One(_)));
        // The configured root itself must be trusted too.
        let t = owned_tree(&[&cases[0].1], &["custom/kubepods"]);
        assert!(matches!(
            pod_dir(&pod_dirs(&t, Some(Path::new("custom/kubepods"))).dirs, UID),
            PodDir::None
        ));
        assert_eq!(root_naming(Path::new("x/kubepods")), Naming::Cgroupfs);
        assert_eq!(
            root_naming(Path::new("a.slice/a-kubepods.slice")),
            Naming::Systemd("a-kubepods".into())
        );
    }

    #[test]
    fn pod_dir_search_not_found_and_ambiguous() {
        let other = "kubepods/pod11111111-2222-3333-4444-555555555555";
        assert_eq!(found(&tree(&[other, "system.slice"]), UID), None);
        // Two root-owned directories for one uid: neither is taken.
        let a = format!("kubepods/pod{UID}");
        let b = format!("kubepods.slice/kubepods-pod{UID_}.slice");
        let dirs = pod_dirs(&tree(&[&a, &b]), None).dirs;
        let PodDir::Several(both) = pod_dir(&dirs, UID) else {
            panic!("not ambiguous")
        };
        assert_eq!(both.len(), 2);
        // A static pod's cgroup is named by its config hash (32 hex digits,
        // no dashes), never taken for a pod uid.
        assert_eq!(
            Naming::Cgroupfs.pod("pod0f3c1a2b4d5e6f708192a3b4c5d6e7f8"),
            None
        );
        // look-alikes
        for name in [
            format!("xpod{UID}"),
            "pod1234".into(),
            format!("pod{UID}x"),
            format!("pod{UID}.slice"),
        ] {
            assert_eq!(Naming::Cgroupfs.pod(&name), None, "{name}");
        }
        let s = Naming::Systemd("kubepods".into());
        assert_eq!(
            s.pod(&format!("kubepods-pod{UID_}.slice")).as_deref(),
            Some(UID)
        );
        assert_eq!(s.pod(&format!("kubepods-pod{UID_}")), None);
        assert_eq!(s.pod(&format!("xkubepods-pod{UID_}.slice")), None);
        assert_eq!(s.pod("kubepods-burstable.slice"), None);
        assert_eq!(s.qos("kubepods-guaranteed.slice"), None);
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

    #[cfg(target_os = "linux")]
    struct TempDir(PathBuf);
    #[cfg(target_os = "linux")]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(target_os = "linux")]
    fn temp(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("panopticon-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    /// Create `rel` and its ancestors below `root`, each 0755 whatever the
    /// umask: a group- or other-writable directory is never trusted.
    #[cfg(target_os = "linux")]
    fn mkdirs(root: &Path, rel: impl AsRef<Path>) {
        use std::os::unix::fs::PermissionsExt;
        let mut at = root.to_path_buf();
        for c in rel.as_ref().components() {
            at.push(c);
            let _ = std::fs::create_dir(&at);
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    #[cfg(target_os = "linux")]
    fn chmod(root: &Path, rel: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(target_os = "linux")]
    fn ino(root: &Path, rel: &str) -> u64 {
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(root.join(rel)).unwrap())
    }
    /// The owner of the directories a test creates.
    #[cfg(target_os = "linux")]
    fn me() -> u32 {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() }
    }
    fn sel(key: &str, uid: &str) -> SelectedPod {
        SelectedPod {
            key: key.into(),
            uid: uid.into(),
        }
    }
    const UID2: &str = "11111111-2222-3333-4444-555555555555";

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_paths_and_pods_to_inodes() {
        let t = temp("resolve");
        let root = &t.0;
        let pod = format!("kubepods/burstable/pod{UID}");
        mkdirs(root, format!("{pod}/ctr"));
        mkdirs(root, "system.slice");

        let pods = [sel("pay/co-1", UID), sel("pay/gone", UID2)];
        let r = resolve_owned_by(root, &["/system.slice".into()], &pods, None, me()).unwrap();
        assert_eq!(
            r.ids,
            BTreeSet::from([ino(root, "system.slice"), ino(root, &pod)])
        );
        assert_eq!(r.unresolved, ["pay/gone"]);

        // Security scan F5: directories not owned by the trusted owner
        // (root in production) are not taken as a pod's; a cgroup_filter
        // path is the operator's own and is not checked.
        let r = resolve_owned_by(root, &["/system.slice".into()], &pods, None, me() + 1).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino(root, "system.slice")]));
        assert_eq!(r.unresolved, ["pay/co-1", "pay/gone"]);

        // A second directory for the uid: neither is taken.
        let dup = format!("kubepods/pod{UID}");
        mkdirs(root, &dup);
        let r = resolve_owned_by(root, &[], &pods, None, me()).unwrap();
        assert!(r.ids.is_empty());
        assert_eq!(r.unresolved, ["pay/co-1", "pay/gone"]);
        // A duplicate outside the kubepods hierarchy changes nothing.
        std::fs::remove_dir(root.join(&dup)).unwrap();
        mkdirs(root, format!("user.slice/user@1000.service/pod{UID}"));
        let r = resolve_owned_by(root, &[], &pods, None, me()).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino(root, &pod)]));

        // A group- or other-writable pod directory, or one on the way, is
        // not taken: anyone with that access could have made it.
        for (dir, mode) in [
            (pod.as_str(), 0o775),
            (pod.as_str(), 0o757),
            ("kubepods/burstable", 0o777),
            ("kubepods", 0o775),
        ] {
            chmod(root, dir, mode);
            let r = resolve_owned_by(root, &[], &pods[..1], None, me()).unwrap();
            assert!(r.ids.is_empty(), "{dir} {mode:o}");
            assert_eq!(r.unresolved, ["pay/co-1"], "{dir} {mode:o}");
            chmod(root, dir, 0o755);
        }
        let r = resolve_owned_by(root, &[], &pods[..1], None, me()).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino(root, &pod)]));

        // A missing path refuses to start and names it.
        let e = resolve(root, &["nope.slice".into()], &[], None)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("nope.slice") && e.contains("os error 2)"),
            "ENOENT: {e}"
        );
    }

    /// `pod_cgroup_root`: a root-owned directory reached without a symlink
    /// or mount crossing is searched; anything else refuses, naming it.
    /// A pod found nowhere is counted as `not_found`.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_with_a_configured_pod_root() {
        let t = temp("podroot");
        let root = &t.0;
        let pod = format!("custom/kubepods/burstable/pod{UID}");
        mkdirs(root, &pod);
        mkdirs(root, "elsewhere/kubepods");
        std::os::unix::fs::symlink("custom", root.join("linked")).unwrap();
        let pods = [sel("pay/co-1", UID)];

        let before = pod_unresolved()[0];
        let r = resolve_owned_by(root, &[], &pods, None, me()).unwrap();
        assert!(r.ids.is_empty(), "custom root not searched unless named");
        assert!(pod_unresolved()[0] > before, "counted as not_found");

        let r = resolve_owned_by(root, &[], &pods, Some("/custom/kubepods"), me()).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino(root, &pod)]));

        for (bad, why) in [
            ("/linked/kubepods", "os error 40"),
            ("/missing/kubepods", "os error 2"),
            ("custom/kubepods", "absolute"),
            ("/custom/../custom/kubepods", "plain path"),
        ] {
            let e = resolve_owned_by(root, &[], &pods, Some(bad), me())
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("pod_cgroup_root") && e.contains(why),
                "{bad}: {e}"
            );
        }
        let e = resolve_owned_by(root, &[], &pods, Some("/custom/kubepods"), me() + 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not owned by root"), "{e}");
        chmod(root, "custom", 0o775);
        let e = resolve_owned_by(root, &[], &pods, Some("/custom/kubepods"), me())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("custom is group- or other-writable (mode 775)"),
            "{e}"
        );
        chmod(root, "custom", 0o755);

        // Inside a recognised root: each pod found once, not ambiguous.
        let inner = format!("kubepods/burstable/pod{UID2}");
        mkdirs(root, &inner);
        let both = [sel("pay/co-1", UID), sel("pay/inner", UID2)];
        let r = resolve_owned_by(root, &[], &both, Some("/kubepods/burstable"), me()).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino(root, &inner)]));
        assert_eq!(r.unresolved, ["pay/co-1"]);
    }

    /// Symlinks are never followed: as a `cgroup_filter` path or component
    /// (refused, even to the root itself), or as a pod directory (unresolved).
    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_refuses_symlinks() {
        let t = temp("symlink");
        let root = &t.0;
        mkdirs(root, "system.slice/sshd.service");
        let real = format!("kubepods/burstable/pod{UID}");
        mkdirs(root, &real);
        use std::os::unix::fs::symlink as link;
        link(".", root.join("self")).unwrap();
        link("system.slice", root.join("sys")).unwrap();
        link(root.join(&real), root.join(format!("kubepods/pod{UID2}"))).unwrap();
        // A QoS level that is a link to the real one.
        link("burstable", root.join("kubepods/besteffort")).unwrap();

        for p in ["self", "sys", "sys/sshd.service"] {
            let e = resolve(root, &[p.into()], &[], None)
                .unwrap_err()
                .to_string();
            assert!(e.contains(p) && e.contains("os error 40"), "ELOOP: {e}");
        }
        // pod UID2 is a link to a pod directory, and pod UID is reachable
        // through the linked QoS level too; the real one is found once.
        let r = resolve_owned_by(root, &[], &[sel("pay/linked", UID2)], None, me()).unwrap();
        assert!(r.ids.is_empty());
        assert_eq!(r.unresolved, ["pay/linked"]);
        let r = resolve_owned_by(root, &[], &[sel("pay/real", UID)], None, me()).unwrap();
        assert_eq!(r.ids, BTreeSet::from([ino(root, &real)]));
    }

    /// A bind mount puts pod B's cgroup over pod A's directory: A is not
    /// resolved (to B's inode or at all), B still is. Needs root:
    /// `sudo <test binary> --ignored resolve_refuses_a_bind_mount`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root to bind mount"]
    fn resolve_refuses_a_bind_mount() {
        struct Umount(std::ffi::CString);
        impl Drop for Umount {
            fn drop(&mut self) {
                // SAFETY: valid C string.
                unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
            }
        }
        let t = temp("bind");
        let root = &t.0;
        let a = format!("kubepods/pod{UID}");
        let b = format!("kubepods/pod{UID2}");
        mkdirs(root, &a);
        mkdirs(root, &b);
        mkdirs(root, "plain");
        let cs = |rel: &str| {
            std::ffi::CString::new(root.join(rel).into_os_string().into_encoded_bytes()).unwrap()
        };
        let (src, dst) = (cs(&b), cs(&a));
        // SAFETY: valid C strings; no data argument.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "bind mount: {}", std::io::Error::last_os_error());
        let _umount = Umount(dst);
        let b_ino = ino(root, &b);
        assert_eq!(ino(root, &a), b_ino, "the bind mount is in place");

        let r = resolve(root, &[], &[sel("pay/a", UID), sel("pay/b", UID2)], None).unwrap();
        assert_eq!(r.ids, BTreeSet::from([b_ino]));
        assert_eq!(r.unresolved, ["pay/a"]);
        let e = resolve(root, std::slice::from_ref(&a), &[], None)
            .unwrap_err()
            .to_string();
        assert!(e.contains(&a) && e.contains("os error 18"), "EXDEV: {e}");
        assert!(resolve(root, &["plain".into()], &[], None).is_ok());
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
        fn set_options(&mut self, o: ScopeOptions) -> Result<()> {
            self.0.push(format!(
                "opt{}{}",
                o.capture_loopback as u8, o.creator_rule as u8
            ));
            Ok(())
        }
        fn ids(&mut self) -> Result<BTreeSet<u64>> {
            unimplemented!()
        }
        fn generation(&mut self) -> Result<u64> {
            unimplemented!()
        }
        fn disarm(&mut self) -> Result<()> {
            unimplemented!()
        }
    }

    #[test]
    fn publish_writes_the_map_then_bumps_once() {
        let s = |v: &[u64]| v.iter().copied().collect::<BTreeSet<u64>>();
        let mut m = Log::default();
        let d = publish(&mut m, &s(&[1, 2]), &s(&[2, 3, 4]), None).unwrap();
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
        let d = publish(&mut m, &s(&[2]), &s(&[2, 3]), None).unwrap();
        assert!(!d.is_narrowing());
        assert_eq!(m.0, ["+3", "gen"]);

        // No change: no generation bump.
        let mut m = Log::default();
        assert_eq!(
            publish(&mut m, &s(&[2]), &s(&[2]), None).unwrap(),
            AllowDiff::default()
        );
        assert!(m.0.is_empty());

        // A failed write after a delete still bumps, then reports the error.
        let mut m = Log(vec![], Some(4));
        assert!(publish(&mut m, &s(&[1]), &s(&[3, 4]), None).is_err());
        assert_eq!(m.0, ["-1", "+3", "gen"]);

        // Options alone: written, then one bump (the cached verdicts go
        // stale); with ids, between the deletes and the inserts.
        let o = ScopeOptions {
            capture_loopback: true,
            creator_rule: false,
        };
        let mut m = Log::default();
        let d = publish(&mut m, &s(&[2]), &s(&[2]), Some(o)).unwrap();
        assert_eq!(d, AllowDiff::default());
        assert_eq!(m.0, ["opt10", "gen"]);
        let mut m = Log(vec![], Some(4));
        assert!(publish(&mut m, &s(&[1]), &s(&[4]), Some(o)).is_err());
        assert_eq!(m.0, ["-1", "opt10", "gen"]);
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
