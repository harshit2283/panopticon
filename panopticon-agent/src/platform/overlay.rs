//! The file a uprobe lands on when a container's binary or library is seen
//! through overlayfs.
//!
//! A container's root is an overlay mount. Each container shows an image
//! file under a device of its own, but the kernel puts a uprobe on the
//! file's real inode (`d_real_inode`), which every container of the image
//! shares. If the agent keyed what it attached by the device it examined,
//! it would attach that real inode once per container. Each copy of a
//! probe fires, so every call would be emitted once per copy.
//!
//! [`lower_file_id`] finds that real inode, or gives up. It looks the path
//! up in the overlay's layer directories, as overlayfs would, and accepts
//! the file it finds only if that file is the one examined. On a
//! single-filesystem overlay, overlayfs reports a file's real inode number,
//! so the file found must have the examined inode number on the layers'
//! device, and the same size and mtime.
//!
//! A copied-up file is the exception: overlayfs reports its lower origin's
//! number, while its data and the probe live on the upper copy. The lookup
//! takes the upper copy first, and the copy's own number then fails the
//! check. Any doubt gives `None`, and the caller keys the file by the
//! examined `(dev, ino)`. That can attach a file twice, never zero times.

/// An overlay mount that serves a path: its layer directories (upper
/// first, then the lower ones in order), as the mounter named them, and
/// the path inside each layer.
#[derive(Debug, PartialEq, Eq)]
pub struct OverlayPath {
    pub layers: Vec<String>,
    pub rel: String,
}

/// Decode the octal escapes `/proc/<pid>/mountinfo` uses (`\040` for a
/// space). None if an escape is malformed.
fn unescape_octal(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let oct = b.get(i + 1..i + 4)?;
            if !oct.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return None;
            }
            let v = oct.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0'));
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Whether mount point `mp` covers `path` (a whole-component prefix).
fn covers(mp: &str, path: &str) -> bool {
    mp == "/" || path == mp || path.strip_prefix(mp).is_some_and(|r| r.starts_with('/'))
}

/// The overlay mount serving `path` (absolute, in the process's mount
/// namespace) according to that process's `mountinfo`. The mount must be
/// the one whose device the examined file showed (`dev`, major and minor).
/// It is the mount with the longest mount point covering the path; when
/// mounts stack, the later one is on top. None, rather than a guess, for:
/// - any other filesystem;
/// - layers named by `lowerdir+` / `datadir+`, or data-only layers (`::`);
/// - a layer path holding `:` or `\` (escaped differently by different
///   kernels);
/// - a path with `.`, `..` or empty components.
pub fn overlay_path(mountinfo: &str, path: &str, dev: (u32, u32)) -> Option<OverlayPath> {
    if !path.starts_with('/') {
        return None;
    }
    let mut best: Option<(usize, Vec<&str>, String)> = None;
    for line in mountinfo.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 10 {
            continue;
        }
        let Some(mp) = unescape_octal(f[4]) else {
            continue;
        };
        if covers(&mp, path) && best.as_ref().is_none_or(|(len, _, _)| mp.len() >= *len) {
            best = Some((mp.len(), f, mp));
        }
    }
    let (_, f, mp) = best?;
    let sep = f.iter().skip(6).position(|x| *x == "-")? + 6;
    let (fstype, superopts) = (*f.get(sep + 1)?, *f.get(sep + 3)?);
    if fstype != "overlay" {
        return None;
    }
    let (maj, min) = f[2].split_once(':')?;
    if (maj.parse().ok()?, min.parse().ok()?) != dev {
        return None;
    }
    let root = unescape_octal(f[3])?;
    let rest = if mp == "/" { path } else { &path[mp.len()..] };
    let rel = if root == "/" {
        rest.to_string()
    } else {
        format!("{root}{rest}")
    };
    if rel.len() < 2
        || !rel.starts_with('/')
        || rel[1..]
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return None;
    }

    let (mut upper, mut lower) = (None, None);
    for opt in superopts.split(',') {
        let (key, value) = opt.split_once('=').unwrap_or((opt, ""));
        match key {
            "lowerdir+" | "datadir+" => return None,
            "upperdir" | "lowerdir" => {
                if value.contains("\\072") || value.contains("\\134") {
                    return None;
                }
                let value = unescape_octal(value)?;
                if key == "upperdir" {
                    upper = Some(value);
                } else {
                    lower = Some(value);
                }
            }
            _ => {}
        }
    }
    let lower = lower?;
    let mut layers: Vec<String> = upper.into_iter().collect();
    for l in lower.split(':') {
        if !l.starts_with('/') {
            return None; // "::" (data-only layers) or a relative path
        }
        layers.push(l.to_string());
    }
    if layers.iter().any(|l| l.contains('\\')) {
        return None;
    }
    Some(OverlayPath { layers, rel })
}

/// The real `(dev, ino)` of a file the agent examined at `path` in process
/// `pid`'s mount namespace (`key`: its examined `FileKey`), when that file
/// is on an overlay mount and the lookup proves which layer file it is
/// (module docs). The answer is trusted only when all of these hold:
/// - the agent has CAP_SYS_ADMIN, so it can read the `trusted.overlay.*`
///   marks;
/// - the process's mount namespace is owned by the initial user namespace,
///   so the mount was made by a host-privileged runtime whose layer paths
///   resolve under `/proc/1/root`;
/// - every layer is on one device.
#[cfg(target_os = "linux")]
pub fn lower_file_id(
    pid: u32,
    path: &str,
    key: super::proc_scanner::FileKey,
) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let (dev, ino, mtime, size) = key;
    if !cap_sys_admin() || !mount_ns_in_init_userns(pid) {
        return None;
    }
    let mountinfo = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
    let ovl = overlay_path(&mountinfo, path, (libc::major(dev), libc::minor(dev)))?;
    let mut layers = Vec::with_capacity(ovl.layers.len());
    let mut layer_dev = None;
    for dir in &ovl.layers {
        let fd = super::proc_scanner::open_path_in_root(&format!("/proc/1/root{dir}")).ok()?;
        let m = std::fs::File::from(fd.try_clone().ok()?).metadata().ok()?;
        if !m.is_dir() || layer_dev.is_some_and(|d| d != m.dev()) {
            return None;
        }
        layer_dev = Some(m.dev());
        layers.push(fd);
    }
    let comps: Vec<&str> = ovl.rel[1..].split('/').collect();
    let found = find_in_layers(&layers, &comps)?;
    let m = std::fs::File::from(found).metadata().ok()?;
    let m_mtime = m.mtime().saturating_mul(1_000_000_000) + m.mtime_nsec();
    (m.is_file()
        && Some(m.dev()) == layer_dev
        && m.ino() == ino
        && m.size() == size
        && m_mtime == mtime)
        .then_some((m.dev(), ino))
}

/// What one layer holds at a path ([`walk_layer`]).
#[cfg(target_os = "linux")]
enum Walk {
    /// Nothing there, and nothing here hides the layers below.
    Absent,
    /// A regular file, with no overlay mark (`O_PATH` descriptor).
    Found(std::os::fd::OwnedFd),
    /// Anything that overlayfs might resolve some other way: a whiteout,
    /// a symlink, an opaque or redirected directory, a metacopy, an error.
    Stop,
}

/// The first layer file at `comps`, looked up layer by layer the way
/// overlayfs merges them. None on any [`Walk::Stop`], and when no layer has
/// the file.
#[cfg(target_os = "linux")]
fn find_in_layers(layers: &[std::os::fd::OwnedFd], comps: &[&str]) -> Option<std::os::fd::OwnedFd> {
    for layer in layers {
        match walk_layer(layer, comps) {
            Walk::Found(fd) => return Some(fd),
            Walk::Absent => continue,
            Walk::Stop => return None,
        }
    }
    None
}

/// Look `comps` up in one layer, one component at a time, never following
/// a symlink.
#[cfg(target_os = "linux")]
fn walk_layer(layer: &std::os::fd::OwnedFd, comps: &[&str]) -> Walk {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut cur: Option<OwnedFd> = None;
    let mut opaque = false;
    for (i, comp) in comps.iter().enumerate() {
        let Ok(name) = std::ffi::CString::new(*comp) else {
            return Walk::Stop;
        };
        let dir = cur.as_ref().map_or(layer.as_raw_fd(), |f| f.as_raw_fd());
        // SAFETY: openat(2) on a NUL-terminated name; the fd is owned here.
        let fd = unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let enoent = std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
            return if enoent && !opaque {
                Walk::Absent
            } else {
                Walk::Stop
            };
        }
        // SAFETY: a descriptor just returned by openat(2).
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let Some(ty) = fd
            .try_clone()
            .ok()
            .and_then(|f| std::fs::File::from(f).metadata().ok())
            .map(|m| m.file_type())
        else {
            return Walk::Stop;
        };
        if i + 1 == comps.len() {
            let plain =
                ty.is_file() && !overlay_mark(&fd, "metacopy") && !overlay_mark(&fd, "whiteout");
            return if plain { Walk::Found(fd) } else { Walk::Stop };
        }
        if !ty.is_dir() || overlay_mark(&fd, "redirect") {
            return Walk::Stop;
        }
        opaque |= overlay_mark(&fd, "opaque");
        cur = Some(fd);
    }
    Walk::Stop
}

/// Whether a layer entry carries overlayfs's `trusted.overlay.<what>` or
/// `user.overlay.<what>` attribute. Any error other than "no such
/// attribute" or "no attributes here" counts as carrying it.
#[cfg(target_os = "linux")]
fn overlay_mark(fd: &std::os::fd::OwnedFd, what: &str) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(path) = std::ffi::CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
        return true;
    };
    ["trusted", "user"].iter().any(|ns| {
        let Ok(name) = std::ffi::CString::new(format!("{ns}.overlay.{what}")) else {
            return true;
        };
        // SAFETY: getxattr(2) size query (no buffer) on NUL-terminated strings.
        let r = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        r >= 0 || {
            let e = std::io::Error::last_os_error().raw_os_error();
            e != Some(libc::ENODATA) && e != Some(libc::EOPNOTSUPP)
        }
    })
}

/// CAP_SYS_ADMIN in the agent's effective set: without it the kernel hides
/// `trusted.*` attributes, and an opaque directory would look plain.
#[cfg(target_os = "linux")]
fn cap_sys_admin() -> bool {
    const CAP_SYS_ADMIN: u32 = 21;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            let hex = s
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))?
                .trim()
                .to_string();
            u64::from_str_radix(&hex, 16).ok()
        })
        .is_some_and(|eff| eff & (1 << CAP_SYS_ADMIN) != 0)
}

/// Whether `pid`'s mount namespace is owned by the initial user namespace
/// (that of pid 1, as the agent sees it): its mounts were made by a
/// host-privileged runtime, not by an unprivileged user in a namespace of
/// its own.
#[cfg(target_os = "linux")]
fn mount_ns_in_init_userns(pid: u32) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    const NS_GET_USERNS: libc::c_ulong = 0xb701; // _IO(0xb7, 0x1)
    let Ok(mnt) = std::fs::File::open(format!("/proc/{pid}/ns/mnt")) else {
        return false;
    };
    // SAFETY: ioctl(2) on an open namespace fd; the returned fd is owned here.
    let userns = unsafe { libc::ioctl(mnt.as_raw_fd(), NS_GET_USERNS as _) };
    if userns < 0 {
        return false;
    }
    let userns = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(userns) });
    let (Ok(owner), Ok(init)) = (userns.metadata(), std::fs::metadata("/proc/1/ns/user")) else {
        return false;
    };
    (owner.dev(), owner.ino()) == (init.dev(), init.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container root as containerd mounts it (lab, kernel 7.0).
    const CONTAINERD: &str = "405 377 0:49 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/snapshots/172/fs:/var/lib/containerd/snapshots/171/fs,upperdir=/var/lib/containerd/snapshots/173/fs,workdir=/var/lib/containerd/snapshots/173/work,nouserxattr\n\
406 405 0:51 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
407 405 8:1 /etc/hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw\n";

    #[test]
    fn test_overlay_path_layers_upper_first() {
        let o = overlay_path(CONTAINERD, "/app/server", (0, 49)).unwrap();
        assert_eq!(
            o.layers,
            vec![
                "/var/lib/containerd/snapshots/173/fs",
                "/var/lib/containerd/snapshots/172/fs",
                "/var/lib/containerd/snapshots/171/fs",
            ]
        );
        assert_eq!(o.rel, "/app/server");
    }

    #[test]
    fn test_overlay_path_needs_the_examined_device_and_overlay() {
        assert_eq!(overlay_path(CONTAINERD, "/app/server", (0, 52)), None);
        // A bind mount over the overlay serves this path: not overlay.
        assert_eq!(overlay_path(CONTAINERD, "/etc/hosts", (8, 1)), None);
        assert_eq!(overlay_path(CONTAINERD, "/etc/hosts", (0, 49)), None);
        assert_eq!(overlay_path(CONTAINERD, "relative", (0, 49)), None);
    }

    #[test]
    fn test_overlay_path_longest_and_latest_mount_wins() {
        let mi = "1 0 0:40 / / rw - overlay overlay rw,lowerdir=/a\n\
2 1 0:41 / /opt rw - overlay overlay rw,lowerdir=/b\n\
3 1 0:42 /sub /opt rw - overlay overlay rw,lowerdir=/c:/d,upperdir=/u\n";
        let o = overlay_path(mi, "/opt/bin/x", (0, 42)).unwrap();
        assert_eq!(o.layers, vec!["/u", "/c", "/d"]);
        assert_eq!(o.rel, "/sub/bin/x", "the mount's root joins the path");
        assert_eq!(overlay_path(mi, "/opt/bin/x", (0, 41)), None, "shadowed");
        assert_eq!(overlay_path(mi, "/optx", (0, 40)).unwrap().rel, "/optx");
    }

    #[test]
    fn test_overlay_path_refuses_what_it_cannot_read_exactly() {
        let line = |opts: &str| format!("1 0 0:40 / / rw - overlay overlay {opts}\n");
        let refused = [
            "rw,lowerdir+=/a,upperdir=/u",
            "rw,lowerdir=/a,datadir+=/d",
            "rw,lowerdir=/a::/data",
            "rw,lowerdir=/a\\072b:/c",
            "rw,lowerdir=/a\\134:b",
            "rw,lowerdir=rel/a",
            "rw,upperdir=/u",
            "rw,lowerdir=/a\\9",
        ];
        for opts in refused {
            assert_eq!(overlay_path(&line(opts), "/x", (0, 40)), None, "{opts}");
        }
        let spaced = overlay_path(&line("rw,lowerdir=/my\\040layer"), "/x", (0, 40)).unwrap();
        assert_eq!(spaced.layers, vec!["/my layer"]);
        let ok = line("rw,lowerdir=/a");
        for path in ["/", "/a/./b", "/a/../b", "/a//b"] {
            assert_eq!(overlay_path(&ok, path, (0, 40)), None, "{path}");
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::*;
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::MetadataExt;

        fn dir_fd(p: &std::path::Path) -> OwnedFd {
            OwnedFd::from(std::fs::File::open(p).unwrap())
        }

        fn ino_of(fd: OwnedFd) -> u64 {
            std::fs::File::from(fd).metadata().unwrap().ino()
        }

        /// The lookup takes the first layer that has the file. A layer
        /// that has something else at the path (here a symlink, as a
        /// whiteout or a redirect would be) stops it rather than falling
        /// through to a lower copy.
        #[test]
        fn test_find_in_layers_first_plain_file_or_nothing() {
            let base = std::env::temp_dir().join(format!("panopticon-ovl-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            for l in ["upper", "mid", "low"] {
                std::fs::create_dir_all(base.join(l).join("usr/bin")).unwrap();
            }
            std::fs::write(base.join("low/usr/bin/app"), b"low").unwrap();
            std::fs::write(base.join("low/usr/bin/lib"), b"low").unwrap();
            std::fs::write(base.join("mid/usr/bin/lib"), b"mid").unwrap();
            std::os::unix::fs::symlink("/etc/passwd", base.join("upper/usr/bin/link")).unwrap();
            std::fs::write(base.join("low/usr/bin/link"), b"low").unwrap();
            std::fs::create_dir_all(base.join("low/opt")).unwrap();
            std::fs::write(base.join("low/opt/x"), b"low").unwrap();
            std::os::unix::fs::symlink(base.join("low/opt"), base.join("upper/opt")).unwrap();

            let layers: Vec<OwnedFd> = ["upper", "mid", "low"]
                .iter()
                .map(|l| dir_fd(&base.join(l)))
                .collect();
            let ino = |p: &str| std::fs::metadata(base.join(p)).unwrap().ino();
            let find = |rel: &str| {
                let comps: Vec<&str> = rel.split('/').collect();
                find_in_layers(&layers, &comps).map(ino_of)
            };
            assert_eq!(find("usr/bin/app"), Some(ino("low/usr/bin/app")));
            assert_eq!(find("usr/bin/lib"), Some(ino("mid/usr/bin/lib")));
            assert_eq!(find("usr/bin/link"), None, "a symlink on top stops");
            assert_eq!(find("opt/x"), None, "a symlinked directory stops");
            assert_eq!(find("usr/bin/none"), None);
            assert_eq!(find("usr/bin"), None, "a directory is not a file");

            // An opaque directory hides the layers below it (user xattrs:
            // skipped where the test filesystem has none).
            let opaque = std::ffi::CString::new(base.join("upper/usr").to_str().unwrap()).unwrap();
            let name = std::ffi::CString::new("user.overlay.opaque").unwrap();
            // SAFETY: setxattr(2) on NUL-terminated strings and a 1-byte value.
            let set = unsafe {
                libc::setxattr(opaque.as_ptr(), name.as_ptr(), b"y".as_ptr().cast(), 1, 0)
            };
            if set == 0 {
                assert_eq!(find("usr/bin/app"), None, "hidden under an opaque dir");
            }
            std::fs::remove_dir_all(&base).ok();
        }
    }
}
