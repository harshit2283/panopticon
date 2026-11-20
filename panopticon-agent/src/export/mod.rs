//! Export modules for agent output (JSONL, Prometheus, OTLP).

pub mod audit;
pub mod http_server;
pub mod json;
pub mod metrics;
pub mod otlp;
#[cfg(unix)]
pub mod pcap;
#[cfg(unix)]
pub mod raw_capture;

/// Open an export file owner-only (0600) for writing. `append` keeps what
/// the file holds; otherwise any existing file is replaced by a fresh inode,
/// so a reader that opened the old one sees none of the new data. A symlink
/// or non-regular file (FIFO, device) at `path` is refused, and the mode is
/// set on the open descriptor, not by path.
#[cfg(unix)]
pub fn open_private(path: &str, append: bool) -> anyhow::Result<std::fs::File> {
    use anyhow::{Context, bail};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => {
            bail!("refusing to write {path}: not a regular file (symlink, FIFO or device)")
        }
        Ok(_) if !append => {
            std::fs::remove_file(path).with_context(|| format!("cannot replace {path}"))?
        }
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if append {
        options.create(true).append(true);
    } else {
        // Fails if someone recreated the path since it was removed.
        options.create_new(true);
    }
    let file = options
        .open(path)
        .with_context(|| format!("cannot open {path}"))?;
    if !file.metadata()?.file_type().is_file() {
        bail!("refusing to write {path}: not a regular file");
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot restrict permissions on {path}"))?;
    Ok(file)
}

#[cfg(not(unix))]
pub fn open_private(path: &str, append: bool) -> anyhow::Result<std::fs::File> {
    use anyhow::Context;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    options
        .open(path)
        .with_context(|| format!("cannot open {path}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::open_private;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn open_private_replaces_inode_and_refuses_links() {
        let dir = std::env::temp_dir().join(format!("panopticon_private_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out");
        let p = path.to_str().unwrap();

        // A world-readable file someone already holds open.
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut early_reader = std::fs::File::open(&path).unwrap();
        open_private(p, false)
            .unwrap()
            .write_all(b"SECRET")
            .unwrap();
        let mut seen = String::new();
        early_reader.read_to_string(&mut seen).unwrap();
        assert!(!seen.contains("SECRET"), "pre-opened reader saw {seen}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Append keeps content and tightens an existing file on its fd.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        open_private(p, true).unwrap().write_all(b"+more").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"SECRET+more");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // A symlink is refused in both modes, and its target is untouched.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        for append in [false, true] {
            assert!(open_private(link.to_str().unwrap(), append).is_err());
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"SECRET+more");
        std::fs::remove_dir_all(&dir).ok();
    }
}
