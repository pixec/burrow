//! Unpacked layer trees kept between imports.
//!
//! Every image that shares a base with one already imported shares a prefix
//! of its layer list, and a Kit composition shares its whole workload with
//! every other composition of that workload. Unpacking those layers again is
//! what made an import slow, so each prefix's tree is kept under
//! `<data-dir>/build/staged/<key>` and a later import starts from the longest
//! prefix it has, as a hardlink farm, and unpacks only what comes after.
//!
//! A hardlink farm is safe here because a layer never writes through an
//! existing file: `oci::apply_entries` unlinks a path before replacing it,
//! and a whiteout unlinks it outright, so the cached inodes are never
//! modified by the tree built on top of them.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::{Digest as _, Sha256};

/// How long an unused prefix tree is kept.
const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub struct Cache {
    root: PathBuf,
}

impl Cache {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("build").join("staged"),
        }
    }

    fn entry(&self, layers: &[PathBuf]) -> PathBuf {
        let mut hasher = Sha256::new();
        for layer in layers {
            hasher.update(layer.file_name().unwrap_or_default().as_encoded_bytes());
            hasher.update(b"\n");
        }
        let key: String = hasher
            .finalize()
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect();
        self.root.join(key)
    }

    /// Lays `layers` out in `dest`, which must not exist yet, and returns how
    /// many of them came from the cache.
    pub fn populate(&self, layers: &[PathBuf], dest: &Path) -> io::Result<usize> {
        let cached = (1..=layers.len())
            .rev()
            .find(|&n| self.entry(&layers[..n]).join("root").is_dir())
            .unwrap_or(0);
        if cached > 0 {
            let entry = self.entry(&layers[..cached]);
            link_tree(&entry.join("root"), dest)?;
            touch(&entry);
        } else {
            std::fs::create_dir(dest)?;
        }
        for n in cached..layers.len() {
            crate::oci::unpack_layer(&layers[n], dest)?;
            self.record(&layers[..=n], dest)?;
        }
        Ok(cached)
    }

    fn record(&self, layers: &[PathBuf], tree: &Path) -> io::Result<()> {
        let entry = self.entry(layers);
        if entry.join("root").is_dir() {
            return Ok(());
        }
        let _ = std::fs::remove_dir_all(&entry);
        std::fs::create_dir_all(&entry)?;
        let pending = entry.join("root.pending");
        link_tree(tree, &pending)?;
        std::fs::rename(&pending, entry.join("root"))?;
        touch(&entry);
        Ok(())
    }

    /// Drops prefix trees nothing has used within the TTL, and any left
    /// half-recorded.
    pub fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return;
        };
        let cutoff = SystemTime::now() - TTL;
        for entry in entries.flatten() {
            let path = entry.path();
            let used = std::fs::metadata(path.join("used"))
                .and_then(|m| m.modified())
                .ok();
            let stale = match used {
                Some(used) => used < cutoff,
                None => true,
            };
            if stale || !path.join("root").is_dir() {
                let _ = std::fs::remove_dir_all(&path);
            }
        }
    }
}

fn touch(entry: &Path) {
    let _ = std::fs::File::create(entry.join("used"));
}

/// Recreates `src`'s directories under `dst` with every file hardlinked.
fn link_tree(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, lchown, symlink};

    let meta = std::fs::symlink_metadata(src)?;
    std::fs::create_dir(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = entry.metadata()?;
        let kind = meta.file_type();
        if kind.is_dir() {
            link_tree(&from, &to)?;
        } else if kind.is_symlink() {
            symlink(std::fs::read_link(&from)?, &to)?;
            lchown(&to, Some(meta.uid()), Some(meta.gid()))?;
        } else {
            std::fs::hard_link(&from, &to)?;
        }
    }
    // After the children: a directory the image made unwritable would
    // otherwise refuse them.
    std::fs::set_permissions(dst, meta.permissions())?;
    lchown(dst, Some(meta.uid()), Some(meta.gid()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(dir: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(dir).unwrap();
        let path = dir.join(name);
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        for (entry, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_uid(u64::from(owner.uid()));
            header.set_gid(u64::from(owner.gid()));
            header.set_cksum();
            builder
                .append_data(&mut header, entry, content.as_bytes())
                .unwrap();
        }
        builder.finish().unwrap();
        path
    }

    fn read(path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("burrow-staged-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_shared_prefix_is_unpacked_once_and_whiteouts_leave_it_alone() {
        let dir = Scratch::new("shared");
        let cache = Cache::new(dir.path());
        let base = layer(
            dir.path(),
            "base",
            &[("bin/sh", "shell"), ("etc/motd", "hi")],
        );
        let a = layer(dir.path(), "a", &[("app/a", "a")]);
        let b = layer(dir.path(), "b", &[("app/b", "b"), ("etc/.wh.motd", "")]);

        let first = dir.path().join("first");
        assert_eq!(cache.populate(&[base.clone(), a], &first).unwrap(), 0);
        assert_eq!(read(&first.join("app/a")).as_deref(), Some("a"));

        let second = dir.path().join("second");
        assert_eq!(cache.populate(&[base, b], &second).unwrap(), 1);
        assert_eq!(read(&second.join("bin/sh")).as_deref(), Some("shell"));
        assert_eq!(read(&second.join("app/b")).as_deref(), Some("b"));
        assert!(!second.join("app/a").exists());
        assert!(!second.join("etc/motd").exists());
        assert_eq!(read(&first.join("etc/motd")).as_deref(), Some("hi"));
    }

    #[test]
    fn a_replaced_file_does_not_change_the_cached_one() {
        let dir = Scratch::new("replaced");
        let cache = Cache::new(dir.path());
        let base = layer(dir.path(), "base", &[("etc/motd", "old")]);
        let top = layer(dir.path(), "top", &[("etc/motd", "new")]);
        let first = dir.path().join("first");
        cache.populate(std::slice::from_ref(&base), &first).unwrap();
        let second = dir.path().join("second");
        assert_eq!(cache.populate(&[base, top], &second).unwrap(), 1);
        assert_eq!(read(&second.join("etc/motd")).as_deref(), Some("new"));
        assert_eq!(read(&first.join("etc/motd")).as_deref(), Some("old"));
    }

    #[test]
    fn unused_trees_are_pruned() {
        let dir = Scratch::new("pruned");
        let cache = Cache::new(dir.path());
        let base = layer(dir.path(), "base", &[("f", "x")]);
        cache
            .populate(std::slice::from_ref(&base), &dir.path().join("t"))
            .unwrap();
        let entry = cache.entry(std::slice::from_ref(&base));
        assert!(entry.join("root").is_dir());
        let old = SystemTime::now() - TTL - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(entry.join("used"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        cache.prune();
        assert!(!entry.exists());
    }
}
