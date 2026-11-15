//! The reader against images made the way template root disks are, with
//! every feature their filesystems use; see `fixtures/make-images.sh`.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use burrow_diskread::Image;
use burrow_diskread::protocol::{Kind, Time};

/// The fixture `name`, unpacked once to a file of its own.
fn fixture(name: &str) -> PathBuf {
    static UNPACKING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _unpacking = UNPACKING.lock().unwrap();
    let out = std::env::temp_dir().join(format!("burrow-diskread-{}-{name}", std::process::id()));
    if !out.exists() {
        let packed = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.gz"));
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(packed).unwrap())
            .read_to_end(&mut bytes)
            .unwrap();
        let partial = out.with_extension("partial");
        std::fs::write(&partial, bytes).unwrap();
        std::fs::rename(&partial, &out).unwrap();
    }
    out
}

fn image(name: &str) -> Image {
    Image::open(std::fs::File::open(fixture(name)).unwrap()).unwrap()
}

fn read_all(image: &Image, path: &str, offset: u64, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    image
        .read(path, offset, len, |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    out
}

#[test]
fn owners_modes_and_times_are_read() {
    let image = image("root.ext4");
    let notes = image.stat("/home/me/notes.txt").unwrap();
    assert_eq!(
        (notes.kind, notes.uid, notes.gid, notes.mode),
        (Kind::File, 1000, 1001, 0o644)
    );
    assert_eq!(
        notes.mtime,
        Time {
            secs: 981_173_106,
            nanos: 0
        }
    );
    let ssh = image.stat("/home/me/.ssh").unwrap();
    assert_eq!((ssh.kind, ssh.mode), (Kind::Dir, 0o700));
    let app = image.stat("/var/lib/app").unwrap();
    assert_eq!(app.mode, 0o750);
    assert_eq!(
        app.mtime,
        Time {
            secs: 1_262_304_000,
            nanos: 0
        }
    );
    assert_eq!(image.stat("/var/lib/app/ping").unwrap().mode, 0o4755);
    assert_eq!(read_all(&image, "/home/me/notes.txt", 0, 100), b"hello\n");
}

#[test]
fn fast_and_slow_symlinks_and_hard_links_are_told_apart() {
    let image = image("root.ext4");
    let fast = image.stat("/home/me/fast").unwrap();
    assert_eq!(
        (fast.kind, fast.target.as_deref()),
        (Kind::Symlink, Some(&b"notes.txt"[..]))
    );
    let slow = image.stat("/home/me/slow").unwrap();
    let mut long = b"long/".repeat(30);
    long.extend_from_slice(b"target");
    assert_eq!(slow.target, Some(long));
    let db = image.stat("/var/lib/app/db").unwrap();
    let link = image.stat("/var/lib/app/db.link").unwrap();
    assert_eq!((db.inode, db.links), (link.inode, 2));
}

#[test]
fn extended_attributes_are_read_from_the_inode_and_its_block() {
    let image = image("root.ext4");
    let ping = image.stat("/var/lib/app/ping").unwrap();
    let capability = ping
        .xattrs
        .iter()
        .find(|(name, _)| name == b"security.capability")
        .map(|(_, value)| value)
        .expect("the setcap'd binary keeps its capability");
    // VFS_CAP_REVISION_2 with the effective flag, then CAP_NET_RAW (13)
    // permitted.
    assert_eq!(
        u32::from_le_bytes(capability[..4].try_into().unwrap()),
        0x0200_0001
    );
    assert_eq!(
        u32::from_le_bytes(capability[4..8].try_into().unwrap()),
        1 << 13
    );
    let db = image.stat("/var/lib/app/db").unwrap();
    let value = |name: &[u8]| {
        db.xattrs
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(value(b"user.small"), Some(b"tiny".to_vec()));
    assert_eq!(value(b"user.big"), Some(b"x".repeat(2000)));
    let acl = value(b"system.posix_acl_access").expect("the ACL is carried");
    assert_eq!(&acl[..4], &2u32.to_le_bytes());
    assert_eq!((acl.len() - 4) % 8, 0);
}

#[test]
fn a_large_sparse_file_and_a_hashed_directory_are_read() {
    let image = image("root.ext4");
    let sparse = image.stat("/var/lib/big/sparse").unwrap();
    assert_eq!(sparse.size, (3 << 30) + 3);
    assert_eq!(read_all(&image, "/var/lib/big/sparse", 3 << 30, 10), b"end");
    assert_eq!(read_all(&image, "/var/lib/big/sparse", 1 << 30, 4), [0; 4]);
    let many = image.list("/var/lib/app/many").unwrap();
    assert_eq!(many.len(), 3000);
    assert!(many.iter().any(|entry| entry.name == b"file-2999"));
    assert_eq!(
        image.stat("/var/lib/app/many/file-1234").unwrap().kind,
        Kind::File
    );
}

/// The copy was taken with its last change committed to the journal and not
/// yet written in place; it reads as the guest would see it after replay,
/// its times to the nanosecond.
#[test]
fn a_journal_left_to_replay_is_replayed() {
    let image = image("dirty.ext4");
    assert_eq!(
        read_all(&image, "/home/me/late.txt", 0, 100),
        b"journaled\n"
    );
    let err = image.stat("/home/me/notes.txt").unwrap_err();
    assert!(err.contains("no such file"), "{err}");
}

#[test]
fn a_tree_streams_as_tar_with_its_metadata() {
    let image = image("root.ext4");
    let mut archive = Vec::new();
    let summary = image
        .tar("/var/lib/app", u64::MAX, u64::MAX, &mut archive)
        .unwrap();
    assert_eq!(summary.skipped, 2, "the device and the fifo are left out");
    assert_eq!(summary.entries, 3005);

    let mut seen = std::collections::HashMap::new();
    for entry in tar::Archive::new(&archive[..]).entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        let mut xattrs = Vec::new();
        let mut mtime = None;
        if let Some(extensions) = entry.pax_extensions().unwrap() {
            for extension in extensions {
                let extension = extension.unwrap();
                let key = extension.key().unwrap().to_string();
                if key == "mtime" {
                    mtime = Some(extension.value().unwrap().to_string());
                } else if let Some(name) = key.strip_prefix("SCHILY.xattr.") {
                    xattrs.push(name.to_string());
                }
            }
        }
        let header = entry.header().clone();
        let mut body = Vec::new();
        entry.read_to_end(&mut body).unwrap();
        seen.insert(name, (header, xattrs, mtime, body));
    }
    let (app, _, mtime, _) = &seen["app"];
    assert!(app.entry_type().is_dir());
    assert_eq!(app.mode().unwrap(), 0o750);
    assert_eq!(mtime.as_deref(), Some("1262304000.000000000"));
    let (db, db_xattrs, _, body) = &seen["app/db"];
    assert_eq!(body, b"data");
    assert!(db_xattrs.contains(&"user.big".to_string()));
    assert!(db_xattrs.contains(&"system.posix_acl_access".to_string()));
    assert_eq!(db.size().unwrap(), 4);
    let (link, _, _, _) = &seen["app/db.link"];
    assert!(link.entry_type().is_hard_link());
    assert_eq!(link.link_name().unwrap().unwrap().to_str(), Some("app/db"));
    let (ping, ping_xattrs, _, _) = &seen["app/ping"];
    assert_eq!(ping.mode().unwrap(), 0o4755);
    assert!(ping_xattrs.contains(&"security.capability".to_string()));
    assert!(!seen.contains_key("app/null") && !seen.contains_key("app/pipe"));

    let mut home = Vec::new();
    image
        .tar("/home/me", u64::MAX, u64::MAX, &mut home)
        .unwrap();
    let names: Vec<String> = tar::Archive::new(&home[..])
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(names.contains(&"me/.ssh/id".to_string()));
    let mut archive = tar::Archive::new(&home[..]);
    let symlink = archive
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.path().unwrap().ends_with("slow"))
        .unwrap();
    assert!(symlink.header().entry_type().is_symlink());
    assert_eq!(
        symlink
            .link_name()
            .unwrap()
            .unwrap()
            .to_string_lossy()
            .len(),
        156
    );
    assert_eq!(
        (
            symlink.header().uid().unwrap(),
            symlink.header().gid().unwrap()
        ),
        (0, 0)
    );
}

#[test]
fn a_tar_past_its_limits_is_refused() {
    let image = image("root.ext4");
    let err = image
        .tar("/var/lib/app", u64::MAX, 100, std::io::sink())
        .unwrap_err();
    assert!(err.contains("more than 100 files"), "{err}");
    let err = image
        .tar("/var/lib/big", 1 << 20, u64::MAX, std::io::sink())
        .unwrap_err();
    assert!(err.contains("more than 1048576 bytes"), "{err}");
    let err = image
        .tar("/", u64::MAX, u64::MAX, std::io::sink())
        .unwrap_err();
    assert!(err.contains("not a path below /"), "{err}");
    let err = image
        .tar("/nope", u64::MAX, u64::MAX, std::io::sink())
        .unwrap_err();
    assert!(err.contains("no such file"), "{err}");
}

#[test]
fn something_that_is_not_ext4_is_refused() {
    let path = std::env::temp_dir().join(format!("burrow-diskread-junk-{}", std::process::id()));
    std::fs::write(&path, vec![0x5a; 1 << 16]).unwrap();
    let err = Image::open(std::fs::File::open(&path).unwrap())
        .err()
        .unwrap();
    assert!(err.contains("not a readable ext4 filesystem"), "{err}");
    let _ = std::fs::remove_file(path);
}
