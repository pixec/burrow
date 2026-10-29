//! What a Windows file's attributes say in POSIX terms.
//!
//! Windows has no mode bits. These follow what libuv reports for Node on
//! Windows, so SDK code written against Node's `fs.Stats` reads the same
//! values here: a directory is 0777, a file is 0666 or 0444 when it is
//! read-only, plus 0111 when its extension makes it runnable, and a symlink
//! or a junction is a link.

pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

const RUNNABLE: &[&str] = &["exe", "com", "bat", "cmd"];

/// Whether the reparse point is one POSIX would call a symlink. Other tags
/// (deduplication, cloud files, app execution aliases) are files that
/// happen to be stored differently, and are reported as what they hold.
pub fn is_link(attributes: u32, reparse_tag: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && matches!(
            reparse_tag,
            IO_REPARSE_TAG_SYMLINK | IO_REPARSE_TAG_MOUNT_POINT
        )
}

/// `st_mode` for an object with these attributes and this name.
pub fn mode(attributes: u32, reparse_tag: u32, name: &str) -> u32 {
    if is_link(attributes, reparse_tag) {
        return S_IFLNK | 0o777;
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return S_IFDIR | 0o777;
    }
    let mut mode = if attributes & FILE_ATTRIBUTE_READONLY != 0 {
        0o444
    } else {
        0o666
    };
    let runnable = std::path::Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| RUNNABLE.iter().any(|r| r.eq_ignore_ascii_case(ext)));
    if runnable {
        mode |= 0o111;
    }
    S_IFREG | mode
}

/// The `d_type` name a directory entry is listed with.
pub fn entry_type(attributes: u32, reparse_tag: u32) -> &'static str {
    if is_link(attributes, reparse_tag) {
        "symlink"
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        "dir"
    } else {
        "file"
    }
}

/// The attributes a chmod leaves: Windows has one permission bit, and it is
/// the owner's write bit, as Node maps it.
pub fn attributes_for_chmod(attributes: u32, mode: u32) -> u32 {
    if mode & 0o200 == 0 {
        attributes | FILE_ATTRIBUTE_READONLY
    } else {
        attributes & !FILE_ATTRIBUTE_READONLY
    }
}

/// 100ns ticks since 1601, a FILETIME, as Unix nanoseconds.
pub fn filetime_to_unix_ns(ticks: i64) -> i64 {
    const EPOCH_DIFF_TICKS: i64 = 116_444_736_000_000_000;
    if ticks == 0 {
        return 0;
    }
    (ticks - EPOCH_DIFF_TICKS).saturating_mul(100)
}

/// The inverse, for setting times.
pub fn unix_ns_to_filetime(ns: i64) -> i64 {
    const EPOCH_DIFF_TICKS: i64 = 116_444_736_000_000_000;
    ns.div_euclid(100) + EPOCH_DIFF_TICKS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_read_as_node_reports_them() {
        assert_eq!(mode(0x20, 0, "a.txt"), S_IFREG | 0o666);
        assert_eq!(mode(0x21, 0, "a.txt"), S_IFREG | 0o444);
        assert_eq!(mode(0x20, 0, "tool.EXE"), S_IFREG | 0o777);
        assert_eq!(mode(0x21, 0, "run.cmd"), S_IFREG | 0o555);
        assert_eq!(mode(FILE_ATTRIBUTE_DIRECTORY, 0, "d"), S_IFDIR | 0o777);
    }

    #[test]
    fn symlinks_and_junctions_are_links_and_other_reparse_points_are_not() {
        let link = FILE_ATTRIBUTE_REPARSE_POINT;
        assert_eq!(mode(link, IO_REPARSE_TAG_SYMLINK, "l"), S_IFLNK | 0o777);
        let junction = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY;
        assert_eq!(entry_type(junction, IO_REPARSE_TAG_MOUNT_POINT), "symlink");
        // A deduplicated file is still a file.
        assert_eq!(entry_type(link, 0x8000_0013), "file");
        assert_eq!(entry_type(FILE_ATTRIBUTE_DIRECTORY, 0), "dir");
    }

    #[test]
    fn chmod_moves_only_the_read_only_bit() {
        assert_eq!(attributes_for_chmod(0x20, 0o444), 0x21);
        assert_eq!(attributes_for_chmod(0x21, 0o644), 0x20);
        assert_eq!(attributes_for_chmod(0x20, 0o600), 0x20);
    }

    #[test]
    fn filetimes_convert_both_ways() {
        // 2001-09-09T01:46:40Z.
        let ns = 1_000_000_000_000_000_000;
        assert_eq!(filetime_to_unix_ns(unix_ns_to_filetime(ns)), ns);
        assert_eq!(unix_ns_to_filetime(0), 116_444_736_000_000_000);
        assert_eq!(filetime_to_unix_ns(0), 0);
    }
}
