pub mod common {
    pub mod v1 {
        tonic::include_proto!("burrow.common.v1");
    }
}

pub mod api {
    pub mod v1 {
        tonic::include_proto!("burrow.api.v1");
    }
}

pub mod node {
    pub mod v1 {
        tonic::include_proto!("burrow.node.v1");
    }
}

pub mod guest {
    pub mod v1 {
        tonic::include_proto!("burrow.guest.v1");
    }
}

/// The most file data one Fs read or write carries, and the most the node puts
/// in one upload chunk to a guest.
pub const MAX_FILE_CHUNK: usize = 4 << 20;

/// The gRPC message limit, sent and received, on every hop that carries file
/// data: a full [`MAX_FILE_CHUNK`] and the fields and framing around it, with
/// room to spare. gRPC's own default is 4 MiB, which a full chunk overruns.
pub const MAX_MESSAGE_BYTES: usize = 8 << 20;

impl common::v1::EventKind {
    /// The name the event log and the CLI show.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "",
            Self::Created => "created",
            Self::Started => "started",
            Self::AgentReady => "agent_ready",
            Self::Stopped => "stopped",
            Self::Destroyed => "destroyed",
            Self::SnapshotCreated => "snapshot_created",
            Self::Recovered => "recovered",
            Self::IpAttached => "ip_attached",
            Self::IpDetached => "ip_detached",
        }
    }
}

impl common::v1::SessionStart {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "",
            Self::Boot => "boot",
            Self::Restore => "restore",
            Self::Resume => "resume",
        }
    }
}

impl common::v1::SessionEnd {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Stopped => "stopped",
            Self::GuestExited => "guest_exited",
            Self::Crashed => "crashed",
        }
    }
}

impl api::v1::UsageState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Stopped => "stopped",
        }
    }
}

impl api::v1::CommandState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unknown",
            Self::Running => "running",
            Self::Exited => "exited",
        }
    }
}

impl guest::v1::fs_request::Op {
    /// The syscall an error names, and the paths it reports, as Node's do.
    pub fn describe(&self) -> (&'static str, &str, &str) {
        fn one<'a>(syscall: &'static str, path: &'a str) -> (&'static str, &'a str, &'a str) {
            (syscall, path, "")
        }
        fn two<'a>(
            syscall: &'static str,
            path: &'a str,
            dest: &'a str,
        ) -> (&'static str, &'a str, &'a str) {
            (syscall, path, dest)
        }
        use guest::v1::fs_request::Op;
        match self {
            Op::Stat(stat) if stat.is_nofollow => one("lstat", &stat.path),
            Op::Stat(stat) => one("stat", &stat.path),
            Op::ReadDir(dir) => one("scandir", &dir.path),
            Op::Mkdir(mkdir) => one("mkdir", &mkdir.path),
            Op::Remove(rm) if rm.is_recursive => one("rm", &rm.path),
            Op::Remove(rm) if rm.is_dir_only => one("rmdir", &rm.path),
            Op::Remove(rm) => one("unlink", &rm.path),
            Op::Rename(rename) => two("rename", &rename.src, &rename.dst),
            Op::Copy(copy) if copy.is_recursive => two("cp", &copy.src, &copy.dst),
            Op::Copy(copy) => two("copyfile", &copy.src, &copy.dst),
            Op::Chmod(chmod) => one("chmod", &chmod.path),
            Op::Chown(chown) if chown.is_nofollow => one("lchown", &chown.path),
            Op::Chown(chown) => one("chown", &chown.path),
            Op::Utimes(utimes) if utimes.is_nofollow => one("lutime", &utimes.path),
            Op::Utimes(utimes) => one("utime", &utimes.path),
            Op::Truncate(truncate) => one("truncate", &truncate.path),
            Op::Symlink(symlink) => two("symlink", &symlink.target, &symlink.path),
            Op::Link(link) => two("link", &link.existing, &link.path),
            Op::Readlink(readlink) => one("readlink", &readlink.path),
            Op::Realpath(realpath) => one("realpath", &realpath.path),
            Op::Access(access) => one("access", &access.path),
            Op::Mkdtemp(mkdtemp) => one("mkdtemp", &mkdtemp.prefix),
            Op::Open(open) => one("open", &open.path),
            Op::Read(_) => one("read", ""),
            Op::Write(_) => one("write", ""),
            Op::Fstat(_) => one("fstat", ""),
            Op::Ftruncate(_) => one("ftruncate", ""),
            Op::Fsync(fsync) if fsync.is_data_only => one("fdatasync", ""),
            Op::Fsync(_) => one("fsync", ""),
            Op::Close(_) => one("close", ""),
        }
    }
}

/// The `.proto` files the TypeScript SDK ships.
///
/// They have to be *copies*: the SDK is published as an npm package and loads
/// them at runtime, so it cannot reach into this crate's directory. Copies
/// drift, though. These did, silently, for several fields, and a contract
/// that has quietly diverged is worse than one that never existed, because
/// both sides believe they agree.
///
/// So the copies are checked rather than trusted. `scripts/sync-protos.sh` writes
/// them; this test fails if anyone changes a proto without running it.
#[cfg(test)]
mod sdk_protos {
    use std::path::PathBuf;

    /// The protos the SDKs load. `node` and `guest` are internal to the
    /// fleet and are not shipped in the published packages.
    const SHIPPED: [&str; 2] = ["common", "api"];

    const SDK_DIRS: [&str; 2] = [
        "../../sdk/typescript/proto",
        "../../sdk/python/src/burrow/proto",
    ];

    fn source_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto")
    }

    #[test]
    fn the_sdk_copies_match_the_source() {
        let mut stale = Vec::new();
        for dir in SDK_DIRS {
            for name in SHIPPED {
                let file = format!("{name}.proto");
                let source = std::fs::read_to_string(source_dir().join(&file))
                    .unwrap_or_else(|err| panic!("reading {file}: {err}"));
                let sdk = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir);
                let shipped = match std::fs::read_to_string(sdk.join(&file)) {
                    Ok(text) => text,
                    Err(_) => {
                        stale.push(format!("{dir}/{file} (missing from the SDK)"));
                        continue;
                    }
                };
                if source != shipped {
                    stale.push(format!("{dir}/{file}"));
                }
            }
        }

        assert!(
            stale.is_empty(),
            "the SDK's proto copies have drifted from this crate's: {}.\n\
             Run scripts/sync-protos.sh to update them.",
            stale.join(", ")
        );
    }
}
