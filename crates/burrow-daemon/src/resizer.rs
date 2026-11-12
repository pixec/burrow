//! Shrinking a root disk, offline.
//!
//! ext4 shrinks only unmounted, and the host never reads a guest's filesystem,
//! so a stopped sandbox's disk is shrunk by a short helper VM: the sandbox's
//! own kernel, booted read-only from a small image this node builds out of its
//! own agent and e2fsprogs, with the disk as a second drive. The agent runs as
//! init with `burrow.mode=resize-disk`, checks and shrinks the filesystem when
//! asked, and says how big it now is. The host cuts the file only to a length
//! the guest has said the filesystem fits in.

use std::path::{Path, PathBuf};
use std::time::Duration;

use burrow_proto::guest::v1 as guestpb;
use burrow_vmm::{DriveSpec, Vm, VmSpec};
use tonic::Status;

/// The helper's root, in the node's data directory and, while it runs, in the
/// sandbox's.
pub const HELPER_IMAGE: &str = "resize.ext4";
/// The tools the agent runs, at the path it runs them from.
const TOOLS: &[&str] = &["e2fsck", "resize2fs"];
const TOOL_DIR: &str = "usr/sbin";
const HELPER_MEM_MIB: u32 = 512;
/// A check and a shrink of a large, full filesystem take minutes.
const SHRINK_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The helper image, built on first use by this process from the binaries it
/// runs with, so a node upgrade rebuilds it.
#[derive(Default)]
pub struct Resizer {
    built: tokio::sync::Mutex<Option<PathBuf>>,
}

impl Resizer {
    async fn image(&self, data_dir: &Path, guest_binary: &Path) -> Result<PathBuf, Status> {
        let mut built = self.built.lock().await;
        if let Some(path) = built.as_ref()
            && tokio::fs::try_exists(path).await.unwrap_or(false)
        {
            return Ok(path.clone());
        }
        let path = build(data_dir, guest_binary).await?;
        *built = Some(path.clone());
        Ok(path)
    }

    /// Boots a helper on the stopped VM `spec` describes, with its drive
    /// `disk` attached, and has it shrink the filesystem there to
    /// `target_bytes`. The guest's answer is returned as it gave it: a size
    /// above the target means the target was below its minimum and nothing
    /// changed.
    #[allow(clippy::too_many_arguments)]
    pub async fn shrink(
        &self,
        data_dir: &Path,
        guest_binary: &Path,
        mut spec: VmSpec,
        disk: &str,
        target_bytes: u64,
        vmm_overhead_mib: u32,
        agent_timeout: Duration,
    ) -> Result<guestpb::RootDiskResponse, Status> {
        let image = self.image(data_dir, guest_binary).await?;
        let linked = spec.workdir.join(HELPER_IMAGE);
        let _ = tokio::fs::remove_file(&linked).await;
        if tokio::fs::hard_link(&image, &linked).await.is_err() {
            tokio::fs::copy(&image, &linked)
                .await
                .map_err(|err| Status::internal(format!("staging the resize helper: {err}")))?;
        }
        let burrow_vmm::Boot::Kernel { kernel, .. } = spec.boot.clone() else {
            return Err(Status::failed_precondition(
                "only a guest booted from its own kernel can be resized offline",
            ));
        };
        spec.boot = burrow_vmm::Boot::Kernel {
            kernel,
            cmdline: format!(
                "{} root=/dev/vda ro init=/usr/bin/burrow-guest burrow.mode=resize-disk",
                burrow_vmm::DEFAULT_BOOT_ARGS
            ),
        };
        spec.drives = vec![
            DriveSpec::root_ro(HELPER_IMAGE),
            DriveSpec {
                id: "disk".into(),
                path: disk.into(),
                is_root: false,
                is_read_only: false,
            },
        ];
        spec.net = None;
        spec.vcpus = 1;
        spec.mem_mib = HELPER_MEM_MIB;
        spec.limits = crate::sandbox::cgroup_limits(
            &burrow_proto::common::v1::ResourcePolicy {
                vcpus: 1,
                ..Default::default()
            },
            spec.hypervisor()
                .memory_ceiling_mib(HELPER_MEM_MIB, vmm_overhead_mib),
        );
        spec.is_vsock_enabled = true;
        spec.is_dirty_pages_tracked = false;
        spec.is_memory_lazy = false;
        spec.memory_chain.clear();
        spec.prefetch = None;
        spec.record_prefetch = None;
        spec.memory_source = None;
        let result = run(spec, target_bytes, agent_timeout).await;
        let _ = tokio::fs::remove_file(&linked).await;
        result
    }
}

async fn run(
    spec: VmSpec,
    target_bytes: u64,
    agent_timeout: Duration,
) -> Result<guestpb::RootDiskResponse, Status> {
    let vm = Vm::boot(spec)
        .await
        .map_err(|err| Status::internal(format!("booting the resize helper: {err}")))?;
    let asked = async {
        vm.wait_for_vsock(crate::guestconn::AGENT_PORT, agent_timeout)
            .await
            .map_err(|err| Status::internal(format!("the resize helper never came up: {err}")))?;
        let mut agent = crate::guestconn::connect(vm.guest(), SHRINK_TIMEOUT)
            .await
            .map_err(|err| Status::internal(format!("reaching the resize helper: {err}")))?;
        let shrunk = agent
            .root_disk(guestpb::RootDiskRequest {
                op: guestpb::root_disk_request::Op::Shrink as i32,
                size_bytes: target_bytes,
                ..Default::default()
            })
            .await?
            .into_inner();
        Ok::<_, Status>(shrunk)
    }
    .await;
    let asked = match asked {
        Err(err) if err.code() == tonic::Code::Internal => {
            let console = vm.console_tail(30).await;
            Err(Status::internal(format!(
                "{}\nconsole:\n{console}",
                err.message()
            )))
        }
        other => other,
    };
    if let Err(err) = vm.kill().await {
        tracing::warn!(%err, "the resize helper's vmm did not stop");
    }
    asked
}

/// Writes the helper image: the agent, the tools and the libraries they load,
/// as `mkfs.ext4 -d` lays a directory out, so nothing is mounted.
async fn build(data_dir: &Path, guest_binary: &Path) -> Result<PathBuf, Status> {
    let staging = data_dir.join("resize-helper");
    let _ = tokio::fs::remove_dir_all(&staging).await;
    let internal = |what: &str, err: std::io::Error| {
        Status::internal(format!("building the resize helper: {what}: {err}"))
    };
    for dir in [
        "proc", "sys", "dev", "tmp", "run", "etc", "usr/bin", TOOL_DIR,
    ] {
        tokio::fs::create_dir_all(staging.join(dir))
            .await
            .map_err(|err| internal(dir, err))?;
    }
    tokio::fs::symlink("/proc/self/mounts", staging.join("etc/mtab"))
        .await
        .map_err(|err| internal("etc/mtab", err))?;
    let mut files = vec![(
        guest_binary.to_path_buf(),
        staging.join("usr/bin/burrow-guest"),
    )];
    for tool in TOOLS {
        let found = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            .iter()
            .map(|dir| Path::new(dir).join(tool))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                Status::failed_precondition(format!(
                    "this node has no {tool}; install e2fsprogs to shrink disks"
                ))
            })?;
        for library in libraries(&found).await? {
            let dest = staging.join(library.strip_prefix("/").unwrap_or(&library));
            files.push((library, dest));
        }
        files.push((found, staging.join(TOOL_DIR).join(tool)));
    }
    let mut bytes = 0;
    for (from, to) in &files {
        if let Some(parent) = to.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| internal(&parent.display().to_string(), err))?;
        }
        bytes += tokio::fs::copy(from, to)
            .await
            .map_err(|err| internal(&from.display().to_string(), err))?;
    }
    let pending = data_dir.join(format!("{HELPER_IMAGE}.building"));
    let size_mib = bytes.div_ceil(burrow_common::disk::MIB) + 16;
    crate::template::run(
        "mkfs.ext4",
        &[
            "-q",
            "-F",
            "-L",
            "burrow-resize",
            "-b",
            "4096",
            "-d",
            &staging.to_string_lossy(),
            &pending.to_string_lossy(),
            &format!("{size_mib}M"),
        ],
    )
    .await?;
    let _ = tokio::fs::remove_dir_all(&staging).await;
    let image = data_dir.join(HELPER_IMAGE);
    tokio::fs::rename(&pending, &image)
        .await
        .map_err(|err| internal("publishing", err))?;
    tracing::info!(image = %image.display(), size_mib, "built the resize helper");
    Ok(image)
}

/// The shared libraries `binary` loads, its interpreter among them, as `ldd`
/// resolves them on this host.
async fn libraries(binary: &Path) -> Result<Vec<PathBuf>, Status> {
    let output = tokio::process::Command::new("ldd")
        .arg(binary)
        .output()
        .await
        .map_err(|err| Status::internal(format!("ldd {}: {err}", binary.display())))?;
    Ok(parse_ldd(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_ldd(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            let path = match line.split_once("=>") {
                Some((_, resolved)) => resolved.split_whitespace().next()?,
                None => line.split_whitespace().next()?,
            };
            path.starts_with('/').then(|| PathBuf::from(path))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldd_output_names_every_library_and_the_interpreter() {
        let output = "\tlinux-vdso.so.1 (0x0000ffff9c5e1000)
\tlibext2fs.so.2 => /lib/aarch64-linux-gnu/libext2fs.so.2 (0x0000ffff9c4f0000)
\tlibc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0000ffff9c330000)
\t/lib/ld-linux-aarch64.so.1 (0x0000ffff9c5a4000)
\tlibmissing.so.1 => not found
";
        assert_eq!(
            parse_ldd(output),
            [
                "/lib/aarch64-linux-gnu/libext2fs.so.2",
                "/lib/aarch64-linux-gnu/libc.so.6",
                "/lib/ld-linux-aarch64.so.1",
            ]
            .map(PathBuf::from)
        );
    }
}
