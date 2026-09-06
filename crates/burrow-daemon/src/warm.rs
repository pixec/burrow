//! Warm pools: creating a sandbox by restoring a pre-booted snapshot.
//!
//! A cold create pays for a kernel boot and an agent handshake every time.
//! Warming a template boots it once, snapshots the running VM, and lets every
//! later create resume from that image instead.
//!
//! Three things are baked into a snapshot that must not be shared between the
//! sandboxes restored from it:
//!
//! - **The tap device.** Firecracker records the host device and refuses to
//!   restore onto a different one, so each restore passes a `network_override`
//!   naming its own tap.
//! - **The guest's address.** It lives in guest memory, so every clone wakes
//!   holding the warm snapshot's address. The agent is told its real one on
//!   handshake and reapplies it.
//! - **The scratch disk.** The guest's in-memory filesystem state refers to
//!   the disk as it was at snapshot time, so each clone gets its *own copy* of
//!   the warm scratch. Sharing it would corrupt every clone at once.
//!
//! The kernel, rootfs, and memory file are shared by hard link: the first two
//! are read-only, and restoring has been verified not to modify the third.

use std::path::{Path, PathBuf};

use tonic::Status;

use burrow_vmm::{DriveSpec, MicroVm, MicroVmSpec, NetSpec};

/// Files that make up a template's warm snapshot.
const WARM_DIR: &str = "warm";
/// Where a rebuild is assembled before it is swapped in.
const WARM_STAGING_DIR: &str = "warm.tmp";
const WARM_TAP: &str = "btwarm";

/// Serialises warm builds across the whole node.
///
/// Every build drives the same fixed tap and the same throwaway lease, so two
/// running at once delete each other's interface mid-boot, leaving a snapshot
/// of a guest whose networking died under it.
static WARM_BUILD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Blocks warm builds for as long as the guard is held.
///
/// Deleting a template while a build of it is in flight would otherwise let
/// the build's final swap recreate the directory that was just removed, and a
/// snapshot of a template nobody can list is disk nothing will ever reclaim.
pub async fn hold_builds() -> tokio::sync::MutexGuard<'static, ()> {
    WARM_BUILD_LOCK.lock().await
}

/// A warm snapshot is only usable by a build of the agent that understands the
/// same handshake. Bumping this invalidates existing snapshots rather than
/// restoring a guest that will not accept its new address.
///
/// 2 added the node's inspection CA and the guest's note saying it installed
/// it. Older snapshots are still correct, but their guests install the
/// certificate on every create, so they are retired rather than kept.
const WARM_FORMAT: &str = "3";

/// Pages a restore of this snapshot touches first, recorded once when the
/// snapshot is built and replayed on every create from it.
pub const PREFETCH_PLAN: &str = "prefetch.bin";

/// The cpu and memory the snapshot was taken with.
///
/// Firecracker restores machine configuration *from the snapshot*, so a
/// restored guest has the memory the snapshot had, not the memory the caller
/// asked for. Without recording this, a sandbox created with `--mem-mib 2048`
/// from a 512 MiB snapshot silently gets 512 MiB and no error.
const SHAPE_FILE: &str = "shape";

/// The trust material a warm snapshot is built with already installed.
///
/// The node's inspection CA is the same for every sandbox here, so installing
/// it once at warm time takes the whole job off the create path: the guest
/// wakes with the certificate already in its trust stores and its own note
/// saying so, and the create's handshake finds nothing to do.
///
/// The cost is a piece of defence in depth. A guest restored from such a
/// snapshot trusts the CA whether or not its sandbox asked to be inspected, so
/// one wrongly routed through the inspecting proxy no longer fails loudly on an
/// unverifiable certificate. No confidentiality is lost: the key is the node's,
/// and the node already owns the guest's memory. Whether a session is
/// intercepted is still the proxy's decision from the sandbox's policy.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    pub ca: String,
    pub bundles: Vec<burrow_proto::agent::v1::TrustBundle>,
}

/// vcpus and memory a warm snapshot was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub vcpus: u32,
    pub mem_mib: u32,
}

impl Shape {
    /// What a sandbox asking for these resources needs.
    pub fn wanted(resources: &burrow_proto::common::v1::ResourcePolicy) -> Self {
        Self {
            vcpus: resources.vcpus.max(1),
            mem_mib: if resources.mem_mib == 0 {
                512
            } else {
                resources.mem_mib
            },
        }
    }

    fn parse(text: &str) -> Option<Self> {
        // Split on runs of whitespace rather than the first one, so padding
        // does not leave the second field unparseable.
        let mut fields = text.split_whitespace();
        let shape = Self {
            vcpus: fields.next()?.parse().ok()?,
            mem_mib: fields.next()?.parse().ok()?,
        };
        // A third field means a format this build does not understand; cold
        // booting is the safe answer.
        fields.next().is_none().then_some(shape)
    }
}

/// The shape a template's warm snapshot was taken with, if it has one.
pub async fn warm_shape(templates_dir: &Path, template: &str) -> Option<Shape> {
    let text = tokio::fs::read_to_string(warm_dir(templates_dir, template).join(SHAPE_FILE))
        .await
        .ok()?;
    Shape::parse(&text)
}

pub fn warm_dir(templates_dir: &Path, template: &str) -> PathBuf {
    templates_dir.join(template).join(WARM_DIR)
}

/// Where a new snapshot is assembled before it replaces the live one.
///
/// Building in place would pull the snapshot out from under creates that
/// already decided to restore from it and are about to link its files.
fn warm_staging_dir(templates_dir: &Path, template: &str) -> PathBuf {
    templates_dir.join(template).join(WARM_STAGING_DIR)
}

/// Whether `template` has a warm snapshot usable for `wanted`.
///
/// A snapshot of the wrong shape is *not* usable: restoring it would hand the
/// caller a guest with different cpu and memory than they asked for.
pub async fn is_warm_for(templates_dir: &Path, template: &str, wanted: Shape) -> bool {
    is_warm(templates_dir, template).await
        && warm_shape(templates_dir, template).await == Some(wanted)
}

/// Whether `template` has a usable warm snapshot at all, whatever its shape.
pub async fn is_warm(templates_dir: &Path, template: &str) -> bool {
    let dir = warm_dir(templates_dir, template);
    for file in [
        burrow_vmm::SNAPSHOT_FILE,
        burrow_vmm::SNAPSHOT_MEM_FILE,
        "scratch.ext4",
    ] {
        if !tokio::fs::try_exists(dir.join(file)).await.unwrap_or(false) {
            return false;
        }
    }
    // A snapshot from an older agent would resume into a guest that cannot be
    // re-addressed, which is worse than a cold boot.
    matches!(
        tokio::fs::read_to_string(dir.join("format")).await,
        Ok(version) if version.trim() == WARM_FORMAT
    )
}

/// Files a sandbox needs in its working directory to restore from warm.
///
/// The scratch disk is copied because the guest will write to it; everything
/// else is hard-linked because it is read-only or verified immutable.
pub async fn stage_from_warm(
    templates_dir: &Path,
    template: &str,
    workdir: &Path,
) -> std::io::Result<()> {
    let began = std::time::Instant::now();
    let warm = warm_dir(templates_dir, template);
    let template_dir = templates_dir.join(template);

    tokio::fs::create_dir_all(workdir).await?;
    for (source, name) in [
        (template_dir.join("vmlinux"), "vmlinux"),
        (template_dir.join("rootfs.ext4"), "rootfs.ext4"),
        (
            warm.join(burrow_vmm::SNAPSHOT_FILE),
            burrow_vmm::SNAPSHOT_FILE,
        ),
        (
            warm.join(burrow_vmm::SNAPSHOT_MEM_FILE),
            burrow_vmm::SNAPSHOT_MEM_FILE,
        ),
    ] {
        let dest = workdir.join(name);
        let _ = tokio::fs::remove_file(&dest).await;
        tokio::fs::hard_link(&source, &dest).await?;
    }

    let linked = std::time::Instant::now();

    // Optional: a snapshot built before profiling existed simply has none.
    let plan = warm.join(PREFETCH_PLAN);
    if tokio::fs::try_exists(&plan).await.unwrap_or(false) {
        let dest = workdir.join(PREFETCH_PLAN);
        let _ = tokio::fs::remove_file(&dest).await;
        let _ = tokio::fs::hard_link(&plan, &dest).await;
    }

    // The one file that must not be shared.
    let scratch = workdir.join("scratch.ext4");
    let _ = tokio::fs::remove_file(&scratch).await;
    let before_scratch = std::time::Instant::now();
    copy_sparse(&warm.join("scratch.ext4"), &scratch).await?;
    tracing::debug!(
        template,
        link_ms = (linked - began).as_millis() as u64,
        scratch_ms = before_scratch.elapsed().as_millis() as u64,
        "staged a warm snapshot"
    );
    Ok(())
}

/// Copies a disk image while preserving its holes.
///
/// A freshly formatted scratch disk is almost entirely holes: a 1 GiB image
/// occupies well under a megabyte. `fs::copy` expands those holes into real
/// zeroes, turning a create into a gigabyte of writes, which costs more than
/// the boot the warm pool exists to avoid. `cp --sparse=always` copies only the
/// data, and `--reflink=auto` makes it metadata-only on copy-on-write
/// filesystems.
pub async fn copy_sparse(source: &Path, dest: &Path) -> std::io::Result<()> {
    let output = tokio::process::Command::new("cp")
        .args(["--sparse=always", "--reflink=auto"])
        .arg(source)
        .arg(dest)
        .output()
        .await?;

    if output.status.success() {
        return Ok(());
    }
    // Fall back rather than fail: a slow create beats no create.
    tracing::warn!(
        stderr = %String::from_utf8_lossy(&output.stderr).trim(),
        "sparse copy failed; falling back to a full copy"
    );
    tokio::fs::copy(source, dest).await.map(|_| ())
}

/// Boots a template, waits for its agent, and snapshots the running VM.
///
/// The warm VM runs on a fixed tap of its own. It never carries a policy or
/// serves anyone: its only job is to reach the point where a sandbox would be
/// ready, and stop there.
#[allow(clippy::too_many_arguments)]
pub async fn build_warm_snapshot(
    templates_dir: &Path,
    template: &str,
    firecracker_bin: &Path,
    extra_boot_args: &str,
    agent_timeout: std::time::Duration,
    scratch_mib: u32,
    shape: Shape,
    trust: &Trust,
) -> Result<u64, Status> {
    // Defence in depth: the name becomes a directory under `templates_dir` and
    // this function removes and recreates it, so a caller that skipped
    // validation must not be able to point it at an arbitrary host path.
    crate::template::validate_name(template)?;

    // Held for the whole build, profiling included: both halves drive the same
    // fixed tap, so overlapping builds break each other's networking.
    let _serialised = WARM_BUILD_LOCK.lock().await;

    let template_dir = templates_dir.join(template);
    if !tokio::fs::try_exists(template_dir.join("rootfs.ext4"))
        .await
        .unwrap_or(false)
    {
        return Err(Status::not_found(format!("no template {template}")));
    }

    // Assembled beside the live snapshot and swapped in at the end. Rebuilding
    // in place would delete the files out from under a create that has already
    // decided to restore from them.
    let live = warm_dir(templates_dir, template);
    let dir = warm_staging_dir(templates_dir, template);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|err| Status::internal(format!("warm dir: {err}")))?;

    for name in ["vmlinux", "rootfs.ext4"] {
        tokio::fs::hard_link(template_dir.join(name), dir.join(name))
            .await
            .map_err(|err| Status::internal(format!("staging {name}: {err}")))?;
    }
    crate::sandbox::create_scratch(&dir.join("scratch.ext4"), scratch_mib)
        .await
        .map_err(|err| Status::internal(format!("warm scratch: {err}")))?;

    // A throwaway lease: the address only has to be valid enough for the guest
    // to finish booting, and every clone is re-addressed on resume anyway.
    let lease = burrow_net::ipam::warm_lease();
    burrow_net::tap::delete(WARM_TAP).await;
    let tap = burrow_net::tap::create_named(WARM_TAP, &lease)
        .await
        .map_err(|err| Status::internal(format!("warm tap: {err}")))?;

    let mut spec = MicroVmSpec::new(format!("warm-{template}"), &dir);
    // Taken under the transport it will be restored under: a snapshot does not
    // cross between PCI and MMIO.
    spec.enable_pci = true;
    spec.firecracker_bin = firecracker_bin.to_path_buf();
    spec.kernel = "vmlinux".into();
    // Baked into the snapshot: a restore takes its machine configuration from
    // here, not from what a later caller asks for.
    spec.vcpus = shape.vcpus;
    spec.mem_mib = shape.mem_mib;
    spec.drives = vec![
        DriveSpec::root_ro("rootfs.ext4"),
        DriveSpec::scratch_rw("scratch.ext4"),
    ];
    spec.vsock = true;
    spec.net = Some(NetSpec {
        tap: tap.clone(),
        guest_mac: Some(lease.guest_mac()),
    });
    spec.boot_args = format!(
        "{} root=/dev/vda ro init=/usr/bin/burrow-agent {} {}",
        burrow_vmm::DEFAULT_BOOT_ARGS,
        lease.kernel_ip_arg(),
        extra_boot_args
    );
    // The warm VM is transient and shares the node with real sandboxes only
    // briefly, so it takes no cgroup of its own.
    spec.cgroup_root = None;

    let outcome = snapshot_when_ready(spec, agent_timeout, &lease, trust).await;
    burrow_net::tap::delete(WARM_TAP).await;

    match outcome {
        Ok(()) => {
            // Restore the snapshot once, purely to learn which pages a guest
            // reaches for. Doing it here costs one boot at warm time and saves
            // thousands of faults on every create afterwards.
            if let Err(err) =
                profile_restore(&dir, firecracker_bin, agent_timeout, shape, trust).await
            {
                tracing::warn!(template, %err, "could not record a prefetch plan");
            }
            // Shape first, format last: `format` is the commit marker that
            // makes a snapshot warm, and one that is warm without a shape can
            // never be matched to a request, so the node keeps winning
            // placement and every create cold-boots.
            tokio::fs::write(
                dir.join(SHAPE_FILE),
                format!("{} {}", shape.vcpus, shape.mem_mib),
            )
            .await
            .map_err(|err| Status::internal(format!("recording warm shape: {err}")))?;
            tokio::fs::write(dir.join("format"), WARM_FORMAT)
                .await
                .map_err(|err| Status::internal(format!("marking warm snapshot: {err}")))?;
            let size = tokio::fs::metadata(dir.join(burrow_vmm::SNAPSHOT_MEM_FILE))
                .await
                .map(|m| m.len())
                .unwrap_or(0);

            // The swap. Creates staging from the old snapshot hold open file
            // handles or link its inodes; the window where neither directory
            // is in place is a rename apart, rather than a whole build long.
            let _ = tokio::fs::remove_dir_all(&live).await;
            tokio::fs::rename(&dir, &live)
                .await
                .map_err(|err| Status::internal(format!("publishing the warm snapshot: {err}")))?;

            tracing::info!(template, size, "warm snapshot ready");
            Ok(size)
        }
        Err(err) => {
            // A partial warm snapshot would be picked up by the next create.
            // The live one is left alone: it is still usable.
            let _ = tokio::fs::remove_dir_all(&dir).await;
            Err(err)
        }
    }
}

/// Drives the agent through the paths a clone will take on create.
///
/// The handshake is the expensive one, reaching the netlink code, the entropy
/// ioctl and the clock syscall; the health call afterwards settles the gRPC
/// server's own machinery.
async fn exercise_agent(
    vm: &MicroVm,
    lease: &burrow_net::ipam::Lease,
    trust: &Trust,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut agent = crate::agentconn::connect(vm.vsock_uds_path()).await?;
    agent
        .handshake(crate::agentconn::handshake_full(
            true,
            Some(burrow_proto::agent::v1::NetworkConfig {
                // Its own address: re-applying it changes nothing, and the
                // point is to touch the code rather than the configuration.
                ip: lease.guest_ip.to_string(),
                prefix_len: lease.prefix_len as u32,
                gateway: lease.host_ip.to_string(),
                dns: lease.host_ip.to_string(),
            }),
            trust.ca.clone(),
            trust.bundles.clone(),
            // A warm snapshot is shared by every sandbox restored from it, so
            // it must not carry any one sandbox's volumes.
            Vec::new(),
        ))
        .await?;
    agent
        .health(burrow_proto::agent::v1::AgentHealthRequest {})
        .await?;
    Ok(())
}

/// Restores the freshly built snapshot with fault recording on, so later
/// creates have a plan to replay.
///
/// The recording VM is otherwise identical to a real create, same tap and same
/// handshake, because a plan gathered from a different code path would prefetch
/// the wrong pages.
async fn profile_restore(
    dir: &Path,
    firecracker_bin: &Path,
    agent_timeout: std::time::Duration,
    shape: Shape,
    trust: &Trust,
) -> Result<(), Status> {
    let lease = burrow_net::ipam::warm_lease();
    burrow_net::tap::delete(WARM_TAP).await;
    let tap = burrow_net::tap::create_named(WARM_TAP, &lease)
        .await
        .map_err(|err| Status::internal(format!("profiling tap: {err}")))?;

    let mut spec = MicroVmSpec::new("warm-profile", dir);
    spec.enable_pci = true;
    spec.firecracker_bin = firecracker_bin.to_path_buf();
    spec.kernel = "vmlinux".into();
    spec.drives = vec![
        DriveSpec::root_ro("rootfs.ext4"),
        DriveSpec::scratch_rw("scratch.ext4"),
    ];
    spec.vsock = true;
    spec.net = Some(NetSpec {
        tap: tap.clone(),
        guest_mac: Some(lease.guest_mac()),
    });
    spec.cgroup_root = None;
    spec.vcpus = shape.vcpus;
    spec.mem_mib = shape.mem_mib;
    spec.record_prefetch = Some(PREFETCH_PLAN.to_string());

    // The profiling guest writes to the scratch disk *after* the snapshot was
    // taken, so a clone restoring that snapshot would find a disk that had
    // moved under its in-memory filesystem state. Put back exactly as the
    // snapshot expects it.
    let scratch = dir.join("scratch.ext4");
    let pristine = dir.join("scratch.ext4.pristine");
    let _ = tokio::fs::remove_file(&pristine).await;
    copy_sparse(&scratch, &pristine)
        .await
        .map_err(|err| Status::internal(format!("preserving the warm scratch: {err}")))?;

    let outcome = async {
        let vm = MicroVm::restore(spec, true)
            .await
            .map_err(|err| Status::internal(format!("profiling restore: {err}")))?;
        // Faults taken while reaching a usable agent are exactly the ones a
        // real create pays for.
        let ready = vm
            .wait_for_vsock(crate::agentconn::AGENT_PORT, agent_timeout)
            .await;
        if ready.is_ok() {
            let _ = exercise_agent(&vm, &lease, trust).await;
        }
        vm.kill()
            .await
            .map_err(|err| Status::internal(format!("stopping the profiling vm: {err}")))
    }
    .await;

    burrow_net::tap::delete(WARM_TAP).await;

    let _ = tokio::fs::remove_file(&scratch).await;
    if let Err(err) = tokio::fs::rename(&pristine, &scratch).await {
        // Without the original disk the snapshot is not safely restorable, so
        // this is fatal rather than a lost optimisation.
        return Err(Status::internal(format!(
            "could not restore the warm scratch disk: {err}"
        )));
    }
    outcome
}

async fn snapshot_when_ready(
    spec: MicroVmSpec,
    agent_timeout: std::time::Duration,
    lease: &burrow_net::ipam::Lease,
    trust: &Trust,
) -> Result<(), Status> {
    let vm = MicroVm::boot(spec)
        .await
        .map_err(|err| Status::internal(format!("warm boot: {err}")))?;

    if let Err(err) = vm
        .wait_for_vsock(crate::agentconn::AGENT_PORT, agent_timeout)
        .await
    {
        let console = vm.console_tail(30).await;
        let _ = vm.kill().await;
        return Err(Status::internal(format!(
            "warm guest never became ready: {err}\nconsole:\n{console}"
        )));
    }

    // A full handshake before snapshotting, result thrown away. Not needed for
    // correctness, since every clone handshakes again on create, but it bakes
    // the warmed guest-side state into the snapshot. Measured: the first
    // handshake after a restore cost ~180ms against ~9ms for a second on a
    // fresh channel, so the cost is guest coldness rather than transport.
    if let Err(err) = exercise_agent(&vm, lease, trust).await {
        // Not fatal: a snapshot without the warm-up is slower, not wrong.
        tracing::warn!(%err, "could not pre-warm the guest before snapshotting");
    }

    // Snapshot a quiesced guest: anything mid-flight at this moment is frozen
    // into every sandbox that later restores from it.
    if let Err(err) = vm.pause().await {
        let _ = vm.kill().await;
        return Err(Status::internal(format!("pausing warm vm: {err}")));
    }
    if let Err(err) = vm.snapshot(burrow_vmm::SnapshotType::Full).await {
        let _ = vm.kill().await;
        return Err(Status::internal(format!("snapshotting warm vm: {err}")));
    }
    vm.kill()
        .await
        .map_err(|err| Status::internal(format!("stopping warm vm: {err}")))
}

#[cfg(test)]
mod shape_tests {
    use super::*;
    use burrow_proto::common::v1 as common;

    #[test]
    fn defaults_fill_in_for_an_unset_policy() {
        let wanted = Shape::wanted(&common::ResourcePolicy::default());
        assert_eq!(
            wanted,
            Shape {
                vcpus: 1,
                mem_mib: 512
            }
        );
    }

    #[test]
    fn an_explicit_policy_is_taken_as_given() {
        let wanted = Shape::wanted(&common::ResourcePolicy {
            vcpus: 4,
            mem_mib: 2048,
            ..Default::default()
        });
        assert_eq!(
            wanted,
            Shape {
                vcpus: 4,
                mem_mib: 2048
            }
        );
    }

    #[test]
    fn a_shape_round_trips_through_its_file() {
        let shape = Shape {
            vcpus: 2,
            mem_mib: 1024,
        };
        let text = format!("{} {}", shape.vcpus, shape.mem_mib);
        assert_eq!(Shape::parse(&text), Some(shape));
        assert_eq!(Shape::parse("  2   1024  \n"), Some(shape));
    }

    #[test]
    fn a_malformed_shape_file_reads_as_absent() {
        // Absent is the safe answer: it means "cold boot", which is slower and
        // correct, rather than restoring a snapshot of unknown size.
        for bad in ["", "2", "two 1024", "2 lots", "\n"] {
            assert_eq!(Shape::parse(bad), None, "{bad:?} should not parse");
        }
    }

    /// The bug this exists to prevent: a caller asking for more memory than
    /// the snapshot holds must not be quietly given the snapshot's.
    #[test]
    fn a_differently_shaped_request_does_not_match() {
        let snapshot = Shape {
            vcpus: 1,
            mem_mib: 512,
        };
        let asked = Shape::wanted(&common::ResourcePolicy {
            mem_mib: 2048,
            ..Default::default()
        });
        assert_ne!(snapshot, asked);
    }
}
