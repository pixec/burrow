//! Warm pools: creating a sandbox by restoring a pre-booted snapshot.
//!
//! A cold create pays for a kernel boot and an agent handshake every time.
//! Warming a template boots it once, snapshots the running VM, and lets every
//! later create resume from that image instead.
//!
//! Three things are baked into a snapshot that must not be shared between the
//! sandboxes restored from it:
//!
//! - **The tap device.** A snapshot records the host device it was taken
//!   with, so each restore names its own tap: Firecracker through a
//!   `network_override`, Cloud Hypervisor in the config it is restored from.
//! - **The guest's address.** It lives in guest memory, so every clone wakes
//!   holding the warm snapshot's address. The agent is told its real one on
//!   handshake and reapplies it.
//! - **The root disk.** The guest's in-memory filesystem state refers to the
//!   disk as it was at snapshot time, so each clone gets its *own clone* of
//!   the warm disk. Sharing it would corrupt every clone at once.
//!
//! The kernel, the image and the memory file are shared by hard link: the
//! guest never sees the image, the kernel is read-only, and restoring has been
//! verified not to modify the memory file.
//!
//! A restore cannot change a guest's vCPUs or memory, so a template keeps one
//! snapshot per machine shape, each in a directory of its own named by the
//! hypervisor it was taken under and its vCPUs and memory. A create restores
//! the one matching what it asked for, and a shape with none boots cold and
//! has one built behind it. The node bounds how many it keeps and evicts the
//! least recently restored past that; see [`WarmPolicy`].

use std::path::{Path, PathBuf};

use tonic::Status;

use burrow_proto::common::v1 as common;
use burrow_vmm::{Hypervisor, HypervisorExt, NetSpec, Vm, VmSpec};

use crate::rootdisk::{DiskLayout, IMAGE, ROOT_DISK};
use crate::sandbox::NodeConfig;

/// A template's warm snapshots, one directory per shape.
const WARM_DIR: &str = "warm";
/// Where a build is assembled before it is swapped in. One at a time on the
/// whole node, under [`WARM_BUILD_LOCK`].
const WARM_STAGING_DIR: &str = "warm.tmp";
/// Unix seconds of the last restore from a snapshot, which eviction orders by.
const USED_FILE: &str = "used";
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
///
/// 4 is the first with drives that flush: Firecracker restores a drive's
/// cache mode from the snapshot's device state, so a guest restored from a
/// snapshot taken before drives were `Writeback` would go on dropping its
/// flushes in the host page cache.
///
/// 5 boots on a root disk, without the overlay: an older snapshot's guest has
/// the overlay mounted in its memory and a scratch drive in its device state.
///
/// 6 keeps a snapshot per shape in a directory of its own. A 5 is the one
/// snapshot directly under `warm/`, and is rebuilt at its shape in the new
/// layout.
///
/// 7 boots with a virtio-mem region to grow into, sized by the shape's
/// growth limit, and with the kernel told to online what is plugged.
const WARM_FORMAT: &str = "7";

/// Whether a warm snapshot's `format` file names the format this build writes.
fn is_current_format(text: &str) -> bool {
    text.trim() == WARM_FORMAT
}

/// Pages a restore of this snapshot touches first, recorded once when the
/// snapshot is built and replayed on every create from it.
pub const PREFETCH_PLAN: &str = "prefetch.bin";

/// The cpu, memory and disk the snapshot was taken with.
///
/// Firecracker restores machine configuration *from the snapshot*, so a
/// restored guest has the memory the snapshot had, not the memory the caller
/// asked for. Without recording this, a sandbox created with `--mem-mib 2048`
/// from a 512 MiB snapshot silently gets 512 MiB and no error. The disk is
/// the same: the guest's filesystem fills the disk it was snapshotted on.
const SHAPE_FILE: &str = "shape";

/// Which hypervisor took the snapshot, and so which files it is made of.
const HYPERVISOR_FILE: &str = "hypervisor";

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
    pub bundles: Vec<burrow_proto::guest::v1::TrustBundle>,
}

/// vcpus, memory and root disk a warm snapshot was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub vcpus: u32,
    pub mem_mib: u32,
    /// MiB. 0 in a request is the template's image plus headroom, which
    /// [`resolve_disk`] turns into a size; a built snapshot records the size.
    pub disk_mib: u32,
    /// What the memory can grow to, which sizes the snapshot's hotplug
    /// region. 0 is the node's default, which [`Self::resolved`] fills in.
    pub max_mem_mib: u32,
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
            disk_mib: resources.disk_mib,
            max_mem_mib: resources.max_mem_mib,
        }
        .resolved()
    }

    /// With the node's default for a growth limit left unset.
    pub fn resolved(self) -> Self {
        Self {
            max_mem_mib: crate::sandbox::max_mem_mib(self.mem_mib, self.max_mem_mib),
            ..self
        }
    }

    /// The directory a snapshot of this machine under `hypervisor` is kept
    /// in. The disk is left out: a create asking for a larger one restores
    /// the snapshot and grows it.
    fn dir_name(self, hypervisor: Hypervisor) -> String {
        match self.max_mem_mib > self.mem_mib {
            true => format!(
                "{hypervisor}-{}x{}-{}",
                self.vcpus, self.mem_mib, self.max_mem_mib
            ),
            false => format!("{hypervisor}-{}x{}", self.vcpus, self.mem_mib),
        }
    }

    fn is_machine(self, other: Shape) -> bool {
        (self.vcpus, self.mem_mib, self.max_mem_mib)
            == (other.vcpus, other.mem_mib, other.max_mem_mib)
    }

    fn parse(text: &str) -> Option<Self> {
        // Split on runs of whitespace rather than the first one, so padding
        // does not leave the second field unparseable.
        let mut fields = text.split_whitespace();
        let shape = Self {
            vcpus: fields.next()?.parse().ok()?,
            mem_mib: fields.next()?.parse().ok()?,
            disk_mib: fields.next()?.parse().ok()?,
            // Absent before format 7, whose snapshots are rebuilt at the
            // node's default.
            max_mem_mib: fields.next().map_or(Some(0), |field| field.parse().ok())?,
        };
        // Another field means a format this build does not understand; cold
        // booting is the safe answer.
        fields.next().is_none().then_some(shape)
    }

    fn render(self) -> String {
        format!(
            "{} {} {} {}",
            self.vcpus, self.mem_mib, self.disk_mib, self.max_mem_mib
        )
    }
}

/// `shape` with its disk the size a create of `template` would get.
pub async fn resolve_disk(
    templates_dir: &Path,
    template: &str,
    shape: Shape,
) -> Result<Shape, Status> {
    let image = tokio::fs::metadata(templates_dir.join(template).join(IMAGE))
        .await
        .map_err(|err| Status::not_found(format!("template {template}: {err}")))?;
    Ok(Shape {
        disk_mib: crate::rootdisk::disk_mib(shape.disk_mib, image.len())?,
        ..shape
    })
}

/// `--warm-shapes`: `VCPUSxMEM_MIB`, e.g. `2x2048`.
pub fn parse_shape(text: &str) -> Result<Shape, String> {
    let (vcpus, mem_mib) = text
        .split_once('x')
        .ok_or_else(|| format!("{text:?} is not VCPUSxMEM_MIB, e.g. 2x2048"))?;
    Ok(Shape {
        vcpus: vcpus
            .parse()
            .map_err(|_| format!("{text:?}: {vcpus:?} is not a vCPU count"))?,
        mem_mib: mem_mib
            .parse()
            .map_err(|_| format!("{text:?}: {mem_mib:?} is not MiB of memory"))?,
        disk_mib: 0,
        max_mem_mib: 0,
    })
}

/// How many warm snapshots this node keeps, and how much disk they may take,
/// from the `--warm-*` flags.
#[derive(Debug, Clone)]
pub struct WarmPolicy {
    pub per_template: usize,
    pub per_node: usize,
    pub per_template_bytes: u64,
    pub per_node_bytes: u64,
    /// Built for every template as it lands, and never evicted. The default
    /// shape, what a create naming no resources asks for, is always among
    /// them.
    pub pinned: Vec<Shape>,
    /// Creates of a shape with no snapshot before one is built for it.
    pub demand: u32,
}

impl Default for WarmPolicy {
    fn default() -> Self {
        Self {
            per_template: 4,
            per_node: 16,
            per_template_bytes: 8 << 30,
            per_node_bytes: 32 << 30,
            pinned: vec![Shape::wanted(&Default::default())],
            demand: 1,
        }
    }
}

impl WarmPolicy {
    pub fn is_pinned(&self, shape: Shape) -> bool {
        self.pinned.iter().any(|pinned| pinned.is_machine(shape))
    }

    /// Which of `entries` to evict, least recently used first, so that every
    /// template and then the node fit their caps. Pinned shapes count against
    /// the caps and are never chosen.
    pub fn evictions(&self, entries: &[(String, Warm)]) -> Vec<usize> {
        let mut order: Vec<usize> = (0..entries.len())
            .filter(|&index| !self.is_pinned(entries[index].1.shape))
            .collect();
        order.sort_by_key(|&index| entries[index].1.used_at);
        let mut evicted = std::collections::HashSet::new();

        let mut templates: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
        templates.sort_unstable();
        templates.dedup();
        for template in templates {
            let kept = |evicted: &std::collections::HashSet<usize>| {
                entries
                    .iter()
                    .enumerate()
                    .filter(|(index, (name, _))| name == template && !evicted.contains(index))
                    .fold((0, 0u64), |(count, bytes), (_, (_, warm))| {
                        (count + 1, bytes + warm.bytes)
                    })
            };
            for &index in order.iter().filter(|&&index| entries[index].0 == template) {
                let (count, bytes) = kept(&evicted);
                if count <= self.per_template && bytes <= self.per_template_bytes {
                    break;
                }
                evicted.insert(index);
            }
        }

        for &index in &order {
            let (count, bytes) = entries
                .iter()
                .enumerate()
                .filter(|(index, _)| !evicted.contains(index))
                .fold((0, 0u64), |(count, bytes), (_, (_, warm))| {
                    (count + 1, bytes + warm.bytes)
                });
            if count <= self.per_node && bytes <= self.per_node_bytes {
                break;
            }
            evicted.insert(index);
        }

        let mut evicted: Vec<usize> = evicted.into_iter().collect();
        evicted.sort_unstable();
        evicted
    }
}

/// One warm snapshot of a template, as found on disk.
#[derive(Debug, Clone)]
pub struct Warm {
    pub dir: PathBuf,
    pub hypervisor: Hypervisor,
    pub shape: Shape,
    /// Disk its files take, counting blocks a clone shares with the image.
    pub bytes: u64,
    /// Unix seconds of the last restore from it, or of its build.
    pub used_at: i64,
}

impl Warm {
    pub fn to_proto(&self, template: &str, policy: &WarmPolicy) -> common::WarmShape {
        common::WarmShape {
            template: template.to_string(),
            resources: Some(common::ResourcePolicy {
                vcpus: self.shape.vcpus,
                mem_mib: self.shape.mem_mib,
                disk_mib: self.shape.disk_mib,
                max_mem_mib: self.shape.max_mem_mib,
                ..Default::default()
            }),
            size_bytes: self.bytes,
            last_used_at_unix_ms: self.used_at.saturating_mul(1000),
            is_pinned: policy.is_pinned(self.shape),
            node_id: String::new(),
        }
    }
}

/// The snapshot in `dir`, if it is complete and in the current format.
async fn read_warm(dir: &Path) -> Option<Warm> {
    use std::os::unix::fs::MetadataExt as _;

    let hypervisor: Hypervisor = tokio::fs::read_to_string(dir.join(HYPERVISOR_FILE))
        .await
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let format = tokio::fs::read_to_string(dir.join("format")).await.ok()?;
    if !is_current_format(&format) {
        return None;
    }
    let shape = Shape::parse(&tokio::fs::read_to_string(dir.join(SHAPE_FILE)).await.ok()?)?;
    let mut bytes = 0;
    for file in hypervisor.layout().files().chain([ROOT_DISK]) {
        bytes += tokio::fs::metadata(dir.join(file)).await.ok()?.blocks() * 512;
    }
    if let Ok(plan) = tokio::fs::metadata(dir.join(PREFETCH_PLAN)).await {
        bytes += plan.blocks() * 512;
    }
    let used_at = match tokio::fs::read_to_string(dir.join(USED_FILE)).await {
        Ok(text) => text.trim().parse().ok(),
        Err(_) => None,
    };
    let used_at = match used_at {
        Some(at) => at,
        None => tokio::fs::metadata(dir.join("format")).await.ok()?.mtime(),
    };
    Some(Warm {
        dir: dir.to_path_buf(),
        hypervisor,
        shape,
        bytes,
        used_at,
    })
}

pub fn warm_dir(templates_dir: &Path, template: &str) -> PathBuf {
    templates_dir.join(template).join(WARM_DIR)
}

/// Where a new snapshot is assembled before it is published.
///
/// Building in place would pull the snapshot out from under creates that
/// already decided to restore from it and are about to link its files.
fn warm_staging_dir(templates_dir: &Path, template: &str) -> PathBuf {
    templates_dir.join(template).join(WARM_STAGING_DIR)
}

/// The snapshot of `template` under `hypervisor` with `wanted`'s vCPUs and
/// memory, whatever its disk.
///
/// One of another machine is *not* usable: restoring it would hand the caller
/// a guest with different cpu and memory than they asked for.
pub async fn find(
    templates_dir: &Path,
    template: &str,
    hypervisor: Hypervisor,
    wanted: Shape,
) -> Option<Warm> {
    let dir = warm_dir(templates_dir, template).join(wanted.dir_name(hypervisor));
    read_warm(&dir)
        .await
        .filter(|warm| warm.hypervisor == hypervisor && warm.shape.is_machine(wanted))
}

/// Where `template`'s snapshot of `wanted` under `hypervisor` is, when it is
/// there but does not read back: a file of it gone.
pub async fn find_broken(
    templates_dir: &Path,
    template: &str,
    hypervisor: Hypervisor,
    wanted: Shape,
) -> Option<PathBuf> {
    let dir = warm_dir(templates_dir, template).join(wanted.dir_name(hypervisor));
    is_broken(&dir).await.then_some(dir)
}

async fn is_broken(dir: &Path) -> bool {
    tokio::fs::try_exists(dir).await.unwrap_or(false) && read_warm(dir).await.is_none()
}

/// Removes the snapshot in `dir` if it is still broken once no build is
/// swapping it, and says whether it did.
pub async fn discard_broken(dir: &Path) -> std::io::Result<bool> {
    let _no_builds = WARM_BUILD_LOCK.lock().await;
    if !is_broken(dir).await {
        return Ok(false);
    }
    tokio::fs::remove_dir_all(dir).await?;
    Ok(true)
}

/// Every usable warm snapshot of `template`.
pub async fn list(templates_dir: &Path, template: &str) -> Vec<Warm> {
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(warm_dir(templates_dir, template)).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(warm) = read_warm(&entry.path()).await {
            out.push(warm);
        }
    }
    out.sort_by_key(|warm| (warm.shape.vcpus, warm.shape.mem_mib));
    out
}

/// Every usable warm snapshot on the node, by template.
pub async fn list_all(templates_dir: &Path) -> Vec<(String, Warm)> {
    let mut out = Vec::new();
    let Ok(mut templates) = tokio::fs::read_dir(templates_dir).await else {
        return out;
    };
    while let Ok(Some(entry)) = templates.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        for warm in list(templates_dir, &name).await {
            out.push((name.clone(), warm));
        }
    }
    out
}

/// What under `template`'s warm directory cannot be restored: snapshots in an
/// older format, the single snapshot of the layout before shapes, and pieces
/// of either. Each comes with the shape it recorded, if it did, so it can be
/// rebuilt in the current format.
pub async fn stale(templates_dir: &Path, template: &str) -> Vec<(PathBuf, Option<Shape>)> {
    let root = warm_dir(templates_dir, template);
    if tokio::fs::try_exists(root.join("format"))
        .await
        .unwrap_or(false)
    {
        let shape = recorded_shape(&root).await;
        return vec![(root, shape)];
    }
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(&root).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if read_warm(&path).await.is_none() {
            let shape = recorded_shape(&path).await;
            out.push((path, shape));
        }
    }
    out
}

async fn recorded_shape(dir: &Path) -> Option<Shape> {
    Shape::parse(&tokio::fs::read_to_string(dir.join(SHAPE_FILE)).await.ok()?)
}

/// Whether `template` has a usable warm snapshot at all, whatever its shape.
pub async fn is_warm(templates_dir: &Path, template: &str) -> bool {
    !list(templates_dir, template).await.is_empty()
}

/// Files a sandbox needs in its working directory to restore from warm.
///
/// The root disk is cloned because the guest will write to it; everything
/// else is hard-linked because it is read-only or verified immutable.
pub async fn stage_from_warm(
    templates_dir: &Path,
    template: &str,
    snapshot: &Warm,
    workdir: &Path,
) -> std::io::Result<()> {
    let began = std::time::Instant::now();
    let warm = &snapshot.dir;
    let template_dir = templates_dir.join(template);
    let layout = snapshot.hypervisor.layout();

    tokio::fs::create_dir_all(workdir).await?;
    let linked = [
        (template_dir.join("vmlinux"), "vmlinux"),
        (template_dir.join(IMAGE), IMAGE),
    ]
    .into_iter()
    .chain(layout.files().map(|name| (warm.join(name), name)));
    for (source, name) in linked {
        let dest = workdir.join(name);
        let _ = tokio::fs::remove_file(&dest).await;
        tokio::fs::hard_link(&source, &dest).await?;
    }

    let linked = std::time::Instant::now();

    // Optional: profiling is best effort, and a warm snapshot whose profiling
    // run failed simply has no plan.
    let plan = warm.join(PREFETCH_PLAN);
    if tokio::fs::try_exists(&plan).await.unwrap_or(false) {
        let dest = workdir.join(PREFETCH_PLAN);
        let _ = tokio::fs::remove_file(&dest).await;
        let _ = tokio::fs::hard_link(&plan, &dest).await;
    }

    // The one file that must not be shared.
    let before_disk = std::time::Instant::now();
    crate::rootdisk::clone(&warm.join(ROOT_DISK), &workdir.join(ROOT_DISK)).await?;
    // Best effort: a snapshot whose use went unrecorded is only evicted a
    // little sooner than it should be.
    let _ = tokio::fs::write(warm.join(USED_FILE), burrow_common::unix_now().to_string()).await;
    tracing::debug!(
        template,
        link_ms = (linked - began).as_millis() as u64,
        disk_ms = before_disk.elapsed().as_millis() as u64,
        "staged a warm snapshot"
    );
    Ok(())
}

/// Boots a template, waits for its agent, and snapshots the running VM.
///
/// The warm VM runs on a fixed tap of its own. It never carries a policy or
/// serves anyone: its only job is to reach the point where a sandbox would be
/// ready, and stop there.
///
/// It runs under the template's hypervisor and the node's confinement all the
/// same, taking the jailer, the cgroup root and the resource limits straight
/// off [`NodeConfig`] the way `SandboxManager::build_spec` does. A warm build boots a tenant's own image
/// and runs its init: exempting it would have the one VM on the node that
/// nobody is watching be the only one running unjailed and uncapped.
pub async fn build_warm_snapshot(
    config: &NodeConfig,
    template: &str,
    shape: Shape,
    trust: &Trust,
) -> Result<Warm, Status> {
    let templates_dir = config.templates_dir();
    let agent_timeout = config.agent_timeout;
    // Defence in depth: the name becomes a directory under `templates_dir` and
    // this function removes and recreates it, so a caller that skipped
    // validation must not be able to point it at an arbitrary host path.
    crate::template::validate_name(template)?;

    // Held for the whole build, profiling included: both halves drive the same
    // fixed tap, so overlapping builds break each other's networking.
    let _serialised = WARM_BUILD_LOCK.lock().await;

    let template_dir = templates_dir.join(template);
    if !tokio::fs::try_exists(template_dir.join(IMAGE))
        .await
        .unwrap_or(false)
    {
        return Err(Status::not_found(format!("no template {template}")));
    }
    let shape = resolve_disk(&templates_dir, template, shape).await?;
    let environment = crate::oci::image_environment(&config.data_dir, template).await;
    let is_systemd = environment.systemd;
    let (hypervisor, guest_os) = environment.machine()?;
    if !config.hypervisors.contains(&hypervisor) {
        return Err(Status::failed_precondition(format!(
            "template {template} runs under {hypervisor}, which this node does not offer"
        )));
    }
    let backend = config.backend(hypervisor);
    let capabilities = hypervisor.capabilities();

    // Assembled beside the live snapshot and swapped in at the end. Rebuilding
    // in place would delete the files out from under a create that has already
    // decided to restore from them.
    let live = warm_dir(&templates_dir, template).join(shape.dir_name(hypervisor));
    let dir = warm_staging_dir(&templates_dir, template);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|err| Status::internal(format!("warm dir: {err}")))?;

    // Under the jailer the VM's files have to live in the chroot the jailer
    // builds, which is fixed by the vm id and is not the staging directory the
    // snapshot is published from. So the VM runs there and its products are
    // moved into the staging directory afterwards; without the jailer the two
    // are the same place and nothing moves.
    let vm_id = format!("warm-{template}");
    let run_dir = match config.jail_for(hypervisor) {
        Some(jail) => jail.chroot_for(hypervisor, &vm_id),
        None => dir.clone(),
    };
    if run_dir != dir {
        let _ = tokio::fs::remove_dir_all(&run_dir).await;
        tokio::fs::create_dir_all(&run_dir)
            .await
            .map_err(|err| Status::internal(format!("warm chroot: {err}")))?;
    }

    for name in ["vmlinux", IMAGE] {
        tokio::fs::hard_link(template_dir.join(name), run_dir.join(name))
            .await
            .map_err(|err| Status::internal(format!("staging {name}: {err}")))?;
    }
    crate::rootdisk::clone(&run_dir.join(IMAGE), &run_dir.join(ROOT_DISK))
        .await
        .map_err(|err| Status::internal(format!("warm root disk: {err}")))?;
    crate::rootdisk::grow(&run_dir.join(ROOT_DISK), shape.disk_mib).await?;
    if let Some(jail) = config.jail_for(hypervisor) {
        // The kernel and image are hard links into the template's own
        // directory and are left alone for the reason
        // [`crate::sandbox::grant_to_jail`] gives; the root disk is this
        // build's own and has to be writable by the uid the VMM drops to.
        let shared = ["vmlinux".to_string(), IMAGE.to_string()].into();
        crate::sandbox::grant_to_jail(&run_dir, jail, &shared)
            .await
            .map_err(|err| Status::internal(format!("preparing the warm jail: {err}")))?;
    }

    // A throwaway lease: the address only has to be valid enough for the guest
    // to finish booting, and every clone is re-addressed on resume anyway.
    let lease = burrow_net::ipam::warm_lease();
    burrow_net::tap::delete(WARM_TAP).await;
    let tap = burrow_net::tap::create_named(WARM_TAP, &lease)
        .await
        .map_err(|err| Status::internal(format!("warm tap: {err}")))?;

    let mut spec = VmSpec::new(vm_id.clone(), &run_dir, backend.clone());
    spec.guest_os = guest_os;
    // Taken under the transport it will be restored under: a snapshot does not
    // cross between PCI and MMIO.
    spec.is_pci_enabled = true;
    // Baked into the snapshot: a restore takes its machine configuration from
    // here, not from what a later caller asks for.
    spec.vcpus = shape.vcpus;
    spec.mem_mib = shape.mem_mib;
    spec.mem_hotplug_mib =
        crate::sandbox::hotplug_region(hypervisor, guest_os, shape.mem_mib, shape.max_mem_mib);
    spec.drives = DiskLayout::Root.drives();
    spec.is_vsock_enabled = true;
    spec.net = Some(NetSpec {
        tap: tap.clone(),
        guest_mac: Some(lease.guest_mac()),
    });
    spec.boot = burrow_vmm::Boot::Kernel {
        kernel: "vmlinux".into(),
        cmdline: format!(
            "{} {} init=/usr/bin/burrow-guest {} {} {}",
            burrow_vmm::DEFAULT_BOOT_ARGS,
            DiskLayout::Root.boot_args(),
            lease.kernel_ip_arg(),
            crate::sandbox::guest_mode_arg(is_systemd),
            crate::sandbox::guest_boot_args(&config.extra_boot_args, config.is_console_verbose)
        ),
    };
    apply_confinement(&mut spec, config, shape);

    let outcome = snapshot_when_ready(spec, agent_timeout, &lease, trust).await;
    burrow_net::tap::delete(WARM_TAP).await;

    match outcome {
        Ok(()) => {
            // Restore the snapshot once, purely to learn which pages a guest
            // reaches for. Doing it here costs one boot at warm time and saves
            // thousands of faults on every create afterwards. Only the
            // page-fault handler records faults, or replays a plan.
            if capabilities.is_lazy_memory_supported
                && let Err(err) =
                    profile_restore(&vm_id, &run_dir, &backend, config, shape, trust).await
            {
                tracing::warn!(template, %err, "could not record a prefetch plan");
            }
            if run_dir != dir {
                let collected = collect_products(&run_dir, &dir, hypervisor).await;
                // The chroot itself is the jailer's; what was worth keeping is
                // out of it.
                let _ = config.remove_workdir(&run_dir).await;
                if let Err(err) = collected {
                    let _ = tokio::fs::remove_dir_all(&dir).await;
                    return Err(err);
                }
            }
            // Shape first, format last: `format` is the commit marker that
            // makes a snapshot warm, and one that is warm without a shape can
            // never be matched to a request, so the node keeps winning
            // placement and every create cold-boots.
            tokio::fs::write(dir.join(SHAPE_FILE), shape.render())
                .await
                .map_err(|err| Status::internal(format!("recording warm shape: {err}")))?;
            tokio::fs::write(dir.join(HYPERVISOR_FILE), hypervisor.as_str())
                .await
                .map_err(|err| Status::internal(format!("recording warm hypervisor: {err}")))?;
            tokio::fs::write(dir.join(USED_FILE), burrow_common::unix_now().to_string())
                .await
                .map_err(|err| Status::internal(format!("recording warm use: {err}")))?;
            // Everything on the disk before the marker, and the marker before
            // the swap: every create restores from this snapshot, so one torn
            // by a power cut would corrupt every guest made from it.
            crate::fsync::tree(&dir)
                .await
                .map_err(|err| Status::internal(format!("syncing the warm snapshot: {err}")))?;
            tokio::fs::write(dir.join("format"), WARM_FORMAT)
                .await
                .map_err(|err| Status::internal(format!("marking warm snapshot: {err}")))?;
            crate::fsync::files_then_dir(&dir, vec!["format".into()])
                .await
                .map_err(|err| Status::internal(format!("syncing the warm marker: {err}")))?;
            // The swap. Creates staging from the old snapshot hold open file
            // handles or link its inodes; the window where neither directory
            // is in place is a rename apart, rather than a whole build long.
            let parent = warm_dir(&templates_dir, template);
            tokio::fs::create_dir_all(&parent)
                .await
                .map_err(|err| Status::internal(format!("warm dir: {err}")))?;
            let _ = tokio::fs::remove_dir_all(&live).await;
            tokio::fs::rename(&dir, &live)
                .await
                .map_err(|err| Status::internal(format!("publishing the warm snapshot: {err}")))?;
            if let Err(err) = crate::fsync::dir(&parent).await {
                tracing::warn!(template, %err, "could not sync the warm snapshot's rename");
            }

            let warm = read_warm(&live).await.ok_or_else(|| {
                Status::internal("the published warm snapshot does not read back")
            })?;
            tracing::info!(
                template,
                vcpus = shape.vcpus,
                mem_mib = shape.mem_mib,
                disk_mib = shape.disk_mib,
                bytes = warm.bytes,
                "warm snapshot ready"
            );
            Ok(warm)
        }
        Err(err) => {
            // A partial warm snapshot would be picked up by the next create.
            // The live one is left alone: it is still usable.
            let _ = tokio::fs::remove_dir_all(&dir).await;
            if run_dir != dir {
                let _ = config.remove_workdir(&run_dir).await;
            }
            Err(err)
        }
    }
}

/// Gives a warm VM the same cgroup and limits a sandbox of this shape would
/// get. The jail travels with the backend.
///
/// Kept beside the two specs that need it rather than derived from a sandbox's,
/// because a warm VM has no policy and no lease to build one from; what it
/// shares with a sandbox is exactly the confinement, and that is what is copied.
fn apply_confinement(spec: &mut VmSpec, config: &NodeConfig, shape: Shape) {
    spec.cgroup_root = config.cgroup_root.clone();
    spec.is_limits_required = config.is_resource_limits_required;
    spec.limits = crate::sandbox::cgroup_limits(
        &burrow_proto::common::v1::ResourcePolicy {
            vcpus: shape.vcpus,
            ..Default::default()
        },
        config.memory_ceiling_mib(spec.hypervisor(), shape.mem_mib),
    );
}

/// Moves what the jailed build produced into the directory it is published
/// from, and gives it back to the daemon.
///
/// The files come out owned by the uid the VMM dropped to. A warm snapshot is
/// hard-linked into every sandbox restored from it and is never rewritten, so
/// leaving it owned by that uid would make one shared memory image writable by
/// every jailed VMM on the node, the very thing
/// [`crate::sandbox::grant_to_jail`] refuses to do for a template's rootfs.
/// Ownership goes back to whoever owns the staging directory, which is the
/// daemon, leaving the files readable by the jail and writable by nobody in it.
async fn collect_products(
    run_dir: &Path,
    dir: &Path,
    hypervisor: Hypervisor,
) -> Result<(), Status> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = tokio::fs::metadata(dir)
        .await
        .map_err(|err| Status::internal(format!("reading the warm staging dir: {err}")))?;
    let (uid, gid) = (owner.uid(), owner.gid());

    let layout = hypervisor.layout();
    for name in layout.files().chain([ROOT_DISK]) {
        tokio::fs::rename(run_dir.join(name), dir.join(name))
            .await
            .map_err(|err| Status::internal(format!("collecting {name}: {err}")))?;
    }
    // Optional: a build whose profiling pass failed simply has no plan.
    let plan = run_dir.join(PREFETCH_PLAN);
    if tokio::fs::try_exists(&plan).await.unwrap_or(false) {
        let _ = tokio::fs::rename(&plan, dir.join(PREFETCH_PLAN)).await;
    }

    let collected = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        for entry in std::fs::read_dir(&collected)?.flatten() {
            std::os::unix::fs::chown(entry.path(), Some(uid), Some(gid))?;
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|err| Status::internal(format!("chown did not run: {err}")))?
    .map_err(|err| Status::internal(format!("reclaiming the warm snapshot: {err}")))
}

/// Drives the agent through the paths a clone will take on create.
///
/// The handshake is the expensive one, reaching the netlink code, the entropy
/// ioctl and the clock syscall; the health call afterwards settles the gRPC
/// server's own machinery.
async fn exercise_agent(
    vm: &Vm,
    lease: &burrow_net::ipam::Lease,
    trust: &Trust,
    agent_timeout: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut agent = crate::guestconn::connect(vm.guest(), agent_timeout).await?;
    agent
        .handshake(crate::guestconn::handshake_full(
            true,
            Some(burrow_proto::guest::v1::NetworkConfig {
                // Its own address: re-applying it changes nothing, and the
                // point is to touch the code rather than the configuration.
                ip: lease.guest_ip.to_string(),
                prefix_len: lease.prefix_len as u32,
                gateway: lease.host_ip.to_string(),
                dns: lease.host_ip.to_string(),
                ip6: lease.guest_ip6().to_string(),
                prefix_len6: lease.prefix_len6() as u32,
                gateway6: lease.host_ip6().to_string(),
                public_addresses: Vec::new(),
            }),
            trust.ca.clone(),
            trust.bundles.clone(),
            // A warm snapshot is shared by every sandbox restored from it, so
            // it must not carry any one sandbox's volumes.
            Vec::new(),
        ))
        .await?;
    agent
        .health(burrow_proto::guest::v1::GuestHealthRequest {})
        .await?;
    // A clone's first exec otherwise faults in the agent's spawn path, the
    // kernel's fork and exec, and the shell, one page at a time.
    let start = burrow_proto::guest::v1::ExecInput {
        input: Some(burrow_proto::guest::v1::exec_input::Input::Start(
            burrow_proto::guest::v1::ExecStart {
                cmd: vec!["sh".into(), "-c".into(), "true".into()],
                ..Default::default()
            },
        )),
    };
    let mut output = agent.exec(tokio_stream::once(start)).await?.into_inner();
    while output.message().await?.is_some() {}
    Ok(())
}

/// Restores the freshly built snapshot with fault recording on, so later
/// creates have a plan to replay.
///
/// The recording VM is otherwise identical to a real create, same tap and same
/// handshake, because a plan gathered from a different code path would prefetch
/// the wrong pages.
async fn profile_restore(
    vm_id: &str,
    dir: &Path,
    backend: &burrow_vmm::Backend,
    config: &NodeConfig,
    shape: Shape,
    trust: &Trust,
) -> Result<(), Status> {
    let agent_timeout = config.agent_timeout;
    let lease = burrow_net::ipam::warm_lease();
    burrow_net::tap::delete(WARM_TAP).await;
    let tap = burrow_net::tap::create_named(WARM_TAP, &lease)
        .await
        .map_err(|err| Status::internal(format!("profiling tap: {err}")))?;

    // The build's own id, not one of its own: under the jailer the chroot is
    // derived from the id, and this VM restores the files that are inside the
    // one the build already filled.
    let mut spec = VmSpec::new(vm_id.to_string(), dir, backend.clone());
    spec.is_pci_enabled = true;
    spec.drives = DiskLayout::Root.drives();
    spec.is_vsock_enabled = true;
    spec.net = Some(NetSpec {
        tap: tap.clone(),
        guest_mac: Some(lease.guest_mac()),
    });
    spec.vcpus = shape.vcpus;
    spec.mem_mib = shape.mem_mib;
    spec.mem_hotplug_mib = crate::sandbox::hotplug_region(
        backend.hypervisor(),
        burrow_vmm::GuestOs::Linux,
        shape.mem_mib,
        shape.max_mem_mib,
    );
    spec.record_prefetch = Some(PREFETCH_PLAN.to_string());
    apply_confinement(&mut spec, config, shape);

    // The profiling guest writes to the disk *after* the snapshot was taken,
    // so a clone restoring that snapshot would find a disk that had moved
    // under its in-memory filesystem state. Put back exactly as the snapshot
    // expects it.
    let disk = dir.join(ROOT_DISK);
    let pristine = dir.join("root.ext4.pristine");
    crate::rootdisk::clone(&disk, &pristine)
        .await
        .map_err(|err| Status::internal(format!("preserving the warm disk: {err}")))?;

    let outcome = async {
        let vm = Vm::restore(spec, true)
            .await
            .map_err(|err| Status::internal(format!("profiling restore: {err}")))?;
        // Faults taken while reaching a usable agent are exactly the ones a
        // real create pays for.
        let ready = vm
            .wait_for_vsock(crate::guestconn::AGENT_PORT, agent_timeout)
            .await;
        if ready.is_ok() {
            let _ = exercise_agent(&vm, &lease, trust, agent_timeout).await;
        }
        vm.kill()
            .await
            .map_err(|err| Status::internal(format!("stopping the profiling vm: {err}")))
    }
    .await;

    burrow_net::tap::delete(WARM_TAP).await;

    let _ = tokio::fs::remove_file(&disk).await;
    if let Err(err) = tokio::fs::rename(&pristine, &disk).await {
        // Without the original disk the snapshot is not safely restorable, so
        // this is fatal rather than a lost optimisation.
        return Err(Status::internal(format!(
            "could not restore the warm root disk: {err}"
        )));
    }
    outcome
}

async fn snapshot_when_ready(
    spec: VmSpec,
    agent_timeout: std::time::Duration,
    lease: &burrow_net::ipam::Lease,
    trust: &Trust,
) -> Result<(), Status> {
    let vm = Vm::boot(spec)
        .await
        .map_err(|err| Status::internal(format!("warm boot: {err}")))?;

    if let Err(err) = vm
        .wait_for_vsock(crate::guestconn::AGENT_PORT, agent_timeout)
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
    if let Err(err) = exercise_agent(&vm, lease, trust, agent_timeout).await {
        // Not fatal: a snapshot without the warm-up is slower, not wrong.
        tracing::warn!(%err, "could not pre-warm the guest before snapshotting");
    }

    // Snapshot a quiesced guest: anything mid-flight at this moment is frozen
    // into every sandbox that later restores from it.
    if let Err(err) = vm.pause().await {
        let _ = vm.kill().await;
        return Err(Status::internal(format!("pausing warm vm: {err}")));
    }
    if let Err(err) = vm.snapshot().await {
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
                mem_mib: 512,
                disk_mib: 0,
                max_mem_mib: 8192,
            }
        );
    }

    #[test]
    fn an_explicit_policy_is_taken_as_given() {
        let wanted = Shape::wanted(&common::ResourcePolicy {
            vcpus: 4,
            mem_mib: 2048,
            disk_mib: 4096,
            max_mem_mib: 4096,
            ..Default::default()
        });
        assert_eq!(
            wanted,
            Shape {
                vcpus: 4,
                mem_mib: 2048,
                disk_mib: 4096,
                max_mem_mib: 4096,
            }
        );
    }

    #[test]
    fn a_shape_round_trips_through_its_file() {
        let shape = Shape {
            vcpus: 2,
            mem_mib: 1024,
            disk_mib: 1324,
            max_mem_mib: 16384,
        };
        assert_eq!(Shape::parse(&shape.render()), Some(shape));
        assert_eq!(Shape::parse("  2   1024 1324 16384 \n"), Some(shape));
    }

    #[test]
    fn a_malformed_shape_file_reads_as_absent() {
        // Absent is the safe answer: it means "cold boot", which is slower and
        // correct, rather than restoring a snapshot of unknown size.
        for bad in [
            "",
            "2",
            "2 1024",
            "two 1024 1 1",
            "2 lots 1 1",
            "2 1024 1 1 1",
            "\n",
        ] {
            assert_eq!(Shape::parse(bad), None, "{bad:?} should not parse");
        }
    }

    /// Snapshots from before shapes had directories of their own are
    /// rebuilt in the new layout rather than restored.
    #[test]
    fn only_the_current_format_is_warm() {
        assert_eq!(WARM_FORMAT, "7");
        assert!(is_current_format("7"));
        assert!(is_current_format("7\n"));
        for old in ["", "1", "2", "3", "4", "5", "6", "8"] {
            assert!(!is_current_format(old), "{old:?} should be rebuilt");
        }
    }

    #[test]
    fn a_pre_warmed_shape_parses_from_its_flag() {
        assert_eq!(
            parse_shape("2x2048"),
            Ok(Shape {
                vcpus: 2,
                mem_mib: 2048,
                disk_mib: 0,
                max_mem_mib: 0,
            })
        );
        for bad in ["", "2", "2x", "x2048", "2x2048x1", "twox2048", "2*2048"] {
            assert!(parse_shape(bad).is_err(), "{bad:?} should not parse");
        }
    }

    /// Two shapes of one template live side by side, and the disk is not
    /// part of where either is kept.
    #[test]
    fn each_shape_has_a_directory_of_its_own() {
        let shape = |vcpus, mem_mib, disk_mib| Shape {
            vcpus,
            mem_mib,
            disk_mib,
            max_mem_mib: mem_mib,
        };
        assert_eq!(
            shape(2, 2048, 1324).dir_name(Hypervisor::Firecracker),
            "firecracker-2x2048"
        );
        assert_eq!(
            shape(2, 2048, 4096).dir_name(Hypervisor::Firecracker),
            shape(2, 2048, 1324).dir_name(Hypervisor::Firecracker)
        );
        assert_ne!(
            shape(2, 2048, 0).dir_name(Hypervisor::CloudHypervisor),
            shape(2, 2048, 0).dir_name(Hypervisor::Firecracker)
        );
        assert_ne!(
            shape(4, 2048, 0).dir_name(Hypervisor::Firecracker),
            shape(2, 2048, 0).dir_name(Hypervisor::Firecracker)
        );
        let growable = Shape {
            max_mem_mib: 16384,
            ..shape(1, 1024, 0)
        };
        assert_eq!(
            growable.dir_name(Hypervisor::Firecracker),
            "firecracker-1x1024-16384"
        );
        assert!(!growable.is_machine(shape(1, 1024, 0)));
    }

    fn entry(template: &str, vcpus: u32, mem_mib: u32, bytes: u64, used_at: i64) -> (String, Warm) {
        (
            template.to_string(),
            Warm {
                dir: PathBuf::new(),
                hypervisor: Hypervisor::Firecracker,
                shape: Shape {
                    vcpus,
                    mem_mib,
                    disk_mib: 1324,
                    max_mem_mib: 0,
                }
                .resolved(),
                bytes,
                used_at,
            },
        )
    }

    fn policy(per_template: usize, per_node: usize) -> WarmPolicy {
        WarmPolicy {
            per_template,
            per_node,
            per_template_bytes: u64::MAX,
            per_node_bytes: u64::MAX,
            ..Default::default()
        }
    }

    #[test]
    fn the_least_recently_used_shape_is_evicted_first() {
        let entries = [
            entry("app", 2, 1024, 1, 300),
            entry("app", 2, 2048, 1, 100),
            entry("app", 4, 4096, 1, 200),
        ];
        assert_eq!(policy(2, 16).evictions(&entries), vec![1]);
        assert_eq!(policy(1, 16).evictions(&entries), vec![1, 2]);
        assert!(policy(3, 16).evictions(&entries).is_empty());
    }

    /// The default shape is what a create naming nothing asks for, so it
    /// stays however long ago it was last restored.
    #[test]
    fn a_pinned_shape_is_never_evicted() {
        let entries = [
            entry("app", 1, 512, 1, 0),
            entry("app", 2, 2048, 1, 100),
            entry("app", 4, 4096, 1, 200),
        ];
        assert_eq!(policy(2, 16).evictions(&entries), vec![1]);
        // Even past a cap only pinned shapes would meet.
        let mut pinned = policy(0, 16);
        pinned
            .pinned
            .push(parse_shape("4x4096").unwrap().resolved());
        assert_eq!(pinned.evictions(&entries), vec![1]);
    }

    #[test]
    fn the_node_cap_evicts_across_templates() {
        let entries = [
            entry("app", 2, 1024, 1, 100),
            entry("db", 2, 1024, 1, 50),
            entry("db", 4, 1024, 1, 400),
            entry("web", 2, 1024, 1, 300),
        ];
        assert_eq!(policy(4, 2).evictions(&entries), vec![0, 1]);
    }

    #[test]
    fn the_disk_caps_evict_until_the_rest_fits() {
        let entries = [
            entry("app", 2, 1024, 600, 100),
            entry("app", 2, 2048, 600, 200),
            entry("db", 2, 1024, 600, 300),
        ];
        let mut by_template = policy(16, 16);
        by_template.per_template_bytes = 1000;
        assert_eq!(by_template.evictions(&entries), vec![0]);
        let mut by_node = policy(16, 16);
        by_node.per_node_bytes = 1000;
        assert_eq!(by_node.evictions(&entries), vec![0, 1]);
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-warm-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_snapshot(dir: &Path, format: &str, shape: &str) {
        std::fs::create_dir_all(dir).unwrap();
        for file in Hypervisor::Firecracker.layout().files().chain([ROOT_DISK]) {
            std::fs::write(dir.join(file), b"x").unwrap();
        }
        std::fs::write(dir.join(HYPERVISOR_FILE), "firecracker").unwrap();
        std::fs::write(dir.join(SHAPE_FILE), shape).unwrap();
        std::fs::write(dir.join("format"), format).unwrap();
    }

    #[tokio::test]
    async fn a_create_finds_only_its_own_machine() {
        let templates = temp("find");
        let warm = warm_dir(&templates, "app");
        write_snapshot(
            &warm.join("firecracker-2x2048"),
            WARM_FORMAT,
            "2 2048 1324 2048",
        );
        write_snapshot(
            &warm.join("firecracker-1x512"),
            WARM_FORMAT,
            "1 512 1324 512",
        );
        std::fs::write(warm.join("firecracker-2x2048").join(USED_FILE), "1234").unwrap();

        let wanted = |vcpus, mem_mib| Shape {
            vcpus,
            mem_mib,
            disk_mib: 4096,
            max_mem_mib: mem_mib,
        };
        let found = find(&templates, "app", Hypervisor::Firecracker, wanted(2, 2048))
            .await
            .unwrap();
        assert_eq!(found.shape.disk_mib, 1324);
        assert_eq!(found.used_at, 1234);
        assert!(
            find(&templates, "app", Hypervisor::Firecracker, wanted(4, 2048))
                .await
                .is_none()
        );
        assert!(
            find(
                &templates,
                "app",
                Hypervisor::CloudHypervisor,
                wanted(2, 2048)
            )
            .await
            .is_none()
        );
        assert_eq!(list(&templates, "app").await.len(), 2);
        assert!(stale(&templates, "app").await.is_empty());
        let _ = std::fs::remove_dir_all(&templates);
    }

    /// A snapshot with a file gone is broken and discarded, but not once a
    /// build has swapped a whole one in for it.
    #[tokio::test]
    async fn only_a_snapshot_still_broken_is_discarded() {
        let templates = temp("broken");
        let wanted = parse_shape("2x2048").unwrap();
        let live = warm_dir(&templates, "app").join("firecracker-2x2048");
        write_snapshot(&live, WARM_FORMAT, "2 2048 1324");
        assert!(
            find_broken(&templates, "app", Hypervisor::Firecracker, wanted)
                .await
                .is_none()
        );

        std::fs::remove_file(live.join(ROOT_DISK)).unwrap();
        assert!(
            find(&templates, "app", Hypervisor::Firecracker, wanted)
                .await
                .is_none()
        );
        let broken = find_broken(&templates, "app", Hypervisor::Firecracker, wanted)
            .await
            .unwrap();
        assert_eq!(broken, live);

        write_snapshot(&live, WARM_FORMAT, "2 2048 1324");
        assert!(!discard_broken(&broken).await.unwrap());
        assert!(live.exists());

        std::fs::remove_file(live.join(ROOT_DISK)).unwrap();
        assert!(discard_broken(&broken).await.unwrap());
        assert!(!live.exists());
        let _ = std::fs::remove_dir_all(&templates);
    }

    /// A snapshot of the layout before shapes, and one of an older format,
    /// are discarded with the shapes they recorded so they can be rebuilt.
    #[tokio::test]
    async fn older_snapshots_are_stale_with_their_shapes() {
        let templates = temp("stale");
        let warm = warm_dir(&templates, "flat");
        write_snapshot(&warm, "5", "2 1024 1324");
        assert_eq!(
            stale(&templates, "flat").await,
            vec![(
                warm.clone(),
                Some(Shape {
                    vcpus: 2,
                    mem_mib: 1024,
                    disk_mib: 1324,
                    max_mem_mib: 0,
                })
            )]
        );
        assert!(list(&templates, "flat").await.is_empty());

        let warm = warm_dir(&templates, "app");
        write_snapshot(
            &warm.join("firecracker-1x512"),
            WARM_FORMAT,
            "1 512 1324 512",
        );
        write_snapshot(&warm.join("firecracker-4x4096"), "6", "4 4096 1324");
        let found = stale(&templates, "app").await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, warm.join("firecracker-4x4096"));
        assert_eq!(found[0].1.map(|shape| shape.vcpus), Some(4));
        let _ = std::fs::remove_dir_all(&templates);
    }

    /// The bug this exists to prevent: a caller asking for more memory than
    /// the snapshot holds must not be quietly given the snapshot's.
    #[test]
    fn a_differently_shaped_request_does_not_match() {
        let snapshot = Shape {
            vcpus: 1,
            mem_mib: 512,
            disk_mib: 0,
            max_mem_mib: 8192,
        };
        let asked = Shape::wanted(&common::ResourcePolicy {
            mem_mib: 2048,
            ..Default::default()
        });
        assert!(!snapshot.is_machine(asked));
    }
}
