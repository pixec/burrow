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
use burrow_vmm::{Hypervisor, HypervisorExt, MachineSpec, Vm};

use crate::rootdisk::{IMAGE, ROOT_DISK};
use crate::sandbox::NodeConfig;

/// Warm snapshots, one directory per build and in it one per shape, beside
/// the builds rather than in them: a build never changes once published.
const WARM_DIR: &str = "warm";
/// Where a snapshot is assembled before it is swapped in, beside the build's
/// own. One at a time on the whole node, under [`WARM_BUILD_LOCK`].
const WARM_STAGING_SUFFIX: &str = ".tmp";
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
/// 8 writes a Cloud Hypervisor guest's console to `console.pipe`. A 7 names
/// `console.log`, which the node now owns, so a jailed VMM cannot open it.
///
/// 9 boots a Cloud Hypervisor guest's NIC with checksum and segmentation
/// offload, which an 8's guest negotiated without and keeps across a restore.
/// A 9 also records the digests of its guest's agent and kernel, which must
/// match the node's agent and the template's kernel.
///
/// 10 records its guest's OS, whose agent it is checked against, the disk
/// it takes, measured once when it is built, and the size of each of its
/// files, which a restore checks them against.
///
/// A snapshot in any other format is discarded.
const WARM_FORMAT: &str = "10";

/// Whether a warm snapshot's `format` file names the format this build writes.
fn is_current_format(text: &str) -> bool {
    text.trim() == WARM_FORMAT
}

/// The digest of the agent a warm snapshot's guest runs.
///
/// A snapshot whose agent is not the one this node ships is stale like one in
/// another format: every create from it would upgrade its agent in place on
/// the first call into the guest.
const AGENT_FILE: &str = "agent";

/// The guest OS a warm snapshot's guest runs, which says whose agent it is.
const GUEST_OS_FILE: &str = "guest_os";

/// The disk a warm snapshot takes: its memory, and its root disk's blocks
/// not shared with its image. Measured once, when it is built, because a
/// snapshot never changes and measuring a large disk's extents takes time.
const BYTES_FILE: &str = "bytes";

/// The digest of the agent this node ships for each guest OS, set once at
/// startup. A guest whose OS the node ships no agent for keeps whichever it
/// runs, so its snapshot is current with any.
static AGENTS: std::sync::OnceLock<std::collections::HashMap<burrow_vmm::GuestOs, String>> =
    std::sync::OnceLock::new();

pub fn set_agents(digests: std::collections::HashMap<burrow_vmm::GuestOs, String>) {
    let _ = AGENTS.set(digests);
}

type Agents = std::collections::HashMap<burrow_vmm::GuestOs, String>;

fn agent() -> Option<&'static Agents> {
    AGENTS.get()
}

/// The digest of the agent this node ships for `guest_os`, empty for none.
pub fn shipped_agent(guest_os: burrow_vmm::GuestOs) -> String {
    agent()
        .and_then(|agents| agents.get(&guest_os))
        .cloned()
        .unwrap_or_default()
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

/// The size of each of the snapshot's files when it was built. One of another
/// size was truncated or overwritten, and restoring it fails every create.
const SIZES_FILE: &str = "sizes";

fn render_sizes(sizes: &[(&str, u64)]) -> String {
    sizes
        .iter()
        .map(|(name, size)| format!("{name} {size}\n"))
        .collect()
}

fn parse_sizes(text: &str) -> Option<std::collections::HashMap<&str, u64>> {
    text.lines()
        .map(|line| {
            let (name, size) = line.split_once(' ')?;
            Some((name, size.parse().ok()?))
        })
        .collect()
}

/// The digest of the kernel the snapshot's guest booted. A restore boots the
/// template's kernel, so a snapshot of any other is stale: rebuilding a
/// template with another kernel rebuilds its warm snapshots.
const KERNEL_FILE: &str = "kernel";

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
            max_mem_mib: fields.next()?.parse().ok()?,
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
    /// build and then the node fit their caps. Pinned shapes count against
    /// the caps and are never chosen, unless `wanted` is given and leaves
    /// their build out: a build no tag resolves to keeps no pinned shape.
    pub fn evictions(
        &self,
        entries: &[(String, Warm)],
        wanted: Option<&std::collections::HashSet<String>>,
    ) -> Vec<usize> {
        let is_kept = |(key, warm): &(String, Warm)| {
            self.is_pinned(warm.shape) && wanted.is_none_or(|wanted| wanted.contains(key))
        };
        let mut order: Vec<usize> = (0..entries.len())
            .filter(|&index| !is_kept(&entries[index]))
            .collect();
        // A build no tag resolves to goes first, then by use.
        order.sort_by_key(|&index| {
            let (key, warm) = &entries[index];
            (
                wanted.is_some_and(|wanted| wanted.contains(key)),
                warm.used_at,
            )
        });
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
    pub fn to_proto(&self, key: &str, policy: &WarmPolicy) -> common::WarmShape {
        common::WarmShape {
            build_digest: crate::template::digest_of(key),
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
            template: String::new(),
        }
    }
}

/// The snapshot in `dir`, if it is complete, in the current format, of its
/// template's kernel and, when `agent` is given, built with that agent.
async fn read_warm(dir: &Path, agents: Option<&Agents>) -> Option<Warm> {
    let (dir, agents) = (dir.to_path_buf(), agents.cloned());
    tokio::task::spawn_blocking(move || read_warm_now(&dir, agents.as_ref()))
        .await
        .ok()
        .flatten()
}

/// [`read_warm`] on the calling thread. A create reads every snapshot on the
/// node to charge its disk, so its dozen small reads each are made in one
/// blocking call rather than a dozen.
fn read_warm_now(dir: &Path, agents: Option<&Agents>) -> Option<Warm> {
    use std::os::unix::fs::MetadataExt as _;

    let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok();
    let hypervisor: Hypervisor = read(HYPERVISOR_FILE)?.trim().parse().ok()?;
    if !is_current_format(&read("format")?) {
        return None;
    }
    let guest_os = burrow_vmm::GuestOs::from_record(read(GUEST_OS_FILE)?.trim())?;
    if let Some(shipped) = agents.and_then(|agents| agents.get(&guest_os))
        && read(AGENT_FILE)?.trim() != shipped
    {
        return None;
    }
    let shape = Shape::parse(&read(SHAPE_FILE)?)?;
    let sizes = read(SIZES_FILE)?;
    let sizes = parse_sizes(&sizes)?;
    for file in hypervisor.layout().files().chain([ROOT_DISK]) {
        let meta = std::fs::metadata(dir.join(file)).ok()?;
        if sizes.get(file) != Some(&meta.len()) {
            return None;
        }
    }
    let bytes = read(BYTES_FILE)?.trim().parse().ok()?;
    let used_at = match read(USED_FILE).and_then(|text| text.trim().parse().ok()) {
        Some(at) => at,
        None => std::fs::metadata(dir.join("format")).ok()?.mtime(),
    };
    Some(Warm {
        dir: dir.to_path_buf(),
        hypervisor,
        shape,
        bytes,
        used_at,
    })
}

/// The disk a snapshot in `dir` takes: its files' blocks, its root disk by
/// what it does not share with its image, since a reflinked clone of a large
/// image costs only what the build wrote to it.
async fn measure(dir: &Path, hypervisor: Hypervisor) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut bytes = crate::rootdisk::unshared_bytes(&dir.join(ROOT_DISK))?;
        for file in hypervisor.layout().files() {
            bytes += std::fs::metadata(dir.join(file))?.blocks() * 512;
        }
        if let Ok(plan) = std::fs::metadata(dir.join(PREFETCH_PLAN)) {
            bytes += plan.blocks() * 512;
        }
        Ok(bytes)
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Every build's warm snapshots, beside `builds_dir`.
fn warm_root(builds_dir: &Path) -> PathBuf {
    builds_dir.parent().map_or_else(
        || builds_dir.join(WARM_DIR),
        |data_dir| data_dir.join(WARM_DIR),
    )
}

/// The warm snapshots of the build in `key`. Keyed by the build, which never
/// changes, so a snapshot can never be restored onto a disk it was not taken
/// over and nothing has to invalidate one.
pub fn warm_dir(builds_dir: &Path, key: &str) -> PathBuf {
    warm_root(builds_dir).join(key)
}

/// Where a new snapshot is assembled before it is published.
///
/// Building in place would pull the snapshot out from under creates that
/// already decided to restore from it and are about to link its files.
fn warm_staging_dir(builds_dir: &Path, key: &str) -> PathBuf {
    warm_root(builds_dir).join(format!("{key}{WARM_STAGING_SUFFIX}"))
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
    read_warm(&dir, agent())
        .await
        .filter(|warm| warm.hypervisor == hypervisor && warm.shape.is_machine(wanted))
}

/// Where `template`'s snapshot of `wanted` under `hypervisor` is, when it is
/// there but does not read back: a file of it gone, or built with another
/// agent.
pub async fn find_broken(
    templates_dir: &Path,
    template: &str,
    hypervisor: Hypervisor,
    wanted: Shape,
) -> Option<PathBuf> {
    let dir = warm_dir(templates_dir, template).join(wanted.dir_name(hypervisor));
    is_broken(&dir, agent()).await.then_some(dir)
}

async fn is_broken(dir: &Path, agents: Option<&Agents>) -> bool {
    tokio::fs::try_exists(dir).await.unwrap_or(false) && read_warm(dir, agents).await.is_none()
}

/// Removes the snapshot in `dir` if it is still broken once no build is
/// swapping it, and says whether it did.
pub async fn discard_broken(dir: &Path) -> std::io::Result<bool> {
    let _no_builds = WARM_BUILD_LOCK.lock().await;
    if !is_broken(dir, agent()).await {
        return Ok(false);
    }
    tokio::fs::remove_dir_all(dir).await?;
    Ok(true)
}

/// A file a sandbox linked from a warm snapshot, by name and inode, so the
/// snapshot can be told apart from one rebuilt since after the sandbox's own
/// link is gone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Restored {
    name: std::ffi::OsString,
    file: (u64, u64),
}

impl Restored {
    pub fn of(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;

        let meta = std::fs::metadata(path)?;
        let name = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("a restored file has a name"))?;
        Ok(Self {
            name: name.to_os_string(),
            file: (meta.dev(), meta.ino()),
        })
    }
}

/// Removes the snapshot in `dir` if `restored` is still one of its own files,
/// and says whether it did. A snapshot rebuilt since is left alone.
pub async fn discard_restored(dir: &Path, restored: &Restored) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let _no_builds = WARM_BUILD_LOCK.lock().await;
    let Ok(own) = tokio::fs::metadata(dir.join(&restored.name)).await else {
        return Ok(false);
    };
    if (own.dev(), own.ino()) != restored.file {
        return Ok(false);
    }
    tokio::fs::remove_dir_all(dir).await?;
    Ok(true)
}

/// Every usable warm snapshot of `template`.
pub async fn list(templates_dir: &Path, template: &str) -> Vec<Warm> {
    let dir = warm_dir(templates_dir, template);
    tokio::task::spawn_blocking(move || list_now(&dir))
        .await
        .unwrap_or_default()
}

fn list_now(dir: &Path) -> Vec<Warm> {
    let mut out: Vec<Warm> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| read_warm_now(&entry.path(), agent()))
        .collect();
    out.sort_by_key(|warm| (warm.shape.vcpus, warm.shape.mem_mib));
    out
}

/// Every usable warm snapshot on the node, by build.
pub async fn list_all(templates_dir: &Path) -> Vec<(String, Warm)> {
    let root = warm_root(templates_dir);
    tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&root).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name.contains('.') {
                continue;
            }
            for warm in list_now(&entry.path()) {
                out.push((name.clone(), warm));
            }
        }
        out
    })
    .await
    .unwrap_or_default()
}

/// What under `template`'s warm directory cannot be restored: snapshots in
/// another format or with another agent, and pieces of one.
pub async fn stale(templates_dir: &Path, template: &str) -> Vec<PathBuf> {
    let root = warm_dir(templates_dir, template);
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(&root).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if read_warm(&path, agent()).await.is_none() {
            out.push(path);
        }
    }
    out
}

/// Whether `template` has a usable warm snapshot at all, whatever its shape.
pub async fn is_warm(templates_dir: &Path, template: &str) -> bool {
    !list(templates_dir, template).await.is_empty()
}

/// Files a sandbox needs in its working directory to restore from warm, but
/// its disk ([`clone_warm_disk`]): hard links, every one read-only or
/// verified immutable.
pub async fn link_warm(
    templates_dir: &Path,
    template: &str,
    snapshot: &Warm,
    workdir: &Path,
    phases: &mut burrow_vmm::Phases,
) -> std::io::Result<()> {
    let warm = &snapshot.dir;
    let template_dir = templates_dir.join(template);
    let layout = snapshot.hypervisor.layout();

    tokio::fs::create_dir_all(workdir).await?;
    let boot = match tokio::fs::try_exists(warm.join(crate::boot::FIRMWARE)).await? {
        true => (warm.join(crate::boot::FIRMWARE), crate::boot::FIRMWARE),
        false => (template_dir.join(crate::boot::KERNEL), crate::boot::KERNEL),
    };
    let linked = [boot, (template_dir.join(IMAGE), IMAGE)]
        .into_iter()
        .chain(layout.files().map(|name| (warm.join(name), name)));
    for (source, name) in linked {
        let dest = workdir.join(name);
        let _ = tokio::fs::remove_file(&dest).await;
        tokio::fs::hard_link(&source, &dest).await?;
    }

    // Copied, being the TPM's secrets: a link would be one inode shared
    // with every sandbox of the template.
    let tpm = warm.join(crate::tpm::FILE);
    if tokio::fs::try_exists(&tpm).await? {
        tokio::fs::copy(&tpm, workdir.join(crate::tpm::FILE)).await?;
    }

    // Optional: profiling is best effort, and a warm snapshot whose profiling
    // run failed simply has no plan.
    let plan = warm.join(PREFETCH_PLAN);
    if tokio::fs::try_exists(&plan).await.unwrap_or(false) {
        let dest = workdir.join(PREFETCH_PLAN);
        let _ = tokio::fs::remove_file(&dest).await;
        let _ = tokio::fs::hard_link(&plan, &dest).await;
    }
    phases.mark("link");
    Ok(())
}

/// Gives `workdir` its own copy of the snapshot's disk, the one file of it
/// that must not be shared.
pub async fn clone_warm_disk(
    snapshot: &Warm,
    workdir: &Path,
    phases: &mut burrow_vmm::Phases,
) -> std::io::Result<()> {
    let warm = &snapshot.dir;
    crate::rootdisk::clone(&warm.join(ROOT_DISK), &workdir.join(ROOT_DISK)).await?;
    phases.mark("disk");
    // Best effort, and behind the create: a snapshot whose use went
    // unrecorded is only evicted a little sooner than it should be.
    let used = warm.join(USED_FILE);
    tokio::spawn(async move {
        let _ = tokio::fs::write(used, burrow_common::unix_now().to_string()).await;
    });
    Ok(())
}

/// Boots a template, waits for its agent, and snapshots the running VM.
///
/// The warm VM runs on a fixed tap of its own. It never carries a policy or
/// serves anyone: its only job is to reach the point where a sandbox would be
/// ready, and stop there.
///
/// Its boot takes a cold-boot slot like a sandbox's, until its agent accepts.
///
/// It runs under the template's hypervisor and the node's confinement all the
/// same, taking the jailer, the cgroup root and the resource limits straight
/// off [`NodeConfig`] the way `SandboxManager::build_spec` does. A warm build boots a tenant's own image
/// and runs its init: exempting it would have the one VM on the node that
/// nobody is watching be the only one running unjailed and uncapped.
pub async fn build_warm_snapshot(
    config: &NodeConfig,
    pool: burrow_net::ipam::AddressPool,
    template: &str,
    shape: Shape,
    trust: &Trust,
    cold_boots: &crate::coldboot::ColdBoots,
) -> Result<Warm, Status> {
    let templates_dir = config.builds_dir();
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
    let (hypervisor, guest_os) = environment.machine()?;
    crate::sandbox::require_min_machine(template, guest_os, shape)?;
    let agent_timeout = config.agent_timeout(guest_os);
    if !config.hypervisors.contains(&hypervisor) {
        return Err(Status::failed_precondition(format!(
            "template {template} runs under {hypervisor}, which this node does not offer"
        )));
    }
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
    let vm_id = format!("warm-{}", template.get(..16).unwrap_or(template));
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

    // A firmware guest's snapshot carries the firmware it booted, as a
    // sandbox does, and so goes stale with nothing on the node.
    let boot = crate::boot::file(guest_os);
    let mut linked = vec![IMAGE];
    match boot {
        crate::boot::FIRMWARE => {
            crate::boot::take_firmware(&config.cloud_hypervisor.firmware, &run_dir)
                .await
                .map_err(|err| Status::internal(format!("staging the firmware: {err}")))?
        }
        kernel => linked.push(kernel),
    }
    for name in linked {
        tokio::fs::hard_link(template_dir.join(name), run_dir.join(name))
            .await
            .map_err(|err| Status::internal(format!("staging {name}: {err}")))?;
    }
    let kernel = crate::kernels::digest(&run_dir.join(boot))
        .await
        .map_err(|err| Status::internal(format!("hashing the boot file: {err}")))?;
    crate::rootdisk::clone(&run_dir.join(IMAGE), &run_dir.join(ROOT_DISK))
        .await
        .map_err(|err| Status::internal(format!("warm root disk: {err}")))?;
    crate::rootdisk::grow(&run_dir.join(ROOT_DISK), shape.disk_mib).await?;
    if let Some(jail) = config.jail_for(hypervisor) {
        // The kernel and image are hard links into the template's own
        // directory and are left alone for the reason
        // [`crate::sandbox::grant_to_jail`] gives; the root disk is this
        // build's own and has to be writable by the uid the VMM drops to.
        crate::sandbox::grant_to_jail(&run_dir, jail, &crate::boot::shared())
            .await
            .map_err(|err| Status::internal(format!("preparing the warm jail: {err}")))?;
    }

    // A throwaway lease: the address only has to be valid enough for the guest
    // to finish booting, and every clone is re-addressed on resume anyway.
    let lease = pool.warm_lease();
    burrow_net::tap::delete(WARM_TAP).await;
    let tap = burrow_net::tap::create_named(WARM_TAP, &lease)
        .await
        .map_err(|err| Status::internal(format!("warm tap: {err}")))?;

    // A TPM template's snapshot holds a TPM, made fresh for the build, which
    // every sandbox restored from it starts with a copy of.
    let tpm = environment.tpm.then(|| config.tpm(&vm_id, lease.block));
    if let Some(tpm) = &tpm {
        let _ = tokio::fs::remove_dir_all(&tpm.dir).await;
    }
    let spec = crate::spec::warm(
        config,
        &crate::spec::Guest {
            id: &vm_id,
            workdir: &run_dir,
            hypervisor,
            guest_os,
            lease: &lease,
            tap: &tap,
        },
        shape,
        environment.booted_systemd(),
        tpm.clone(),
    );

    let outcome = match cold_boots.admit(&vm_id).await {
        Ok(cold_boot) => {
            snapshot_when_ready(
                spec,
                cold_boot,
                agent_timeout,
                &lease,
                trust,
                config.upgrade_for(guest_os),
                capabilities.is_tap_networked && guest_os == burrow_vmm::GuestOs::Linux,
                guest_os == burrow_vmm::GuestOs::Windows,
            )
            .await
        }
        Err(err) => Err(err),
    };
    burrow_net::tap::delete(WARM_TAP).await;

    match outcome {
        Ok(built_with) => {
            // Restore the snapshot once, purely to learn which pages a guest
            // reaches for. Doing it here costs one boot at warm time and saves
            // thousands of faults on every create afterwards. Only the
            // page-fault handler records faults, or replays a plan.
            if capabilities.is_lazy_memory_supported
                && let Err(err) = profile_restore(
                    &vm_id, &run_dir, hypervisor, config, &pool, shape, trust, guest_os,
                )
                .await
            {
                tracing::warn!(template, %err, "could not record a prefetch plan");
            }
            if run_dir != dir {
                let collected = collect_products(&run_dir, &dir, hypervisor, boot).await;
                // The chroot itself is the jailer's; what was worth keeping is
                // out of it.
                let _ = config.remove_workdir(&run_dir).await;
                if let Err(err) = collected {
                    let _ = tokio::fs::remove_dir_all(&dir).await;
                    return Err(err);
                }
            }
            if let Some(tpm) = &tpm {
                let packed = crate::tpm::pack(&tpm.dir, &dir.join(crate::tpm::FILE)).await;
                let _ = tokio::fs::remove_dir_all(&tpm.dir).await;
                if let Err(err) = packed {
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
            tokio::fs::write(dir.join(KERNEL_FILE), &kernel)
                .await
                .map_err(|err| Status::internal(format!("recording warm kernel: {err}")))?;
            tokio::fs::write(dir.join(USED_FILE), burrow_common::unix_now().to_string())
                .await
                .map_err(|err| Status::internal(format!("recording warm use: {err}")))?;
            tokio::fs::write(dir.join(AGENT_FILE), built_with)
                .await
                .map_err(|err| Status::internal(format!("recording warm agent: {err}")))?;
            tokio::fs::write(dir.join(GUEST_OS_FILE), guest_os.as_str())
                .await
                .map_err(|err| Status::internal(format!("recording warm guest: {err}")))?;
            let bytes = measure(&dir, hypervisor)
                .await
                .map_err(|err| Status::internal(format!("measuring the warm snapshot: {err}")))?;
            tokio::fs::write(dir.join(BYTES_FILE), bytes.to_string())
                .await
                .map_err(|err| Status::internal(format!("recording warm size: {err}")))?;
            let mut sizes = Vec::new();
            for file in hypervisor.layout().files().chain([ROOT_DISK]) {
                let meta = tokio::fs::metadata(dir.join(file))
                    .await
                    .map_err(|err| Status::internal(format!("sizing warm {file}: {err}")))?;
                sizes.push((file, meta.len()));
            }
            tokio::fs::write(dir.join(SIZES_FILE), render_sizes(&sizes))
                .await
                .map_err(|err| Status::internal(format!("recording warm sizes: {err}")))?;
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

            let warm = read_warm(&live, agent()).await.ok_or_else(|| {
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
            if let Some(tpm) = &tpm {
                let _ = tokio::fs::remove_dir_all(&tpm.dir).await;
            }
            if run_dir != dir {
                let _ = config.remove_workdir(&run_dir).await;
            }
            Err(err)
        }
    }
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
    boot: &'static str,
) -> Result<(), Status> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = tokio::fs::metadata(dir)
        .await
        .map_err(|err| Status::internal(format!("reading the warm staging dir: {err}")))?;
    let (uid, gid) = (owner.uid(), owner.gid());

    let layout = hypervisor.layout();
    let carried = (boot == crate::boot::FIRMWARE).then_some(boot);
    for name in layout.files().chain([ROOT_DISK]).chain(carried) {
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
/// server's own machinery. Returns the client it did this on and the digest of
/// the agent it leaves running, upgraded to `upgrade` when that differs.
async fn exercise_agent(
    vm: &Vm,
    lease: &burrow_net::ipam::Lease,
    trust: &Trust,
    agent_timeout: std::time::Duration,
    upgrade: Option<&crate::guestconn::GuestUpgrade>,
    guest_os: burrow_vmm::GuestOs,
) -> Result<
    (
        burrow_proto::guest::v1::guest_client::GuestClient<tonic::transport::Channel>,
        String,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let agent = crate::guestconn::connect(vm.guest(), agent_timeout).await?;
    let (mut agent, response) = crate::guestconn::handshake_upgrading(
        agent,
        vm.guest(),
        crate::guestconn::handshake_full(
            true,
            Some(burrow_proto::guest::v1::NetworkConfig {
                // The lease its tap was made with.
                ip: lease.guest_ip.to_string(),
                prefix_len: lease.prefix_len as u32,
                gateway: lease.host_ip.to_string(),
                dns: lease.host_ip.to_string(),
                ip6: lease.guest_ip6().to_string(),
                prefix_len6: lease.prefix_len6() as u32,
                gateway6: lease.host_ip6().to_string(),
                public_addresses: Vec::new(),
                is_address_kept: false,
                pool: lease.pool().cidr(),
                pool6: lease.pool().cidr6(),
            }),
            trust.ca.clone(),
            trust.bundles.clone(),
            // A warm snapshot is shared by every sandbox restored from it, so
            // it must not carry any one sandbox's volumes.
            Vec::new(),
            String::new(),
        ),
        upgrade,
        agent_timeout,
    )
    .await?;
    if let Err(err) = warm_up(&mut agent, guest_os).await {
        // Not fatal: a snapshot without the warm-up is slower, not wrong.
        tracing::warn!(%err, "could not pre-warm the guest before snapshotting");
    }
    Ok((agent, response.agent_digest))
}

async fn warm_up(
    agent: &mut burrow_proto::guest::v1::guest_client::GuestClient<tonic::transport::Channel>,
    guest_os: burrow_vmm::GuestOs,
) -> Result<(), tonic::Status> {
    agent
        .health(burrow_proto::guest::v1::GuestHealthRequest {})
        .await?;
    // A clone's first exec otherwise faults in the agent's spawn path, the
    // kernel's fork and exec, and the shell, one page at a time.
    let start = burrow_proto::guest::v1::ExecInput {
        input: Some(burrow_proto::guest::v1::exec_input::Input::Start(
            burrow_proto::guest::v1::ExecStart {
                cmd: match guest_os {
                    burrow_vmm::GuestOs::Windows => {
                        vec!["cmd.exe".into(), "/c".into(), "rem".into()]
                    }
                    _ => vec!["sh".into(), "-c".into(), "true".into()],
                },
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
#[allow(clippy::too_many_arguments)]
async fn profile_restore(
    vm_id: &str,
    dir: &Path,
    hypervisor: Hypervisor,
    config: &NodeConfig,
    pool: &burrow_net::ipam::AddressPool,
    shape: Shape,
    trust: &Trust,
    guest_os: burrow_vmm::GuestOs,
) -> Result<(), Status> {
    let agent_timeout = config.agent_timeout(guest_os);
    // Not the snapshot's own address: a clone's handshake re-addresses its
    // guest, and a plan recorded without that would leave the code doing it
    // to fault in on every create.
    let lease = pool.profiling_lease();
    burrow_net::tap::delete(WARM_TAP).await;
    let tap = burrow_net::tap::create_named(WARM_TAP, &lease)
        .await
        .map_err(|err| Status::internal(format!("profiling tap: {err}")))?;

    // The build's own id, not one of its own: under the jailer the chroot is
    // derived from the id, and this VM restores the files that are inside the
    // one the build already filled.
    let spec = crate::spec::profile(
        config,
        &crate::spec::Guest {
            id: vm_id,
            workdir: dir,
            hypervisor,
            guest_os: burrow_vmm::GuestOs::Linux,
            lease: &lease,
            tap: &tap,
        },
        shape,
    );

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
            let _ = exercise_agent(
                &vm,
                &lease,
                trust,
                agent_timeout,
                config.upgrade_for(guest_os),
                guest_os,
            )
            .await;
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

/// Has the warm guest write back its page cache, so the disk published with
/// the snapshot holds every write the guest has acknowledged.
async fn sync_guest<T>(agent: &mut burrow_proto::guest::v1::guest_client::GuestClient<T>)
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
    use burrow_proto::guest::v1::{RootDiskRequest, root_disk_request::Op};
    let request = RootDiskRequest {
        op: Op::Sync as i32,
        ..Default::default()
    };
    if let Err(err) = agent.root_disk(request).await {
        tracing::warn!(%err, "could not sync the warm guest before snapshotting it");
    }
}

#[allow(clippy::too_many_arguments)]
async fn snapshot_when_ready(
    spec: MachineSpec,
    cold_boot: crate::coldboot::ColdBoot,
    agent_timeout: std::time::Duration,
    lease: &burrow_net::ipam::Lease,
    trust: &Trust,
    upgrade: Option<&crate::guestconn::GuestUpgrade>,
    is_cleared: bool,
    is_settled: bool,
) -> Result<String, Status> {
    let guest_os = spec.guest_os;
    let vm = Vm::boot(spec)
        .await
        .map_err(|err| Status::internal(format!("warm boot: {err}")))?;

    let ready = vm
        .wait_for_vsock(crate::guestconn::AGENT_PORT, agent_timeout)
        .await;
    drop(cold_boot);
    if let Err(err) = ready {
        let console = vm.console_tail(30).await;
        let _ = vm.kill().await;
        return Err(Status::internal(format!(
            "warm guest never became ready: {err}\nconsole:\n{console}"
        )));
    }

    // A full handshake before snapshotting. It bakes the warmed guest-side
    // state into the snapshot: measured, the first handshake after a restore
    // cost ~180ms against ~9ms for a second on a fresh channel, so the cost is
    // guest coldness rather than transport. It also brings the agent up to
    // this node's, which the snapshot is then keyed on, so no create from it
    // upgrades the agent in place.
    let (mut agent, digest) =
        match exercise_agent(&vm, lease, trust, agent_timeout, upgrade, guest_os).await {
            Ok(exercised) => exercised,
            Err(err) => {
                let _ = vm.kill().await;
                return Err(Status::internal(format!(
                    "the warm guest's agent did not handshake: {err}"
                )));
            }
        };
    // Taken without an address, so a clone's handshake adds its own and has
    // nothing to remove. Not fatal: a guest that keeps the warm address is
    // re-addressed the slower way.
    if is_cleared
        && let Err(err) = agent
            .clear_network(burrow_proto::guest::v1::ClearNetworkRequest {})
            .await
    {
        tracing::warn!(%err, "could not clear the warm guest's network");
    }
    sync_guest(&mut agent).await;
    drop(agent);
    if is_settled {
        settle(&vm).await;
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
        .map_err(|err| Status::internal(format!("stopping warm vm: {err}")))?;
    Ok(digest)
}

/// Waits, up to [`SETTLE_LIMIT`], for a guest to go quiet. Windows spends
/// its first minutes after boot on services, updates and scans, and a
/// snapshot taken in the middle of that hands the same work to every clone.
async fn settle(vm: &Vm) {
    let started = std::time::Instant::now();
    let mut quiet = 0;
    let mut last = vm.cpu_usage_usec();
    while started.elapsed() < SETTLE_LIMIT && quiet < 2 {
        tokio::time::sleep(SETTLE_WINDOW).await;
        let now = vm.cpu_usage_usec();
        let busy = match (last, now) {
            (Some(last), Some(now)) => now.saturating_sub(last),
            _ => return,
        };
        last = now;
        // Under a fifth of one CPU across the window.
        quiet = match busy < SETTLE_WINDOW.as_micros() as u64 / 5 {
            true => quiet + 1,
            false => 0,
        };
    }
    tracing::info!(
        settled = quiet >= 2,
        took_ms = started.elapsed().as_millis() as u64,
        "waited for the warm guest to go quiet"
    );
}

const SETTLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);
const SETTLE_LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

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
            "2 1024 1324",
            "two 1024 1 1",
            "2 lots 1 1",
            "2 1024 1 1 1",
            "\n",
        ] {
            assert_eq!(Shape::parse(bad), None, "{bad:?} should not parse");
        }
    }

    #[test]
    fn only_the_current_format_is_warm() {
        assert_eq!(WARM_FORMAT, "10");
        assert!(is_current_format("10"));
        assert!(is_current_format("10\n"));
        for other in ["", "9", "11"] {
            assert!(!is_current_format(other), "{other:?} is not current");
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
        assert_eq!(policy(2, 16).evictions(&entries, None), vec![1]);
        assert_eq!(policy(1, 16).evictions(&entries, None), vec![1, 2]);
        assert!(policy(3, 16).evictions(&entries, None).is_empty());
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
        assert_eq!(policy(2, 16).evictions(&entries, None), vec![1]);
        // Even past a cap only pinned shapes would meet.
        let mut pinned = policy(0, 16);
        pinned
            .pinned
            .push(parse_shape("4x4096").unwrap().resolved());
        assert_eq!(pinned.evictions(&entries, None), vec![1]);
    }

    #[test]
    fn the_node_cap_evicts_across_templates() {
        let entries = [
            entry("app", 2, 1024, 1, 100),
            entry("db", 2, 1024, 1, 50),
            entry("db", 4, 1024, 1, 400),
            entry("web", 2, 1024, 1, 300),
        ];
        assert_eq!(policy(4, 2).evictions(&entries, None), vec![0, 1]);
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
        assert_eq!(by_template.evictions(&entries, None), vec![0]);
        let mut by_node = policy(16, 16);
        by_node.per_node_bytes = 1000;
        assert_eq!(by_node.evictions(&entries, None), vec![0, 1]);
    }

    /// A build counts its snapshot as the newest, so the caps pick it only
    /// when the pinned snapshots leave it no room, which is how the node
    /// knows not to build it at all.
    #[test]
    fn a_snapshot_the_pinned_ones_leave_no_room_for_is_its_own_eviction() {
        let entries = [
            entry("app", 1, 512, 6 << 30, 0),
            entry("app", 1, 1024, 6 << 30, i64::MAX),
        ];
        let mut policy = policy(16, 16);
        policy.per_template_bytes = 8 << 30;
        assert_eq!(policy.evictions(&entries, None), vec![1]);
        policy.per_template_bytes = 12 << 30;
        assert!(policy.evictions(&entries, None).is_empty());
    }

    /// A pinned snapshot of a build no tag resolves to is evicted like any
    /// other, and before a wanted build's.
    #[test]
    fn a_build_nobody_wants_keeps_no_pinned_snapshot() {
        let entries = [
            entry("old", 1, 512, 6 << 30, 5),
            entry("new", 1, 512, 6 << 30, 1),
            entry("new", 2, 1024, 6 << 30, 0),
        ];
        let mut policy = policy(16, 16);
        policy.per_node_bytes = 12 << 30;
        assert_eq!(policy.evictions(&entries, None), vec![2]);
        let wanted: std::collections::HashSet<String> = ["new".to_string()].into();
        assert_eq!(policy.evictions(&entries, Some(&wanted)), vec![0]);
        assert_eq!(
            policy.evictions(&entries, Some(&Default::default())),
            vec![2]
        );
    }

    /// A data directory's builds directory, so its warm snapshots are beside
    /// it and nobody else's.
    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!(
                "burrow-warm-{name}-{}",
                uuid::Uuid::new_v4().simple()
            ))
            .join("builds");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_snapshot(dir: &Path, format: &str, shape: &str) {
        std::fs::create_dir_all(dir).unwrap();
        for file in Hypervisor::Firecracker.layout().files().chain([ROOT_DISK]) {
            std::fs::write(dir.join(file), b"x").unwrap();
        }
        std::fs::write(dir.join(KERNEL_FILE), "kernel").unwrap();
        std::fs::write(dir.join(HYPERVISOR_FILE), "firecracker").unwrap();
        std::fs::write(dir.join(GUEST_OS_FILE), "linux").unwrap();
        std::fs::write(dir.join(BYTES_FILE), "1").unwrap();
        std::fs::write(dir.join(SHAPE_FILE), shape).unwrap();
        let sizes: Vec<(&str, u64)> = Hypervisor::Firecracker
            .layout()
            .files()
            .chain([ROOT_DISK])
            .map(|file| (file, 1))
            .collect();
        std::fs::write(dir.join(SIZES_FILE), render_sizes(&sizes)).unwrap();
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
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    /// A snapshot with a file gone is broken and discarded, but not once a
    /// build has swapped a whole one in for it.
    #[tokio::test]
    async fn only_a_snapshot_still_broken_is_discarded() {
        let templates = temp("broken");
        let wanted = parse_shape("2x2048").unwrap();
        let live = warm_dir(&templates, "app").join("firecracker-2x2048");
        write_snapshot(&live, WARM_FORMAT, "2 2048 1324 0");
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

        write_snapshot(&live, WARM_FORMAT, "2 2048 1324 0");
        assert!(!discard_broken(&broken).await.unwrap());
        assert!(live.exists());

        std::fs::remove_file(live.join(ROOT_DISK)).unwrap();
        assert!(discard_broken(&broken).await.unwrap());
        assert!(!live.exists());
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    /// A snapshot whose restored guest never came up is discarded, but not
    /// one rebuilt since that sandbox linked its files.
    #[tokio::test]
    async fn only_the_snapshot_a_failed_sandbox_restored_is_discarded() {
        let templates = temp("restored");
        let live = warm_dir(&templates, "app").join("firecracker-2x2048");
        let sandbox = templates.join("sbx");
        std::fs::create_dir_all(&sandbox).unwrap();
        let state = Hypervisor::Firecracker.layout().state;
        let link = |snapshot: &Path| {
            let _ = std::fs::remove_file(sandbox.join(state));
            std::fs::hard_link(snapshot.join(state), sandbox.join(state)).unwrap();
        };

        write_snapshot(&live, WARM_FORMAT, "2 2048 1324 0");
        link(&live);
        let restored = Restored::of(&sandbox.join(state)).unwrap();
        std::fs::remove_dir_all(&live).unwrap();
        write_snapshot(&live, WARM_FORMAT, "2 2048 1324 0");
        assert!(!discard_restored(&live, &restored).await.unwrap());
        assert!(live.exists());

        link(&live);
        let restored = Restored::of(&sandbox.join(state)).unwrap();
        std::fs::remove_dir_all(&sandbox).unwrap();
        assert!(discard_restored(&live, &restored).await.unwrap());
        assert!(!live.exists());
        assert!(!discard_restored(&live, &restored).await.unwrap());
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    /// A memory or state file cut short, or overwritten with another size,
    /// makes its snapshot broken, so it is rebuilt rather than restored.
    #[tokio::test]
    async fn a_snapshot_with_a_file_of_another_size_is_broken() {
        let templates = temp("sizes");
        let wanted = parse_shape("2x2048").unwrap();
        let live = warm_dir(&templates, "app").join("firecracker-2x2048");
        let layout = Hypervisor::Firecracker.layout();
        for file in layout.files().chain([ROOT_DISK]) {
            write_snapshot(&live, WARM_FORMAT, "2 2048 1324 0");
            assert!(
                find(&templates, "app", Hypervisor::Firecracker, wanted)
                    .await
                    .is_some()
            );
            std::fs::write(live.join(file), b"").unwrap();
            assert!(
                find(&templates, "app", Hypervisor::Firecracker, wanted)
                    .await
                    .is_none(),
                "{file} cut short"
            );
            assert_eq!(
                find_broken(&templates, "app", Hypervisor::Firecracker, wanted).await,
                Some(live.clone())
            );
        }
        write_snapshot(&live, WARM_FORMAT, "2 2048 1324 0");
        std::fs::remove_file(live.join(SIZES_FILE)).unwrap();
        assert!(read_warm(&live, None).await.is_none());
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    #[test]
    fn sizes_round_trip_through_their_file() {
        let sizes = [("snapshot.mem", 536870912), ("root.ext4", 1)];
        let text = render_sizes(&sizes);
        let parsed = parse_sizes(&text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["snapshot.mem"], 536870912);
        assert_eq!(parse_sizes("snapshot.mem lots\n"), None);
    }

    /// A snapshot built with another agent is stale like one in another
    /// format, so a create finds it broken and it is built again.
    #[tokio::test]
    async fn a_snapshot_with_another_agent_is_stale() {
        let templates = temp("agent");
        let dir = warm_dir(&templates, "app").join("firecracker-1x512");
        write_snapshot(&dir, WARM_FORMAT, "1 512 1324 512");
        let agents = |linux: &str| {
            Agents::from([
                (burrow_vmm::GuestOs::Linux, linux.to_string()),
                (burrow_vmm::GuestOs::Windows, "windows".to_string()),
            ])
        };
        assert!(read_warm(&dir, Some(&agents("new"))).await.is_none());
        std::fs::write(dir.join(AGENT_FILE), "old\n").unwrap();
        assert!(read_warm(&dir, Some(&agents("new"))).await.is_none());
        assert!(is_broken(&dir, Some(&agents("new"))).await);
        assert!(read_warm(&dir, Some(&agents("old"))).await.is_some());
        assert!(!is_broken(&dir, Some(&agents("old"))).await);
        // A node shipping no agent for the snapshot's OS keeps it.
        std::fs::write(dir.join(GUEST_OS_FILE), "windows").unwrap();
        let linux_only = Agents::from([(burrow_vmm::GuestOs::Linux, "new".to_string())]);
        assert!(read_warm(&dir, Some(&linux_only)).await.is_some());
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    /// A snapshot in another format is stale and discarded.
    #[tokio::test]
    async fn a_snapshot_in_another_format_is_stale() {
        let templates = temp("stale");
        let warm = warm_dir(&templates, "app");
        write_snapshot(
            &warm.join("firecracker-1x512"),
            WARM_FORMAT,
            "1 512 1324 512",
        );
        write_snapshot(&warm.join("firecracker-4x4096"), "6", "4 4096 1324 4096");
        assert_eq!(
            stale(&templates, "app").await,
            vec![warm.join("firecracker-4x4096")]
        );
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    /// A snapshot of a firmware guest carries the firmware it booted, so a
    /// template with no kernel at all still has a current snapshot, and a
    /// restore links the snapshot's firmware rather than anything of the
    /// template's.
    #[tokio::test]
    async fn a_snapshot_carrying_its_firmware_needs_no_template_kernel() {
        let templates = temp("firmware");
        let live = warm_dir(&templates, "win").join("firecracker-2x4096");
        write_snapshot(&live, WARM_FORMAT, "2 4096 25600 4096");
        std::fs::create_dir_all(templates.join("win")).unwrap();
        std::fs::write(live.join(crate::boot::FIRMWARE), b"edk2").unwrap();
        std::fs::write(templates.join("win").join(IMAGE), b"image").unwrap();
        let wanted = Shape {
            vcpus: 2,
            mem_mib: 4096,
            disk_mib: 25600,
            max_mem_mib: 4096,
        };
        let warm = find(&templates, "win", Hypervisor::Firecracker, wanted)
            .await
            .unwrap();
        let workdir = templates.join("work");
        link_warm(
            &templates,
            "win",
            &warm,
            &workdir,
            &mut burrow_vmm::Phases::start(),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(workdir.join(crate::boot::FIRMWARE)).unwrap(),
            b"edk2"
        );
        assert!(!workdir.join(crate::boot::KERNEL).exists());
        let _ = std::fs::remove_dir_all(templates.parent().unwrap());
    }

    /// Answers RootDisk, recording the op it was asked for.
    #[derive(Clone, Default)]
    struct RootDiskGuest(std::sync::Arc<std::sync::Mutex<Vec<i32>>>);

    impl tower::Service<tonic::codegen::http::Request<tonic::body::Body>> for RootDiskGuest {
        type Response = tonic::codegen::http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
            struct RootDisk(std::sync::Arc<std::sync::Mutex<Vec<i32>>>);
            impl tonic::server::UnaryService<burrow_proto::guest::v1::RootDiskRequest> for RootDisk {
                type Response = burrow_proto::guest::v1::RootDiskResponse;
                type Future = tonic::codegen::BoxFuture<tonic::Response<Self::Response>, Status>;
                fn call(
                    &mut self,
                    req: tonic::Request<burrow_proto::guest::v1::RootDiskRequest>,
                ) -> Self::Future {
                    self.0.lock().unwrap().push(req.get_ref().op);
                    Box::pin(async { Ok(tonic::Response::new(Default::default())) })
                }
            }
            let ops = self.0.clone();
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.unary(RootDisk(ops), req).await)
            })
        }
    }

    #[tokio::test]
    async fn the_warm_guest_is_synced_before_its_snapshot() {
        use burrow_proto::guest::v1::root_disk_request::Op;
        let guest = RootDiskGuest::default();
        let mut agent = burrow_proto::guest::v1::guest_client::GuestClient::new(guest.clone());
        sync_guest(&mut agent).await;
        assert_eq!(*guest.0.lock().unwrap(), vec![Op::Sync as i32]);
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
