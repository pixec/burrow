//! Guest kernels: the ones this node builds templates with, and what each
//! has built in.
//!
//! What a kernel can do is read from the image, never taken from an
//! operator's word for it. The kernel's own config is exact, so it comes
//! first: the copy a kernel built with `CONFIG_IKCONFIG` embeds between
//! `IKCFG_ST` and `IKCFG_ED` (the Firecracker CI kernels do), else a
//! `<image>.config` beside the image (the file Firecracker CI publishes with
//! each one). A kernel with neither, such as Cloud Hypervisor's, is read for
//! names only built-in code puts in it: a driver's name is its
//! `KBUILD_MODNAME`, a NUL-terminated string that is in the image when the
//! driver is built in and in a module file when it is not. Burrow guests load
//! no modules, so built in is the only kind that counts.

#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use burrow_proto::common::v1 as common;
use burrow_vmm::Hypervisor;
use tonic::Status;

/// What a kernel has built in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub is_kvm_built_in: bool,
    pub is_virtio_mem_built_in: bool,
    pub is_vsock_built_in: bool,
    pub is_virtio_blk_built_in: bool,
    pub is_ext4_built_in: bool,
}

impl Capabilities {
    pub fn to_proto(self) -> common::KernelCapabilities {
        common::KernelCapabilities {
            is_kvm_built_in: self.is_kvm_built_in,
            is_virtio_mem_built_in: self.is_virtio_mem_built_in,
            is_vsock_built_in: self.is_vsock_built_in,
            is_virtio_blk_built_in: self.is_virtio_blk_built_in,
            is_ext4_built_in: self.is_ext4_built_in,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ikconfig,
    Config,
    Strings,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ikconfig => "ikconfig",
            Self::Config => "config",
            Self::Strings => "strings",
        }
    }
}

/// What reading a kernel image found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub arch: &'static str,
    pub version: String,
    pub capabilities: Capabilities,
    pub source: Source,
    /// Burrow attaches every device over virtio-pci, under both hypervisors.
    pub is_virtio_pci_built_in: bool,
    /// The image carries a PVH entry point, which Cloud Hypervisor enters an
    /// x86_64 vmlinux through.
    pub is_pvh: bool,
}

impl Detected {
    /// Why a guest of this kernel cannot run under `hypervisor`, if it cannot.
    pub fn unbootable_under(&self, hypervisor: Hypervisor) -> Option<String> {
        let caps = self.capabilities;
        let mut missing = Vec::new();
        for (has, what) in [
            (self.is_virtio_pci_built_in, "virtio-pci"),
            (caps.is_vsock_built_in, "virtio-vsock"),
            (caps.is_virtio_blk_built_in, "virtio-blk"),
            (caps.is_ext4_built_in, "ext4"),
        ] {
            if !has {
                missing.push(what);
            }
        }
        match hypervisor {
            Hypervisor::Firecracker => {}
            Hypervisor::CloudHypervisor => {
                if self.arch == "x86_64" && !self.is_pvh {
                    missing.push("a PVH entry point (CONFIG_PVH)");
                }
            }
            Hypervisor::Vz => {
                return Some("vz boots installed macOS machines, not a kernel".into());
            }
        }
        (!missing.is_empty()).then(|| format!("it has no {} built in", missing.join(", ")))
    }
}

/// Reads what `image` has built in. `config` is a `.config` shipped beside
/// it, used only when the image embeds none.
pub fn detect(image: &[u8], config: Option<&str>) -> Result<Detected, String> {
    let arch = arch(image)?;
    let version = find(image, b"Linux version ")
        .map(|at| {
            let rest = &image[at + 14..];
            let end = rest.iter().position(|b| *b == b' ' || *b == 0).unwrap_or(0);
            String::from_utf8_lossy(&rest[..end]).into_owned()
        })
        .unwrap_or_default();
    let embedded = ikconfig(image);
    let (config, source) = match (&embedded, config) {
        (Some(text), _) => (Some(text.as_str()), Source::Ikconfig),
        (None, Some(text)) => (Some(text), Source::Config),
        (None, None) => (None, Source::Strings),
    };
    let (capabilities, is_virtio_pci_built_in, is_pvh) = match config {
        Some(text) => {
            let set: HashSet<&str> = text
                .lines()
                .filter_map(|line| line.strip_suffix("=y")?.strip_prefix("CONFIG_"))
                .collect();
            let y = |option: &str| set.contains(option);
            let capabilities = Capabilities {
                is_kvm_built_in: y("KVM") && (arch != "x86_64" || y("KVM_INTEL") || y("KVM_AMD")),
                is_virtio_mem_built_in: y("VIRTIO_MEM"),
                is_vsock_built_in: y("VIRTIO_VSOCKETS"),
                is_virtio_blk_built_in: y("VIRTIO_BLK"),
                is_ext4_built_in: y("EXT4_FS"),
            };
            (capabilities, y("VIRTIO_PCI"), y("PVH"))
        }
        None => {
            let has = |needle: &[u8]| find(image, needle).is_some();
            let capabilities = Capabilities {
                // The anonymous inode every VM is, and on x86_64 the `nested`
                // parameter of a vendor backend.
                is_kvm_built_in: has(b"\0kvm-vm\0")
                    && (arch != "x86_64" || has(b"kvm_intel.nested\0") || has(b"kvm_amd.nested\0")),
                is_virtio_mem_built_in: has(b"\0virtio_mem\0"),
                is_vsock_built_in: has(b"\0vmw_vsock_virtio_transport\0"),
                is_virtio_blk_built_in: has(b"\0virtio_blk\0"),
                // The prefix of every message ext4 prints.
                is_ext4_built_in: has(b"EXT4-fs ("),
            };
            (capabilities, has(b"\0virtio-pci\0"), has_pvh_note(image))
        }
    };
    Ok(Detected {
        arch,
        version,
        capabilities,
        source,
        is_virtio_pci_built_in,
        is_pvh,
    })
}

fn arch(image: &[u8]) -> Result<&'static str, String> {
    if image.starts_with(b"\x7fELF") && image.len() > 20 {
        return match u16::from_le_bytes([image[18], image[19]]) {
            62 => Ok("x86_64"),
            183 => Ok("aarch64"),
            machine => Err(format!(
                "an ELF image for machine {machine}, which no guest here is"
            )),
        };
    }
    if image.get(56..60) == Some(b"ARM\x64") {
        return Ok("aarch64");
    }
    if image.get(0x202..0x206) == Some(b"HdrS") {
        return Err(
            "a compressed bzImage; give its uncompressed vmlinux, which both \
                    hypervisors boot"
                .into(),
        );
    }
    if image.starts_with(&[0x1f, 0x8b]) {
        return Err("gzip-compressed; give the uncompressed Image".into());
    }
    Err("not a kernel image: expected an x86_64 vmlinux (ELF) or an arm64 Image".into())
}

/// The config a kernel built with `CONFIG_IKCONFIG` carries, gzipped between
/// two markers.
fn ikconfig(image: &[u8]) -> Option<String> {
    use std::io::Read as _;
    let start = find(image, b"IKCFG_ST")? + 8;
    let end = start + find(&image[start..], b"IKCFG_ED")?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(&image[start..end])
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// Whether an x86_64 vmlinux carries Xen's PHYS32_ENTRY note, the PVH entry
/// point.
fn has_pvh_note(image: &[u8]) -> bool {
    const PT_NOTE: u32 = 4;
    const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;
    let u16_at = |at: usize| {
        image
            .get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |at: usize| {
        image
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let u64_at = |at: usize| {
        image
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    };
    if !image.starts_with(b"\x7fELF") || image.get(4) != Some(&2) {
        return false;
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (u64_at(0x20), u16_at(0x36), u16_at(0x38))
    else {
        return false;
    };
    for index in 0..usize::from(phnum) {
        let header = phoff as usize + index * usize::from(phentsize);
        if u32_at(header) != Some(PT_NOTE) {
            continue;
        }
        let (Some(offset), Some(size)) = (u64_at(header + 8), u64_at(header + 32)) else {
            continue;
        };
        let (mut at, end) = (offset as usize, (offset + size) as usize);
        while at + 12 <= end {
            let (Some(namesz), Some(descsz), Some(kind)) =
                (u32_at(at), u32_at(at + 4), u32_at(at + 8))
            else {
                break;
            };
            let name = image.get(at + 12..at + 12 + namesz as usize);
            if kind == XEN_ELFNOTE_PHYS32_ENTRY && name == Some(b"Xen\0") {
                return true;
            }
            at +=
                12 + (namesz as usize).next_multiple_of(4) + (descsz as usize).next_multiple_of(4);
        }
    }
    false
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

/// A kernel file as content, read once per file and once per content: every
/// template, warm snapshot and sandbox of one kernel hard-links one inode.
#[derive(Debug, Clone)]
pub struct Inspected {
    pub digest: String,
    pub detected: Arc<Detected>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
}

static DIGESTS: LazyLock<Mutex<HashMap<FileKey, String>>> = LazyLock::new(Default::default);
static DETECTED: LazyLock<Mutex<HashMap<String, Arc<Detected>>>> = LazyLock::new(Default::default);

fn file_key(meta: &std::fs::Metadata) -> FileKey {
    use std::os::unix::fs::MetadataExt as _;
    FileKey {
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.size(),
        mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
    }
}

/// The SHA-256 of the kernel at `path`, hashed once per file.
pub async fn digest(path: &Path) -> std::io::Result<String> {
    let key = file_key(&tokio::fs::metadata(path).await?);
    if let Some(digest) = DIGESTS.lock().unwrap().get(&key) {
        return Ok(digest.clone());
    }
    let digest = crate::blobs::hash_file(path).await?.to_string();
    DIGESTS.lock().unwrap().insert(key, digest.clone());
    Ok(digest)
}

/// The kernel at `path`: its digest, and what it has built in.
pub async fn inspect(path: &Path) -> Result<Inspected, String> {
    inspect_with(path, None).await
}

async fn inspect_with(path: &Path, config: Option<&Path>) -> Result<Inspected, String> {
    let digest = digest(path)
        .await
        .map_err(|err| format!("{}: {err}", path.display()))?;
    if let Some(detected) = DETECTED.lock().unwrap().get(&digest) {
        return Ok(Inspected {
            digest,
            detected: Arc::clone(detected),
        });
    }
    let image = tokio::fs::read(path)
        .await
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let config = match config {
        Some(config) => tokio::fs::read_to_string(config).await.ok(),
        None => None,
    };
    let detected = tokio::task::spawn_blocking(move || detect(&image, config.as_deref()))
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let detected = Arc::new(detected);
    DETECTED
        .lock()
        .unwrap()
        .insert(digest.clone(), Arc::clone(&detected));
    Ok(Inspected { digest, detected })
}

/// A `--kernel` flag: `NAME[@HYPERVISOR+HYPERVISOR]=PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelArg {
    pub name: String,
    pub hypervisors: Vec<Hypervisor>,
    pub path: PathBuf,
}

pub fn parse_kernel_arg(value: &str) -> Result<KernelArg, String> {
    let (head, path) = value
        .split_once('=')
        .ok_or_else(|| format!("{value:?}: expected NAME[@HYPERVISOR+...]=PATH"))?;
    let (name, hypervisors) = match head.split_once('@') {
        Some((name, list)) => (
            name,
            list.split('+')
                .map(str::parse)
                .collect::<Result<Vec<Hypervisor>, _>>()?,
        ),
        None => (head, Vec::new()),
    };
    crate::template::validate_name(name).map_err(|err| format!("{value:?}: {}", err.message()))?;
    if path.is_empty() {
        return Err(format!("{value:?}: no path"));
    }
    Ok(KernelArg {
        name: name.to_string(),
        hypervisors,
        path: path.into(),
    })
}

/// A `--default-kernel` flag: `HYPERVISOR=NAME`.
pub fn parse_default_kernel(value: &str) -> Result<(Hypervisor, String), String> {
    let (hypervisor, name) = value
        .split_once('=')
        .ok_or_else(|| format!("{value:?}: expected HYPERVISOR=NAME"))?;
    Ok((hypervisor.parse()?, name.to_string()))
}

/// Where the node image puts the kernels it ships, and the names they go by.
pub const SHIPPED: [(&str, Hypervisor, &str); 2] = [
    (
        "firecracker-ci",
        Hypervisor::Firecracker,
        "/usr/local/share/burrow/kernels/firecracker-ci",
    ),
    (
        "ch-linux",
        Hypervisor::CloudHypervisor,
        "/usr/local/share/burrow/kernels/ch-linux",
    ),
];

#[derive(Debug, Clone)]
pub struct Kernel {
    pub name: String,
    pub path: PathBuf,
    pub digest: String,
    pub hypervisors: Vec<Hypervisor>,
    pub detected: Arc<Detected>,
}

/// The kernels a template can be built with on this node.
#[derive(Debug, Clone, Default)]
pub struct Kernels {
    list: Vec<Kernel>,
    defaults: HashMap<Hypervisor, String>,
}

impl Kernels {
    /// Reads the kernels the node image ships that are present, and every
    /// kernel named on the command line, which replaces a shipped one of the
    /// same name. A named kernel that cannot be read, is for another
    /// architecture, or lacks what a guest needs refuses startup; so does one
    /// asked to run under a hypervisor it cannot boot under.
    pub async fn load(
        args: &[KernelArg],
        defaults: &[(Hypervisor, String)],
        offered: &[Hypervisor],
    ) -> anyhow::Result<Self> {
        let shipped: Vec<KernelArg> = SHIPPED
            .iter()
            .filter(|(name, _, path)| {
                !args.iter().any(|arg| arg.name == *name) && Path::new(path).exists()
            })
            .map(|(name, _, path)| KernelArg {
                name: name.to_string(),
                hypervisors: Vec::new(),
                path: path.into(),
            })
            .collect();
        let mut list: Vec<Kernel> = Vec::new();
        for arg in shipped.iter().chain(args) {
            if list.iter().any(|k| k.name == arg.name) {
                anyhow::bail!("--kernel {}: named twice", arg.name);
            }
            let config = PathBuf::from(format!("{}.config", arg.path.display()));
            let inspected = inspect_with(&arg.path, Some(&config))
                .await
                .map_err(|err| anyhow::anyhow!("--kernel {}: {err}", arg.name))?;
            let detected = inspected.detected;
            if detected.arch != std::env::consts::ARCH {
                anyhow::bail!(
                    "--kernel {}: an {} kernel, on an {} node",
                    arg.name,
                    detected.arch,
                    std::env::consts::ARCH
                );
            }
            let hypervisors = match arg.hypervisors.is_empty() {
                false => {
                    for hypervisor in &arg.hypervisors {
                        if let Some(why) = detected.unbootable_under(*hypervisor) {
                            anyhow::bail!(
                                "--kernel {}: cannot boot a guest under {hypervisor}: {why}",
                                arg.name
                            );
                        }
                    }
                    arg.hypervisors.clone()
                }
                true => offered
                    .iter()
                    .copied()
                    .filter(|h| detected.unbootable_under(*h).is_none())
                    .collect(),
            };
            if hypervisors.is_empty() {
                anyhow::bail!(
                    "--kernel {}: boots under none of the hypervisors offered here ({})",
                    arg.name,
                    offered
                        .iter()
                        .filter_map(|h| detected
                            .unbootable_under(*h)
                            .map(|why| format!("{h}: {why}")))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
            }
            tracing::info!(
                kernel = arg.name,
                path = %arg.path.display(),
                version = detected.version,
                from = detected.source.as_str(),
                capabilities = ?detected.capabilities,
                hypervisors = ?hypervisors,
                "guest kernel"
            );
            list.push(Kernel {
                name: arg.name.clone(),
                path: arg.path.clone(),
                digest: inspected.digest,
                hypervisors,
                detected,
            });
        }
        let mut kernels = Self {
            list,
            defaults: HashMap::new(),
        };
        for hypervisor in offered {
            let named = defaults
                .iter()
                .find(|(h, _)| h == hypervisor)
                .map(|(_, name)| name.clone());
            let name = match named {
                Some(name) => {
                    if kernels.for_hypervisor(*hypervisor, &name).is_none() {
                        anyhow::bail!(
                            "--default-kernel {hypervisor}={name}: no kernel {name} for {hypervisor}"
                        );
                    }
                    name
                }
                None => match kernels.fallback_default(*hypervisor) {
                    Some(name) => name,
                    None => continue,
                },
            };
            kernels.defaults.insert(*hypervisor, name);
        }
        Ok(kernels)
    }

    /// With no `--default-kernel`: the shipped kernel for the hypervisor, else
    /// the only one it has.
    fn fallback_default(&self, hypervisor: Hypervisor) -> Option<String> {
        let shipped = SHIPPED
            .iter()
            .find(|(_, h, _)| *h == hypervisor)
            .map(|(name, _, _)| *name);
        if let Some(name) = shipped
            && self.for_hypervisor(hypervisor, name).is_some()
        {
            return Some(name.to_string());
        }
        let mut usable = self
            .list
            .iter()
            .filter(|k| k.hypervisors.contains(&hypervisor));
        match (usable.next(), usable.next()) {
            (Some(only), None) => Some(only.name.clone()),
            _ => None,
        }
    }

    fn for_hypervisor(&self, hypervisor: Hypervisor, name: &str) -> Option<&Kernel> {
        self.list
            .iter()
            .find(|k| k.name == name && k.hypervisors.contains(&hypervisor))
    }

    /// The kernel a template under `hypervisor` is built with: `requested`
    /// by name, or the hypervisor's default.
    pub fn choose(&self, hypervisor: Hypervisor, requested: &str) -> Result<&Kernel, Status> {
        let name = match requested {
            "" => self.defaults.get(&hypervisor).ok_or_else(|| {
                Status::failed_precondition(format!(
                    "this node has no default kernel for {hypervisor}: name one with --kernel, or \
                     start burrowd with --default-kernel {hypervisor}=NAME"
                ))
            })?,
            name => name,
        };
        if let Some(kernel) = self.for_hypervisor(hypervisor, name) {
            return Ok(kernel);
        }
        Err(Status::failed_precondition(
            match self.list.iter().find(|k| k.name == name) {
                Some(kernel) => format!(
                    "kernel {name} does not boot under {hypervisor} on this node; it is for {}",
                    kernel
                        .hypervisors
                        .iter()
                        .map(|h| h.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => format!(
                    "this node has no kernel {name}; it has {}",
                    self.list
                        .iter()
                        .map(|k| k.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
        ))
    }

    pub fn to_proto(&self) -> Vec<common::Kernel> {
        self.list
            .iter()
            .map(|kernel| common::Kernel {
                name: kernel.name.clone(),
                digest: kernel.digest.clone(),
                hypervisors: kernel.hypervisors.iter().map(|h| h.to_string()).collect(),
                default_for: self
                    .defaults
                    .iter()
                    .filter(|(_, name)| **name == kernel.name)
                    .map(|(h, _)| h.to_string())
                    .collect(),
                ..describe(&kernel.name, &kernel.digest, &kernel.detected)
            })
            .collect()
    }
}

/// A kernel as a template or a sandbox reports it.
pub fn describe(name: &str, digest: &str, detected: &Detected) -> common::Kernel {
    common::Kernel {
        name: name.to_string(),
        digest: digest.to_string(),
        capabilities: Some(detected.capabilities.to_proto()),
        version: detected.version.clone(),
        arch: detected.arch.to_string(),
        detected_from: detected.source.as_str().to_string(),
        ..Default::default()
    }
}

/// The kernel a guest in `dir` boots, as its record names it: the
/// `vmlinux` there, called `name`. None for a guest booted without one, from
/// firmware or installed whole.
pub async fn in_dir(dir: &Path, name: &str) -> Result<Option<common::Kernel>, Status> {
    let path = dir.join("vmlinux");
    if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Ok(None);
    }
    let inspected = inspect(&path).await.map_err(Status::internal)?;
    Ok(Some(describe(name, &inspected.digest, &inspected.detected)))
}

/// The kernel in `dir`, refused unless it is the one guest memory was saved
/// with: a memory image restores only onto the exact kernel that wrote it.
pub async fn require_saved(
    dir: &Path,
    saved: Option<&common::Kernel>,
) -> Result<Option<common::Kernel>, Status> {
    let name = saved.map_or("", |k| k.name.as_str());
    let found = in_dir(dir, name).await?;
    match (saved, &found) {
        (None, None) => Ok(None),
        (Some(saved), Some(found)) if !saved.digest.is_empty() && saved.digest == found.digest => {
            Ok(Some(found.clone()))
        }
        (Some(saved), _) if saved.digest.is_empty() => Err(Status::failed_precondition(
            "the saved memory records no kernel digest, so the kernel it was written by \
             cannot be told; boot it on its disk instead",
        )),
        (Some(saved), Some(found)) => Err(Status::failed_precondition(format!(
            "the saved memory was written by kernel {} ({}), and this restore would boot {}; \
             memory restores only onto the kernel that wrote it",
            saved.name,
            short(&saved.digest),
            short(&found.digest)
        ))),
        (Some(saved), None) => Err(Status::failed_precondition(format!(
            "the saved memory was written by kernel {} ({}), which did not come with it",
            saved.name,
            short(&saved.digest)
        ))),
        (None, Some(_)) => Err(Status::failed_precondition(
            "the saved memory records no kernel, and a kernel came with it",
        )),
    }
}

pub fn short(digest: &str) -> &str {
    &digest[..digest.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(text: &str) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(text.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    /// An arm64 Image header, then `body`.
    fn arm64(body: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 64];
        image[56..60].copy_from_slice(b"ARM\x64");
        image.extend_from_slice(b"Linux version 6.1.155 (builder) #1 SMP\0");
        image.extend_from_slice(body);
        image
    }

    const FULL: &str = "CONFIG_KVM=y\nCONFIG_VIRTIO_MEM=y\nCONFIG_VIRTIO_VSOCKETS=y\n\
                        CONFIG_VIRTIO_BLK=y\nCONFIG_EXT4_FS=y\nCONFIG_VIRTIO_PCI=y\n";

    #[test]
    fn an_embedded_config_is_read_first() {
        let mut body = b"IKCFG_ST".to_vec();
        body.extend(gzip(FULL));
        body.extend_from_slice(b"IKCFG_ED");
        let detected = detect(&arm64(&body), Some("CONFIG_EXT4_FS=y\n")).unwrap();
        assert_eq!(detected.source, Source::Ikconfig);
        assert_eq!(detected.arch, "aarch64");
        assert_eq!(detected.version, "6.1.155");
        assert!(detected.capabilities.is_kvm_built_in);
        assert!(detected.capabilities.is_virtio_mem_built_in);
        assert_eq!(detected.unbootable_under(Hypervisor::CloudHypervisor), None);
    }

    /// A module is not built in: guests load none.
    #[test]
    fn a_config_beside_the_image_counts_only_what_is_built_in() {
        let config = FULL.replace("CONFIG_VIRTIO_MEM=y", "CONFIG_VIRTIO_MEM=m");
        let detected = detect(&arm64(b""), Some(&config)).unwrap();
        assert_eq!(detected.source, Source::Config);
        assert!(!detected.capabilities.is_virtio_mem_built_in);
        assert!(detected.capabilities.is_vsock_built_in);
    }

    #[test]
    fn without_a_config_driver_names_are_read() {
        let body =
            b"\0kvm-vm\0\0vmw_vsock_virtio_transport\0\0virtio_blk\0EXT4-fs (%s)\0virtio-pci\0";
        let detected = detect(&arm64(body), None).unwrap();
        assert_eq!(detected.source, Source::Strings);
        let caps = detected.capabilities;
        assert!(caps.is_kvm_built_in && caps.is_vsock_built_in && caps.is_virtio_blk_built_in);
        assert!(caps.is_ext4_built_in && detected.is_virtio_pci_built_in);
        assert!(!caps.is_virtio_mem_built_in);
    }

    #[test]
    fn a_kernel_missing_what_a_guest_needs_cannot_boot() {
        let detected = detect(&arm64(b"\0virtio_blk\0"), None).unwrap();
        let why = detected.unbootable_under(Hypervisor::Firecracker).unwrap();
        assert!(why.contains("virtio-pci, virtio-vsock, ext4"), "{why}");
    }

    #[test]
    fn compressed_and_foreign_images_are_refused() {
        let mut bz = vec![0u8; 0x300];
        bz[0x202..0x206].copy_from_slice(b"HdrS");
        assert!(detect(&bz, None).unwrap_err().contains("bzImage"));
        assert!(
            detect(&[0x1f, 0x8b, 8, 0], None)
                .unwrap_err()
                .contains("gzip")
        );
        assert!(
            detect(b"hello", None)
                .unwrap_err()
                .contains("not a kernel image")
        );
    }

    #[test]
    fn kernel_flags_parse() {
        assert_eq!(
            parse_kernel_arg("ch@cloud-hypervisor+firecracker=/k/ch").unwrap(),
            KernelArg {
                name: "ch".into(),
                hypervisors: vec![Hypervisor::CloudHypervisor, Hypervisor::Firecracker],
                path: "/k/ch".into(),
            }
        );
        assert!(parse_kernel_arg("fc=/k/fc").unwrap().hypervisors.is_empty());
        assert!(parse_kernel_arg("/k/fc").is_err());
        assert!(parse_kernel_arg("../x=/k/fc").is_err());
        assert!(parse_kernel_arg("x@qemu=/k").is_err());
        assert_eq!(
            parse_default_kernel("cloud-hypervisor=ch").unwrap(),
            (Hypervisor::CloudHypervisor, "ch".into())
        );
    }

    fn kernel(name: &str, hypervisors: &[Hypervisor]) -> Kernel {
        Kernel {
            name: name.into(),
            path: name.into(),
            digest: format!("{name:0>64}"),
            hypervisors: hypervisors.to_vec(),
            detected: Arc::new(detect(&arm64(b""), Some(FULL)).unwrap()),
        }
    }

    #[test]
    fn a_template_gets_the_kernel_it_names_or_its_hypervisors_default() {
        let mut kernels = Kernels {
            list: vec![
                kernel(
                    "firecracker-ci",
                    &[Hypervisor::Firecracker, Hypervisor::CloudHypervisor],
                ),
                kernel("ch-linux", &[Hypervisor::CloudHypervisor]),
            ],
            defaults: HashMap::new(),
        };
        for h in [Hypervisor::Firecracker, Hypervisor::CloudHypervisor] {
            let name = kernels.fallback_default(h).unwrap();
            kernels.defaults.insert(h, name);
        }
        let pick = |h, name| kernels.choose(h, name).map(|k| k.name.clone());
        assert_eq!(pick(Hypervisor::Firecracker, "").unwrap(), "firecracker-ci");
        assert_eq!(pick(Hypervisor::CloudHypervisor, "").unwrap(), "ch-linux");
        assert_eq!(
            pick(Hypervisor::CloudHypervisor, "firecracker-ci").unwrap(),
            "firecracker-ci"
        );
        let err = pick(Hypervisor::Firecracker, "ch-linux").unwrap_err();
        assert!(
            err.message().contains("does not boot under firecracker"),
            "{}",
            err.message()
        );
        let err = pick(Hypervisor::Firecracker, "nope").unwrap_err();
        assert!(
            err.message().contains("no kernel nope"),
            "{}",
            err.message()
        );
        assert!(kernels.choose(Hypervisor::Vz, "").is_err());
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-kernels-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Memory restores only onto the kernel that wrote it, and state that
    /// does not say which kernel that was is not guessed at.
    #[tokio::test]
    async fn saved_memory_restores_only_onto_its_own_kernel() {
        let dir = scratch("saved");
        std::fs::write(dir.join("vmlinux"), arm64(FULL.as_bytes())).unwrap();
        let found = in_dir(&dir, "ch-linux").await.unwrap().unwrap();
        assert_eq!(found.version, "6.1.155");
        let saved = |digest: &str| common::Kernel {
            name: "ch-linux".into(),
            digest: digest.into(),
            ..Default::default()
        };
        let kept = require_saved(&dir, Some(&saved(&found.digest)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.name, "ch-linux");
        let other = require_saved(&dir, Some(&saved(&"f".repeat(64))))
            .await
            .unwrap_err();
        assert_eq!(other.code(), tonic::Code::FailedPrecondition);
        assert!(
            other
                .message()
                .contains("only onto the kernel that wrote it"),
            "{}",
            other.message()
        );
        let unknown = require_saved(&dir, Some(&saved(""))).await.unwrap_err();
        assert!(
            unknown.message().contains("records no kernel digest"),
            "{}",
            unknown.message()
        );
        assert!(require_saved(&dir, None).await.is_err());
        let empty = scratch("firmware");
        assert_eq!(require_saved(&empty, None).await.unwrap(), None);
        assert!(
            require_saved(&empty, Some(&saved(&found.digest)))
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// Fed the kernels burrow runs: Cloud Hypervisor's own release and the
    /// Firecracker CI ones. They are tens of megabytes, so they are fetched
    /// rather than kept here: point BURROW_TEST_KERNELS at a directory of
    /// them, named as below (with each Firecracker one's published .config).
    #[test]
    #[ignore = "needs BURROW_TEST_KERNELS"]
    fn the_real_kernels() {
        let dir = PathBuf::from(std::env::var("BURROW_TEST_KERNELS").unwrap());
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let caps = |kvm, mem| Capabilities {
            is_kvm_built_in: kvm,
            is_virtio_mem_built_in: mem,
            is_vsock_built_in: true,
            is_virtio_blk_built_in: true,
            is_ext4_built_in: true,
        };
        for (file, arch, version, source, expected) in [
            (
                "ch-vmlinux-x86_64",
                "x86_64",
                "7.2.8+",
                Source::Strings,
                caps(true, true),
            ),
            (
                "ch-Image-arm64",
                "aarch64",
                "7.2.8+",
                Source::Strings,
                caps(true, true),
            ),
            (
                "fc-v1.15-x86_64-6.1.155",
                "x86_64",
                "6.1.155+",
                Source::Ikconfig,
                caps(false, true),
            ),
            (
                "fc-v1.15-aarch64-6.1.155",
                "aarch64",
                "6.1.155+",
                Source::Ikconfig,
                caps(false, true),
            ),
            (
                "fc-v1.13-aarch64-6.1.141",
                "aarch64",
                "6.1.141",
                Source::Ikconfig,
                caps(false, false),
            ),
        ] {
            let image = read(file);
            let detected = detect(&image, None).unwrap();
            assert_eq!(
                (detected.arch, detected.version.as_str(), detected.source),
                (arch, version, source),
                "{file}"
            );
            assert_eq!(detected.capabilities, expected, "{file}");
            for hypervisor in [Hypervisor::Firecracker, Hypervisor::CloudHypervisor] {
                assert_eq!(
                    detected.unbootable_under(hypervisor),
                    None,
                    "{file} {hypervisor}"
                );
            }
            // The driver names agree with the config wherever there is one.
            if source == Source::Ikconfig {
                let mut stripped = image.clone();
                let at = find(&stripped, b"IKCFG_ST").unwrap();
                stripped[at] = b'X';
                let by_strings = detect(&stripped, None).unwrap();
                assert_eq!(by_strings.source, Source::Strings);
                assert_eq!(by_strings.capabilities, expected, "{file} by strings");
                assert_eq!(by_strings.is_pvh, detected.is_pvh, "{file} pvh");
                let config = std::fs::read_to_string(dir.join(format!("{file}.config"))).unwrap();
                let by_file = detect(&stripped, Some(&config)).unwrap();
                assert_eq!(by_file.source, Source::Config);
                assert_eq!(by_file.capabilities, expected, "{file} by its .config");
            }
        }
        let bz = detect(&read("ch-bzImage-x86_64"), None).unwrap_err();
        assert!(bz.contains("bzImage"), "{bz}");
    }
}
