//! Building guest images.
//!
//! A template is built by running the requested steps inside a throwaway
//! sandbox and keeping the root disk it ended up with as the new image. The
//! build sandbox's disk is a clone of its base's image, so the new image
//! shares every block the steps left alone with it. Before the disk is taken
//! the guest trims it, flushes it and freezes it, so the image is a clean
//! filesystem with nothing of it left in the guest's memory; nothing on the
//! host reads or rewrites it.
//!
//! An image imported from an OCI image is written with `mkfs.ext4 -d`, which
//! populates one from a directory without mounting it; see [`from_image`].
//! The build sandbox is destroyed either way.
//!
//! A macOS template is a whole installed machine instead, built in
//! [`crate::macnode`].

#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;
use tonic::Status;

use burrow_proto::api::v1 as api;
use burrow_proto::common::v1 as common;

use crate::sandbox::SandboxManager;

/// Slack added to the measured content size when sizing the new image, so the
/// filesystem has room for metadata and for whatever the sandbox writes later.
const IMAGE_SLACK_MIB: u64 = 256;

pub(crate) type LogTx = mpsc::Sender<Result<api::BuildLog, Status>>;

pub(crate) fn event(event: api::build_log::Event) -> Result<api::BuildLog, Status> {
    Ok(api::BuildLog { event: Some(event) })
}

/// Where builds live: one immutable directory per build, named by its
/// digest's hex.
pub fn builds_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("builds")
}

/// A build's manifest, beside its artifacts. Its digest is the build's.
pub const MANIFEST: &str = "manifest.json";

/// Prefix of the id of a sandbox a build runs its steps in. Such a sandbox
/// is the node's own and has no row in the store, so it is never reported.
pub(crate) const BUILD_SANDBOX_PREFIX: &str = "bld_";

/// Prefix of a build being assembled, renamed into place once complete.
const STAGING_PREFIX: &str = ".tmp-";

/// Where nodes kept templates by name before builds.
const LEGACY_DIR: &str = "images";

/// The directory name of the build `digest` names, `sha256:<hex>` or the
/// hex alone.
pub(crate) fn key_of(digest: &str) -> Result<String, Status> {
    burrow_common::build::Digest::parse(digest)
        .map(|digest| digest.hex().to_string())
        .ok_or_else(|| Status::invalid_argument(format!("{digest:?} is not a build digest")))
}

/// The digest of the build in directory `key`.
pub(crate) fn digest_of(key: &str) -> String {
    format!("{}{key}", burrow_common::build::DIGEST_PREFIX)
}

/// The digest a sandbox record names for the build in `key`, empty for
/// none.
pub(crate) fn record_digest(key: &str) -> String {
    match key.is_empty() {
        true => String::new(),
        false => digest_of(key),
    }
}

/// A fresh directory to assemble a build in, beside the builds.
pub(crate) async fn staging_dir(data_dir: &Path, label: &str) -> Result<PathBuf, Status> {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = builds_dir(data_dir).join(format!(
        "{STAGING_PREFIX}{label}-{}-{serial}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|err| Status::internal(format!("staging a build: {err}")))?;
    Ok(dir)
}

/// Publishes the build assembled in `staging` under its manifest's digest,
/// with one rename, and returns its key. A build already there is the same
/// build, and the staged copy is discarded.
pub(crate) async fn publish(
    data_dir: &Path,
    staging: &Path,
    manifest: &burrow_common::build::Manifest,
) -> Result<String, Status> {
    publish_bytes(data_dir, staging, &manifest.canonical()).await
}

/// [`publish`], given the manifest as the bytes its digest is taken of.
pub(crate) async fn publish_bytes(
    data_dir: &Path,
    staging: &Path,
    manifest: &[u8],
) -> Result<String, Status> {
    let failed = |err: std::io::Error| Status::internal(format!("publishing a build: {err}"));
    tokio::fs::write(staging.join(MANIFEST), manifest)
        .await
        .map_err(failed)?;
    crate::fsync::file(&staging.join(MANIFEST))
        .await
        .map_err(failed)?;
    let key = burrow_common::build::Digest::of(manifest).hex().to_string();
    let dest = builds_dir(data_dir).join(&key);
    if read_manifest(data_dir, &key).await.is_none() {
        // A build left half deleted is moved aside rather than trusted.
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            discard(data_dir, &key).await.map_err(failed)?;
        }
        if let Err(err) = tokio::fs::rename(staging, &dest).await
            && read_manifest(data_dir, &key).await.is_none()
        {
            let _ = tokio::fs::remove_dir_all(staging).await;
            return Err(failed(err));
        }
    }
    let _ = tokio::fs::remove_dir_all(staging).await;
    Ok(key)
}

/// Moves the build in `key` out of the builds with one rename, then removes
/// it. A node that dies in between leaves a staging directory, which the
/// next start sweeps, never a build missing some of its files.
async fn discard(data_dir: &Path, key: &str) -> std::io::Result<()> {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let builds = builds_dir(data_dir);
    let aside = builds.join(format!(
        "{STAGING_PREFIX}del-{key}-{}-{serial}",
        std::process::id()
    ));
    tokio::fs::rename(builds.join(key), &aside).await?;
    tokio::fs::remove_dir_all(&aside).await
}

/// The manifest of the build in `key`, if this node holds all of it: the
/// manifest and every file it names.
pub(crate) async fn read_manifest(
    data_dir: &Path,
    key: &str,
) -> Option<burrow_common::build::Manifest> {
    let dir = builds_dir(data_dir).join(key);
    let bytes = tokio::fs::read(dir.join(MANIFEST)).await.ok()?;
    let manifest: burrow_common::build::Manifest = serde_json::from_slice(&bytes).ok()?;
    let mut files = vec![manifest.rootfs.file.as_str()];
    if !manifest.kernel.is_empty() {
        files.push(crate::boot::KERNEL);
    }
    files.extend(manifest.files.keys().map(String::as_str));
    for file in files {
        validate_name(file).ok()?;
        if !tokio::fs::try_exists(dir.join(file)).await.unwrap_or(false) {
            return None;
        }
    }
    Some(manifest)
}

/// The manifest of the build in `key` as its bytes, which its digest is
/// taken of, if this node holds all of it.
pub(crate) async fn manifest_bytes(data_dir: &Path, key: &str) -> Option<String> {
    read_manifest(data_dir, key).await?;
    tokio::fs::read_to_string(builds_dir(data_dir).join(key).join(MANIFEST))
        .await
        .ok()
}

/// Creates in flight, by the build they use. A delete refuses a build one
/// names, and a create registers before it checks the build is there, so
/// neither can miss the other.
static IN_USE: tokio::sync::Mutex<std::collections::BTreeMap<String, usize>> =
    tokio::sync::Mutex::const_new(std::collections::BTreeMap::new());

/// A create's hold on a build, released when dropped.
pub(crate) struct BuildUse(String);

impl Drop for BuildUse {
    fn drop(&mut self) {
        let key = std::mem::take(&mut self.0);
        tokio::spawn(async move {
            let mut in_use = IN_USE.lock().await;
            if let Some(count) = in_use.get_mut(&key) {
                *count -= 1;
                if *count == 0 {
                    in_use.remove(&key);
                }
            }
        });
    }
}

/// Holds the build in `key` for a create, refused when this node does not
/// hold all of it.
pub(crate) async fn use_build(data_dir: &Path, key: &str) -> Result<BuildUse, Status> {
    *IN_USE.lock().await.entry(key.to_string()).or_default() += 1;
    let held = BuildUse(key.to_string());
    if read_manifest(data_dir, key).await.is_none() {
        return Err(Status::not_found(format!(
            "build {} is not on this node",
            digest_of(key)
        )));
    }
    Ok(held)
}

/// The manifest of a Linux or Windows build staged in `dir`: its rootfs,
/// hashed once here, its kernel if it has one, and `config`.
pub(crate) async fn manifest_for(
    dir: &Path,
    config: &crate::oci::ImageEnvironment,
    agent: String,
) -> Result<burrow_common::build::Manifest, Status> {
    let rootfs = dir.join(crate::rootdisk::IMAGE);
    let bytes = tokio::fs::metadata(&rootfs)
        .await
        .map_err(|err| Status::internal(format!("measuring the rootfs: {err}")))?
        .len();
    let digest = crate::blobs::hash_file(&rootfs)
        .await
        .map_err(|err| Status::internal(format!("hashing the rootfs: {err}")))?;
    let kernel = match tokio::fs::try_exists(dir.join(crate::boot::KERNEL))
        .await
        .unwrap_or(false)
    {
        false => String::new(),
        true if !config.kernel_digest.is_empty() => config.kernel_digest.clone(),
        true => crate::kernels::digest(&dir.join(crate::boot::KERNEL))
            .await
            .map_err(|err| Status::internal(format!("hashing the kernel: {err}")))?,
    };
    Ok(burrow_common::build::Manifest {
        version: burrow_common::build::MANIFEST_VERSION,
        rootfs: burrow_common::build::Artifact {
            file: crate::rootdisk::IMAGE.to_string(),
            digest: digest.to_string(),
            bytes,
        },
        kernel,
        config: serde_json::to_value(config)
            .map_err(|err| Status::internal(format!("image config: {err}")))?,
        hypervisor: config.hypervisor.clone(),
        guest_os: config.guest_os.clone(),
        agent,
        ..Default::default()
    })
}

/// Refuses a data directory holding templates as nodes kept them before
/// builds, which this build cannot use. Dot entries are leftovers and do not
/// count.
pub async fn refuse_legacy(data_dir: &Path) -> Result<(), String> {
    let legacy = data_dir.join(LEGACY_DIR);
    let Ok(mut entries) = tokio::fs::read_dir(&legacy).await else {
        return Ok(());
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Ok(());
    }
    names.sort();
    Err(format!(
        "{} holds templates in the layout before builds ({}), which this build does not \
         support: pull or build them again, then remove the directory; move a Windows \
         template's {} into {} first and import it with `burrow templates import-disk`",
        legacy.display(),
        names.join(", "),
        crate::rootdisk::IMAGE,
        data_dir.join(from_disk::IMPORTS_DIR).display()
    ))
}

/// Removes builds a node died assembling.
pub async fn sweep_pending(data_dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(builds_dir(data_dir)).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(STAGING_PREFIX)
        {
            let _ = tokio::fs::remove_dir_all(entry.path()).await;
        }
    }
}

/// A kernel a template is being built with: the node's name for it, and the
/// file it is.
#[derive(Debug, Clone)]
pub(crate) struct KernelSource {
    pub name: String,
    pub path: PathBuf,
}

/// The kernel a template under `hypervisor` is built with: the one the build
/// names, else the hypervisor's default here.
fn chosen_kernel(
    manager: &SandboxManager,
    hypervisor: &str,
    requested: &str,
) -> Result<KernelSource, Status> {
    let (hypervisor, _) = crate::oci::ImageEnvironment {
        hypervisor: hypervisor.to_string(),
        ..Default::default()
    }
    .machine()?;
    let kernel = manager.kernels().choose(hypervisor, requested)?;
    Ok(KernelSource {
        name: kernel.name.clone(),
        path: kernel.path.clone(),
    })
}

/// Gives a freshly built template its kernel, replacing any it had, and
/// returns the digest it records.
///
/// An OCI image carries a userland and no kernel, so the node supplies one.
/// Hard-linked rather than copied: it is the same bytes for every template of
/// that kernel, and a sandbox hard-links both artifacts out of one directory.
async fn link_kernel(target: &Path, kernel: &KernelSource) -> Result<String, Status> {
    let dest = target.join("vmlinux");
    let pending = target.join("vmlinux.building");
    let _ = tokio::fs::remove_file(&pending).await;
    // Copied or reflinked, never hard-linked: the node's kernel file is the
    // operator's to replace, and a build must not change with it.
    crate::rootdisk::clone(&kernel.path, &pending)
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "kernel {} at {}: {err}",
                kernel.name,
                kernel.path.display()
            ))
        })?;
    tokio::fs::rename(&pending, &dest)
        .await
        .map_err(|err| Status::internal(format!("installing the kernel: {err}")))?;
    crate::kernels::digest(&dest)
        .await
        .map_err(|err| Status::internal(format!("hashing the kernel: {err}")))
}

/// Every build on disk, for an operator to see.
pub async fn list(data_dir: &Path) -> Vec<api::TemplateInfo> {
    scan(data_dir)
        .await
        .into_iter()
        .map(|(info, _)| info)
        .collect()
}

/// The builds this node can start sandboxes from, for the node to advertise
/// to placement.
pub async fn bootable(data_dir: &Path) -> Vec<api::TemplateInfo> {
    scan(data_dir)
        .await
        .into_iter()
        .filter_map(|(info, is_bootable)| is_bootable.then_some(info))
        .collect()
}

async fn scan(data_dir: &Path) -> Vec<(api::TemplateInfo, bool)> {
    let mut out = Vec::new();
    let builds = builds_dir(data_dir);
    let Ok(mut entries) = tokio::fs::read_dir(&builds).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let key = entry.file_name().to_string_lossy().into_owned();
        if key.starts_with('.') {
            continue;
        }
        let Some(manifest) = read_manifest(data_dir, &key).await else {
            continue;
        };
        let size_bytes = tokio::fs::metadata(entry.path().join(&manifest.rootfs.file))
            .await
            .map_or(0, |meta| meta.len());
        let warm = crate::warm::is_warm(&builds, &key).await;
        let environment = crate::oci::image_environment(data_dir, &key).await;
        // Listed even when this build cannot read what it runs on, so an
        // operator can see it and delete it; the names it recorded are shown
        // as they are.
        let (hypervisor, guest_os, is_bootable) = match environment.machine() {
            Ok((hypervisor, guest_os)) => {
                (hypervisor.to_string(), guest_os.as_str().to_string(), true)
            }
            Err(err) => {
                tracing::warn!(
                    build = key,
                    err = err.message(),
                    "build runs on something this node does not know"
                );
                (
                    format!("unknown ({})", environment.hypervisor),
                    environment.guest_os.clone(),
                    false,
                )
            }
        };
        let kernel = crate::kernels::in_dir(&entry.path(), &environment.kernel)
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(build = key, err = err.message(), "reading its kernel");
                None
            });
        let info = api::TemplateInfo {
            digest: digest_of(&key),
            size_bytes,
            is_warm: warm,
            is_kit: environment.kit.is_some(),
            is_systemd: environment.systemd,
            guest_os,
            hypervisor,
            kernel,
            status: burrow_store::READY.to_string(),
            ..Default::default()
        };
        out.push((info, is_bootable));
    }
    out.sort_by(|a, b| a.0.digest.cmp(&b.0.digest));
    out
}

/// Removes a build and its warm snapshots, refused while a create in flight
/// holds it or `user` names something on this node that uses it: a sandbox
/// record, a snapshot or a build sandbox.
pub async fn delete<F, Fut>(data_dir: &Path, digest: &str, user: F) -> Result<(), Status>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    let key = key_of(digest)?;
    let builds = builds_dir(data_dir);
    // Held across the removal: a warm build of this build that is already
    // running publishes its snapshot under the lock, and would otherwise
    // recreate the directory this call just deleted. One queued behind the
    // delete finds no rootfs and stops.
    let _no_builds = crate::warm::hold_builds().await;
    let in_use = IN_USE.lock().await;
    if in_use.contains_key(&key) {
        return Err(Status::failed_precondition(format!(
            "build {digest} is in use by a create in flight"
        )));
    }
    if let Some(user) = user(key.clone()).await {
        return Err(Status::failed_precondition(format!(
            "build {digest} is in use by {user} on this node"
        )));
    }
    if !tokio::fs::try_exists(builds.join(&key))
        .await
        .unwrap_or(false)
    {
        return Err(Status::not_found(format!("no build {digest}")));
    }
    discard(data_dir, &key)
        .await
        .map_err(|err| Status::internal(format!("removing build: {err}")))?;
    drop(in_use);
    let _ = tokio::fs::remove_dir_all(crate::warm::warm_dir(&builds, &key)).await;
    Ok(())
}

/// The hypervisor a template being built records: the one asked for, else the
/// one its base records. Kept as given rather than resolved, so an empty one
/// goes on meaning "the guest's default" wherever the template is pulled to.
///
/// Refused when this node cannot run it: a template is built by booting it,
/// and one this node could not boot is one nothing here could use.
fn chosen_hypervisor(
    manager: &SandboxManager,
    requested: &str,
    inherited: &str,
) -> Result<String, Status> {
    let name = if requested.is_empty() {
        inherited
    } else {
        requested
    };
    let environment = crate::oci::ImageEnvironment {
        hypervisor: name.to_string(),
        ..Default::default()
    };
    let (hypervisor, _) = environment.machine()?;
    manager.require_hypervisor(hypervisor)?;
    Ok(name.to_string())
}

/// Template names become directory names, so they must not be able to escape
/// the images directory or collide with path syntax.
pub(crate) fn validate_name(name: &str) -> Result<(), Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("template name is required"));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.');
    if !ok {
        return Err(Status::invalid_argument(
            "template name may contain only letters, digits, '-', '_', '.' and may not start with '.'",
        ));
    }
    Ok(())
}

/// A finished build.
pub(crate) struct Built {
    /// The template it was built for.
    pub name: String,
    pub key: String,
    pub manifest: burrow_common::build::Manifest,
    /// The build it was made from, empty for none.
    pub parent: String,
}

impl Built {
    fn done(&self) -> api::BuildDone {
        api::BuildDone {
            template: self.name.clone(),
            size_bytes: self.manifest.rootfs.bytes,
            digest: digest_of(&self.key),
            manifest: String::from_utf8(self.manifest.canonical()).unwrap_or_default(),
            parent_digest: record_digest(&self.parent),
        }
    }
}

/// Importing an installed Windows disk as a build.
///
/// The disk is one `scripts/windows` installed: a GPT disk with the system
/// partition last and the agent installed as a service. The node takes it
/// from its `imports` directory, never from an arbitrary path, clones it as
/// the build's image (a reflink where the filesystem has them) and records
/// the image config every sandbox of the build boots with. The disk is left
/// where it was.
pub mod from_disk {
    use std::path::Path;

    use tonic::Status;

    use super::{Built, LogTx, event};
    use burrow_proto::api::v1 as api;
    use burrow_vmm::HypervisorExt as _;

    /// Where a node takes disks to import from, under its data directory.
    pub const IMPORTS_DIR: &str = "imports";

    /// Checks a disk import's request and builds the image config it
    /// records, before anything is read.
    pub(crate) fn plan(
        request: &api::BuildTemplateRequest,
        hypervisor: &str,
    ) -> Result<crate::oci::ImageEnvironment, Status> {
        if !request.steps.is_empty()
            || !request.from.is_empty()
            || !request.from_image.is_empty()
            || !request.kits.is_empty()
            || !request.from_ipsw.is_empty()
        {
            return Err(Status::invalid_argument(
                "a disk import takes no steps and no base; the disk is the whole image",
            ));
        }
        if super::validate_name(&request.from_disk).is_err() {
            return Err(Status::invalid_argument(format!(
                "from_disk {:?} names a file in the node's {IMPORTS_DIR} directory, not a path",
                request.from_disk
            )));
        }
        let environment = crate::oci::ImageEnvironment {
            cmd: vec!["cmd.exe".into()],
            hypervisor: hypervisor.to_string(),
            guest_os: burrow_vmm::GuestOs::Windows.as_str().to_string(),
            tpm: request.is_tpm,
            ..Default::default()
        };
        let (hypervisor, guest_os) = environment.machine()?;
        if !hypervisor.capabilities().runs(guest_os) {
            return Err(Status::failed_precondition(format!(
                "{hypervisor} on this node cannot run {guest_os} guests"
            )));
        }
        Ok(environment)
    }

    /// Imports `request.from_disk` and publishes it as a build.
    pub(crate) async fn import(
        manager: &crate::sandbox::SandboxManager,
        data_dir: &Path,
        request: &api::BuildTemplateRequest,
        tx: &LogTx,
    ) -> Result<Built, Status> {
        let hypervisor = super::chosen_hypervisor(
            manager,
            &request.hypervisor,
            burrow_vmm::Hypervisor::CloudHypervisor.as_str(),
        )?;
        let environment = plan(request, &hypervisor)?;
        let dir = data_dir.join(IMPORTS_DIR);
        let source = dir.join(&request.from_disk);
        let meta = tokio::fs::symlink_metadata(&source).await.map_err(|_| {
            Status::not_found(format!(
                "no disk {} in {} on this node",
                request.from_disk,
                dir.display()
            ))
        })?;
        if !meta.is_file() || meta.len() == 0 || !meta.len().is_multiple_of(512) {
            return Err(Status::invalid_argument(format!(
                "{} is not a raw disk image: it has to be a regular file of whole 512-byte \
                 sectors",
                source.display()
            )));
        }
        let _ = tx.try_send(event(api::build_log::Event::Step(format!(
            "importing {} ({} MiB)",
            request.from_disk,
            meta.len() / burrow_common::disk::MIB
        ))));
        let staging = super::staging_dir(data_dir, "disk").await?;
        let imported = async {
            crate::rootdisk::clone(&source, &staging.join(crate::rootdisk::IMAGE))
                .await
                .map_err(|err| Status::internal(format!("copying the disk: {err}")))?;
            let manifest = super::manifest_for(&staging, &environment, String::new()).await?;
            let key = super::publish(data_dir, &staging, &manifest).await?;
            Ok::<_, Status>((key, manifest))
        }
        .await;
        let (key, manifest) = match imported {
            Ok(imported) => imported,
            Err(err) => {
                let _ = tokio::fs::remove_dir_all(&staging).await;
                return Err(err);
            }
        };
        Ok(Built {
            name: request.name.clone(),
            key,
            manifest,
            parent: String::new(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn request(disk: &str) -> api::BuildTemplateRequest {
            api::BuildTemplateRequest {
                name: "win11".into(),
                from_disk: disk.into(),
                is_tpm: true,
                ..Default::default()
            }
        }

        /// The import records a Windows Cloud Hypervisor image config with
        /// the TPM asked for, and takes a file name, never a path or a base.
        #[test]
        fn a_disk_import_records_windows_and_takes_only_a_file_name() {
            let windows = burrow_vmm::Hypervisor::CloudHypervisor
                .capabilities()
                .runs(burrow_vmm::GuestOs::Windows);
            match plan(&request("win.raw"), "cloud-hypervisor") {
                Ok(environment) => {
                    assert!(windows);
                    assert_eq!(environment.guest_os, "windows");
                    assert_eq!(environment.hypervisor, "cloud-hypervisor");
                    assert!(environment.tpm);
                    assert_eq!(environment.cmd, ["cmd.exe"]);
                }
                Err(err) => {
                    assert!(!windows);
                    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
                }
            }
            for disk in ["../win.raw", "/root/win.raw", "a/b", ".hidden", ""] {
                assert_eq!(
                    plan(&request(disk), "cloud-hypervisor").unwrap_err().code(),
                    tonic::Code::InvalidArgument,
                    "{disk:?}"
                );
            }
            let mut with_steps = request("win.raw");
            with_steps.steps = vec![api::BuildStep { run: "ver".into() }];
            assert!(plan(&with_steps, "cloud-hypervisor").is_err());
            assert!(plan(&request("win.raw"), "firecracker").is_err());
        }
    }
}

/// Runs a build and streams its logs.
///
/// Spawned as a task by the caller; every exit path removes the build sandbox,
/// including failures, so a broken build leaves nothing running.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    manager: SandboxManager,
    data_dir: PathBuf,
    node_id: String,
    request: api::BuildTemplateRequest,
    guest_binary: PathBuf,
    credentials: crate::oci::auth::Store,
    insecure: Vec<String>,
    tx: LogTx,
) {
    // A macOS template is a whole installed machine, not a rootfs, and is
    // neither captured nor warmed like one.
    let built = match crate::macnode::plan(&data_dir, &request).await {
        Ok(None) if !request.from_disk.is_empty() => {
            from_disk::import(&manager, &data_dir, &request, &tx).await
        }
        Ok(Some(plan)) => {
            crate::macnode::build(&manager, &data_dir, &node_id, plan, &guest_binary, &tx).await
        }
        Ok(None) => {
            run_build(
                &manager,
                &data_dir,
                &node_id,
                &request,
                &guest_binary,
                &credentials,
                &insecure,
                &tx,
            )
            .await
        }
        Err(status) => Err(status),
    };
    let built = match built {
        Ok(built) => built,
        Err(status) => {
            let _ = tx.send(Err(status)).await;
            return;
        }
    };
    let _ = tx
        .send(event(api::build_log::Event::Done(built.done())))
        .await;
    // Whoever just built a template is about to create from it, and a build
    // with no snapshot cold-boots.
    if built.manifest.guest_os != burrow_vmm::GuestOs::MacOs.as_str() {
        manager.warm_template(&built.key);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_build(
    manager: &SandboxManager,
    data_dir: &Path,
    node_id: &str,
    request: &api::BuildTemplateRequest,
    guest_binary: &Path,
    credentials: &crate::oci::auth::Store,
    insecure: &[String],
    tx: &LogTx,
) -> Result<Built, Status> {
    if !request.kits.is_empty() {
        if !request.steps.is_empty() || !request.from.is_empty() || !request.from_image.is_empty() {
            return Err(Status::invalid_argument(
                "a kit import takes no steps and no base; the kits are the whole image",
            ));
        }
        let hypervisor = chosen_hypervisor(manager, &request.hypervisor, "")?;
        let kernel = chosen_kernel(manager, &hypervisor, &request.kernel)?;
        let (name, key, manifest) = from_image::import_kit(
            data_dir,
            &request.name,
            &request.kits,
            request.is_systemd,
            &hypervisor,
            &kernel,
            guest_binary,
            credentials,
            insecure,
            tx,
        )
        .await?;
        return Ok(Built {
            name,
            key,
            manifest,
            parent: String::new(),
        });
    }
    let name = request.name.clone();
    burrow_common::build::validate_name(&name).map_err(Status::invalid_argument)?;

    // An OCI base has to be converted into a build before anything can be
    // run in it. With no steps that is the whole build; with steps, the
    // converted image is the base they run on, kept as an untagged build.
    let (base_key, base_manifest, hypervisor, kernel) = if !request.from_image.is_empty() {
        let hypervisor = chosen_hypervisor(manager, &request.hypervisor, "")?;
        let kernel = chosen_kernel(manager, &hypervisor, &request.kernel)?;
        let (key, manifest) = from_image::import(
            data_dir,
            &request.from_image,
            request.is_systemd,
            &hypervisor,
            &kernel,
            guest_binary,
            credentials,
            insecure,
            tx,
        )
        .await?;
        let base = Built {
            name: name.clone(),
            key,
            manifest,
            parent: String::new(),
        };
        if request.steps.is_empty() {
            return Ok(base);
        }
        let _ = tx
            .send(event(api::build_log::Event::Layer(base.done())))
            .await;
        (base.key, base.manifest, hypervisor, kernel)
    } else {
        if request.from.is_empty() {
            return Err(Status::invalid_argument(
                "a build names the build it starts from",
            ));
        }
        let key = key_of(&request.from)?;
        let manifest = read_manifest(data_dir, &key)
            .await
            .ok_or_else(|| Status::not_found(format!("no base build {}", request.from)))?;
        let base = crate::oci::image_environment(data_dir, &key).await;
        let hypervisor = chosen_hypervisor(manager, &request.hypervisor, &base.hypervisor)?;
        let is_same_machine = crate::oci::ImageEnvironment {
            hypervisor: hypervisor.clone(),
            ..Default::default()
        }
        .machine()
        .ok()
            == base.machine().ok();
        // A build on a base keeps the base's kernel, the file itself, unless
        // it names another or moves to a hypervisor the base's may not boot.
        let kernel = match request.kernel.is_empty() && is_same_machine && !base.kernel.is_empty() {
            true => KernelSource {
                name: base.kernel.clone(),
                path: builds_dir(data_dir).join(&key).join(crate::boot::KERNEL),
            },
            false => chosen_kernel(manager, &hypervisor, &request.kernel)?,
        };
        (key, manifest, hypervisor, kernel)
    };

    let _base = use_build(data_dir, &base_key).await?;
    // Steps run on a systemd base, under its systemd, and the image they make
    // keeps it, with the base's boot options.
    let base = crate::oci::image_environment(data_dir, &base_key).await;
    let systemd = (request.is_systemd || base.systemd).then_some(base.systemd_boot);
    let config = crate::oci::ImageEnvironment {
        systemd: systemd.is_some(),
        systemd_boot: systemd.unwrap_or_default(),
        hypervisor: hypervisor.to_string(),
        kernel: kernel.name.clone(),
        kernel_digest: crate::kernels::digest(&kernel.path)
            .await
            .map_err(|err| Status::failed_precondition(format!("kernel {}: {err}", kernel.name)))?,
        ..Default::default()
    };
    let config_key = serde_json::to_string(&config)
        .map_err(|err| Status::internal(format!("image config: {err}")))?;
    let commands: Vec<String> = request
        .steps
        .iter()
        .map(|step| step.run.trim().to_string())
        .filter(|run| !run.is_empty())
        .collect();

    if commands.is_empty() {
        let (key, manifest) = rebase(data_dir, &base_key, &base_manifest, &config, &kernel).await?;
        return Ok(Built {
            name,
            key,
            manifest,
            parent: base_key,
        });
    }

    // Each step's result is a build keyed by the build it ran on and the
    // step, so a rebuild resumes from the longest chain this node has.
    let (mut current, mut parent, mut cached) = (base_key.clone(), String::new(), 0);
    for run in &commands {
        match layers::lookup(data_dir, &layers::key(&current, run, &config_key)).await {
            Some(next) => {
                parent = std::mem::replace(&mut current, next);
                cached += 1;
            }
            None => break,
        }
    }
    if cached > 0 {
        let _ = tx
            .send(event(api::build_log::Event::Step(format!(
                "reusing {cached} cached step(s)"
            ))))
            .await;
        tracing::info!(
            template = name,
            cached_steps = cached,
            total = commands.len(),
            "resuming a build from cached steps"
        );
    }
    if cached == commands.len() {
        let manifest = read_manifest(data_dir, &current)
            .await
            .ok_or_else(|| Status::internal(format!("cached build {current} is gone")))?;
        return Ok(Built {
            name,
            key: current,
            manifest,
            parent,
        });
    }

    let network = build_network(&request.allow_domains);
    let build_id = format!(
        "{BUILD_SANDBOX_PREFIX}{}",
        burrow_common::SandboxId::generate()
    );
    let policy = common::Policy {
        resources: Some(common::ResourcePolicy {
            vcpus: request.vcpus.max(1),
            mem_mib: if request.mem_mib == 0 {
                1024
            } else {
                request.mem_mib
            },
            // The build's disk is the image it makes: its base's plus room
            // for the steps, unless the build names a size.
            disk_mib: request.disk_mib,
            ..Default::default()
        }),
        network: Some(network),
        ..Default::default()
    };

    manager
        .create_seeded(
            build_id.clone(),
            current.clone(),
            policy,
            Default::default(),
            node_id.to_string(),
            None,
            // A build sandbox is internal and short-lived; naming it would
            // spend a name from a namespace the caller owns.
            String::new(),
            String::new(),
            String::new(),
        )
        .await?;

    // From here on the sandbox exists and must be cleaned up on every path.
    let step = Step {
        manager,
        data_dir,
        build_id: &build_id,
        tx,
        name: &name,
        config: &config,
        config_key: &config_key,
        kernel: &kernel,
        agent: &base_manifest.agent,
    };
    let outcome = step.run_all(&commands[cached..], current, parent).await;
    if let Err(err) = manager.delete(&build_id).await {
        tracing::warn!(build = build_id, %err, "could not remove build sandbox");
    }
    outcome
}

/// The build `base` with `config`, for a build with no steps: the same disk,
/// linked rather than copied or hashed again.
async fn rebase(
    data_dir: &Path,
    base_key: &str,
    base: &burrow_common::build::Manifest,
    config: &crate::oci::ImageEnvironment,
    kernel: &KernelSource,
) -> Result<(String, burrow_common::build::Manifest), Status> {
    let staging = staging_dir(data_dir, "build").await?;
    let made = async {
        let source = builds_dir(data_dir).join(base_key).join(&base.rootfs.file);
        let dest = staging.join(&base.rootfs.file);
        if tokio::fs::hard_link(&source, &dest).await.is_err() {
            crate::rootdisk::clone(&source, &dest)
                .await
                .map_err(|err| Status::internal(format!("linking the base's disk: {err}")))?;
        }
        link_kernel(&staging, kernel).await?;
        let manifest = burrow_common::build::Manifest {
            kernel: config.kernel_digest.clone(),
            config: serde_json::to_value(config)
                .map_err(|err| Status::internal(format!("image config: {err}")))?,
            hypervisor: config.hypervisor.clone(),
            guest_os: config.guest_os.clone(),
            ..base.clone()
        };
        let key = publish(data_dir, &staging, &manifest).await?;
        Ok((key, manifest))
    }
    .await;
    if made.is_err() {
        let _ = tokio::fs::remove_dir_all(&staging).await;
    }
    made
}

/// What every step of one build shares.
struct Step<'a> {
    manager: &'a SandboxManager,
    data_dir: &'a Path,
    build_id: &'a str,
    tx: &'a LogTx,
    name: &'a str,
    config: &'a crate::oci::ImageEnvironment,
    config_key: &'a str,
    kernel: &'a KernelSource,
    agent: &'a str,
}

impl Step<'_> {
    /// Runs `commands` in the build sandbox, keeping each one's result as a
    /// build, and returns the last.
    async fn run_all(
        &self,
        commands: &[String],
        mut current: String,
        mut parent: String,
    ) -> Result<Built, Status> {
        let mut manifest = None;
        for (index, run) in commands.iter().enumerate() {
            let _ = self
                .tx
                .send(event(api::build_log::Event::Step(run.clone())))
                .await;
            let exit = exec_streaming(self.manager, self.build_id, run, self.tx).await?;
            if exit != 0 {
                return Err(Status::failed_precondition(format!(
                    "build step failed with exit {exit}: {run}"
                )));
            }
            let is_last = index + 1 == commands.len();
            if is_last {
                let _ = self
                    .tx
                    .send(event(api::build_log::Event::Step(
                        "capturing the root disk".into(),
                    )))
                    .await;
            }
            let (key, captured) = self.capture().await?;
            if let Err(err) = layers::record(
                self.data_dir,
                &layers::key(&current, run, self.config_key),
                &key,
            )
            .await
            {
                // A build that succeeded must not fail because caching did;
                // the cost is a slower rebuild, not a wrong image.
                tracing::warn!(build = self.build_id, %err, "could not cache a build step");
            }
            if !is_last {
                let layer = Built {
                    name: self.name.to_string(),
                    key: key.clone(),
                    manifest: captured.clone(),
                    parent: current.clone(),
                };
                let _ = self
                    .tx
                    .send(event(api::build_log::Event::Layer(layer.done())))
                    .await;
            }
            parent = std::mem::replace(&mut current, key);
            manifest = Some(captured);
        }
        Ok(Built {
            name: self.name.to_string(),
            key: current,
            manifest: manifest.ok_or_else(|| Status::internal("a build with no steps to run"))?,
            parent,
        })
    }

    /// Publishes the build sandbox's root disk as a build.
    async fn capture(&self) -> Result<(String, burrow_common::build::Manifest), Status> {
        let staging = staging_dir(self.data_dir, "build").await?;
        let made = async {
            // Trimmed first, so what the steps deleted is holes in the image
            // rather than blocks every disk cloned from it carries.
            if let Err(err) = root_disk(self.manager, self.build_id, RootDiskOp::Trim).await {
                tracing::debug!(build = self.build_id, %err, "could not trim the build disk");
            }
            capture_disk(
                self.manager,
                self.build_id,
                &staging.join(crate::rootdisk::IMAGE),
            )
            .await?;
            link_kernel(&staging, self.kernel).await?;
            let manifest = manifest_for(&staging, self.config, self.agent.to_string()).await?;
            let key = publish(self.data_dir, &staging, &manifest).await?;
            Ok((key, manifest))
        }
        .await;
        if made.is_err() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
        }
        made
    }
}

/// A build sandbox's egress. Builds fetch packages, so they need it. An
/// explicit domain list narrows it; an empty one means the caller accepts
/// unrestricted access for the duration of the build.
pub(crate) fn build_network(allow_domains: &[String]) -> common::NetworkPolicy {
    if allow_domains.is_empty() {
        common::NetworkPolicy {
            mode: common::NetworkMode::Open as i32,
            ..Default::default()
        }
    } else {
        common::NetworkPolicy {
            mode: common::NetworkMode::Allowlist as i32,
            allow_domains: allow_domains.to_vec(),
            ..Default::default()
        }
    }
}

use burrow_proto::guest::v1::root_disk_request::Op as RootDiskOp;

/// Asks the build sandbox's agent to act on its root filesystem.
async fn root_disk(manager: &SandboxManager, build_id: &str, op: RootDiskOp) -> Result<(), Status> {
    let sandbox = manager.get(build_id).await?;
    let mut agent = sandbox.agent().await?;
    agent
        .root_disk(burrow_proto::guest::v1::RootDiskRequest {
            op: op as i32,
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// Clones the build sandbox's root disk to `dest` with the guest's
/// filesystem frozen: flushed, clean and still, as a disk used without the
/// guest's memory has to be. The guest is thawed whatever happens.
async fn capture_disk(manager: &SandboxManager, build_id: &str, dest: &Path) -> Result<(), Status> {
    let disk = manager.get(build_id).await?.disk_path();
    root_disk(manager, build_id, RootDiskOp::Freeze).await?;
    let cloned = crate::rootdisk::clone(&disk, dest).await;
    let thawed = root_disk(manager, build_id, RootDiskOp::Thaw).await;
    cloned.map_err(|err| Status::internal(format!("capturing the build disk: {err}")))?;
    thawed?;
    crate::fsync::file(dest)
        .await
        .map_err(|err| Status::internal(format!("syncing the captured disk: {err}")))
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

pub async fn run(program: &str, args: &[&str]) -> Result<(), Status> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|err| Status::internal(format!("{program}: {err}")))?;
    if !output.status.success() {
        return Err(Status::internal(format!(
            "{program} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Runs one command in the build sandbox, forwarding its output to the caller.
pub(crate) async fn exec_streaming(
    manager: &SandboxManager,
    sandbox_id: &str,
    command: &str,
    tx: &LogTx,
) -> Result<i32, Status> {
    use burrow_proto::guest::v1 as guestpb;
    use tokio_stream::StreamExt;

    let sandbox = manager.get(sandbox_id).await?;
    let mut agent = sandbox.agent().await?;

    let start = guestpb::ExecInput {
        input: Some(guestpb::exec_input::Input::Start(guestpb::ExecStart {
            cmd: vec!["/bin/sh".into(), "-c".into(), command.to_string()],
            env: Default::default(),
            cwd: String::new(),
            is_pty: false,
            rows: 0,
            cols: 0,
            // The node's own housekeeping, which is root's.
            user: String::new(),
            is_env_cleared: false,
            log_max_bytes: 0,
            log_max_files: 0,
        })),
    };

    let mut stream = agent
        .exec(tokio_stream::iter(vec![start]))
        .await?
        .into_inner();

    let mut exit = 0;
    while let Some(msg) = stream.next().await {
        match msg?.output {
            Some(guestpb::exec_output::Output::Stdout(b)) => {
                let _ = tx.send(event(api::build_log::Event::Stdout(b))).await;
            }
            Some(guestpb::exec_output::Output::Stderr(b)) => {
                let _ = tx.send(event(api::build_log::Event::Stderr(b))).await;
            }
            Some(guestpb::exec_output::Output::ExitCode(code)) => exit = code,
            // A build step is watched to completion here; there is nothing to
            // come back to it for.
            Some(guestpb::exec_output::Output::CommandId(_))
            | Some(guestpb::exec_output::Output::ExitSignal(_))
            | Some(guestpb::exec_output::Output::LostBytes(_))
            | None => {}
        }
    }
    Ok(exit)
}

/// Build distribution: serving a build's artifacts to peers and pulling one
/// from a peer, by digest.
///
/// The seam the object store takes over: a node fetching a build it lacks
/// reads the same manifest and wants the same artifacts by digest, wherever
/// they come from.
pub mod distribute {
    use std::path::Path;

    use tonic::Status;

    use crate::blobs::{BlobStore, Digest};
    use burrow_common::build::Manifest;
    use burrow_proto::node::v1 as nodepb;

    /// The files of a build that travel as blobs, with their digests: the
    /// rootfs and the kernel. The warm snapshot does not: it is tied to the
    /// host that took it, so a receiving node warms the build itself.
    fn artifacts(manifest: &Manifest) -> Result<Vec<(String, Digest)>, Status> {
        let mut wanted = vec![(manifest.rootfs.file.clone(), &manifest.rootfs.digest)];
        if !manifest.kernel.is_empty() {
            wanted.push((crate::boot::KERNEL.to_string(), &manifest.kernel));
        }
        wanted
            .into_iter()
            .map(|(file, digest)| {
                super::validate_name(&file)?;
                let digest = Digest::parse(digest).ok_or_else(|| {
                    Status::invalid_argument(format!("{file}: not a sha-256 digest"))
                })?;
                Ok((file, digest))
            })
            .collect()
    }

    /// A local build's manifest, its artifacts stored as blobs on the way so
    /// a fetch has something to serve. Nothing is hashed: the manifest
    /// already names every artifact.
    pub async fn manifest(
        data_dir: &Path,
        digest: &str,
    ) -> Result<nodepb::TemplateManifest, Status> {
        let key = super::key_of(digest)?;
        let manifest = super::read_manifest(data_dir, &key)
            .await
            .ok_or_else(|| Status::not_found(format!("no build {digest}")))?;
        // An installed macOS machine stays on the Mac that installed it until
        // builds are fetched from the object store.
        if !manifest.files.is_empty() {
            return Err(Status::failed_precondition(format!(
                "build {digest} is an installed macOS machine, which stays on the Mac that \
                 installed it"
            )));
        }
        let dir = super::builds_dir(data_dir).join(&key);
        let store = BlobStore::new(data_dir);
        for (file, digest) in artifacts(&manifest)? {
            store
                .adopt(&dir.join(&file), &digest)
                .await
                .map_err(|err| Status::internal(format!("storing {file}: {err}")))?;
        }
        Ok(nodepb::TemplateManifest {
            digest: super::digest_of(&key),
            manifest: super::manifest_bytes(data_dir, &key)
                .await
                .ok_or_else(|| Status::not_found(format!("no build {digest}")))?,
        })
    }

    /// Opens a stored blob for streaming to a peer.
    pub async fn open_blob(data_dir: &Path, digest: &str) -> Result<tokio::fs::File, Status> {
        // Parsed, not trusted: the digest names a path, and an unchecked one
        // would let a peer ask for any file on this node.
        let digest = Digest::parse(digest)
            .ok_or_else(|| Status::invalid_argument("not a sha-256 digest"))?;
        let store = BlobStore::new(data_dir);
        tokio::fs::File::open(store.path(&digest))
            .await
            .map_err(|_| Status::not_found(format!("no blob {digest}")))
    }

    /// The manifest a peer sent, verified against the digest it claims.
    pub fn verify(manifest: &nodepb::TemplateManifest) -> Result<Manifest, Status> {
        let digest = burrow_common::build::Digest::parse(&manifest.digest)
            .ok_or_else(|| Status::invalid_argument("not a build digest"))?;
        Manifest::verified(&manifest.manifest, &digest).map_err(Status::data_loss)
    }

    /// Fetches whatever of the build this node is missing and installs it.
    ///
    /// Returns `(bytes_transferred, blobs_reused)`. A node that already has
    /// an artifact, say a shared kernel or a retried pull, transfers nothing
    /// for it, and one that already holds the build transfers nothing at all.
    pub async fn pull(
        data_dir: &Path,
        source_address: &str,
        wire: &nodepb::TemplateManifest,
        token: Option<&str>,
    ) -> Result<(u64, u32), Status> {
        // The manifest travels from the source through the orchestrator, and
        // a compromised peer controls it verbatim; it is only trusted once it
        // hashes to the digest the orchestrator asked for.
        let manifest = verify(wire)?;
        let key = super::key_of(&wire.digest)?;
        if super::read_manifest(data_dir, &key).await.is_some() {
            return Ok((0, 0));
        }
        let wanted = artifacts(&manifest)?;
        let store = BlobStore::new(data_dir);
        let mut transferred = 0;
        let mut reused = 0;
        let mut client = None;
        for (_, digest) in &wanted {
            if store.has(digest).await {
                reused += 1;
                continue;
            }
            // Connected lazily: a pull where everything is already present
            // should not need the peer at all.
            if client.is_none() {
                client = Some(connect(source_address, token).await?);
            }
            transferred += fetch_blob(client.as_mut().expect("connected"), &store, digest).await?;
        }

        // Assembled beside the builds and published with one rename, so a
        // create sees either nothing or the whole build.
        let staging = super::staging_dir(data_dir, &key).await?;
        let assembled = async {
            for (file, digest) in &wanted {
                store
                    .materialise(digest, &staging.join(file))
                    .await
                    .map_err(|err| Status::internal(format!("installing {file}: {err}")))?;
            }
            super::publish_bytes(data_dir, &staging, wire.manifest.as_bytes()).await
        }
        .await;
        if assembled.is_err() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
        }
        assembled?;

        tracing::info!(
            build = wire.digest,
            source = source_address,
            transferred,
            reused,
            "build pulled from peer"
        );
        Ok((transferred, reused))
    }

    /// Presents the cluster token when dialling a peer node.
    #[derive(Clone)]
    pub struct PeerAuth(Option<String>);

    impl tonic::service::Interceptor for PeerAuth {
        fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
            if let Some(token) = &self.0 {
                let value = format!("Bearer {token}")
                    .parse()
                    .map_err(|_| Status::internal("malformed node token"))?;
                req.metadata_mut().insert("authorization", value);
            }
            Ok(req)
        }
    }

    type PeerClient = nodepb::node_service_client::NodeServiceClient<
        tonic::service::interceptor::InterceptedService<tonic::transport::Channel, PeerAuth>,
    >;

    async fn connect(address: &str, token: Option<&str>) -> Result<PeerClient, Status> {
        let endpoint = if address.starts_with("http") {
            address.to_string()
        } else {
            format!("http://{address}")
        };
        let channel = tonic::transport::Endpoint::try_from(endpoint)
            .map_err(|err| Status::invalid_argument(format!("source address: {err}")))?
            .connect()
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach {address}: {err}")))?;

        Ok(
            nodepb::node_service_client::NodeServiceClient::with_interceptor(
                channel,
                PeerAuth(token.map(str::to_string)),
            ),
        )
    }

    /// Longest a peer may go without sending the next chunk of a blob.
    const BLOB_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    async fn fetch_blob(
        client: &mut PeerClient,
        store: &BlobStore,
        digest: &Digest,
    ) -> Result<u64, Status> {
        let mut stream = client
            .fetch_blob(nodepb::BlobRequest {
                digest: digest.to_string(),
            })
            .await?
            .into_inner();

        let mut writer = store
            .receive(digest.clone())
            .await
            .map_err(|err| Status::internal(format!("staging blob: {err}")))?;
        let mut bytes = 0u64;
        // Per chunk, not for the transfer as a whole: a rootfs is gigabytes and
        // may legitimately take minutes, but a peer that opens the stream and
        // then says nothing must not hold a fetch open for the life of the
        // node.
        while let Some(chunk) = tokio::time::timeout(BLOB_CHUNK_TIMEOUT, stream.message())
            .await
            .map_err(|_| {
                Status::deadline_exceeded(format!(
                    "peer sent nothing for {BLOB_CHUNK_TIMEOUT:?} while serving blob {digest}"
                ))
            })??
        {
            bytes += chunk.data.len() as u64;
            writer
                .write(&chunk.data)
                .await
                .map_err(|err| Status::internal(format!("writing blob: {err}")))?;
        }
        // Rejects a peer that served the wrong bytes rather than installing
        // them as the image everyone runs.
        writer
            .finish()
            .await
            .map_err(|err| Status::data_loss(err.to_string()))?;
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn scratch(name: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("burrow-distribute-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        async fn build(data_dir: &Path, config: &crate::oci::ImageEnvironment) -> String {
            let staging = super::super::staging_dir(data_dir, "test").await.unwrap();
            tokio::fs::write(staging.join(crate::rootdisk::IMAGE), b"rootfs")
                .await
                .unwrap();
            tokio::fs::write(staging.join(crate::boot::KERNEL), b"kernel")
                .await
                .unwrap();
            let manifest = super::super::manifest_for(&staging, config, String::new())
                .await
                .unwrap();
            super::super::publish(data_dir, &staging, &manifest)
                .await
                .unwrap()
        }

        /// A build's manifest carries its image config, so the environment
        /// and trust bundles an image names travel with it, and naming the
        /// build is enough to read it back.
        #[tokio::test]
        async fn a_build_is_described_by_its_manifest_without_hashing_again() {
            let source = scratch("source");
            let config = crate::oci::ImageEnvironment {
                env: vec!["PATH=/usr/bin".into(), "CURL_CA_BUNDLE=/cacert.pem".into()],
                working_dir: "/app".into(),
                ..Default::default()
            };
            let key = build(&source, &config).await;
            let wire = manifest(&source, &key).await.unwrap();
            assert_eq!(wire.digest, super::super::digest_of(&key));
            let parsed = verify(&wire).unwrap();
            assert_eq!(parsed.config["working_dir"], "/app");
            assert!(
                BlobStore::new(&source)
                    .has(&Digest::parse(&parsed.rootfs.digest).unwrap())
                    .await
            );

            let environment = crate::oci::image_environment(&source, &key).await;
            assert_eq!(environment.trust_bundles()[0].path, "/cacert.pem");
            let _ = std::fs::remove_dir_all(&source);
        }

        /// A manifest that does not hash to the digest it travels under is
        /// refused before anything is fetched or written.
        #[tokio::test]
        async fn a_manifest_that_does_not_match_its_digest_is_refused() {
            let source = scratch("tampered");
            let dest = scratch("tampered-dest");
            let key = build(&source, &Default::default()).await;
            let mut wire = manifest(&source, &key).await.unwrap();
            wire.manifest = wire.manifest.replace("rootfs.ext4", "../../etc");
            assert!(pull(&dest, "unused:0", &wire, None).await.is_err());
            assert!(!super::super::builds_dir(&dest).exists());
            let _ = std::fs::remove_dir_all(&source);
            let _ = std::fs::remove_dir_all(&dest);
        }

        /// A pull of a build this node already holds transfers nothing.
        #[tokio::test]
        async fn a_build_already_held_is_not_pulled_again() {
            let source = scratch("held");
            let key = build(&source, &Default::default()).await;
            let wire = manifest(&source, &key).await.unwrap();
            assert_eq!(
                pull(&source, "unused:0", &wire, None).await.unwrap(),
                (0, 0)
            );
            let _ = std::fs::remove_dir_all(&source);
        }
    }
}

/// Caching build steps, so a rebuild only re-runs what changed.
///
/// Each step's result is a build of its own, keyed by the build the step ran
/// on, the step and the config the build is made with. Changing step three
/// leaves the builds of steps one and two in place and runs everything after,
/// as a Dockerfile would. The index maps a key to the build's digest, and an
/// entry is only used while this node still holds that build.
pub mod layers {
    use std::path::{Path, PathBuf};

    use sha2::{Digest as _, Sha256};

    /// Bumped when the meaning of a key changes.
    const KEY_VERSION: &str = "burrow-layer-v3";

    fn index_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("layers")
    }

    /// The key for running `step` on the build `parent` with `config`.
    pub fn key(parent: &str, step: &str, config: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(KEY_VERSION.as_bytes());
        for part in [parent, step, config] {
            // Length-prefixed so no two splits of the same bytes collide.
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The build cached for `key`, if this node still holds it.
    pub async fn lookup(data_dir: &Path, key: &str) -> Option<String> {
        let recorded = tokio::fs::read_to_string(index_dir(data_dir).join(key))
            .await
            .ok()?;
        let build = super::key_of(recorded.trim()).ok()?;
        super::read_manifest(data_dir, &build).await.map(|_| build)
    }

    /// Records the build `build` as the result of `key`.
    pub async fn record(data_dir: &Path, key: &str, build: &str) -> std::io::Result<()> {
        let index = index_dir(data_dir);
        tokio::fs::create_dir_all(&index).await?;
        // Written via a temporary and renamed: a half-written index entry
        // would name a build that does not exist.
        let temp = index.join(format!(".{key}.tmp"));
        tokio::fs::write(&temp, super::digest_of(build)).await?;
        tokio::fs::rename(&temp, index.join(key)).await
    }

    /// Drops index entries older than `max_age`, and those whose build this
    /// node no longer holds. Returns how many went.
    pub async fn prune(data_dir: &Path, max_age: std::time::Duration) -> usize {
        let index = index_dir(data_dir);
        let Ok(mut entries) = tokio::fs::read_dir(&index).await else {
            return 0;
        };
        let mut removed = 0;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let expired = tokio::fs::metadata(&path)
                .await
                .ok()
                .and_then(|meta| meta.modified().ok())
                .and_then(|at| at.elapsed().ok())
                // An unreadable timestamp reads as "recent", so an entry is
                // never dropped on the strength of a failed stat.
                .is_some_and(|elapsed| elapsed > max_age);
            let name = entry.file_name().to_string_lossy().into_owned();
            let gone = !name.starts_with('.') && lookup(data_dir, &name).await.is_none();
            if (expired || gone) && tokio::fs::remove_file(&path).await.is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rebuild with another kernel replaces the one the template had,
    /// where the old code kept whatever `vmlinux` was already there.
    #[tokio::test]
    async fn a_rebuild_takes_the_kernel_it_names() {
        let dir = std::env::temp_dir().join(format!("burrow-link-kernel-{}", std::process::id()));
        let target = dir.join("template");
        tokio::fs::create_dir_all(&target).await.unwrap();
        for name in ["old", "new"] {
            tokio::fs::write(dir.join(name), name).await.unwrap();
        }
        let kernel = |name: &str| KernelSource {
            name: name.into(),
            path: dir.join(name),
        };
        let old = link_kernel(&target, &kernel("old")).await.unwrap();
        let new = link_kernel(&target, &kernel("new")).await.unwrap();
        assert_ne!(old, new);
        assert_eq!(
            tokio::fs::read(target.join("vmlinux")).await.unwrap(),
            b"new"
        );
        assert_eq!(
            new,
            crate::blobs::hash_file(&dir.join("new"))
                .await
                .unwrap()
                .to_string()
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    async fn staged(
        data_dir: &Path,
        rootfs: &[u8],
        config: &crate::oci::ImageEnvironment,
    ) -> String {
        let staging = staging_dir(data_dir, "test").await.unwrap();
        tokio::fs::write(staging.join(crate::rootdisk::IMAGE), rootfs)
            .await
            .unwrap();
        let manifest = manifest_for(&staging, config, String::new()).await.unwrap();
        publish(data_dir, &staging, &manifest).await.unwrap()
    }

    /// A node with templates in the old layout refuses to start; leftover
    /// dot entries and an empty or absent directory do not stop it.
    #[tokio::test]
    async fn templates_in_the_old_layout_are_refused() {
        let data_dir = std::env::temp_dir().join(format!("burrow-legacy-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        assert!(refuse_legacy(&data_dir).await.is_ok());
        tokio::fs::create_dir_all(data_dir.join("images/.python.building"))
            .await
            .unwrap();
        assert!(refuse_legacy(&data_dir).await.is_ok());
        tokio::fs::create_dir_all(data_dir.join("images/python"))
            .await
            .unwrap();
        let err = refuse_legacy(&data_dir).await.unwrap_err();
        assert!(
            err.contains("(python)") && err.contains("pull or build"),
            "{err}"
        );
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A build recording a hypervisor this node does not know is listed, so
    /// an operator can see and delete it, but not advertised.
    #[tokio::test]
    async fn a_build_on_an_unknown_hypervisor_is_listed() {
        let data_dir =
            std::env::temp_dir().join(format!("burrow-list-unknown-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        let config = crate::oci::ImageEnvironment {
            hypervisor: "future-vmm".into(),
            ..Default::default()
        };
        let key = staged(&data_dir, b"", &config).await;
        let listed = list(&data_dir).await;
        let advertised = bootable(&data_dir).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        assert!(advertised.is_empty());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].digest, digest_of(&key));
        assert!(
            listed[0].hypervisor.contains("future-vmm"),
            "{}",
            listed[0].hypervisor
        );
    }

    /// A build is published whole by one rename and never changes: the
    /// same contents publish to the same directory, different ones to
    /// another, and a half-assembled build is swept away.
    #[tokio::test]
    async fn builds_are_published_by_digest_and_never_replaced() {
        let data_dir = std::env::temp_dir().join(format!("burrow-publish-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        let first = staged(&data_dir, b"one", &Default::default()).await;
        let again = staged(&data_dir, b"one", &Default::default()).await;
        let other = staged(&data_dir, b"two", &Default::default()).await;
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(
            tokio::fs::read(
                builds_dir(&data_dir)
                    .join(&first)
                    .join(crate::rootdisk::IMAGE)
            )
            .await
            .unwrap(),
            b"one"
        );
        // A build missing a file is not held, and publishing it again
        // repairs it.
        let rootfs = builds_dir(&data_dir)
            .join(&first)
            .join(crate::rootdisk::IMAGE);
        std::fs::remove_file(&rootfs).unwrap();
        assert!(read_manifest(&data_dir, &first).await.is_none());
        assert_eq!(staged(&data_dir, b"one", &Default::default()).await, first);
        assert_eq!(std::fs::read(&rootfs).unwrap(), b"one");
        let leftover = staging_dir(&data_dir, "crashed").await.unwrap();
        sweep_pending(&data_dir).await;
        assert!(!leftover.exists());
        assert_eq!(list(&data_dir).await.len(), 2);
        let refused = delete(&data_dir, &digest_of(&first), |_| async {
            Some("snapshot snap_1".to_string())
        })
        .await
        .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        let held = use_build(&data_dir, &first).await.unwrap();
        let refused = delete(&data_dir, &digest_of(&first), |_| async { None })
            .await
            .unwrap_err();
        assert!(
            refused.message().contains("create in flight"),
            "{refused:?}"
        );
        drop(held);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        delete(&data_dir, &digest_of(&first), |_| async { None })
            .await
            .unwrap();
        assert_eq!(list(&data_dir).await.len(), 1);
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }
}

#[cfg(test)]
mod layer_tests {
    use super::layers;

    #[test]
    fn a_step_keys_by_its_parent_its_command_and_its_config() {
        let key = layers::key("a", "apk add curl", "{}");
        assert_eq!(key, layers::key("a", "apk add curl", "{}"));
        assert_ne!(key, layers::key("b", "apk add curl", "{}"));
        assert_ne!(key, layers::key("a", "apk add git", "{}"));
        assert_ne!(key, layers::key("a", "apk add curl", r#"{"systemd":true}"#));
        // Length-prefixing keeps the boundaries part of the key.
        assert_ne!(layers::key("a", "bc", ""), layers::key("ab", "c", ""));
    }

    /// An entry is only offered while its build is on the node, and pruning
    /// drops one whose build is gone.
    #[tokio::test]
    async fn a_cached_step_is_offered_while_its_build_is_held() {
        let dir = std::env::temp_dir().join(format!("burrow-layers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let staging = super::staging_dir(&dir, "test").await.unwrap();
        tokio::fs::write(staging.join(crate::rootdisk::IMAGE), b"layer")
            .await
            .unwrap();
        let manifest = super::manifest_for(&staging, &Default::default(), String::new())
            .await
            .unwrap();
        let build = super::publish(&dir, &staging, &manifest).await.unwrap();

        let key = layers::key("base", "one", "{}");
        assert!(layers::lookup(&dir, &key).await.is_none());
        layers::record(&dir, &key, &build).await.unwrap();
        assert_eq!(layers::lookup(&dir, &key).await, Some(build.clone()));
        assert_eq!(
            layers::prune(&dir, std::time::Duration::from_secs(3600)).await,
            0
        );

        super::delete(&dir, &super::digest_of(&build), |_| async { None })
            .await
            .unwrap();
        assert!(layers::lookup(&dir, &key).await.is_none());
        assert_eq!(
            layers::prune(&dir, std::time::Duration::from_secs(3600)).await,
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Converting an OCI image into a burrow template, which is how every template
/// a node holds comes to exist.
pub mod from_image {
    use std::path::Path;

    use tonic::Status;

    use super::{IMAGE_SLACK_MIB, KernelSource, LogTx, event, path, run};
    use burrow_common::build::Manifest;
    use burrow_proto::api::v1 as api;

    /// Directories the guest needs that an image will not contain.
    ///
    /// The root is mounted read-only and the agent cannot create them itself,
    /// so they have to exist in the image.
    const REQUIRED_DIRS: [&str; 5] = ["proc", "sys", "dev", "tmp", "run"];

    /// Pulls an image, converts it, and publishes it as a build.
    #[allow(clippy::too_many_arguments)]
    pub async fn import(
        data_dir: &Path,
        image: &str,
        is_systemd: bool,
        hypervisor: &str,
        kernel: &KernelSource,
        guest_binary: &Path,
        credentials: &crate::oci::auth::Store,
        insecure: &[String],
        tx: &LogTx,
    ) -> Result<(String, Manifest), Status> {
        let reference = crate::oci::Reference::parse(image)?;

        require_agent(guest_binary).await?;

        let mut progress = |line: String| {
            let _ = tx.try_send(event(api::build_log::Event::Step(line)));
        };
        let pulled =
            crate::oci::pull(&reference, data_dir, credentials, insecure, &mut progress).await?;
        // A Kit pulled on its own is a one-Kit set: its descriptor is recorded
        // so a create runs its lifecycle, exactly as an import of several
        // would. A mixin alone cannot compose, and stays an ordinary template.
        if crate::kit::is_kit(&pulled) {
            let loaded = crate::kit::load(image, &pulled)?;
            let blobs = [(pulled.digest.clone(), pulled.layers.clone())].into();
            match crate::kit::assemble(vec![loaded], blobs, &mut progress) {
                Ok((template, layers)) => {
                    let mut environment = template.environment();
                    environment.systemd = is_systemd;
                    environment.hypervisor = hypervisor.to_string();
                    return stage(data_dir, &layers, &environment, kernel, guest_binary, tx).await;
                }
                Err(err) => progress(format!(
                    "{image} is a kit but not a runnable set ({err}); importing it as a plain template"
                )),
            }
        }
        let mut environment = pulled.environment;
        if environment.systemd && !is_systemd {
            progress(format!("{image} runs systemd; booting it under the agent"));
        }
        environment.systemd |= is_systemd;
        environment.hypervisor = hypervisor.to_string();
        stage(
            data_dir,
            &pulled.layers,
            &environment,
            kernel,
            guest_binary,
            tx,
        )
        .await
    }

    /// Pulls a Sandbox Kit composition and publishes it as one template: the
    /// Kits' layers overlaid in dependency order, the workload's config merged
    /// with its mixins', and every descriptor recorded beside the rootfs so a
    /// create can compose what the Kits asked for.
    #[allow(clippy::too_many_arguments)]
    pub async fn import_kit(
        data_dir: &Path,
        name: &str,
        refs: &[String],
        is_systemd: bool,
        hypervisor: &str,
        kernel: &KernelSource,
        guest_binary: &Path,
        credentials: &crate::oci::auth::Store,
        insecure: &[String],
        tx: &LogTx,
    ) -> Result<(String, String, Manifest), Status> {
        require_agent(guest_binary).await?;
        let mut progress = |line: String| {
            let _ = tx.try_send(event(api::build_log::Event::Step(line)));
        };
        let (template, layers) =
            crate::kit::load_set(refs, data_dir, credentials, insecure, &mut progress).await?;
        let name = if name.is_empty() {
            template.template_name()
        } else {
            name.to_string()
        };
        burrow_common::build::validate_name(&name).map_err(Status::invalid_argument)?;
        let mut environment = template.environment();
        environment.systemd = is_systemd;
        environment.hypervisor = hypervisor.to_string();
        let (key, manifest) =
            stage(data_dir, &layers, &environment, kernel, guest_binary, tx).await?;
        Ok((name, key, manifest))
    }

    async fn require_agent(guest_binary: &Path) -> Result<(), Status> {
        if !tokio::fs::try_exists(guest_binary).await.unwrap_or(false) {
            return Err(Status::failed_precondition(format!(
                "the guest agent is not at {}; set --guest-binary",
                guest_binary.display()
            )));
        }
        Ok(())
    }

    async fn stage(
        data_dir: &Path,
        layers: &[std::path::PathBuf],
        environment: &crate::oci::ImageEnvironment,
        kernel: &KernelSource,
        guest_binary: &Path,
        tx: &LogTx,
    ) -> Result<(String, Manifest), Status> {
        static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staging = data_dir
            .join("build")
            .join(format!("import-{}-{serial}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&staging).await;
        tokio::fs::create_dir_all(&staging)
            .await
            .map_err(|err| Status::internal(format!("staging: {err}")))?;
        let rootdir = staging.join("root");

        let outcome = populate(
            data_dir,
            &rootdir,
            layers,
            environment,
            kernel,
            guest_binary,
            tx,
        )
        .await;
        // Removed on every path: a failed unpack of a large image is the
        // likeliest way to leave gigabytes behind.
        let _ = tokio::fs::remove_dir_all(&staging).await;
        outcome
    }

    async fn populate(
        data_dir: &Path,
        rootdir: &Path,
        layers: &[std::path::PathBuf],
        environment: &crate::oci::ImageEnvironment,
        kernel: &KernelSource,
        guest_binary: &Path,
        tx: &LogTx,
    ) -> Result<(String, Manifest), Status> {
        let _ = tx
            .send(event(api::build_log::Event::Step(format!(
                "unpacking {} layer(s)",
                layers.len()
            ))))
            .await;
        // Blocking file work, and a large image is a lot of it.
        let layers = layers.to_vec();
        let unpack_into = rootdir.to_path_buf();
        let cache = crate::staged::Cache::new(data_dir);
        let cached = tokio::task::spawn_blocking(move || {
            let cached = cache.populate(&layers, &unpack_into)?;
            cache.prune();
            Ok::<_, std::io::Error>(cached)
        })
        .await
        .map_err(|err| Status::internal(format!("unpack did not run: {err}")))?
        .map_err(|err| Status::internal(format!("unpacking image: {err}")))?;
        if cached > 0 {
            let _ = tx
                .send(event(api::build_log::Event::Step(format!(
                    "{cached} layer(s) already staged"
                ))))
                .await;
        }

        for dir in REQUIRED_DIRS {
            let path = rootdir.join(dir);
            if std::fs::symlink_metadata(&path).is_err() {
                let _ = tokio::fs::create_dir_all(&path).await;
            }
        }
        // Without this the VM boots an image with no init and panics.
        let (rootdir_owned, guest_binary_owned) =
            (rootdir.to_path_buf(), guest_binary.to_path_buf());
        tokio::task::spawn_blocking(move || install_agent(&rootdir_owned, &guest_binary_owned))
            .await
            .map_err(|err| Status::internal(format!("installing the agent did not run: {err}")))?
            .map_err(|err| Status::failed_precondition(format!("installing the agent: {err}")))?;
        if environment.systemd {
            stamp_updated(rootdir)
                .map_err(|err| Status::internal(format!("stamping /etc and /var: {err}")))?;
        }

        // A container runtime takes HOME and USER from the image user's passwd
        // entry rather than from ENV, and a Kit's descriptors reference them
        // as `${{ kit.env.HOME }}`. Read them out of the rootfs the same way.
        let mut environment = environment.clone();
        if environment.kit.is_some() {
            let passwd = match real_path_in(rootdir, "etc/passwd") {
                Ok(path) => tokio::fs::read_to_string(path).await.unwrap_or_default(),
                Err(_) => String::new(),
            };
            add_login_env(&mut environment, &passwd);
        }

        assemble(data_dir, rootdir, &environment, kernel, tx).await
    }

    /// `rel` under `root`, refused when any part of it is a link: the tree is
    /// an image's, and the node writes and reads it as root, so a link there
    /// could point it at any path on the host.
    fn real_path_in(root: &Path, rel: &str) -> std::io::Result<std::path::PathBuf> {
        let mut path = root.to_path_buf();
        for part in rel.split('/') {
            path.push(part);
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(std::io::Error::other(format!(
                    "/{rel} passes through a link in the image"
                )));
            }
        }
        Ok(path)
    }

    /// `parent`'s directory `name`, made when it is missing and refused when
    /// it is a link or not a directory. `parent` must already be checked:
    /// only the last component of a path is looked at without following it.
    fn real_dir(parent: &Path, name: &str) -> std::io::Result<std::path::PathBuf> {
        let path = parent.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::other(format!(
                "{} is a link in the image",
                path.display()
            ))),
            Ok(meta) if meta.is_dir() => Ok(path),
            Ok(_) => Err(std::io::Error::other(format!(
                "{} is not a directory",
                path.display()
            ))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&path)?;
                Ok(path)
            }
            Err(err) => Err(err),
        }
    }

    /// Writes the agent to the image's /usr/bin, which must be a directory
    /// of the image's own, never through a link out of it.
    fn install_agent(rootdir: &Path, guest_binary: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let bin = real_dir(&real_dir(rootdir, "usr")?, "bin")?;
        let dest = bin.join("burrow-guest");
        match std::fs::symlink_metadata(&dest) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&dest)?,
            Ok(_) => std::fs::remove_file(&dest)?,
            Err(_) => {}
        }
        let mut to = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&dest)?;
        std::io::copy(&mut std::fs::File::open(guest_binary)?, &mut to)?;
        to.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o755))
    }

    /// Marks /etc and /var up to date with /usr, as systemd-update-done does
    /// on an image's first boot.
    ///
    /// Every sandbox boots a fresh copy of the image, so to systemd each would
    /// be that first boot, rebuilding the linker cache, the journal catalog and
    /// the image's declared users on every cold create. A stamp the image
    /// ships is kept, and a directory that is a link is left alone: the image
    /// chose where it points.
    fn stamp_updated(rootdir: &Path) -> std::io::Result<()> {
        let usr = match std::fs::symlink_metadata(rootdir.join("usr")) {
            Ok(usr) if usr.is_dir() => usr.modified()?,
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        let Ok(since) = usr.duration_since(std::time::UNIX_EPOCH) else {
            return Ok(());
        };
        let nanos = since.as_nanos();
        for dir in ["etc", "var"] {
            if !std::fs::symlink_metadata(rootdir.join(dir)).is_ok_and(|meta| meta.is_dir()) {
                continue;
            }
            let stamp = rootdir.join(dir).join(".updated");
            if std::fs::symlink_metadata(&stamp).is_ok() {
                continue;
            }
            std::fs::write(&stamp, format!("TIMESTAMP_NSEC={nanos}\n"))?;
            std::fs::File::options()
                .write(true)
                .open(&stamp)?
                .set_times(std::fs::FileTimes::new().set_modified(usr))?;
        }
        Ok(())
    }

    /// Adds HOME and USER for the image's user, where the image did not
    /// declare them, to the merged env and to the workload's own config: a
    /// create composes from the recorded Kits, not from the merge.
    fn add_login_env(environment: &mut crate::oci::ImageEnvironment, passwd: &str) {
        let user = environment.user.split(':').next().unwrap_or_default();
        let user = if user.is_empty() { "root" } else { user };
        let (login, home) = passwd_entry(passwd, user).unwrap_or(("root", "/root"));
        let declared = environment.as_map();
        let mut additions = Vec::new();
        if !declared.contains_key("HOME") {
            additions.push(format!("HOME={home}"));
        }
        if !declared.contains_key("USER") {
            additions.push(format!("USER={login}"));
        }
        environment.env.extend(additions.iter().cloned());
        if let Some(kit) = environment.kit.as_mut() {
            kit.kits[kit.workload].config.env.extend(additions);
        }
    }

    /// The login name and home of a user named by login or uid.
    fn passwd_entry<'a>(passwd: &'a str, user: &str) -> Option<(&'a str, &'a str)> {
        passwd.lines().find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 {
                return None;
            }
            (fields[0] == user || fields[2] == user).then_some((fields[0], fields[5]))
        })
    }

    async fn assemble(
        data_dir: &Path,
        rootdir: &Path,
        environment: &crate::oci::ImageEnvironment,
        kernel: &KernelSource,
        tx: &LogTx,
    ) -> Result<(String, Manifest), Status> {
        let content_bytes = directory_size(rootdir).await;
        // Images are sized by their contents, plus room for what the sandbox
        // writes later and for filesystem metadata.
        let size_mib = (content_bytes / (1024 * 1024)) + IMAGE_SLACK_MIB;

        let _ = tx
            .send(event(api::build_log::Event::Step(format!(
                "building a {size_mib}MiB rootfs"
            ))))
            .await;
        let staging = super::staging_dir(data_dir, "import").await?;
        let made = async {
            let rootfs = staging.join(crate::rootdisk::IMAGE);
            run(
                "mkfs.ext4",
                &[
                    "-q",
                    "-F",
                    "-L",
                    "burrow-root",
                    "-b",
                    "4096",
                    "-d",
                    &path(rootdir),
                    &path(&rootfs),
                    &format!("{size_mib}M"),
                ],
            )
            .await?;
            let environment = crate::oci::ImageEnvironment {
                kernel: kernel.name.clone(),
                kernel_digest: super::link_kernel(&staging, kernel).await?,
                ..environment.clone()
            };
            let agent = crate::warm::shipped_agent(burrow_vmm::GuestOs::Linux);
            let manifest = super::manifest_for(&staging, &environment, agent).await?;
            let key = super::publish(data_dir, &staging, &manifest).await?;
            Ok((key, manifest))
        }
        .await;
        if made.is_err() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
        }
        made
    }

    /// Apparent size of a directory tree, for sizing the filesystem.
    async fn directory_size(root: &Path) -> u64 {
        let root = root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            fn walk(dir: &Path) -> u64 {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return 0;
                };
                entries
                    .flatten()
                    // symlink_metadata: a layer symlink like `a -> .` or
                    // `a -> /` must be counted as a link, never followed.
                    .map(|entry| match std::fs::symlink_metadata(entry.path()) {
                        Ok(meta) if meta.is_dir() => walk(&entry.path()),
                        Ok(meta) => meta.len(),
                        Err(_) => 0,
                    })
                    .sum()
            }
            walk(&root)
        })
        .await
        .unwrap_or(0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn scratch(name: &str) -> std::path::PathBuf {
            let dir =
                std::env::temp_dir().join(format!("burrow-stamp-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            for sub in ["usr", "etc", "var"] {
                std::fs::create_dir_all(dir.join(sub)).unwrap();
            }
            dir
        }

        /// systemd's ConditionNeedsUpdate holds while /usr is newer than the
        /// stamp, so the stamp has to carry /usr's own time.
        #[test]
        fn stamps_carry_the_time_of_usr() {
            let dir = scratch("time");
            stamp_updated(&dir).unwrap();
            let usr = std::fs::metadata(dir.join("usr"))
                .unwrap()
                .modified()
                .unwrap();
            for sub in ["etc", "var"] {
                let stamp = dir.join(sub).join(".updated");
                assert_eq!(std::fs::metadata(&stamp).unwrap().modified().unwrap(), usr);
                let nanos = usr
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                assert_eq!(
                    std::fs::read_to_string(&stamp).unwrap(),
                    format!("TIMESTAMP_NSEC={nanos}\n")
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn an_image_keeps_its_own_stamp_and_its_links() {
            let dir = scratch("own");
            std::fs::write(dir.join("etc/.updated"), "mine").unwrap();
            std::fs::remove_dir(dir.join("var")).unwrap();
            let elsewhere = dir.join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, dir.join("var")).unwrap();
            stamp_updated(&dir).unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.join("etc/.updated")).unwrap(),
                "mine"
            );
            assert!(!elsewhere.join(".updated").exists());
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// An image whose /usr or /usr/bin is a link would otherwise have the
        /// node write the agent wherever the link points on the host.
        #[test]
        fn the_agent_is_never_written_through_a_link_in_the_image() {
            use std::os::unix::fs::{PermissionsExt, symlink};
            let agent = scratch("agent-src").join("burrow-guest");
            std::fs::write(&agent, b"agent").unwrap();

            let dir = scratch("agent-ok");
            install_agent(&dir, &agent).unwrap();
            let installed = dir.join("usr/bin/burrow-guest");
            assert_eq!(std::fs::read(&installed).unwrap(), b"agent");
            assert_eq!(
                std::fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
                0o755
            );

            let host = scratch("agent-host");
            let dir = scratch("agent-usr");
            std::fs::remove_dir(dir.join("usr")).unwrap();
            symlink(&host, dir.join("usr")).unwrap();
            assert!(install_agent(&dir, &agent).is_err());
            assert!(!host.join("bin").exists());

            let dir = scratch("agent-bin");
            std::fs::create_dir(dir.join("usr/bin")).unwrap();
            let target = host.join("victim");
            std::fs::write(&target, b"host file").unwrap();
            symlink(&target, dir.join("usr/bin/burrow-guest")).unwrap();
            install_agent(&dir, &agent).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"host file");
            assert!(
                !std::fs::symlink_metadata(dir.join("usr/bin/burrow-guest"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );

            assert!(real_path_in(&dir, "usr/bin/burrow-guest").is_ok());
            let dir = scratch("passwd");
            std::fs::create_dir(dir.join("etc/x")).unwrap();
            symlink(&target, dir.join("etc/passwd")).unwrap();
            assert!(real_path_in(&dir, "etc/passwd").is_err());
        }
    }
}
