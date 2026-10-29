//! Building a macOS template: installing a restore image into a directory of
//! machine files, the way the daemon's template pipeline imports an OCI image
//! for a Linux one.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use block2::RcBlock;
use objc2::AllocAnyThread;
use objc2::rc::Retained;
use objc2_foundation::NSError;
use objc2_virtualization::{
    VZMacAuxiliaryStorage, VZMacAuxiliaryStorageInitializationOptions, VZMacOSInstaller,
    VZMacOSRestoreImage,
};
use tokio::sync::oneshot;

use super::{
    AUX_FILE, DISK_FILE, HARDWARE_MODEL_FILE, MacOsBoot, OnQueue, Requirements, VzConfig, VzVm,
    dropped, file_url, invalid, ns_error, write_machine_id,
};
use crate::error::Result;
use crate::{Backend, Boot, DriveSpec, GuestOs, NetSpec, VmSpec};

const PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// What was installed.
#[derive(Debug, Clone)]
pub struct InstalledImage {
    /// e.g. `26B123`.
    pub build: String,
    /// e.g. `27.2.0`.
    pub version: String,
    pub requirements: Requirements,
    /// What the installer ran with.
    pub vcpus: u32,
    pub mem_mib: u32,
}

/// The machine an install runs in, and the disk it installs onto.
#[derive(Debug, Clone)]
pub struct InstallSpec {
    /// The template directory, which ends up holding the machine's files.
    pub template: PathBuf,
    /// `None` takes the restore image's minimum.
    pub vcpus: Option<u32>,
    pub mem_mib: Option<u32>,
    /// Rounded down to whole GiB.
    pub disk_bytes: u64,
}

/// Installs the restore image at `ipsw` into `spec.workdir`, creating its
/// disk (an ASIF image, sparse), auxiliary storage, hardware model, machine
/// identifier and [`Requirements`]. `on_progress` is called with the fraction
/// done.
///
/// The result boots to Setup Assistant, which [`super::Provisioning`] or a
/// person at a display completes once before the directory is usable as a
/// template.
pub async fn install(
    ipsw: &Path,
    spec: &InstallSpec,
    on_progress: impl Fn(f64),
) -> Result<InstalledImage> {
    let image = load(ipsw).await?;
    let dir = &spec.template;
    std::fs::create_dir_all(dir)?;
    let installed = unsafe {
        let image = image.get();
        let supported = image
            .mostFeaturefulSupportedConfiguration()
            .ok_or_else(|| invalid("no hardware model in the restore image runs on this host"))?;
        let model = supported.hardwareModel();
        if !model.isSupported() {
            return Err(invalid(
                "the restore image's hardware model is unsupported here",
            ));
        }
        let requirements = Requirements {
            min_vcpus: supported.minimumSupportedCPUCount() as u32,
            min_mem_mib: (supported.minimumSupportedMemorySize() >> 20) as u32,
        };
        let vcpus = spec.vcpus.unwrap_or(requirements.min_vcpus);
        let mem_mib = spec.mem_mib.unwrap_or(requirements.min_mem_mib);
        requirements.check(vcpus, mem_mib)?;
        requirements.write(dir)?;
        std::fs::write(
            dir.join(HARDWARE_MODEL_FILE),
            model.dataRepresentation().to_vec(),
        )?;
        VZMacAuxiliaryStorage::initCreatingStorageAtURL_hardwareModel_options_error(
            VZMacAuxiliaryStorage::alloc(),
            &file_url(&dir.join(AUX_FILE)),
            &model,
            VZMacAuxiliaryStorageInitializationOptions::empty(),
        )
        .map_err(|err| ns_error(&err))?;
        let version = image.operatingSystemVersion();
        InstalledImage {
            build: image.buildVersion().to_string(),
            version: format!(
                "{}.{}.{}",
                version.majorVersion, version.minorVersion, version.patchVersion
            ),
            requirements,
            vcpus,
            mem_mib,
        }
    };
    write_machine_id(dir)?;
    create_disk(&dir.join(DISK_FILE), spec.disk_bytes).await?;

    let vm = VzVm::create(&template_spec(dir, &installed)?, &VzConfig::default()).await?;
    let ipsw = OnQueue(file_url(ipsw));
    let (tx, rx) = oneshot::channel();
    let tx = OnQueue(Cell::new(Some(tx)));
    let (installer_tx, installer_rx) = oneshot::channel();
    let inner = vm.machine.0.clone();
    vm.machine.0.queue.exec_async(move || unsafe {
        let installer = VZMacOSInstaller::initWithVirtualMachine_restoreImageURL(
            VZMacOSInstaller::alloc(),
            inner.vm.get(),
            ipsw.get(),
        );
        let done = RcBlock::new(move |err: *mut NSError| {
            if let Some(tx) = tx.get().take() {
                let _ = tx.send(err.as_ref().map(ns_error));
            }
        });
        installer.installWithCompletionHandler(&done);
        let _ = installer_tx.send(Arc::new(OnQueue(installer)));
    });
    let installer = installer_rx.await.map_err(|_| dropped())?;

    tokio::pin!(rx);
    loop {
        tokio::select! {
            done = &mut rx => {
                return match done.map_err(|_| dropped())? {
                    None => Ok(installed),
                    Some(err) => Err(err),
                };
            }
            _ = tokio::time::sleep(PROGRESS_INTERVAL) => {
                let (tx, rx) = oneshot::channel();
                let installer = installer.clone();
                vm.machine.0.queue.exec_async(move || {
                    let _ = tx.send(unsafe { installer.get().progress() }.fractionCompleted());
                });
                on_progress(rx.await.map_err(|_| dropped())?);
            }
        }
    }
}

/// The machine the installer runs, as Apple's sample configures it: the
/// template's own files, NAT, no vsock.
fn template_spec(dir: &Path, installed: &InstalledImage) -> Result<VmSpec> {
    let mut spec = VmSpec::new("install", dir, Backend::Vz(VzConfig::default()));
    spec.guest_os = GuestOs::MacOs;
    spec.boot = Boot::MacOs(MacOsBoot::read(dir)?);
    spec.drives = vec![root_drive()];
    spec.vcpus = installed.vcpus;
    spec.mem_mib = installed.mem_mib;
    spec.net = Some(NetSpec {
        tap: String::new(),
        guest_mac: None,
    });
    Ok(spec)
}

/// The installed disk, as a sandbox's spec names it.
pub fn root_drive() -> DriveSpec {
    DriveSpec {
        id: "disk".into(),
        path: DISK_FILE.into(),
        is_root: true,
        is_read_only: false,
    }
}

async fn load(ipsw: &Path) -> Result<OnQueue<Retained<VZMacOSRestoreImage>>> {
    let (tx, rx) = oneshot::channel();
    let tx = std::sync::Mutex::new(Some(tx));
    // Called on an arbitrary thread, hence the lock rather than a cell.
    let done = RcBlock::new(move |image: *mut VZMacOSRestoreImage, err: *mut NSError| {
        let result = match unsafe { Retained::retain(image) } {
            Some(image) => Ok(OnQueue(image)),
            None => Err(unsafe { err.as_ref() }.map_or_else(dropped, ns_error)),
        };
        if let Some(tx) = tx.lock().unwrap().take() {
            let _ = tx.send(result);
        }
    });
    unsafe { VZMacOSRestoreImage::loadFileURL_completionHandler(&file_url(ipsw), &done) };
    rx.await.map_err(|_| dropped())?
}

/// An empty ASIF image, as Apple's sample installs onto. Unlike a raw image
/// its sparseness is in the format rather than the filesystem, so a template
/// stays small when it is copied off APFS (into the object store, onto
/// another node), and it clones with `clonefile` all the same.
async fn create_disk(path: &Path, bytes: u64) -> Result<()> {
    let status = tokio::process::Command::new("/usr/sbin/diskutil")
        .args([
            "image", "create", "blank", "--fs", "none", "--format", "ASIF", "--size",
        ])
        .arg(format!("{}GiB", bytes >> 30))
        .arg(path)
        .status()
        .await?;
    if !status.success() {
        return Err(invalid("diskutil could not create the disk image"));
    }
    Ok(())
}
