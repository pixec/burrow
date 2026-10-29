//! Apple's Virtualization.framework, for macOS guests on a Mac node.
//!
//! Unlike the Linux backends there is no VMM process to spawn and talk to over
//! a socket: the machine lives in the framework, driven from whatever process
//! created it (the framework runs each guest in an XPC service of its own),
//! and every call on it (start, pause, save, a vsock connect) must be made on
//! the serial dispatch queue it was created with, with the answer arriving as
//! a block invoked on that same queue. [`VzVm`] owns that queue and turns each
//! call into a future, so it can sit behind [`crate::Vm`] like any backend.
//!
//! A machine boots from [`crate::Boot::MacOs`]: the auxiliary storage its boot
//! firmware keeps state in, the hardware model it was installed for and the
//! machine identifier that makes it one particular Mac, with its installed
//! disk the first of [`crate::VmSpec::drives`]. A template is such a set of
//! files made by [`install`]; a sandbox's are APFS clones of them made by
//! [`clone_machine`], which cost no disk until the guest writes.
//!
//! A snapshot is the framework's own save file, one opaque blob of device
//! state and memory encrypted with a key tied to this host: it restores here
//! and nowhere else, so it can neither move to another node nor live in the
//! object store.

mod install;

use std::cell::Cell;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject};
use objc2::{AllocAnyThread, Message, msg_send};
use objc2_foundation::{NSArray, NSData, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleNetworkDeviceAttachment, VZMACAddress,
    VZMacAuxiliaryStorage, VZMacGraphicsDeviceConfiguration, VZMacGraphicsDisplayConfiguration,
    VZMacHardwareModel, VZMacKeyboardConfiguration, VZMacMachineIdentifier, VZMacOSBootLoader,
    VZMacOSVirtualMachineStartOptions, VZMacPlatformConfiguration, VZMacTrackpadConfiguration,
    VZNATNetworkDeviceAttachment, VZVirtioBlockDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
    VZVirtualMachineState,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::{Boot, GuestOs, Hypervisor, VSOCK_UDS, VmSpec};

pub use install::{InstallSpec, InstalledImage, install, root_drive};

/// The disk macOS is installed on. Cloned, never copied.
pub const DISK_FILE: &str = "disk.img";
/// The boot firmware's NVRAM. Written by the guest, so cloned per sandbox.
pub const AUX_FILE: &str = "aux.img";
/// The hardware model the template was installed for, as the framework's
/// opaque data representation.
pub const HARDWARE_MODEL_FILE: &str = "hardware-model";
/// The machine identifier, ditto. Fresh per sandbox, except that a saved
/// state only restores into the identity it was saved from.
pub const MACHINE_ID_FILE: &str = "machine-id";
/// The [`Requirements`] the template was installed with.
pub const REQUIREMENTS_FILE: &str = "requirements.json";
/// The framework's save file, device state and memory in one: both halves of
/// this backend's [`crate::Layout`].
pub const SAVE_FILE: &str = "snapshot.vzsave";

/// The display a guest is given. Headless or not, a macOS guest gets the same
/// one, Apple's sample's: a saved state only restores into an identical device
/// set, and WindowServer wants a display to lay the login session out on.
const DISPLAY: (isize, isize, isize) = (1920, 1200, 80);

/// Apple's licence allows two macOS guests running at once on one Mac.
pub const MAX_RUNNING: usize = 2;

/// Whether this host can run guests under the framework at all.
pub fn is_supported() -> bool {
    unsafe { VZVirtualMachine::isSupported() }
}

/// What a node reports for this backend: the host's macOS, which is the
/// framework's version.
pub fn host_version() -> String {
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    let name = c"kern.osproductversion";
    let ok = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } == 0;
    match ok {
        true => format!(
            "macOS {}",
            String::from_utf8_lossy(&buf[..len.saturating_sub(1)])
        ),
        false => "macOS".into(),
    }
}

/// How this node runs Virtualization.framework guests.
#[derive(Debug, Clone, Default)]
pub struct VzConfig {
    /// Where the guest's NIC leads, when [`VmSpec::net`] asks for one.
    pub network: Network,
    /// Passed on a boot, which only the first boot after an install honours.
    /// For the template pipeline; a sandbox boots an already set up disk.
    pub provisioning: Option<Provisioning>,
}

/// Where the guest's network interface leads.
#[derive(Debug, Clone, Default)]
pub enum Network {
    /// The framework's own NAT onto the host's network. Unfiltered: it can
    /// carry no egress policy, so it is for templates and development only.
    #[default]
    Nat,
    /// One end of a connected `SOCK_DGRAM` socket pair, one Ethernet frame
    /// per datagram. The other end belongs to a network stack in the daemon,
    /// which is where a sandbox's egress policy would be enforced.
    Datagram(Arc<OwnedFd>),
}

/// A macOS machine's platform identity, the boot source [`install`] makes
/// and [`clone_machine`] copies. Paths are relative to the VM's working
/// directory, as every path in a [`VmSpec`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsBoot {
    pub aux: String,
    pub hardware_model: String,
    pub machine_id: String,
    /// The installed macOS's minimums, which the spec is validated against.
    pub requirements: Requirements,
}

impl MacOsBoot {
    /// The machine whose files sit in `dir` under the standard names.
    pub fn read(dir: &Path) -> Result<Self> {
        Ok(Self {
            aux: AUX_FILE.into(),
            hardware_model: HARDWARE_MODEL_FILE.into(),
            machine_id: MACHINE_ID_FILE.into(),
            requirements: Requirements::read(dir)?,
        })
    }
}

/// The account a fresh install is given on its first boot, in place of a
/// person clicking through Setup Assistant.
///
/// macOS 27 hosts and guests only: the framework passes it to the guest's
/// setup over a protocol older guests ignore. objc2-virtualization 0.3 does
/// not bind it yet, so it is reached by name.
#[derive(Debug, Clone)]
pub struct Provisioning {
    pub full_name: String,
    pub username: String,
    pub password: String,
    pub is_auto_login: bool,
    pub is_remote_login_enabled: bool,
}

impl Provisioning {
    fn start_options(&self) -> Result<Retained<VZMacOSVirtualMachineStartOptions>> {
        let class = AnyClass::get(c"VZMacGuestProvisioningOptions")
            .ok_or_else(|| invalid("guest provisioning needs a macOS 27 host"))?;
        unsafe {
            let guest: Retained<AnyObject> = msg_send![class, new];
            let _: () = msg_send![&guest, setFullName: &*NSString::from_str(&self.full_name)];
            let _: () = msg_send![&guest, setUsername: &*NSString::from_str(&self.username)];
            let _: () = msg_send![&guest, setPassword: &*NSString::from_str(&self.password)];
            let _: () = msg_send![&guest, setLogsInAutomatically: self.is_auto_login];
            let _: () = msg_send![&guest, setEnablesRemoteLogin: self.is_remote_login_enabled];
            let options = VZMacOSVirtualMachineStartOptions::new();
            let set: std::result::Result<(), Retained<NSError>> =
                msg_send![&options, setGuestProvisioningOptions: &*guest, error: _];
            set.map_err(|err| ns_error(&err))?;
            Ok(options)
        }
    }
}

/// The smallest machine the installed macOS supports, recorded at install
/// from the restore image's `VZMacOSConfigurationRequirements` so that later
/// boots, which have no restore image to ask, can default to and enforce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Requirements {
    pub min_vcpus: u32,
    pub min_mem_mib: u32,
}

impl Requirements {
    /// What the machine directory at `dir` was installed with.
    pub fn read(dir: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(
            dir.join(REQUIREMENTS_FILE),
        )?)?)
    }

    pub(crate) fn write(&self, dir: &Path) -> Result<()> {
        std::fs::write(dir.join(REQUIREMENTS_FILE), serde_json::to_vec(self)?)?;
        Ok(())
    }

    /// Refuses a machine the guest does not support or the host cannot run.
    pub fn check(&self, vcpus: u32, mem_mib: u32) -> Result<()> {
        let (max_vcpus, max_mem_mib) = unsafe {
            (
                VZVirtualMachineConfiguration::maximumAllowedCPUCount(),
                VZVirtualMachineConfiguration::maximumAllowedMemorySize() >> 20,
            )
        };
        if vcpus < self.min_vcpus || vcpus as usize > max_vcpus {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{vcpus} vCPUs is outside {}..={max_vcpus}: this macOS needs at least {}, \
                     this host allows at most {max_vcpus}",
                    self.min_vcpus, self.min_vcpus
                ),
            )));
        }
        if mem_mib < self.min_mem_mib || u64::from(mem_mib) > max_mem_mib {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{mem_mib} MiB of memory is outside {}..={max_mem_mib}: this macOS needs at \
                     least {} MiB, this host allows at most {max_mem_mib} MiB",
                    self.min_mem_mib, self.min_mem_mib
                ),
            )));
        }
        Ok(())
    }
}

/// The macOS boot `spec` asks for, refused unless it is one this backend can
/// give a machine of its shape.
fn macos_boot(spec: &VmSpec) -> Result<&MacOsBoot> {
    let Boot::MacOs(boot) = &spec.boot else {
        return Err(Error::Unsupported {
            hypervisor: Hypervisor::Vz,
            what: "boot anything but an installed macOS",
        });
    };
    if spec.guest_os != GuestOs::MacOs {
        return Err(Error::Unsupported {
            hypervisor: Hypervisor::Vz,
            what: "run a guest other than macOS",
        });
    }
    boot.requirements.check(spec.vcpus, spec.mem_mib)?;
    Ok(boot)
}

/// What a boot is started with. Public for a caller that drives a machine on
/// the main queue itself, as a window must.
pub fn start_options(
    provisioning: Option<&Provisioning>,
) -> Result<Retained<VZMacOSVirtualMachineStartOptions>> {
    match provisioning {
        Some(provisioning) => provisioning.start_options(),
        None => Ok(unsafe { VZMacOSVirtualMachineStartOptions::new() }),
    }
}

/// A framework object that may only be used on its machine's queue.
///
/// Retaining and releasing are thread safe; messaging is not. The wrapper lets
/// the handle travel to the queue inside a dispatched closure, and every use
/// of [`Self::get`] happens in one.
struct OnQueue<T>(T);

// SAFETY: see above; the only access is from closures run on the queue.
unsafe impl<T> Send for OnQueue<T> {}
unsafe impl<T> Sync for OnQueue<T> {}

impl<T> OnQueue<T> {
    fn get(&self) -> &T {
        &self.0
    }
}

struct Inner {
    vm: OnQueue<Retained<VZVirtualMachine>>,
    queue: DispatchRetained<DispatchQueue>,
}

impl Drop for Inner {
    // The machine tears its devices down as it is freed, which is a call on
    // its queue like any other.
    fn drop(&mut self) {
        let vm = OnQueue(self.vm.get().retain());
        self.queue.exec_async(move || drop(vm));
    }
}

/// The machine on its queue, shared with the vsock bridge.
#[derive(Clone)]
struct Machine(Arc<Inner>);

/// A macOS guest under Virtualization.framework.
pub struct VzVm {
    machine: Machine,
    workdir: PathBuf,
    boot_latency: Duration,
    /// Serves the guest's vsock ports at [`VSOCK_UDS`]; stopped with the VM.
    bridge: Option<JoinHandle<()>>,
}

impl VzVm {
    pub(crate) async fn boot(spec: VmSpec, config: VzConfig) -> Result<Self> {
        let started = Instant::now();
        let mut vm = Self::create(&spec, &config).await?;
        let options = OnQueue(start_options(config.provisioning.as_ref())?);
        vm.machine
            .call(move |vm, done| unsafe {
                vm.startWithOptions_completionHandler(options.get(), &done)
            })
            .await?;
        vm.boot_latency = started.elapsed();
        tracing::info!(
            vm_id = spec.vm_id,
            latency_ms = vm.boot_latency.as_millis() as u64,
            "vz vm started"
        );
        Ok(vm)
    }

    /// Restores the machine from the [`SAVE_FILE`] in its working directory,
    /// which must have been saved from a machine of the same identity and
    /// shape, and whose disk must be as it was when the state was saved.
    pub(crate) async fn restore(spec: VmSpec, config: VzConfig, resume: bool) -> Result<Self> {
        let started = Instant::now();
        let mut vm = Self::create(&spec, &config).await?;
        let url = OnQueue(file_url(&spec.workdir.join(SAVE_FILE)));
        vm.machine
            .call(move |vm, done| unsafe {
                vm.restoreMachineStateFromURL_completionHandler(url.get(), &done)
            })
            .await
            .map_err(|err| Error::Snapshot(err.to_string()))?;
        if resume {
            vm.resume().await?;
        }
        vm.boot_latency = started.elapsed();
        tracing::info!(
            vm_id = spec.vm_id,
            latency_ms = vm.boot_latency.as_millis() as u64,
            "vz vm restored"
        );
        Ok(vm)
    }

    /// Configures the machine `spec` describes on a queue of its own,
    /// stopped, with its vsock bridge listening.
    async fn create(spec: &VmSpec, config: &VzConfig) -> Result<Self> {
        let configuration = OnQueue(configuration(spec, config)?);
        let queue = DispatchQueue::new(&format!("burrow.vz.{}", spec.vm_id), None);
        let (tx, rx) = oneshot::channel();
        let target = queue.clone();
        queue.exec_async(move || {
            let vm = unsafe {
                VZVirtualMachine::initWithConfiguration_queue(
                    VZVirtualMachine::alloc(),
                    configuration.get(),
                    &target,
                )
            };
            let _ = tx.send(OnQueue(vm));
        });
        let vm = rx.await.map_err(|_| dropped())?;
        let machine = Machine(Arc::new(Inner { vm, queue }));
        let bridge = match spec.is_vsock_enabled {
            true => Some(machine.serve_vsock(&spec.workdir.join(VSOCK_UDS))?),
            false => None,
        };
        Ok(Self {
            machine,
            workdir: spec.workdir.clone(),
            boot_latency: Duration::ZERO,
            bridge,
        })
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    pub async fn pause(&self) -> Result<Duration> {
        self.machine
            .call(|vm, done| unsafe { vm.pauseWithCompletionHandler(&done) })
            .await
    }

    pub async fn resume(&self) -> Result<Duration> {
        self.machine
            .call(|vm, done| unsafe { vm.resumeWithCompletionHandler(&done) })
            .await
    }

    /// Saves a **paused** machine into its [`SAVE_FILE`], replacing the one
    /// it was last restored from, which the framework will not overwrite.
    pub async fn snapshot(&self) -> Result<Duration> {
        let path = self.workdir.join(SAVE_FILE);
        match std::fs::remove_file(&path) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
            _ => {}
        }
        let url = OnQueue(file_url(&path));
        self.machine
            .call(move |vm, done| unsafe {
                vm.saveMachineStateToURL_completionHandler(url.get(), &done)
            })
            .await
    }

    /// Waits for the guest to shut itself down, as after a `shutdown -h` in
    /// it.
    pub async fn wait_stopped(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let state = self.machine.with_vm(|vm| unsafe { vm.state() }).await?;
            if state == VZVirtualMachineState::Stopped || state == VZVirtualMachineState::Error {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    what: "the guest to shut down".into(),
                    timeout_ms: timeout.as_millis() as u64,
                });
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Hard stop, with no chance for the guest to shut down, unless it has
    /// already stopped itself.
    pub async fn kill(self) -> Result<()> {
        if let Some(bridge) = &self.bridge {
            bridge.abort();
        }
        let state = self.machine.with_vm(|vm| unsafe { vm.state() }).await?;
        tracing::debug!(workdir = %self.workdir.display(), state = state.0, "stopping vz vm");
        if state != VZVirtualMachineState::Stopped && state != VZVirtualMachineState::Error {
            let stopped = self
                .machine
                .call(|vm, done| unsafe { vm.stopWithCompletionHandler(&done) })
                .await;
            if let Err(err) = &stopped {
                tracing::warn!(workdir = %self.workdir.display(), %err, "vz vm did not stop");
            }
            stopped?;
        }
        let _ = std::fs::remove_file(self.workdir.join(VSOCK_UDS));
        Ok(())
    }
}

impl Drop for VzVm {
    fn drop(&mut self) {
        if let Some(bridge) = &self.bridge {
            bridge.abort();
        }
    }
}

impl Machine {
    /// Opens a connection to a guest vsock port.
    ///
    /// The framework hands back a connection object owning a socket; the
    /// stream is a duplicate of that socket, so it outlives the object, which
    /// is released on the queue straight away.
    async fn connect(&self, port: u32) -> Result<UnixStream> {
        let (tx, rx) = oneshot::channel::<Result<OwnedFd>>();
        let tx = OnQueue(Cell::new(Some(tx)));
        let inner = self.0.clone();
        self.0.queue.exec_async(move || {
            let device = unsafe { inner.vm.get().socketDevices() }
                .firstObject()
                .and_then(|device| device.downcast::<VZVirtioSocketDevice>().ok());
            let Some(device) = device else {
                if let Some(tx) = tx.get().take() {
                    let _ = tx.send(Err(invalid("the machine has no vsock device")));
                }
                return;
            };
            let done = RcBlock::new(
                move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                    let Some(tx) = tx.get().take() else { return };
                    let result = match unsafe { conn.as_ref() } {
                        Some(conn) => dup(unsafe { conn.fileDescriptor() }),
                        None => Err(unsafe { err.as_ref() }.map_or_else(dropped, ns_error)),
                    };
                    let _ = tx.send(result);
                },
            );
            unsafe { device.connectToPort_completionHandler(port, &done) };
        });
        let fd = rx.await.map_err(|_| dropped())??;
        let stream = std::os::unix::net::UnixStream::from(fd);
        stream.set_nonblocking(true)?;
        Ok(UnixStream::from_std(stream)?)
    }

    /// Serves the guest's vsock ports on a Unix socket at `path`, speaking
    /// the `CONNECT <port>` handshake Firecracker and Cloud Hypervisor do, so
    /// [`crate::GuestAddr`] reaches this guest the way it reaches theirs.
    fn serve_vsock(&self, path: &Path) -> Result<JoinHandle<()>> {
        // A previous VM in a reused working directory leaves its socket.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        let machine = self.clone();
        Ok(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let machine = machine.clone();
                tokio::spawn(async move {
                    if let Err(err) = machine.bridge(stream).await {
                        tracing::debug!(%err, "vsock bridge connection ended");
                    }
                });
            }
        }))
    }

    async fn bridge(&self, mut host: UnixStream) -> Result<()> {
        let port = read_connect(&mut host).await?;
        // A refused connect closes the socket without a reply, as the Linux
        // backends do when nothing in the guest listens.
        let mut guest = self.connect(port).await?;
        host.write_all(format!("OK {port}\n").as_bytes()).await?;
        tokio::io::copy_bidirectional(&mut host, &mut guest).await?;
        Ok(())
    }

    /// Runs `op` on the queue, handing it a completion block, and waits for
    /// the block to be called.
    async fn call(
        &self,
        op: impl FnOnce(&VZVirtualMachine, RcBlock<dyn Fn(*mut NSError)>) + Send + 'static,
    ) -> Result<Duration> {
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        let tx = OnQueue(Cell::new(Some(tx)));
        let inner = self.0.clone();
        self.0.queue.exec_async(move || {
            let done = RcBlock::new(move |err: *mut NSError| {
                if let Some(tx) = tx.get().take() {
                    let _ = tx.send(unsafe { err.as_ref() }.map(ns_error));
                }
            });
            op(inner.vm.get(), done);
        });
        match rx.await.map_err(|_| dropped())? {
            None => Ok(started.elapsed()),
            Some(err) => Err(err),
        }
    }

    async fn with_vm<R: Send + 'static>(
        &self,
        op: impl FnOnce(&VZVirtualMachine) -> R + Send + 'static,
    ) -> Result<R> {
        let (tx, rx) = oneshot::channel();
        let inner = self.0.clone();
        self.0.queue.exec_async(move || {
            let _ = tx.send(op(inner.vm.get()));
        });
        rx.await.map_err(|_| dropped())
    }
}

/// Builds the framework's configuration for `spec`, validated, including for
/// save and restore. Public for a caller that drives a machine on the main
/// queue itself, as a window must.
pub fn configuration(
    spec: &VmSpec,
    node: &VzConfig,
) -> Result<Retained<VZVirtualMachineConfiguration>> {
    let boot = macos_boot(spec)?;
    let dir = &spec.workdir;
    unsafe {
        let platform = VZMacPlatformConfiguration::new();
        let model = VZMacHardwareModel::initWithDataRepresentation(
            VZMacHardwareModel::alloc(),
            &*read_data(&dir.join(&boot.hardware_model))?,
        )
        .filter(|model| model.isSupported())
        .ok_or_else(|| invalid("hardware model is unreadable or unsupported on this host"))?;
        let identifier = VZMacMachineIdentifier::initWithDataRepresentation(
            VZMacMachineIdentifier::alloc(),
            &*read_data(&dir.join(&boot.machine_id))?,
        )
        .ok_or_else(|| invalid("machine identifier is unreadable"))?;
        let aux = VZMacAuxiliaryStorage::initWithURL(
            VZMacAuxiliaryStorage::alloc(),
            &file_url(&dir.join(&boot.aux)),
        );
        platform.setHardwareModel(&model);
        platform.setMachineIdentifier(&identifier);
        platform.setAuxiliaryStorage(Some(&aux));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&VZMacOSBootLoader::new()));
        config.setCPUCount(spec.vcpus as usize);
        config.setMemorySize(u64::from(spec.mem_mib) << 20);

        let mut disks = Vec::new();
        for drive in &spec.drives {
            let attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &file_url(&dir.join(&drive.path)),
                drive.is_read_only,
            )
            .map_err(|err| ns_error(&err))?;
            disks.push(
                VZVirtioBlockDeviceConfiguration::initWithAttachment(
                    VZVirtioBlockDeviceConfiguration::alloc(),
                    &attachment,
                )
                .into_super(),
            );
        }
        config.setStorageDevices(&NSArray::from_retained_slice(&disks));

        if let Some(spec_net) = &spec.net {
            let net = VZVirtioNetworkDeviceConfiguration::new();
            match &node.network {
                Network::Nat => net.setAttachment(Some(&VZNATNetworkDeviceAttachment::new())),
                Network::Datagram(fd) => {
                    let handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                        NSFileHandle::alloc(),
                        fd.as_raw_fd(),
                        false,
                    );
                    net.setAttachment(Some(
                        &VZFileHandleNetworkDeviceAttachment::initWithFileHandle(
                            VZFileHandleNetworkDeviceAttachment::alloc(),
                            &handle,
                        ),
                    ));
                }
            }
            if let Some(mac) = &spec_net.guest_mac {
                let mac =
                    VZMACAddress::initWithString(VZMACAddress::alloc(), &NSString::from_str(mac))
                        .ok_or_else(|| invalid("malformed MAC address"))?;
                net.setMACAddress(&mac);
            }
            config.setNetworkDevices(&NSArray::from_retained_slice(&[net.into_super()]));
        }

        if spec.is_vsock_enabled {
            config.setSocketDevices(&NSArray::from_retained_slice(&[
                VZVirtioSocketDeviceConfiguration::new().into_super(),
            ]));
        }

        let display =
            VZMacGraphicsDisplayConfiguration::initWithWidthInPixels_heightInPixels_pixelsPerInch(
                VZMacGraphicsDisplayConfiguration::alloc(),
                DISPLAY.0,
                DISPLAY.1,
                DISPLAY.2,
            );
        let graphics = VZMacGraphicsDeviceConfiguration::new();
        graphics.setDisplays(&NSArray::from_retained_slice(&[display]));
        config.setGraphicsDevices(&NSArray::from_retained_slice(&[graphics.into_super()]));
        config.setKeyboards(&NSArray::from_retained_slice(&[
            VZMacKeyboardConfiguration::new().into_super(),
        ]));
        config.setPointingDevices(&NSArray::from_retained_slice(&[
            VZMacTrackpadConfiguration::new().into_super(),
        ]));

        config.validateWithError().map_err(|err| ns_error(&err))?;
        config
            .validateSaveRestoreSupportWithError()
            .map_err(|err| ns_error(&err))?;
        Ok(config)
    }
}

/// Makes the machine in `workdir` a new sandbox of the template in
/// `template`, returning its boot source.
///
/// The disk and auxiliary storage are APFS clones, sharing blocks with the
/// template until either side writes; `workdir` must be on the same volume. A
/// fresh machine identifier makes it a different Mac to the guest. The
/// sandbox keeps the template's identity, and a clone of its saved state, only
/// when it is to restore that state, which restores into no other identity.
/// The template must be stopped: its disk is cloned as the state left it.
pub fn clone_machine(template: &Path, workdir: &Path, is_identity_kept: bool) -> Result<MacOsBoot> {
    std::fs::create_dir_all(workdir)?;
    for file in [DISK_FILE, AUX_FILE] {
        clonefile(&template.join(file), &workdir.join(file))?;
    }
    for file in [HARDWARE_MODEL_FILE, REQUIREMENTS_FILE] {
        std::fs::copy(template.join(file), workdir.join(file))?;
    }
    if is_identity_kept {
        std::fs::copy(
            template.join(MACHINE_ID_FILE),
            workdir.join(MACHINE_ID_FILE),
        )?;
        if template.join(SAVE_FILE).exists() {
            clonefile(&template.join(SAVE_FILE), &workdir.join(SAVE_FILE))?;
        }
    } else {
        write_machine_id(workdir)?;
    }
    MacOsBoot::read(workdir)
}

fn clonefile(src: &Path, dst: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let src = std::ffi::CString::new(src.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let dst = std::ffi::CString::new(dst.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    if unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) fn write_machine_id(dir: &Path) -> Result<()> {
    let id = unsafe { VZMacMachineIdentifier::new().dataRepresentation() };
    std::fs::write(dir.join(MACHINE_ID_FILE), id.to_vec())?;
    Ok(())
}

async fn read_connect(stream: &mut UnixStream) -> Result<u32> {
    // Byte at a time: whatever follows the line belongs to the guest.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < 64 {
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            let line = String::from_utf8_lossy(&line);
            return line
                .strip_prefix("CONNECT ")
                .and_then(|port| port.trim().parse().ok())
                .ok_or_else(|| invalid("expected CONNECT <port>"));
        }
        line.push(byte[0]);
    }
    Err(invalid("handshake line too long"))
}

fn dup(fd: i32) -> Result<OwnedFd> {
    let fd = unsafe { libc::dup(fd) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_data(path: &Path) -> Result<Retained<NSData>> {
    Ok(NSData::with_bytes(&std::fs::read(path)?))
}

pub(crate) fn file_url(path: &Path) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
}

pub(crate) fn ns_error(err: &NSError) -> Error {
    Error::Io(std::io::Error::other(format!(
        "{} ({} {})",
        err.localizedDescription(),
        err.domain(),
        err.code()
    )))
}

fn invalid(what: &str) -> Error {
    Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, what))
}

/// The queue dropped a reply channel without answering, which only happens
/// when the framework never calls its completion block.
fn dropped() -> Error {
    Error::Io(std::io::Error::other(
        "Virtualization.framework dropped a call without completing it",
    ))
}
