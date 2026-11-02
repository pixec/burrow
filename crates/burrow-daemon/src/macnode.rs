//! What a macOS sandbox does differently on a Mac node.
//!
//! A macOS template is not a kernel and a rootfs but an installed machine
//! with the agent in it, made by `BuildTemplate` from a restore image
//! (`from_ipsw`) or from another macOS template ([`build`]), and a sandbox is
//! an APFS clone of it with a fresh machine identity, booted cold: the
//! framework restores a saved state more slowly than macOS boots, and into
//! one machine at a time, so there is no warm pool. There is no tap and no firewall: the guest's NIC is served
//! by `burrow_net::usernet`, held to the policy the Linux ruleset renders.
//!
//! Every function exists on every target, so the shared create path can call
//! it behind a guest check; off macOS a macOS guest is refused before any of
//! them is reached.

use std::path::Path;

use burrow_proto::api::v1 as api;
use burrow_proto::common::v1 as common;
use burrow_vmm::{GuestOs, VmSpec};
use tonic::Status;

/// Whether `guest_os` is a macOS guest, which only a Mac build can name.
pub fn is_macos(guest_os: GuestOs) -> bool {
    #[cfg(target_os = "macos")]
    return guest_os == GuestOs::MacOs;
    #[cfg(not(target_os = "macos"))]
    {
        let _ = guest_os;
        false
    }
}

/// The writable disk of a macOS guest, which has no scratch image.
pub fn disk_file(guest_os: GuestOs) -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    if guest_os == GuestOs::MacOs {
        return Some(burrow_vmm::vz::DISK_FILE);
    }
    let _ = guest_os;
    None
}

/// Makes `workdir` a new machine cloned from the template in `template_dir`,
/// [`seed`]ed with `root_pem`.
pub async fn prepare(template_dir: &Path, workdir: &Path, root_pem: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if tokio::fs::try_exists(workdir).await.unwrap_or(false) {
            tokio::fs::remove_dir_all(workdir).await?;
        }
        let (from, to) = (template_dir.to_path_buf(), workdir.to_path_buf());
        tokio::task::spawn_blocking(move || burrow_vmm::vz::clone_machine(&from, &to, false))
            .await
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)?;
        seed(workdir, root_pem).await;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (template_dir, workdir, root_pem);
        Err(std::io::Error::other("macOS guests need a macOS node"))
    }
}

/// Turns a sandbox's spec into a macOS machine's: its own clone as the boot
/// source and disk, the resources asked for or the installed macOS's
/// minimums, and vsock for the agent.
#[allow(clippy::result_large_err)]
pub fn apply(spec: &mut VmSpec, resources: &common::ResourcePolicy) -> Result<(), Status> {
    #[cfg(target_os = "macos")]
    {
        let boot = burrow_vmm::MacOsBoot::read(&spec.workdir)
            .map_err(|err| Status::failed_precondition(format!("macOS machine: {err}")))?;
        spec.vcpus = match resources.vcpus {
            0 => boot.requirements.min_vcpus,
            vcpus => vcpus,
        };
        spec.mem_mib = match resources.mem_mib {
            0 => boot.requirements.min_mem_mib,
            mem_mib => mem_mib,
        };
        boot.requirements
            .check(spec.vcpus, spec.mem_mib)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        spec.boot = burrow_vmm::Boot::MacOs(boot);
        // The clone's disk in place of the Linux root and scratch; volumes
        // stay, after it.
        let volumes: Vec<_> = spec
            .drives
            .drain(..)
            .filter(|drive| drive.id.starts_with(burrow_vmm::vz::VOLUME_DISK_PREFIX))
            .collect();
        spec.drives = std::iter::once(burrow_vmm::vz::root_drive())
            .chain(volumes)
            .collect();
        // The lease's NIC stays, its tap name unused: the guest's link is the
        // socket pair `UserNets::attach` gives it.
        spec.is_vsock_enabled = true;
        spec.cgroup_root = None;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (spec, resources);
        Err(Status::failed_precondition(
            "macOS guests need a macOS node",
        ))
    }
}

/// macOS guests one Mac may run at once, by Apple's licence.
#[cfg(target_os = "macos")]
const MAX_RUNNING: usize = burrow_vmm::vz::MAX_RUNNING;
#[cfg(not(target_os = "macos"))]
const MAX_RUNNING: usize = 2;

/// The macOS guests starting on this Mac, each holding one of its slots.
///
/// A guest counts against the limit from the moment its create, boot or
/// resume is admitted rather than once it runs, so two that start together
/// cannot both see a free slot.
#[derive(Clone, Default)]
pub struct Slots {
    starting: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

/// One slot, held while a guest starts and given back when dropped. By then
/// a guest that started counts as running instead.
pub struct Slot {
    starting: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    id: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.starting.lock().unwrap().remove(&self.id);
    }
}

impl Slots {
    /// Takes a slot for `id`, refusing a third guest. `running` is every
    /// macOS sandbox running now, read under the lock its state changes
    /// under, which the caller holds until this returns: a guest cannot
    /// stop counting as starting before it counts as running.
    #[allow(clippy::result_large_err)]
    pub fn reserve(
        &self,
        id: &str,
        running: impl IntoIterator<Item = String>,
    ) -> Result<Slot, Status> {
        let mut starting = self.starting.lock().unwrap();
        let mut held: std::collections::HashSet<String> = running.into_iter().collect();
        held.extend(starting.iter().cloned());
        held.remove(id);
        if held.len() >= MAX_RUNNING {
            return Err(Status::resource_exhausted(format!(
                "this Mac already runs or is starting {} macOS guests, the most Apple's \
                 licence allows",
                held.len()
            )));
        }
        starting.insert(id.to_string());
        Ok(Slot {
            starting: std::sync::Arc::clone(&self.starting),
            id: id.to_string(),
        })
    }
}

/// The smallest disk macOS installs onto.
pub const MIN_DISK_MIB: u32 = 28 * 1024;
/// A `from_ipsw` build's disk when none is asked for.
pub const DEFAULT_DISK_MIB: u32 = 64 * 1024;

const VZ: &str = "vz";

/// A macOS template build, the counterpart of pulling or building a Linux
/// one. Node-local: a restore image is tens of gigabytes on the Mac's own
/// disk, and the template boots only on a Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacBuild {
    pub name: String,
    pub source: MacSource,
    /// The build machine's; `None` is the installed macOS's minimum.
    pub vcpus: Option<u32>,
    pub mem_mib: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacSource {
    /// Install a restore image, boot it once with provisioning and install
    /// the agent over SSH.
    Install { ipsw: Ipsw, disk_mib: u32 },
    /// Clone another macOS template as a new Mac, boot it and run the steps
    /// through the agent.
    Template {
        from: String,
        steps: Vec<String>,
        allow_domains: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipsw {
    /// The newest image in Apple's catalogue, downloaded once.
    Latest,
    Path(std::path::PathBuf),
}

/// Reads `request` as a macOS build, or `None` for any other.
pub async fn plan(
    data_dir: &Path,
    request: &api::BuildTemplateRequest,
) -> Result<Option<MacBuild>, Status> {
    let base = match request.from.as_str() {
        "" => None,
        from => {
            crate::template::validate_name(from)?;
            let dir = crate::template::templates_dir(data_dir).join(from);
            match tokio::fs::try_exists(&dir).await.unwrap_or(false) {
                true => Some(
                    crate::oci::image_environment(data_dir, from)
                        .await
                        .hypervisor,
                ),
                false => None,
            }
        }
    };
    plan_with(request, base.as_deref())
}

/// [`plan`], given the hypervisor the template `from` names records, or
/// `None` when there is no such template.
#[allow(clippy::result_large_err)]
pub fn plan_with(
    request: &api::BuildTemplateRequest,
    base_hypervisor: Option<&str>,
) -> Result<Option<MacBuild>, Status> {
    let invalid = |message: String| Err(Status::invalid_argument(message));
    let machine = |value: u32| (value != 0).then_some(value);
    if !request.from_ipsw.is_empty() {
        if !request.from.is_empty() || !request.from_image.is_empty() || !request.kits.is_empty() {
            return invalid(
                "from_ipsw installs macOS from a restore image, so it takes no from, from_image \
                 or kits"
                    .into(),
            );
        }
        if !matches!(request.hypervisor.as_str(), "" | VZ) {
            return invalid(format!(
                "from_ipsw makes a vz template; {} cannot run macOS",
                request.hypervisor
            ));
        }
        if !request.steps.is_empty() {
            return invalid(
                "a from_ipsw build installs macOS and the agent and takes no steps; run them in \
                 a build from it"
                    .into(),
            );
        }
        if !request.allow_domains.is_empty() {
            return invalid(
                "a from_ipsw build runs on the framework's NAT, which allow_domains cannot \
                 restrict"
                    .into(),
            );
        }
        if request.is_systemd {
            return invalid("a macOS template has no systemd mode".into());
        }
        let disk_mib = match request.disk_mib {
            0 => DEFAULT_DISK_MIB,
            disk_mib => disk_mib,
        };
        if disk_mib < MIN_DISK_MIB {
            return invalid(format!(
                "disk_mib {disk_mib} is too small: macOS needs {MIN_DISK_MIB} MiB to install"
            ));
        }
        let ipsw = match request.from_ipsw.as_str() {
            "latest" => Ipsw::Latest,
            path if Path::new(path).is_absolute() => Ipsw::Path(path.into()),
            other => {
                return invalid(format!(
                    "from_ipsw is \"latest\" or an absolute path on the node, not {other:?}"
                ));
            }
        };
        crate::template::validate_name(&request.name)?;
        return Ok(Some(MacBuild {
            name: request.name.clone(),
            source: MacSource::Install { ipsw, disk_mib },
            vcpus: machine(request.vcpus),
            mem_mib: machine(request.mem_mib),
        }));
    }

    let is_vz = request.hypervisor == VZ
        || (base_hypervisor == Some(VZ)
            && request.from_image.is_empty()
            && request.kits.is_empty());
    if !is_vz {
        if request.disk_mib != 0 {
            return invalid(
                "disk_mib sizes a macOS install; only a from_ipsw build takes it".into(),
            );
        }
        return Ok(None);
    }
    if request.from.is_empty() || !request.from_image.is_empty() || !request.kits.is_empty() {
        return invalid(
            "a vz template is installed from a restore image (from_ipsw) or built on another vz \
             template (from)"
                .into(),
        );
    }
    let from = &request.from;
    if !matches!(request.hypervisor.as_str(), "" | VZ) {
        return invalid(format!(
            "{from} is a vz template, so a build on it is too; {} cannot run macOS",
            request.hypervisor
        ));
    }
    match base_hypervisor {
        None => return Err(Status::not_found(format!("no base template {from}"))),
        Some(VZ) => {}
        Some(_) => return invalid(format!("{from} is not a vz template")),
    }
    if request.disk_mib != 0 {
        return invalid(format!(
            "a build on {from} keeps its disk; disk_mib is for a from_ipsw build"
        ));
    }
    if request.is_systemd {
        return invalid("a macOS template has no systemd mode".into());
    }
    crate::template::validate_name(&request.name)?;
    Ok(Some(MacBuild {
        name: request.name.clone(),
        source: MacSource::Template {
            from: from.clone(),
            steps: request
                .steps
                .iter()
                .map(|step| step.run.trim().to_string())
                .filter(|run| !run.is_empty())
                .collect(),
            allow_domains: request.allow_domains.clone(),
        },
        vcpus: machine(request.vcpus),
        mem_mib: machine(request.mem_mib),
    }))
}

/// Builds `plan` beside its final name and renames it into place, so a scan
/// never lists a half-built machine and a failed rebuild leaves the old one.
#[cfg(target_os = "macos")]
pub async fn build(
    manager: &crate::sandbox::SandboxManager,
    data_dir: &Path,
    node_id: &str,
    plan: MacBuild,
    guest_binary: &Path,
    tx: &crate::template::LogTx,
) -> Result<(), Status> {
    manager.require_hypervisor(burrow_vmm::Hypervisor::Vz)?;
    let templates = crate::template::templates_dir(data_dir);
    let building = templates.join(format!(".{}.building", plan.name));
    let _ = tokio::fs::remove_dir_all(&building).await;
    let started = std::time::Instant::now();
    let built = match &plan.source {
        MacSource::Install { ipsw, disk_mib } => {
            install(
                manager,
                data_dir,
                &plan,
                ipsw,
                *disk_mib,
                &building,
                guest_binary,
                tx,
            )
            .await
        }
        MacSource::Template {
            from,
            steps,
            allow_domains,
        } => {
            derive(
                manager,
                node_id,
                &plan,
                from,
                steps,
                allow_domains,
                &building,
                tx,
            )
            .await
        }
    };
    let published = match built {
        Ok(()) => publish(&templates, &plan.name, &building).await,
        Err(err) => Err(err),
    };
    if let Err(err) = published {
        let _ = tokio::fs::remove_dir_all(&building).await;
        return Err(err);
    }
    let size_bytes =
        tokio::fs::metadata(templates.join(&plan.name).join(burrow_vmm::vz::DISK_FILE))
            .await
            .map_or(0, |meta| meta.len());
    tracing::info!(
        template = plan.name,
        secs = started.elapsed().as_secs(),
        "macOS template ready"
    );
    let _ = tx
        .send(crate::template::event(api::build_log::Event::Done(
            api::BuildDone {
                template: plan.name,
                size_bytes,
            },
        )))
        .await;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub async fn build(
    _: &crate::sandbox::SandboxManager,
    _: &Path,
    _: &str,
    _: MacBuild,
    _: &Path,
    _: &crate::template::LogTx,
) -> Result<(), Status> {
    Err(Status::failed_precondition(
        "macOS templates are built on a Mac node offering vz; this node cannot install or boot \
         macOS",
    ))
}

/// A line of progress for the caller. Dropped rather than waited on when the
/// caller is behind: the next one says more.
#[cfg(target_os = "macos")]
fn say(tx: &crate::template::LogTx, line: String) {
    tracing::info!("{line}");
    let _ = tx.try_send(crate::template::event(api::build_log::Event::Stdout(
        format!("{line}\n").into_bytes(),
    )));
}

#[cfg(target_os = "macos")]
async fn step(tx: &crate::template::LogTx, step: String) {
    let _ = tx
        .send(crate::template::event(api::build_log::Event::Step(step)))
        .await;
}

/// Records what the template runs on and renames it into place.
#[cfg(target_os = "macos")]
async fn publish(templates: &Path, name: &str, building: &Path) -> Result<(), Status> {
    let failed =
        |err: std::io::Error| Status::internal(format!("publishing template {name}: {err}"));
    let environment = crate::oci::ImageEnvironment {
        hypervisor: burrow_vmm::Hypervisor::Vz.to_string(),
        guest_os: GuestOs::MacOs.as_str().to_string(),
        ..Default::default()
    };
    let environment = serde_json::to_vec(&environment)
        .map_err(|err| Status::internal(format!("image config: {err}")))?;
    tokio::fs::write(building.join("image.json"), environment)
        .await
        .map_err(failed)?;
    let dir = templates.join(name);
    if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        let old = templates.join(format!(".{name}.old"));
        let _ = tokio::fs::remove_dir_all(&old).await;
        tokio::fs::rename(&dir, &old).await.map_err(failed)?;
        tokio::fs::rename(building, &dir).await.map_err(failed)?;
        tokio::fs::remove_dir_all(&old).await.map_err(failed)?;
    } else {
        tokio::fs::rename(building, &dir).await.map_err(failed)?;
    }
    Ok(())
}

/// Installs the restore image into `building`, boots it once with
/// provisioning and NAT, copies the guest agent in over SSH as the
/// provisioned admin and installs it as a LaunchDaemon, turns Remote Login
/// off again and shuts the guest down from inside. SSH rather than writing
/// the disk offline: the agent's files must be root-owned on the guest's Data
/// volume, which the host can only write as root, and a running guest is also
/// what proves the agent answers on vsock before the template is published.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
async fn install(
    manager: &crate::sandbox::SandboxManager,
    data_dir: &Path,
    plan: &MacBuild,
    ipsw: &Ipsw,
    disk_mib: u32,
    building: &Path,
    guest_binary: &Path,
    tx: &crate::template::LogTx,
) -> Result<(), Status> {
    // The installer and the first boot are a running macOS guest each, for
    // the whole build.
    let build_id = format!("bld_{}", burrow_common::SandboxId::generate());
    let _slot = manager.reserve_mac_slot(&build_id, GuestOs::MacOs).await?;
    let ipsw = match ipsw {
        Ipsw::Path(path) => {
            if !tokio::fs::try_exists(path).await.unwrap_or(false) {
                return Err(Status::failed_precondition(format!(
                    "no restore image at {} on this node",
                    path.display()
                )));
            }
            path.clone()
        }
        Ipsw::Latest => {
            step(tx, "fetching the latest restore image".into()).await;
            crate::ipsw::fetch_latest(data_dir, |line| say(tx, line)).await?
        }
    };
    step(tx, format!("installing {}", ipsw.display())).await;
    let started = std::time::Instant::now();
    let spec = burrow_vmm::vz::InstallSpec {
        template: building.to_path_buf(),
        vcpus: plan.vcpus,
        mem_mib: plan.mem_mib,
        disk_bytes: u64::from(disk_mib) << 20,
    };
    let progress = tx.clone();
    // The installer's future holds the framework's blocks, which may not
    // cross threads, so it runs on a thread of its own.
    let installed = tokio::task::spawn_blocking(move || {
        let last = std::cell::Cell::new(None);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| err.to_string())?
            .block_on(burrow_vmm::vz::install(&ipsw, &spec, |fraction| {
                let percent = (fraction * 100.0) as u32;
                if last.replace(Some(percent)) != Some(percent) {
                    say(&progress, format!("installing macOS: {percent}%"));
                }
            }))
            .map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| Status::internal(format!("the installer did not run: {err}")))?
    .map_err(|err| Status::internal(format!("installing macOS: {err}")))?;
    say(
        tx,
        format!(
            "installed macOS {} ({}) in {}s",
            installed.version,
            installed.build,
            started.elapsed().as_secs()
        ),
    );
    step(
        tx,
        "first boot: provisioning and installing the agent".into(),
    )
    .await;
    first_boot(
        building,
        &plan.name,
        installed.vcpus,
        installed.mem_mib,
        guest_binary,
        tx,
    )
    .await
    .map_err(|err| Status::internal(format!("first boot: {err:#}")))
}

/// How long the provisioned first boot gets to come up on the network, which
/// includes macOS creating the account.
#[cfg(target_os = "macos")]
const FIRST_BOOT: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a guest gets to shut itself down.
#[cfg(target_os = "macos")]
const SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(180);

/// Boots the machine in `dir` once, provisioned, and installs the agent in it.
#[cfg(target_os = "macos")]
async fn first_boot(
    dir: &Path,
    name: &str,
    vcpus: u32,
    mem_mib: u32,
    guest_binary: &Path,
    tx: &crate::template::LogTx,
) -> anyhow::Result<()> {
    use std::time::Duration;

    let boot = burrow_vmm::MacOsBoot::read(dir)?;
    let password = uuid::Uuid::new_v4().simple().to_string();
    let mac = {
        let b = *uuid::Uuid::new_v4().as_bytes();
        // Locally administered, unicast.
        format!(
            "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4]
        )
    };
    let mut spec = VmSpec::new(
        format!("template-{name}"),
        dir,
        burrow_vmm::Backend::Vz(burrow_vmm::VzConfig {
            provisioning: Some(burrow_vmm::vz::Provisioning {
                full_name: "Burrow".into(),
                username: "burrow".into(),
                password: password.clone(),
                is_auto_login: true,
                is_remote_login_enabled: true,
            }),
            ..Default::default()
        }),
    );
    spec.guest_os = GuestOs::MacOs;
    spec.vcpus = vcpus;
    spec.mem_mib = mem_mib;
    spec.boot = burrow_vmm::Boot::MacOs(boot);
    spec.drives = vec![burrow_vmm::vz::root_drive()];
    spec.net = Some(burrow_vmm::NetSpec {
        tap: String::new(),
        guest_mac: Some(mac.clone()),
    });
    spec.is_vsock_enabled = true;
    spec.cgroup_root = None;
    // The installer's machine holds the auxiliary storage until the framework
    // has freed it, a moment after the install returns.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let vm = loop {
        match burrow_vmm::Vm::boot(spec.clone()).await {
            Ok(vm) => break vm,
            Err(err) if std::time::Instant::now() < deadline => {
                tracing::debug!(%err, "the installed machine is not free yet");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(err) => return Err(err.into()),
        }
    };
    let result = async {
        let address = wait_for_ssh(&mac, FIRST_BOOT).await?;
        say(
            tx,
            format!("provisioned guest is up at {address}; installing the agent"),
        );
        let ssh = Ssh::new(dir, &address, &password)?;
        ssh.copy(guest_binary, "burrow-guest").await?;
        ssh.sudo("./burrow-guest install && rm burrow-guest")
            .await?;
        vm.wait_for_vsock(crate::guestconn::AGENT_PORT, Duration::from_secs(60))
            .await?;
        say(tx, "agent answers on vsock; shutting the guest down".into());
        // Remote Login was only for this; nothing in a sandbox knows the
        // password, but nothing should be listening for it either.
        ssh.sudo("launchctl disable system/com.openssh.sshd; shutdown -h +0")
            .await
            .ok();
        let burrow_vmm::Vm::Vz(vz) = &vm else {
            unreachable!("booted with the vz backend")
        };
        vz.wait_stopped(SHUTDOWN).await?;
        anyhow::Ok(())
    }
    .await;
    vm.kill().await?;
    result
}

/// Clones `from` into a build sandbox, a new Mac booted cold on the node's
/// network stack, runs the steps in it through the agent as a Linux build
/// does, shuts it down from inside and keeps its machine in `building`. The
/// account and everything else come from `from`: only a first boot after an
/// install is provisioned.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
async fn derive(
    manager: &crate::sandbox::SandboxManager,
    node_id: &str,
    plan: &MacBuild,
    from: &str,
    steps: &[String],
    allow_domains: &[String],
    building: &Path,
    tx: &crate::template::LogTx,
) -> Result<(), Status> {
    let build_id = format!("bld_{}", burrow_common::SandboxId::generate());
    let policy = common::Policy {
        resources: Some(common::ResourcePolicy {
            vcpus: plan.vcpus.unwrap_or(0),
            mem_mib: plan.mem_mib.unwrap_or(0),
            ..Default::default()
        }),
        network: Some(crate::template::build_network(allow_domains)),
        ..Default::default()
    };
    step(tx, format!("booting a new Mac cloned from {from}")).await;
    manager
        .create_seeded(
            build_id.clone(),
            from.to_string(),
            policy,
            Default::default(),
            node_id.to_string(),
            None,
            String::new(),
        )
        .await?;
    let outcome = async {
        for run in steps {
            step(tx, run.clone()).await;
            let exit = crate::template::exec_streaming(manager, &build_id, run, tx).await?;
            if exit != 0 {
                return Err(Status::failed_precondition(format!(
                    "build step failed with exit {exit}: {run}"
                )));
            }
        }
        step(tx, "shutting down".into()).await;
        let workdir = manager.shut_down_from_inside(&build_id, SHUTDOWN).await?;
        let to = building.to_path_buf();
        tokio::task::spawn_blocking(move || burrow_vmm::vz::clone_machine(&workdir, &to, true))
            .await
            .map_err(|err| Status::internal(format!("keeping the machine did not run: {err}")))?
            .map_err(|err| Status::internal(format!("keeping the machine: {err}")))?;
        Ok(())
    }
    .await;
    if let Err(err) = manager.delete(&build_id).await {
        tracing::warn!(build = build_id, %err, "could not remove build sandbox");
    }
    outcome
}

/// Writes onto a stopped macOS machine's Data volume what its guest cannot
/// write for itself, before it boots cold: `pem`'s root as a trusted anchor,
/// and Full Disk Access for the agent.
///
/// A running guest keeps both from root. trustd authorizes each change to the
/// admin trust settings again in its own process and wants an administrator
/// in a dialog, whatever the rights database says, and TCC's database is
/// under SIP. On a disk nothing runs from they are plain files. The root
/// replaces whichever one an earlier boot wrote, so a guest trusts only the
/// root it boots with, and none when `pem` is empty. Full Disk Access is what
/// opendirectoryd asks of a caller deleting a user.
///
/// Never before a restore: the saved kernel would not know its disk changed.
/// A failure is logged and the boot goes on without it.
pub async fn seed(workdir: &Path, pem: &str) {
    #[cfg(target_os = "macos")]
    if let Err(err) = seed_disk(&workdir.join(burrow_vmm::vz::DISK_FILE), pem).await {
        tracing::warn!(
            workdir = %workdir.display(),
            "could not write the inspection root and the agent's Full Disk Access onto the \
             guest's disk: {err:#}"
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (workdir, pem);
}

/// Where the agent is installed, as TCC names it.
#[cfg(target_os = "macos")]
const AGENT_PATH: &str = "/usr/local/libexec/burrow-guest";
/// trustd's admin trust settings, as `security trust-settings-export -d`
/// writes them.
#[cfg(target_os = "macos")]
const ADMIN_TRUST: &str = "private/var/protected/trustd/private/Admin.plist";
#[cfg(target_os = "macos")]
const TCC_DB: &str = "Library/Application Support/com.apple.TCC/TCC.db";
/// The key marking a trust settings entry as one a boot wrote. trustd
/// ignores it.
#[cfg(target_os = "macos")]
const MARK: &str = "burrow";

#[cfg(target_os = "macos")]
async fn seed_disk(disk: &Path, pem: &str) -> anyhow::Result<()> {
    let disk_arg = disk.to_string_lossy();
    let attached = plist(&["image", "attach", "--noMount", "--plist", &disk_arg]).await?;
    let whole = attached["system-entities"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entity| entity["content-hint"] == "GUID_partition_scheme")
        .and_then(|entity| entity["dev-entry"].as_str())
        .map(|dev| dev.trim_start_matches("/dev/").to_string())
        .ok_or_else(|| anyhow::anyhow!("attaching the disk showed no partition map"))?;
    let seeded = seed_attached(disk, &whole, pem).await;
    let ejected = run("diskutil", &["eject", &whole]).await;
    seeded.and(ejected)
}

#[cfg(target_os = "macos")]
async fn seed_attached(disk: &Path, whole: &str, pem: &str) -> anyhow::Result<()> {
    let listed = plist(&["apfs", "list", "-plist"]).await?;
    let partition = format!("{whole}s");
    let on_disk = |container: &&serde_json::Value| {
        container["PhysicalStores"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|store| store["DeviceIdentifier"].as_str())
            .any(|store| store.starts_with(&partition))
    };
    let is_data = |volume: &&serde_json::Value| {
        volume["Roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|role| role == "Data"))
    };
    let data = listed["Containers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(on_disk)
        .flat_map(|container| container["Volumes"].as_array().into_iter().flatten())
        .find(is_data)
        .and_then(|volume| volume["DeviceIdentifier"].as_str())
        .ok_or_else(|| anyhow::anyhow!("the disk has no APFS Data volume"))?
        .to_string();
    let mount = disk.with_extension("data");
    tokio::fs::create_dir_all(&mount).await?;
    let mount_arg = mount.to_string_lossy();
    run(
        "diskutil",
        &["mount", "nobrowse", "-mountPoint", &mount_arg, &data],
    )
    .await?;
    let written = async {
        trust_root(&mount.join(ADMIN_TRUST), pem).await?;
        grant_full_disk_access(&mount.join(TCC_DB)).await
    }
    .await;
    let unmounted = run("diskutil", &["unmount", &mount_arg]).await;
    let _ = tokio::fs::remove_dir(&mount).await;
    written.and(unmounted)
}

/// Makes `pem`'s certificate the one root in `settings` marked as a boot's,
/// trusted for every policy as `security add-trusted-cert -d -r trustRoot`
/// would. What anyone else trusted stays.
#[cfg(target_os = "macos")]
async fn trust_root(settings: &Path, pem: &str) -> anyhow::Result<()> {
    let wanted = first_certificate(pem)
        .map(|der| trust_entry(&der))
        .transpose()?;
    let wanted_key = wanted.as_ref().map(|(key, _)| key.as_str());
    let keys = plutil(settings, &["-extract", "trustList", "raw"]).await?;
    let mut is_present = false;
    for key in keys.lines().map(str::trim).filter(|key| !key.is_empty()) {
        if Some(key) == wanted_key {
            is_present = true;
            continue;
        }
        let mark = format!("trustList.{key}.{MARK}");
        if plutil(settings, &["-extract", &mark, "raw"])
            .await
            .is_ok_and(|value| value.trim() == "true")
        {
            rewrite(settings, &["-remove", &format!("trustList.{key}")]).await?;
        }
    }
    if let Some((key, entry)) = wanted.filter(|_| !is_present) {
        rewrite(
            settings,
            &["-insert", &format!("trustList.{key}"), "-xml", &entry],
        )
        .await?;
    }
    Ok(())
}

/// A trust settings entry for `der`, keyed as trustd keys them by the
/// certificate's SHA-1. No settings is every policy, as a root.
#[cfg(target_os = "macos")]
fn trust_entry(der: &[u8]) -> anyhow::Result<(String, String)> {
    use base64::Engine as _;
    use sha1::Digest as _;
    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|err| anyhow::anyhow!("the inspection root: {err}"))?;
    let tbs = &certificate.tbs_certificate;
    let base64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let entry = format!(
        "<dict><key>{MARK}</key><true/><key>issuerName</key><data>{}</data>\
         <key>modDate</key><date>{}</date><key>serialNumber</key><data>{}</data>\
         <key>trustSettings</key><array/></dict>",
        base64(tbs.issuer.as_raw()),
        burrow_common::now_rfc3339(),
        base64(tbs.raw_serial()),
    );
    Ok((hex::encode_upper(sha1::Sha1::digest(der)), entry))
}

/// Gives the agent Full Disk Access by its path, which only root can write,
/// so it survives the agent being upgraded.
#[cfg(target_os = "macos")]
async fn grant_full_disk_access(db: &Path) -> anyhow::Result<()> {
    let db = db.to_string_lossy();
    let grant = format!(
        "insert or replace into access (service, client, client_type, auth_value, \
         auth_reason, auth_version, csreq, flags) values \
         ('kTCCServiceSystemPolicyAllFiles', '{AGENT_PATH}', 1, 2, 4, 1, NULL, 0)"
    );
    run("/usr/bin/sqlite3", &[&db, &grant]).await
}

#[cfg(target_os = "macos")]
fn first_certificate(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .skip_while(|line| line.trim() != "-----BEGIN CERTIFICATE-----")
        .skip(1)
        .take_while(|line| line.trim() != "-----END CERTIFICATE-----")
        .collect();
    (!body.is_empty())
        .then(|| base64::engine::general_purpose::STANDARD.decode(body).ok())
        .flatten()
}

/// `diskutil args`' plist output, as JSON.
#[cfg(target_os = "macos")]
async fn plist(args: &[&str]) -> anyhow::Result<serde_json::Value> {
    let xml = output("diskutil", args, None).await?;
    let json = output("plutil", &["-convert", "json", "-o", "-", "-"], Some(xml)).await?;
    Ok(serde_json::from_slice(&json)?)
}

/// What `plutil args` makes of `path`, which it leaves alone.
#[cfg(target_os = "macos")]
async fn plutil(path: &Path, args: &[&str]) -> anyhow::Result<String> {
    let path = path.to_string_lossy();
    let out = output("plutil", &[args, &["-o", "-", &path]].concat(), None).await?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Edits `path` with `plutil args`, writing the result into the same file:
/// the volume is mounted with ownership ignored, so a new file would lose
/// its owner.
#[cfg(target_os = "macos")]
async fn rewrite(path: &Path, args: &[&str]) -> anyhow::Result<()> {
    let edited = plutil(path, args).await?;
    tokio::fs::write(path, edited).await?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    output(program, args, None).await.map(drop)
}

#[cfg(target_os = "macos")]
async fn output(program: &str, args: &[&str], input: Option<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
    use tokio::io::AsyncWriteExt as _;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(match input {
            Some(_) => std::process::Stdio::piped(),
            None => std::process::Stdio::null(),
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(&input).await?;
    }
    let out = child.wait_with_output().await?;
    anyhow::ensure!(
        out.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(out.stdout)
}

/// Waits for the guest with `mac` to take a lease from the framework's DHCP
/// server and answer on port 22.
#[cfg(target_os = "macos")]
async fn wait_for_ssh(mac: &str, timeout: std::time::Duration) -> anyhow::Result<String> {
    // The lease file writes each octet without its leading zero.
    let wanted = format!(
        "1,{}",
        mac.split(':')
            .map(|octet| octet.trim_start_matches('0'))
            .map(|octet| if octet.is_empty() { "0" } else { octet })
            .collect::<Vec<_>>()
            .join(":")
    );
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let leases = tokio::fs::read_to_string("/var/db/dhcpd_leases")
            .await
            .unwrap_or_default();
        let address = leases.split('}').find_map(|lease| {
            lease.contains(&format!("hw_address={wanted}")).then(|| {
                lease
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("ip_address="))
                    .map(str::to_string)
            })?
        });
        if let Some(address) = address {
            let reachable = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect((address.as_str(), 22)),
            )
            .await;
            if matches!(reachable, Ok(Ok(_))) {
                return Ok(address);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    anyhow::bail!("the provisioned guest did not answer on SSH within {timeout:?}")
}

/// Password SSH to the provisioned admin, the password handed over through
/// `SSH_ASKPASS` rather than an argument or a terminal.
#[cfg(target_os = "macos")]
struct Ssh {
    address: String,
    password: String,
    askpass: std::path::PathBuf,
}

#[cfg(target_os = "macos")]
impl Drop for Ssh {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.askpass);
    }
}

#[cfg(target_os = "macos")]
impl Ssh {
    /// `dir` holds the askpass script while the session lasts. It prints the
    /// password from the environment, so the file itself holds no secret.
    fn new(dir: &Path, address: &str, password: &str) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt as _;
        let askpass = dir.join("askpass.sh");
        std::fs::write(
            &askpass,
            "#!/bin/sh\nprintf '%s\\n' \"$BURROW_VZ_PASSWORD\"\n",
        )?;
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            address: address.to_string(),
            password: password.to_string(),
            askpass,
        })
    }

    fn command(&self, program: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(program);
        command
            .env("SSH_ASKPASS", &self.askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("BURROW_VZ_PASSWORD", &self.password)
            .args([
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=10",
            ]);
        command
    }

    async fn copy(&self, from: &Path, to: &str) -> anyhow::Result<()> {
        let status = self
            .command("scp")
            .arg(from)
            .arg(format!("burrow@{}:{to}", self.address))
            .stdin(std::process::Stdio::null())
            .status()
            .await?;
        anyhow::ensure!(status.success(), "scp to the guest failed: {status}");
        Ok(())
    }

    /// Runs `script` as root, the password fed to `sudo -S` on stdin.
    async fn sudo(&self, script: &str) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let mut child = self
            .command("ssh")
            .arg(format!("burrow@{}", self.address))
            .arg(format!("sudo -S -p '' sh -c '{script}'"))
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped");
        stdin
            .write_all(format!("{}\n", self.password).as_bytes())
            .await?;
        drop(stdin);
        let status = child.wait().await?;
        anyhow::ensure!(status.success(), "{script:?} in the guest failed: {status}");
        Ok(())
    }
}

/// Memory a guest could be given without swapping: free pages plus the
/// inactive, speculative and purgeable ones the kernel reclaims on demand.
/// sysinfo's figure on macOS leaves most of the inactive pages out, which on
/// a Mac in use is most of what is there.
#[cfg(target_os = "macos")]
pub fn available_memory() -> Option<u64> {
    let mut stats: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // libc points at the mach2 crate for this, which would be a dependency
    // for one call.
    #[allow(deprecated)]
    let status = unsafe {
        libc::host_statistics64(
            libc::mach_host_self(),
            libc::HOST_VM_INFO64,
            (&mut stats as *mut libc::vm_statistics64).cast(),
            &mut count,
        )
    };
    if status != libc::KERN_SUCCESS {
        return None;
    }
    let pages = u64::from(stats.free_count)
        + u64::from(stats.inactive_count)
        + u64::from(stats.speculative_count)
        + u64::from(stats.purgeable_count);
    Some(pages * unsafe { libc::vm_page_size } as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    fn root() -> String {
        burrow_proxy::inspect::create_root("test", burrow_proxy::inspect::ROOT_LIFETIME)
            .unwrap()
            .0
    }

    /// A new root replaces the one a boot wrote, none removes it, and what
    /// someone else trusted stays throughout.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn each_boot_leaves_only_its_own_root_trusted() {
        let dir = std::env::temp_dir().join(format!("burrow-admin-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("Admin.plist");
        std::fs::write(
            &settings,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>trustList</key><dict>
<key>0000</key><dict><key>trustSettings</key><array/></dict>
</dict><key>trustVersion</key><integer>1</integer></dict></plist>"#,
        )
        .unwrap();
        let keys = || async {
            let mut keys: Vec<String> = plutil(&settings, &["-extract", "trustList", "raw"])
                .await
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect();
            keys.sort();
            keys
        };
        let key = |pem: &str| trust_entry(&first_certificate(pem).unwrap()).unwrap().0;
        let (old, new) = (root(), root());

        trust_root(&settings, &old).await.unwrap();
        assert_eq!(keys().await, ["0000".to_string(), key(&old)]);
        trust_root(&settings, &new).await.unwrap();
        trust_root(&settings, &new).await.unwrap();
        assert_eq!(keys().await, ["0000".to_string(), key(&new)]);
        trust_root(&settings, "").await.unwrap();
        assert_eq!(keys().await, ["0000"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_trust_entry_is_keyed_by_sha1_and_names_issuer_and_serial() {
        use base64::Engine as _;
        use sha1::Digest as _;
        let der = first_certificate(&root()).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let (key, entry) = trust_entry(&der).unwrap();
        assert_eq!(key, hex::encode_upper(sha1::Sha1::digest(&der)));
        let base64 = |bytes| base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(entry.contains(&base64(parsed.tbs_certificate.issuer.as_raw())));
        assert!(entry.contains(&base64(parsed.tbs_certificate.raw_serial())));
        assert!(entry.contains("<key>trustSettings</key><array/>"));
    }

    /// Seeds the stopped machine in `BURROW_MAC_WORKDIR` with the root in
    /// `BURROW_MAC_ROOT` (a PEM file; unset trusts none). Boot it after to
    /// check: `security verify-cert` and a URLSession fetch through the
    /// inspection proxy, and `burrow user delete`.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "writes a stopped macOS machine's disk"]
    async fn seeds_a_stopped_machine() {
        let workdir = std::env::var("BURROW_MAC_WORKDIR").expect("BURROW_MAC_WORKDIR");
        let pem = std::env::var("BURROW_MAC_ROOT")
            .map(|path| std::fs::read_to_string(path).unwrap())
            .unwrap_or_default();
        seed_disk(&Path::new(&workdir).join(burrow_vmm::vz::DISK_FILE), &pem)
            .await
            .unwrap();
    }

    /// Apple's licence caps a Mac at two running macOS guests; the third
    /// is refused before anything is cloned or booted, whether the other two
    /// run already or are still starting.
    #[test]
    fn a_third_macos_guest_is_refused() {
        let slots = Slots::default();
        let none = || std::iter::empty::<String>();
        let first = slots.reserve("sbx_a", none()).unwrap();
        let _second = slots.reserve("sbx_b", none()).unwrap();
        let refused = slots.reserve("sbx_c", none()).err().unwrap();
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);

        // A started guest gives its slot back and counts as running.
        drop(first);
        assert!(slots.reserve("sbx_c", ["sbx_a".to_string()]).is_err());
        assert!(slots.reserve("sbx_c", none()).is_ok());
        // Restarting a guest is not a guest more.
        assert!(slots.reserve("sbx_b", ["sbx_a".to_string()]).is_ok());
    }

    /// Creates racing for the last slot: exactly as many win as there are
    /// slots, however they interleave.
    #[test]
    fn concurrent_reservations_never_exceed_the_limit() {
        let slots = Slots::default();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let won: Vec<_> = (0..8)
            .map(|i| {
                let (slots, barrier) = (slots.clone(), std::sync::Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    slots.reserve(&format!("sbx_{i}"), std::iter::empty()).ok()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(won.len(), MAX_RUNNING);
    }

    fn request(name: &str) -> api::BuildTemplateRequest {
        api::BuildTemplateRequest {
            name: name.into(),
            ..Default::default()
        }
    }

    fn refusal(request: &api::BuildTemplateRequest, base: Option<&str>) -> tonic::Code {
        plan_with(request, base).err().unwrap().code()
    }

    #[test]
    fn a_from_ipsw_build_installs_with_the_default_disk() {
        let install = api::BuildTemplateRequest {
            from_ipsw: "latest".into(),
            hypervisor: "vz".into(),
            vcpus: 4,
            mem_mib: 8192,
            ..request("macos-27")
        };
        assert_eq!(
            plan_with(&install, None).unwrap(),
            Some(MacBuild {
                name: "macos-27".into(),
                source: MacSource::Install {
                    ipsw: Ipsw::Latest,
                    disk_mib: DEFAULT_DISK_MIB,
                },
                vcpus: Some(4),
                mem_mib: Some(8192),
            })
        );
        // No hypervisor means vz; no machine means the image's minimum.
        let path = api::BuildTemplateRequest {
            from_ipsw: "/Users/me/restore.ipsw".into(),
            disk_mib: MIN_DISK_MIB,
            ..request("macos-27")
        };
        assert_eq!(
            plan_with(&path, None).unwrap().unwrap(),
            MacBuild {
                name: "macos-27".into(),
                source: MacSource::Install {
                    ipsw: Ipsw::Path("/Users/me/restore.ipsw".into()),
                    disk_mib: MIN_DISK_MIB,
                },
                vcpus: None,
                mem_mib: None,
            }
        );
    }

    #[test]
    fn from_ipsw_is_the_only_source_and_only_for_vz() {
        let install = || api::BuildTemplateRequest {
            from_ipsw: "latest".into(),
            ..request("macos-27")
        };
        for other in [
            api::BuildTemplateRequest {
                from: "macos-26".into(),
                ..install()
            },
            api::BuildTemplateRequest {
                from_image: "python:3.12".into(),
                ..install()
            },
            api::BuildTemplateRequest {
                kits: vec!["docker/sandbox-kit".into()],
                ..install()
            },
            api::BuildTemplateRequest {
                hypervisor: "firecracker".into(),
                ..install()
            },
            api::BuildTemplateRequest {
                steps: vec![api::BuildStep { run: "true".into() }],
                ..install()
            },
            api::BuildTemplateRequest {
                allow_domains: vec!["apple.com".into()],
                ..install()
            },
            api::BuildTemplateRequest {
                from_ipsw: "restore.ipsw".into(),
                ..install()
            },
            api::BuildTemplateRequest {
                name: "../escape".into(),
                ..install()
            },
        ] {
            assert_eq!(
                refusal(&other, Some("vz")),
                tonic::Code::InvalidArgument,
                "{other:?}"
            );
        }
    }

    #[test]
    fn a_disk_macos_cannot_install_on_is_refused() {
        let small = api::BuildTemplateRequest {
            from_ipsw: "latest".into(),
            disk_mib: MIN_DISK_MIB - 1,
            ..request("macos-27")
        };
        assert_eq!(refusal(&small, None), tonic::Code::InvalidArgument);
        // Only an install has a disk to size.
        let linux = api::BuildTemplateRequest {
            from: "alpine".into(),
            disk_mib: DEFAULT_DISK_MIB,
            ..request("tools")
        };
        assert_eq!(refusal(&linux, Some("")), tonic::Code::InvalidArgument);
        let derived = api::BuildTemplateRequest {
            from: "macos-27".into(),
            disk_mib: DEFAULT_DISK_MIB,
            ..request("macos-dev")
        };
        assert_eq!(refusal(&derived, Some("vz")), tonic::Code::InvalidArgument);
    }

    #[test]
    fn a_build_on_a_vz_template_runs_its_steps_in_a_clone() {
        let derived = api::BuildTemplateRequest {
            from: "macos-27".into(),
            steps: vec![
                api::BuildStep {
                    run: " brew install git ".into(),
                },
                api::BuildStep { run: "  ".into() },
            ],
            ..request("macos-dev")
        };
        assert_eq!(
            plan_with(&derived, Some("vz")).unwrap(),
            Some(MacBuild {
                name: "macos-dev".into(),
                source: MacSource::Template {
                    from: "macos-27".into(),
                    steps: vec!["brew install git".into()],
                    allow_domains: vec![],
                },
                vcpus: None,
                mem_mib: None,
            })
        );
        // Naming vz is the same build; naming another hypervisor is not one.
        let named = api::BuildTemplateRequest {
            hypervisor: "vz".into(),
            ..derived.clone()
        };
        assert!(plan_with(&named, Some("vz")).unwrap().is_some());
        let other = api::BuildTemplateRequest {
            hypervisor: "cloud-hypervisor".into(),
            ..derived.clone()
        };
        assert_eq!(refusal(&other, Some("vz")), tonic::Code::InvalidArgument);
        let systemd = api::BuildTemplateRequest {
            is_systemd: true,
            ..derived.clone()
        };
        assert_eq!(refusal(&systemd, Some("vz")), tonic::Code::InvalidArgument);
    }

    #[test]
    fn vz_needs_a_vz_base() {
        let vz = |from: &str| api::BuildTemplateRequest {
            from: from.into(),
            hypervisor: "vz".into(),
            ..request("macos-dev")
        };
        assert_eq!(refusal(&vz("macos-27"), None), tonic::Code::NotFound);
        assert_eq!(
            refusal(&vz("alpine"), Some("firecracker")),
            tonic::Code::InvalidArgument
        );
        assert_eq!(refusal(&vz(""), None), tonic::Code::InvalidArgument);
        let image = api::BuildTemplateRequest {
            from_image: "python:3.12".into(),
            ..vz("")
        };
        assert_eq!(refusal(&image, None), tonic::Code::InvalidArgument);
    }

    #[test]
    fn linux_builds_are_left_to_the_rootfs_path() {
        let linux = api::BuildTemplateRequest {
            from: "alpine".into(),
            steps: vec![api::BuildStep {
                run: "apk add git".into(),
            }],
            ..request("tools")
        };
        assert_eq!(plan_with(&linux, Some("")).unwrap(), None);
        assert_eq!(plan_with(&linux, None).unwrap(), None);
        // An OCI base takes the place of `from`, whatever `from` names.
        let image = api::BuildTemplateRequest {
            from_image: "python:3.12".into(),
            ..linux
        };
        assert_eq!(plan_with(&image, Some("vz")).unwrap(), None);
    }

    #[test]
    fn only_a_mac_build_names_a_macos_guest() {
        assert!(!is_macos(GuestOs::Linux));
        assert!(!is_macos(GuestOs::Windows));
        #[cfg(target_os = "macos")]
        assert!(is_macos(GuestOs::MacOs));
    }
}

/// Each macOS sandbox's userspace network stack, keyed by sandbox id.
///
/// The guest's NIC is one end of a datagram socket pair and the stack serves
/// the other, so a VM gets a fresh pair and a fresh stack every time it
/// starts: nothing of the stack is in a saved state. The policy outlives the
/// VM, so a resumed guest is held to what the sandbox was last given.
#[derive(Clone, Default)]
pub struct UserNets {
    #[cfg(target_os = "macos")]
    inner: std::sync::Arc<std::sync::Mutex<UserNetsInner>>,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct UserNetsInner {
    node: Option<std::sync::Arc<burrow_net::usernet::Node>>,
    /// Where published ports listen.
    publish_address: Option<std::net::IpAddr>,
    mesh: Option<std::sync::Arc<burrow_net::usernet::Mesh>>,
    links: std::collections::HashMap<String, Link>,
    policies: std::collections::HashMap<String, burrow_net::usernet::Policy>,
    /// What each sandbox's links have carried, kept across its VMs like the
    /// policy so the reading only goes up.
    meters: std::collections::HashMap<String, std::sync::Arc<burrow_net::usernet::Meter>>,
}

#[cfg(target_os = "macos")]
struct Link {
    handle: burrow_net::usernet::Handle,
    policy: tokio::sync::watch::Sender<burrow_net::usernet::Policy>,
    /// Host ports already handed to [`burrow_net::usernet::Handle::publish`].
    published: std::collections::HashSet<u16>,
}

impl UserNets {
    /// The node's share of egress, built from what serve.rs gives the Linux
    /// proxy and resolver.
    #[cfg(target_os = "macos")]
    pub fn set_node(&self, node: burrow_net::usernet::Node, publish_address: std::net::IpAddr) {
        let mut inner = self.inner.lock().unwrap();
        inner.node = Some(std::sync::Arc::new(node));
        inner.publish_address = Some(publish_address);
        tracing::info!(%publish_address, "published ports listen here");
    }

    /// Starts the node's end of the mesh, which carries the stacks' traffic
    /// to sandboxes on other nodes.
    #[cfg(target_os = "macos")]
    pub async fn start_mesh(
        &self,
        listen: std::net::SocketAddr,
        private_key: &str,
    ) -> std::io::Result<()> {
        let router = self
            .inner
            .lock()
            .unwrap()
            .node
            .as_ref()
            .map(|node| std::sync::Arc::clone(&node.router))
            .ok_or_else(|| std::io::Error::other("no network stack to join to the mesh"))?;
        let mesh = burrow_net::usernet::Mesh::start(listen, private_key, router).await?;
        self.inner.lock().unwrap().mesh = Some(mesh);
        Ok(())
    }

    /// Replaces the mesh's peers, as Linux's `burrow-wg` is reconfigured.
    pub async fn configure_mesh(&self, peers: &[burrow_net::Peer]) {
        #[cfg(target_os = "macos")]
        {
            let mesh = self.inner.lock().unwrap().mesh.clone();
            if let Some(mesh) = mesh {
                mesh.configure(peers).await;
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = peers;
    }

    /// Gives the VM `spec` describes a NIC on a new socket pair, served by a
    /// new stack for `lease`. A spec without a NIC, or not a macOS one, is
    /// left alone.
    #[allow(clippy::result_large_err)]
    pub fn attach(
        &self,
        sandbox_id: &str,
        lease: &burrow_net::ipam::Lease,
        spec: &mut VmSpec,
    ) -> Result<(), Status> {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            let burrow_vmm::Backend::Vz(config) = &mut spec.backend else {
                return Ok(());
            };
            if spec.net.is_none() {
                return Ok(());
            }
            let mut inner = self.inner.lock().unwrap();
            let node = inner
                .node
                .clone()
                .ok_or_else(|| Status::unavailable("this node has no network stack"))?;
            let mut fds = [0; 2];
            if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) }
                != 0
            {
                return Err(Status::internal(format!(
                    "socket pair: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let (guest, host) =
                unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            // The framework's guidance for this attachment: a send buffer
            // of at least a frame and a receive buffer several times that.
            for (opt, size) in [(libc::SO_SNDBUF, 1 << 20), (libc::SO_RCVBUF, 4 << 20)] {
                let size: libc::c_int = size;
                unsafe {
                    libc::setsockopt(
                        guest.as_raw_fd(),
                        libc::SOL_SOCKET,
                        opt,
                        (&size as *const libc::c_int).cast(),
                        size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
            }
            let policy = inner
                .policies
                .get(sandbox_id)
                .cloned()
                .unwrap_or_else(|| none_policy(sandbox_id));
            let (policy, watched) = tokio::sync::watch::channel(policy);
            let meter =
                std::sync::Arc::clone(inner.meters.entry(sandbox_id.to_string()).or_default());
            let handle = burrow_net::usernet::UserNet::attach(
                host,
                burrow_net::usernet::SandboxNet::from_lease(lease),
                watched,
                node,
                meter,
            )
            .map_err(|err| Status::internal(format!("network stack: {err}")))?;
            config.network = burrow_vmm::vz::Network::Datagram(std::sync::Arc::new(guest));
            // Replacing the previous VM's link drops its stack.
            inner.links.insert(
                sandbox_id.to_string(),
                Link {
                    handle,
                    policy,
                    published: Default::default(),
                },
            );
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (sandbox_id, lease, spec);
        Ok(())
    }

    /// What every sync of the boundary renders for one sandbox: its policy,
    /// applied to its next flow, and its published TCP ports.
    pub async fn update(
        &self,
        proxy: &burrow_proxy::SandboxPolicy,
        rules: &burrow_net::firewall::SandboxRules,
    ) {
        #[cfg(target_os = "macos")]
        {
            let policy = burrow_net::usernet::Policy::new(
                proxy.clone(),
                &rules.allow_cidrs,
                &rules.allow_ports,
                &rules.peers,
            );
            let (to_publish, address): (Vec<(u16, u16)>, _) = {
                let mut inner = self.inner.lock().unwrap();
                let address = inner
                    .publish_address
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                inner
                    .policies
                    .insert(rules.sandbox_id.clone(), policy.clone());
                let Some(link) = inner.links.get_mut(&rules.sandbox_id) else {
                    return;
                };
                link.policy.send_replace(policy);
                let ports = rules
                    .ports
                    .iter()
                    .filter(|port| port.protocol == burrow_net::firewall::Protocol::Tcp)
                    .filter(|port| link.published.insert(port.host_port))
                    .map(|port| (port.host_port, port.guest_port))
                    .collect();
                (ports, address)
            };
            for (host_port, guest_port) in to_publish {
                // The address callers reach the node at, which is what the
                // orchestrator reports a port at; Linux's DNAT takes
                // whatever reaches the node from outside.
                match tokio::net::TcpListener::bind((address, host_port)).await {
                    Ok(listener) => {
                        if let Some(link) = self.inner.lock().unwrap().links.get(&rules.sandbox_id)
                        {
                            link.handle.publish(listener, guest_port);
                        }
                    }
                    Err(err) => tracing::error!(
                        sandbox = rules.sandbox_id,
                        host_port,
                        %err,
                        "cannot publish the port"
                    ),
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (proxy, rules);
    }

    /// Drops a sandbox's stack, as its VM stops; `forget` drops its policy
    /// too, as the sandbox goes.
    pub fn detach(&self, sandbox_id: &str, forget: bool) {
        #[cfg(target_os = "macos")]
        {
            let mut inner = self.inner.lock().unwrap();
            inner.links.remove(sandbox_id);
            if forget {
                inner.policies.remove(sandbox_id);
                inner.meters.remove(sandbox_id);
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (sandbox_id, forget);
    }

    /// The bytes a sandbox's links have carried while this daemon has run,
    /// or `None` for a sandbox with no userspace stack.
    pub fn traffic(&self, sandbox_id: &str) -> Option<burrow_net::firewall::Traffic> {
        #[cfg(target_os = "macos")]
        return self
            .inner
            .lock()
            .unwrap()
            .meters
            .get(sandbox_id)
            .map(|meter| meter.traffic());
        #[cfg(not(target_os = "macos"))]
        {
            let _ = sandbox_id;
            None
        }
    }
}

/// Before the first sync names a policy: nothing in or out.
#[cfg(target_os = "macos")]
fn none_policy(sandbox_id: &str) -> burrow_net::usernet::Policy {
    burrow_net::usernet::Policy::new(
        burrow_proxy::SandboxPolicy {
            sandbox_id: sandbox_id.to_string(),
            mode: burrow_proxy::policy::NetworkMode::None,
            ..Default::default()
        },
        &[],
        &[],
        &[],
    )
}
