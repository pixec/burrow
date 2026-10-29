//! What a macOS sandbox does differently on a Mac node.
//!
//! A macOS template is not a kernel and a rootfs but an installed machine
//! with the agent in it (`burrowd vz-template`), and a sandbox is an APFS
//! clone of it with a fresh machine identity, booted cold: the framework restores a saved state
//! more slowly than macOS boots, and into one machine at a time, so there is
//! no warm pool. Until burrowd has a userspace network stack for the guest's
//! NIC there is no tap and no firewall, so a macOS sandbox runs with no
//! network at all, which is the one policy that needs no enforcing.
//!
//! Every function exists on every target, so the shared create path can call
//! it behind a guest check; off macOS a macOS guest is refused before any of
//! them is reached.

use std::path::Path;

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

/// Makes `workdir` a new machine cloned from the template in `template_dir`.
pub async fn prepare(template_dir: &Path, workdir: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if tokio::fs::try_exists(workdir).await.unwrap_or(false) {
            tokio::fs::remove_dir_all(workdir).await?;
        }
        let (template_dir, workdir) = (template_dir.to_path_buf(), workdir.to_path_buf());
        tokio::task::spawn_blocking(move || {
            burrow_vmm::vz::clone_machine(&template_dir, &workdir, false)
        })
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (template_dir, workdir);
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
        spec.drives = vec![burrow_vmm::vz::root_drive()];
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

/// Refuses a third running macOS guest, which Apple's licence does not allow
/// on one Mac.
#[allow(clippy::result_large_err)]
pub fn check_running(running: usize) -> Result<(), Status> {
    #[cfg(target_os = "macos")]
    if running >= burrow_vmm::vz::MAX_RUNNING {
        return Err(Status::resource_exhausted(format!(
            "this Mac already runs {running} macOS guests, the most Apple's licence allows"
        )));
    }
    let _ = running;
    Ok(())
}

/// `burrowd vz-template`: makes a macOS template on this node, the macOS
/// counterpart of pulling an image. Node-local, since the restore image is
/// tens of gigabytes already on this Mac's disk and the template it makes
/// boots only on a Mac.
///
/// Installs the restore image (or starts from `--existing`, a template
/// installed before), boots it once with provisioning and NAT, copies the
/// guest agent in over SSH as the provisioned admin and installs it as a
/// LaunchDaemon, turns Remote Login off again and shuts the guest down from
/// inside. SSH rather than writing the disk offline: the agent's files must
/// be root-owned on the guest's Data volume, which the host can only write as
/// root, and a running guest is also what proves the agent answers on vsock
/// before the template is published.
#[cfg(target_os = "macos")]
#[derive(clap::Args)]
pub struct TemplateArgs {
    /// The node's data directory, as given to `serve`.
    #[arg(long, env = "BURROW_DATA_DIR", default_value = "/var/lib/burrow")]
    pub data_dir: std::path::PathBuf,
    /// The restore image (`UniversalMac_*_Restore.ipsw`). Apple lists the
    /// latest one this host supports at
    /// https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml
    #[arg(long, required_unless_present = "existing")]
    pub ipsw: Option<std::path::PathBuf>,
    /// Upgrade the template of this name in place: install the agent into the
    /// macOS it already holds instead of installing macOS again. It must
    /// never have booted, since only a first boot is provisioned.
    #[arg(long, conflicts_with = "ipsw")]
    pub existing: bool,
    /// The template's name, as sandboxes are created from it.
    #[arg(long)]
    pub name: String,
    /// The macOS guest agent to install (`cargo build -p burrow-guest
    /// --release` on a Mac).
    #[arg(long)]
    pub guest_binary: std::path::PathBuf,
    /// The installed disk's size. macOS 27 needs about 28 GiB to install.
    #[arg(long, default_value_t = 64)]
    pub disk_gib: u32,
    /// The build machine; defaults to the restore image's minimum.
    #[arg(long)]
    pub cpus: Option<u32>,
    #[arg(long)]
    pub memory_mib: Option<u32>,
}

#[cfg(target_os = "macos")]
pub async fn build_template(args: TemplateArgs) -> anyhow::Result<()> {
    crate::template::validate_name(&args.name)
        .map_err(|err| anyhow::anyhow!(err.message().to_string()))?;
    let templates = crate::template::templates_dir(&args.data_dir);
    let dir = templates.join(&args.name);
    let exists = tokio::fs::try_exists(&dir).await.unwrap_or(false);
    match (exists, args.existing) {
        (true, false) => {
            anyhow::bail!("template {} already exists at {}", args.name, dir.display())
        }
        (false, true) => anyhow::bail!("no template {} to upgrade", args.name),
        _ => {}
    }
    // Built beside its final name and renamed into place, so a scan never
    // lists a half-built machine and a failed upgrade leaves the old one.
    let building = templates.join(format!(".{}.building", args.name));
    let _ = tokio::fs::remove_dir_all(&building).await;
    let started = std::time::Instant::now();
    match &args.ipsw {
        Some(ipsw) => {
            let installed = burrow_vmm::vz::install(
                ipsw,
                &burrow_vmm::vz::InstallSpec {
                    template: building.clone(),
                    vcpus: args.cpus,
                    mem_mib: args.memory_mib,
                    disk_bytes: u64::from(args.disk_gib) << 30,
                },
                |fraction| tracing::info!(percent = (fraction * 100.0) as u32, "installing macOS"),
            )
            .await?;
            tracing::info!(
                version = installed.version,
                build = installed.build,
                secs = started.elapsed().as_secs(),
                "macOS installed"
            );
        }
        None => {
            let (from, to) = (dir.clone(), building.clone());
            tokio::task::spawn_blocking(move || burrow_vmm::vz::clone_machine(&from, &to, true))
                .await??;
        }
    }
    install_agent(&building, &args).await?;
    let environment = crate::oci::ImageEnvironment {
        hypervisor: burrow_vmm::Hypervisor::Vz.to_string(),
        guest_os: GuestOs::MacOs.as_str().to_string(),
        ..Default::default()
    };
    tokio::fs::write(
        building.join("image.json"),
        serde_json::to_vec(&environment)?,
    )
    .await?;
    if exists {
        let old = templates.join(format!(".{}.old", args.name));
        tokio::fs::rename(&dir, &old).await?;
        tokio::fs::rename(&building, &dir).await?;
        tokio::fs::remove_dir_all(&old).await?;
    } else {
        tokio::fs::rename(&building, &dir).await?;
    }
    tracing::info!(
        template = args.name,
        secs = started.elapsed().as_secs(),
        "macOS template ready"
    );
    Ok(())
}

/// How long the provisioned first boot gets to come up on the network, which
/// includes macOS creating the account.
#[cfg(target_os = "macos")]
const FIRST_BOOT: std::time::Duration = std::time::Duration::from_secs(300);

/// Boots the machine in `dir` once, provisioned, and installs the agent in it.
#[cfg(target_os = "macos")]
async fn install_agent(dir: &Path, args: &TemplateArgs) -> anyhow::Result<()> {
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
        format!("template-{}", args.name),
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
    spec.vcpus = args.cpus.unwrap_or(boot.requirements.min_vcpus);
    spec.mem_mib = args.memory_mib.unwrap_or(boot.requirements.min_mem_mib);
    spec.boot = burrow_vmm::Boot::MacOs(boot);
    spec.drives = vec![burrow_vmm::vz::root_drive()];
    spec.net = Some(burrow_vmm::NetSpec {
        tap: String::new(),
        guest_mac: Some(mac.clone()),
    });
    spec.is_vsock_enabled = true;
    spec.cgroup_root = None;
    let vm = burrow_vmm::Vm::boot(spec).await?;
    let result = async {
        let address = wait_for_ssh(&mac, FIRST_BOOT).await?;
        tracing::info!(%address, "provisioned guest is up; installing the agent");
        let ssh = Ssh::new(dir, &address, &password)?;
        ssh.copy(&args.guest_binary, "burrow-guest").await?;
        ssh.sudo("./burrow-guest install && rm burrow-guest")
            .await?;
        vm.wait_for_vsock(crate::guestconn::AGENT_PORT, Duration::from_secs(60))
            .await?;
        tracing::info!("agent answers on vsock; shutting the guest down");
        // Remote Login was only for this; nothing in a sandbox knows the
        // password, but nothing should be listening for it either.
        ssh.sudo("launchctl disable system/com.openssh.sshd; shutdown -h +0")
            .await
            .ok();
        let burrow_vmm::Vm::Vz(vz) = &vm else {
            unreachable!("booted with the vz backend")
        };
        vz.wait_stopped(Duration::from_secs(180)).await?;
        anyhow::Ok(())
    }
    .await;
    vm.kill().await?;
    result
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

    /// Apple's licence caps a Mac at two running macOS guests; the third
    /// create is refused before anything is cloned or booted.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_third_macos_guest_is_refused() {
        assert!(check_running(0).is_ok());
        assert!(check_running(1).is_ok());
        let refused = check_running(2).unwrap_err();
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
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
    links: std::collections::HashMap<String, Link>,
    policies: std::collections::HashMap<String, burrow_net::usernet::Policy>,
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
    pub fn set_node(&self, node: burrow_net::usernet::Node) {
        self.inner.lock().unwrap().node = Some(std::sync::Arc::new(node));
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
            let handle = burrow_net::usernet::UserNet::attach(
                host,
                burrow_net::usernet::SandboxNet::from_lease(lease),
                watched,
                node,
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
            let to_publish: Vec<(u16, u16)> = {
                let mut inner = self.inner.lock().unwrap();
                inner
                    .policies
                    .insert(rules.sandbox_id.clone(), policy.clone());
                let Some(link) = inner.links.get_mut(&rules.sandbox_id) else {
                    return;
                };
                link.policy.send_replace(policy);
                rules
                    .ports
                    .iter()
                    .filter(|port| port.protocol == burrow_net::firewall::Protocol::Tcp)
                    .filter(|port| link.published.insert(port.host_port))
                    .map(|port| (port.host_port, port.guest_port))
                    .collect()
            };
            for (host_port, guest_port) in to_publish {
                // Every address, as the Linux DNAT matches whatever the node
                // was reached at.
                match tokio::net::TcpListener::bind(("0.0.0.0", host_port)).await {
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
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (sandbox_id, forget);
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
