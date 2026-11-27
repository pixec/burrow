//! The machine description of every guest the node starts from a template:
//! a sandbox, a template's warm snapshot, and the restore that profiles it.

use std::path::Path;

use burrow_net::Lease;
use burrow_proto::common::v1 as common;
use burrow_vmm::{DriveSpec, GuestOs, Hypervisor, HypervisorExt, MachineSpec, NetSpec, TpmSpec};

use crate::sandbox::NodeConfig;
use crate::warm::Shape;

/// Who the guest is and where it runs.
pub(crate) struct Guest<'a> {
    pub id: &'a str,
    pub workdir: &'a Path,
    pub hypervisor: Hypervisor,
    pub guest_os: GuestOs,
    pub lease: &'a Lease,
    pub tap: &'a str,
}

/// What a sandbox's VM is described with.
///
/// Shared by creation and recovery: a restored VM has to be described with
/// the same resources it was snapshotted with, so the two paths must not be
/// able to drift apart.
pub(crate) struct Sandbox<'a> {
    pub resources: &'a common::ResourcePolicy,
    pub volumes: &'a [common::VolumeMount],
    pub systemd: Option<&'a crate::oci::SystemdBoot>,
    pub is_console_verbose: bool,
    pub is_tpm: bool,
    pub display: Option<crate::oci::Display>,
}

pub(crate) fn sandbox(config: &NodeConfig, guest: &Guest, sandbox: &Sandbox) -> MachineSpec {
    let Guest {
        id,
        hypervisor,
        guest_os,
        lease,
        ..
    } = *guest;
    let resources = sandbox.resources;
    let mut spec = base(config, guest);
    spec.devices.display = sandbox.display.map(crate::oci::Display::spec);
    let capabilities = hypervisor.capabilities();
    spec.cpu.vcpus = resources.vcpus.max(1);
    if capabilities.is_vcpu_hotplug_supported {
        spec.cpu.max_vcpus = crate::sandbox::max_vcpus(hypervisor, spec.cpu.vcpus);
    }
    let mem_mib = if resources.mem_mib == 0 {
        crate::sandbox::DEFAULT_MEM_MIB
    } else {
        resources.mem_mib
    };
    // What the VM booted with, which a restore must describe; what has
    // been plugged since sits in the hotplug region above it.
    spec.memory.mib = match resources.boot_mem_mib {
        0 => mem_mib,
        boot => boot.min(mem_mib),
    };
    spec.memory.plugged_mib = mem_mib - spec.memory.mib;
    spec.memory.hotplug_mib = crate::sandbox::hotplug_region(
        hypervisor,
        guest_os,
        spec.memory.mib,
        resources.max_mem_mib,
    );
    confine(&mut spec, config, resources, mem_mib);
    // Only consulted on restore; a cold boot has no memory file to serve.
    spec.restore.memory.is_lazy = config.is_memory_lazy && capabilities.is_lazy_memory_supported;
    // Required for diff snapshots, and only useful for them. It costs a
    // little guest write performance, which is a good trade against
    // writing the whole of memory on every suspend.
    spec.restore.is_dirty_pages_tracked = true;

    // After the sandbox's own disks, so the guest devices follow them and
    // match what the handshake tells the agent to mount.
    for (index, mount) in crate::volume::block_mounts(sandbox.volumes) {
        spec.devices.drives.push(DriveSpec {
            id: crate::volume::drive_id(index, guest_os),
            path: crate::sandbox::volume_image(index),
            is_root: false,
            is_read_only: mount.is_read_only,
        });
    }
    spec.is_nested_virt_enabled = resources.is_nested_virt_enabled;
    boot(
        &mut spec,
        format!(
            "{} burrow.dns={} burrow.ip6={}/{} burrow.ip6gw={} {} {}",
            lease.kernel_ip_arg(&crate::guestconn::hostname(id)),
            lease.host_ip,
            lease.guest_ip6(),
            lease.prefix_len6(),
            lease.host_ip6(),
            crate::sandbox::guest_mode_arg(sandbox.systemd, hypervisor, false),
            crate::sandbox::guest_boot_args(
                &config.extra_boot_args,
                sandbox.is_console_verbose || config.is_console_verbose
            )
        ),
    );
    if sandbox.is_tpm {
        spec.devices.tpm = Some(config.tpm(id, lease.block));
    }
    if crate::macnode::is_macos(guest_os)
        && let Err(err) = crate::macnode::apply(&mut spec, resources)
    {
        // Booting the unchanged spec fails with the backend's own
        // refusal; this says why it got there.
        tracing::warn!(
            sandbox = id,
            err = err.message(),
            "cannot describe the macOS machine"
        );
    }
    spec
}

/// The VM a template's warm snapshot is taken of. Its shape is baked into
/// the snapshot: a restore takes its machine configuration from here, not
/// from what a later caller asks for.
pub(crate) fn warm(
    config: &NodeConfig,
    guest: &Guest,
    shape: Shape,
    systemd: Option<&crate::oci::SystemdBoot>,
    tpm: Option<TpmSpec>,
    display: Option<crate::oci::Display>,
) -> MachineSpec {
    let mut spec = shaped(config, guest, shape, display);
    boot(
        &mut spec,
        format!(
            "{} {} {}",
            guest.lease.kernel_ip_arg(""),
            crate::sandbox::guest_mode_arg(systemd, guest.hypervisor, true),
            crate::sandbox::guest_boot_args(&config.extra_boot_args, config.is_console_verbose)
        ),
    );
    spec.devices.tpm = tpm;
    spec
}

/// The restore of a warm snapshot that records which pages a create faults
/// on.
/// Only a backend serving lazy memory profiles, and none of those has a
/// display.
pub(crate) fn profile(config: &NodeConfig, guest: &Guest, shape: Shape) -> MachineSpec {
    let mut spec = shaped(config, guest, shape, None);
    spec.restore.memory.record_prefetch = Some(crate::warm::PREFETCH_PLAN.to_string());
    spec
}

/// The devices every template guest has: its root disk, vsock to its agent,
/// and its tap.
fn base(config: &NodeConfig, guest: &Guest) -> MachineSpec {
    let mut spec = MachineSpec::new(
        guest.id.to_string(),
        guest.workdir,
        config.backend(guest.hypervisor),
    );
    spec.guest_os = guest.guest_os;
    spec.devices.drives = crate::rootdisk::drives();
    spec.devices.is_vsock_enabled = true;
    spec.devices.net = Some(NetSpec {
        tap: guest.tap.to_string(),
        guest_mac: Some(guest.lease.guest_mac()),
    });
    spec
}

/// [`base`] at a warm snapshot's shape, capped as one.
fn shaped(
    config: &NodeConfig,
    guest: &Guest,
    shape: Shape,
    display: Option<crate::oci::Display>,
) -> MachineSpec {
    let mut spec = base(config, guest);
    spec.devices.display = display.map(crate::oci::Display::spec);
    spec.cpu.vcpus = shape.vcpus;
    spec.memory.mib = shape.mem_mib;
    spec.memory.hotplug_mib = crate::sandbox::hotplug_region(
        guest.hypervisor,
        guest.guest_os,
        shape.mem_mib,
        shape.max_mem_mib,
    );
    let resources = common::ResourcePolicy {
        vcpus: shape.vcpus,
        ..Default::default()
    };
    confine(&mut spec, config, &resources, shape.mem_mib);
    spec
}

/// The VMM's cgroup, capped for `resources` and a guest of `mem_mib`, with
/// room for the display's frame where it has one.
fn confine(
    spec: &mut MachineSpec,
    config: &NodeConfig,
    resources: &common::ResourcePolicy,
    mem_mib: u32,
) {
    let display_mib = match spec.devices.display {
        Some(_) => burrow_vmm::DISPLAY_OVERHEAD_MIB,
        None => 0,
    };
    spec.limits = crate::sandbox::cgroup_limits(
        resources,
        config.memory_ceiling_mib(spec.hypervisor(), mem_mib) + display_mib,
    );
    spec.cgroup_root = config.cgroup_root.clone();
    spec.is_limits_required = config.is_resource_limits_required;
}

/// Boots the template's kernel into its agent with `args` after the common
/// ones, or its firmware for a guest that boots that.
fn boot(spec: &mut MachineSpec, args: String) {
    spec.boot = match crate::boot::file(spec.guest_os) {
        crate::boot::FIRMWARE => crate::boot::firmware_boot(),
        _ => burrow_vmm::Boot::Kernel {
            kernel: crate::boot::KERNEL.into(),
            cmdline: format!(
                "{} {} init=/usr/bin/burrow-guest {args}",
                burrow_vmm::DEFAULT_BOOT_ARGS,
                crate::rootdisk::BOOT_ARGS,
            ),
        },
    };
}
