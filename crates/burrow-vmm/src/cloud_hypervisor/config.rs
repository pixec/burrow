//! The `VmConfig` Cloud Hypervisor is created with, built from a [`VmSpec`].
//!
//! Every path in it is relative and resolved against the VM's working
//! directory, which is the VMM's own cwd. Cloud Hypervisor writes the config
//! into every snapshot verbatim and restores from it, so relative paths are
//! what let a snapshot taken in one sandbox's directory restore in another's.

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::{Boot, GUEST_CID, GuestOs, Hypervisor, VSOCK_UDS, VmSpec};

use super::{CONSOLE_LOG, CloudHypervisorConfig};

/// The id the NIC is created under, so a restore can find it to retarget it.
pub(crate) const NET_ID: &str = "net0";
/// Cloud Hypervisor's edk2 build, where the node image installs it. A Windows
/// guest boots it from its disk instead of a kernel.
const UEFI_FIRMWARE: &str = "/usr/local/share/cloud-hypervisor/CLOUDHV_EFI.fd";
/// swtpm's socket in the VM's working directory, for Windows 11's TPM 2.0.
const TPM_SOCK: &str = "swtpm.sock";
/// Windows 11's own minimums; Setup and the OOBE refuse less.
const WINDOWS_MIN_VCPUS: u32 = 2;
const WINDOWS_MIN_MEM_MIB: u32 = 4096;

/// Where the guest's console goes, per architecture.
///
/// On aarch64 Cloud Hypervisor's UART is a PL011, which a kernel built for
/// Firecracker has no driver for, so the console is virtio-console (`hvc0`)
/// there. On x86_64 its UART is the 16550 that is `ttyS0` to the guest, as
/// Firecracker's is.
fn console(arch: &str) -> Result<(Value, Value, &'static str)> {
    let file = json!({ "mode": "File", "file": CONSOLE_LOG });
    let off = json!({ "mode": "Off" });
    match arch {
        "x86_64" => Ok((file, off, "")),
        "aarch64" => Ok((off, file, " console=hvc0")),
        _ => Err(Error::Unsupported {
            hypervisor: Hypervisor::CloudHypervisor,
            what: "run on this architecture",
        }),
    }
}

/// The firmware a [`Boot::Firmware`] names, or the node's edk2 build.
fn firmware(boot: &Boot) -> String {
    match boot {
        Boot::Firmware {
            firmware: Some(firmware),
        } => firmware.display().to_string(),
        _ => UEFI_FIRMWARE.into(),
    }
}

/// The `vm.create` body for `spec` on `arch`.
pub(crate) fn vm_config(
    spec: &VmSpec,
    config: &CloudHypervisorConfig,
    arch: &str,
) -> Result<Value> {
    let (mut serial, mut console, console_arg) = console(arch)?;
    let payload = match (&spec.boot, spec.guest_os) {
        (Boot::Kernel { kernel, cmdline }, GuestOs::Linux) => json!({
            "kernel": match &config.kernel {
                Some(kernel) => kernel.display().to_string(),
                None => kernel.clone(),
            },
            "cmdline": format!("{cmdline}{console_arg}"),
        }),
        (Boot::Firmware { .. }, GuestOs::Linux) => json!({ "firmware": firmware(&spec.boot) }),
        // UEFI firmware boots Windows from the first disk. The firmware,
        // bootmgr and EMS all write to the UART (a PL011 on aarch64), and
        // Windows has no virtio-console driver.
        (Boot::Kernel { .. } | Boot::Firmware { .. }, GuestOs::Windows) => {
            if spec.vcpus < WINDOWS_MIN_VCPUS || spec.mem_mib < WINDOWS_MIN_MEM_MIB {
                return Err(Error::Unsupported {
                    hypervisor: Hypervisor::CloudHypervisor,
                    what: "boot windows with fewer than 2 vcpus or 4096 MiB",
                });
            }
            serial = json!({ "mode": "File", "file": CONSOLE_LOG });
            console = json!({ "mode": "Off" });
            json!({ "firmware": firmware(&spec.boot) })
        }
        #[cfg(target_os = "macos")]
        (Boot::MacOs(_), _) | (_, GuestOs::MacOs) => {
            return Err(Error::Unsupported {
                hypervisor: Hypervisor::CloudHypervisor,
                what: "boot macos",
            });
        }
    };
    let disks: Vec<Value> = spec
        .drives
        .iter()
        .map(|drive| {
            json!({
                "id": drive.id,
                "path": drive.path,
                "readonly": drive.is_read_only,
                "image_type": "Raw",
            })
        })
        .collect();
    let mut vm = json!({
        "cpus": { "boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus },
        "memory": { "size": u64::from(spec.mem_mib) * 1024 * 1024 },
        "payload": payload,
        // In the order given, which is the order the guest probes and names
        // them in.
        "disks": disks,
        "serial": serial,
        "console": console,
    });
    if spec.guest_os == GuestOs::Windows {
        vm["tpm"] = json!({ "socket": TPM_SOCK });
        if arch == "x86_64" {
            vm["cpus"]["kvm_hyperv"] = json!(true);
        }
    }
    if let Some(net) = &spec.net {
        let mut nic = json!({ "id": NET_ID, "tap": net.tap });
        if let Some(mac) = &net.guest_mac {
            nic["mac"] = json!(mac);
        }
        vm["net"] = json!([nic]);
    }
    if spec.is_vsock_enabled {
        vm["vsock"] = json!({ "id": "vsock", "cid": GUEST_CID, "socket": VSOCK_UDS });
    }
    Ok(vm)
}

/// Points a snapshot's recorded config at the sandbox restoring it.
///
/// The config is the snapshotted VM's, whose NIC was another sandbox's tap.
/// Everything else in it is relative and already right. The machine's shape
/// cannot change across a restore, so a spec asking for another one is
/// refused here, with both shapes named, rather than deep inside the VMM.
pub(crate) fn retarget(snapshot: &mut Value, spec: &VmSpec) -> Result<()> {
    let vcpus = snapshot["cpus"]["boot_vcpus"].as_u64();
    let memory = snapshot["memory"]["size"].as_u64();
    let wanted = u64::from(spec.mem_mib) * 1024 * 1024;
    if vcpus != Some(u64::from(spec.vcpus)) || memory != Some(wanted) {
        return Err(Error::Snapshot(format!(
            "the snapshot is of {} vcpu / {} MiB and this VM is {} vcpu / {} MiB",
            vcpus.unwrap_or(0),
            memory.unwrap_or(0) / (1024 * 1024),
            spec.vcpus,
            spec.mem_mib
        )));
    }
    if let (Some(net), Some(nics)) = (&spec.net, snapshot["net"].as_array_mut()) {
        for nic in nics.iter_mut().filter(|nic| nic["id"] == NET_ID) {
            nic["tap"] = json!(net.tap);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Backend, DriveSpec, NetSpec};

    fn config() -> CloudHypervisorConfig {
        CloudHypervisorConfig {
            bin: "/usr/local/bin/cloud-hypervisor".into(),
            kernel: None,
            jail: None,
        }
    }

    fn spec() -> VmSpec {
        let mut spec = VmSpec::new(
            "sbx_1",
            "/var/lib/burrow/sandboxes/sbx_1",
            Backend::CloudHypervisor(config()),
        );
        spec.vcpus = 2;
        spec.mem_mib = 1024;
        spec.boot = Boot::Kernel {
            kernel: "vmlinux".into(),
            cmdline: "console=ttyS0 root=/dev/vda ro".into(),
        };
        spec.drives = vec![
            DriveSpec::root_ro("rootfs.ext4"),
            DriveSpec::scratch_rw("scratch.ext4"),
            DriveSpec {
                id: "volume0".into(),
                path: "volume0.ext4".into(),
                is_root: false,
                is_read_only: true,
            },
        ];
        spec.net = Some(NetSpec {
            tap: "bt7".into(),
            guest_mac: Some("06:00:0a:00:00:1e".into()),
        });
        spec.is_vsock_enabled = true;
        spec
    }

    #[test]
    fn the_machine_is_the_spec_with_relative_paths() {
        let vm = vm_config(&spec(), &config(), "aarch64").unwrap();
        assert_eq!(vm["cpus"], json!({ "boot_vcpus": 2, "max_vcpus": 2 }));
        assert_eq!(vm["memory"]["size"], 1024 * 1024 * 1024u64);
        assert_eq!(vm["payload"]["kernel"], "vmlinux");
        assert_eq!(
            vm["net"],
            json!([{ "id": "net0", "tap": "bt7", "mac": "06:00:0a:00:00:1e" }])
        );
        assert_eq!(
            vm["vsock"],
            json!({ "id": "vsock", "cid": 3, "socket": "vsock.sock" })
        );
    }

    /// The guest finds its disks by order, so the order is the spec's.
    #[test]
    fn disks_keep_the_order_given() {
        let vm = vm_config(&spec(), &config(), "aarch64").unwrap();
        let disks = vm["disks"].as_array().unwrap();
        let ids: Vec<&str> = disks.iter().map(|d| d["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["rootfs", "scratch", "volume0"]);
        assert_eq!(disks[0]["readonly"], true);
        assert_eq!(disks[1]["readonly"], false);
        assert_eq!(disks[1]["path"], "scratch.ext4");
    }

    #[test]
    fn the_console_is_one_the_guest_kernel_can_drive() {
        let arm = vm_config(&spec(), &config(), "aarch64").unwrap();
        assert_eq!(arm["serial"]["mode"], "Off");
        assert_eq!(arm["console"]["file"], "console.log");
        assert!(
            arm["payload"]["cmdline"]
                .as_str()
                .unwrap()
                .ends_with(" console=hvc0")
        );

        let x86 = vm_config(&spec(), &config(), "x86_64").unwrap();
        assert_eq!(x86["serial"]["file"], "console.log");
        assert_eq!(x86["console"]["mode"], "Off");
        assert_eq!(x86["payload"]["cmdline"], "console=ttyS0 root=/dev/vda ro");
    }

    #[test]
    fn a_configured_kernel_replaces_the_templates() {
        let config = CloudHypervisorConfig {
            kernel: Some("/var/lib/burrow/vmlinux-ch".into()),
            ..config()
        };
        let vm = vm_config(&spec(), &config, "aarch64").unwrap();
        assert_eq!(vm["payload"]["kernel"], "/var/lib/burrow/vmlinux-ch");
    }

    #[test]
    fn windows_boots_firmware_with_a_tpm_on_the_uart() {
        let mut windows = spec();
        windows.guest_os = GuestOs::Windows;
        windows.vcpus = 4;
        windows.mem_mib = 8192;
        let vm = vm_config(&windows, &config(), "aarch64").unwrap();
        assert_eq!(vm["payload"], json!({ "firmware": UEFI_FIRMWARE }));
        assert_eq!(vm["cpus"], json!({ "boot_vcpus": 4, "max_vcpus": 4 }));
        assert_eq!(vm["memory"]["size"], 8192 * 1024 * 1024u64);
        assert_eq!(vm["tpm"], json!({ "socket": "swtpm.sock" }));
        assert_eq!(vm["serial"]["file"], "console.log");
        assert_eq!(vm["console"]["mode"], "Off");

        let x86 = vm_config(&windows, &config(), "x86_64").unwrap();
        assert_eq!(x86["cpus"]["kvm_hyperv"], true);
    }

    #[test]
    fn a_named_firmware_replaces_the_nodes() {
        let mut uefi = spec();
        uefi.boot = Boot::Firmware {
            firmware: Some("/opt/OVMF.fd".into()),
        };
        let vm = vm_config(&uefi, &config(), "aarch64").unwrap();
        assert_eq!(vm["payload"], json!({ "firmware": "/opt/OVMF.fd" }));
    }

    #[test]
    fn what_it_cannot_run_is_refused_by_name() {
        let mut windows = spec();
        windows.guest_os = GuestOs::Windows;
        windows.mem_mib = 4095;
        assert!(matches!(
            vm_config(&windows, &config(), "aarch64"),
            Err(Error::Unsupported { .. })
        ));
        windows.mem_mib = 4096;
        windows.vcpus = 1;
        assert!(vm_config(&windows, &config(), "aarch64").is_err());
        assert!(vm_config(&spec(), &config(), "riscv64").is_err());
    }

    /// A warm snapshot is restored by every sandbox of its template, each on
    /// its own tap.
    #[test]
    fn a_restore_takes_its_own_tap_and_refuses_another_shape() {
        let mut snapshot = vm_config(&spec(), &config(), "aarch64").unwrap();
        snapshot["net"][0]["tap"] = json!("btwarm");
        let mut mine = spec();
        mine.net.as_mut().unwrap().tap = "bt12".into();
        retarget(&mut snapshot, &mine).unwrap();
        assert_eq!(snapshot["net"][0]["tap"], "bt12");
        // The guest keeps the MAC it was snapshotted with.
        assert_eq!(snapshot["net"][0]["mac"], "06:00:0a:00:00:1e");

        mine.mem_mib = 2048;
        assert!(matches!(
            retarget(&mut snapshot, &mine),
            Err(Error::Snapshot(_))
        ));
    }
}
