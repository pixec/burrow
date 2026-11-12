//! The CPU this node's guests see, recorded on the memory state they save so
//! the orchestrator restores it only on a compatible CPU.
//!
//! On x86_64 the features are what KVM can give a guest
//! (`KVM_GET_SUPPORTED_CPUID`), the set both Firecracker and Cloud Hypervisor
//! build a guest's CPUID from, which also takes in what the host kernel
//! hides. On aarch64 they are the host's hwcaps.

use std::sync::OnceLock;

use burrow_proto::common::v1::CpuFingerprint;
use serde::{Deserialize, Serialize};

/// [`CpuFingerprint`] as a manifest stores it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cpu {
    pub vendor: String,
    pub family: u32,
    pub model: u32,
    pub features: Vec<String>,
    pub physical_address_bits: u32,
}

impl Cpu {
    /// As a record carries it: none for an empty one, from a manifest
    /// written before fingerprints or a node that could not read its own.
    pub fn fingerprint(&self) -> Option<CpuFingerprint> {
        (!self.vendor.is_empty()).then(|| CpuFingerprint {
            vendor: self.vendor.clone(),
            family: self.family,
            model: self.model,
            features: self.features.clone(),
            physical_address_bits: self.physical_address_bits,
        })
    }
}

/// This host's, read once. Empty where it cannot be read, which the
/// orchestrator places no memory restore on.
pub fn host() -> &'static Cpu {
    static HOST: OnceLock<Cpu> = OnceLock::new();
    HOST.get_or_init(|| match read() {
        Ok(cpu) => cpu,
        Err(err) => {
            tracing::warn!(%err, "cannot read the CPU fingerprint; no saved memory restores here");
            Cpu::default()
        }
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read() -> std::io::Result<Cpu> {
    use std::arch::x86_64::__cpuid_count;
    let leaf0 = __cpuid_count(0, 0);
    let leaf1 = __cpuid_count(1, 0);
    let extended = __cpuid_count(0x8000_0000, 0).eax;
    let address = match extended >= 0x8000_0008 {
        true => __cpuid_count(0x8000_0008, 0).eax,
        false => 36,
    };
    Ok(x86(
        [leaf0.ebx, leaf0.edx, leaf0.ecx],
        leaf1.eax,
        address,
        &kvm::supported_cpuid()?,
    ))
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn read() -> std::io::Result<Cpu> {
    let midr =
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1")?;
    let midr = u64::from_str_radix(midr.trim().trim_start_matches("0x"), 16)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")?;
    Ok(aarch64(midr, &cpuinfo, kvm::ipa_bits()?))
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn read() -> std::io::Result<Cpu> {
    Err(std::io::Error::other("no CPU fingerprint on this platform"))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod kvm {
    use std::os::fd::AsRawFd as _;

    fn open() -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
    }

    /// `KVM_GET_SUPPORTED_CPUID`, as `(function, index, [eax, ebx, ecx, edx])`.
    #[cfg(target_arch = "x86_64")]
    pub fn supported_cpuid() -> std::io::Result<Vec<(u32, u32, [u32; 4])>> {
        const MAX_ENTRIES: usize = 256;
        const KVM_GET_SUPPORTED_CPUID: libc::Ioctl = 0xc008_ae05_u32 as libc::Ioctl;
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Entry {
            function: u32,
            index: u32,
            flags: u32,
            registers: [u32; 4],
            padding: [u32; 3],
        }
        #[repr(C)]
        struct Cpuid {
            nent: u32,
            padding: u32,
            entries: [Entry; MAX_ENTRIES],
        }
        let kvm = open()?;
        let mut cpuid = Cpuid {
            nent: MAX_ENTRIES as u32,
            padding: 0,
            entries: [Entry::default(); MAX_ENTRIES],
        };
        // SAFETY: the buffer holds `nent` entries, which KVM writes at most.
        let done = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_GET_SUPPORTED_CPUID, &mut cpuid) };
        if done < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cpuid.entries[..cpuid.nent as usize]
            .iter()
            .map(|e| (e.function, e.index, e.registers))
            .collect())
    }

    /// The largest guest physical address width KVM offers.
    #[cfg(target_arch = "aarch64")]
    pub fn ipa_bits() -> std::io::Result<u32> {
        const KVM_CHECK_EXTENSION: libc::Ioctl = 0xae03 as libc::Ioctl;
        const KVM_CAP_ARM_VM_IPA_SIZE: libc::c_ulong = 165;
        let kvm = open()?;
        // SAFETY: KVM_CHECK_EXTENSION takes its argument by value.
        let bits = unsafe {
            libc::ioctl(
                kvm.as_raw_fd(),
                KVM_CHECK_EXTENSION,
                KVM_CAP_ARM_VM_IPA_SIZE,
            )
        };
        match bits {
            ..0 => Err(std::io::Error::last_os_error()),
            // Without the capability a guest gets KVM's fixed 40 bits.
            0 => Ok(40),
            bits => Ok(bits as u32),
        }
    }
}

const EAX: usize = 0;
const EBX: usize = 1;
const ECX: usize = 2;
const EDX: usize = 3;

/// The feature registers compared, as `(leaf, subleaf, register)`.
const FEATURE_REGISTERS: &[(u32, u32, usize)] = &[
    (0x1, 0, ECX),
    (0x1, 0, EDX),
    (0x7, 0, EBX),
    (0x7, 0, ECX),
    (0x7, 0, EDX),
    (0x7, 1, EAX),
    (0xd, 0, EAX),
    (0xd, 1, EAX),
    (0x8000_0001, 0, ECX),
    (0x8000_0001, 0, EDX),
    (0x8000_0008, 0, EBX),
];

/// Bits that are not something a guest can use: set by the guest's own
/// kernel (OSXSAVE, OSPKE), by the hypervisor, or meaning a feature is gone
/// (FDP_EXCPTN_ONLY, ZERO_FCS_FDS).
const IGNORED: &[(u32, u32, usize, u32)] = &[
    (0x1, 0, ECX, 27),
    (0x1, 0, ECX, 31),
    (0x7, 0, ECX, 4),
    (0x7, 0, EBX, 6),
    (0x7, 0, EBX, 13),
];

const NAMES: &[(u32, u32, usize, u32, &str)] = &[
    (0x1, 0, ECX, 0, "sse3"),
    (0x1, 0, ECX, 1, "pclmulqdq"),
    (0x1, 0, ECX, 9, "ssse3"),
    (0x1, 0, ECX, 12, "fma"),
    (0x1, 0, ECX, 13, "cx16"),
    (0x1, 0, ECX, 19, "sse4_1"),
    (0x1, 0, ECX, 20, "sse4_2"),
    (0x1, 0, ECX, 21, "x2apic"),
    (0x1, 0, ECX, 22, "movbe"),
    (0x1, 0, ECX, 23, "popcnt"),
    (0x1, 0, ECX, 25, "aes"),
    (0x1, 0, ECX, 26, "xsave"),
    (0x1, 0, ECX, 28, "avx"),
    (0x1, 0, ECX, 29, "f16c"),
    (0x1, 0, ECX, 30, "rdrand"),
    (0x1, 0, EDX, 0, "fpu"),
    (0x1, 0, EDX, 4, "tsc"),
    (0x1, 0, EDX, 8, "cx8"),
    (0x1, 0, EDX, 15, "cmov"),
    (0x1, 0, EDX, 19, "clflush"),
    (0x1, 0, EDX, 23, "mmx"),
    (0x1, 0, EDX, 24, "fxsr"),
    (0x1, 0, EDX, 25, "sse"),
    (0x1, 0, EDX, 26, "sse2"),
    (0x7, 0, EBX, 0, "fsgsbase"),
    (0x7, 0, EBX, 3, "bmi1"),
    (0x7, 0, EBX, 4, "hle"),
    (0x7, 0, EBX, 5, "avx2"),
    (0x7, 0, EBX, 7, "smep"),
    (0x7, 0, EBX, 8, "bmi2"),
    (0x7, 0, EBX, 9, "erms"),
    (0x7, 0, EBX, 10, "invpcid"),
    (0x7, 0, EBX, 11, "rtm"),
    (0x7, 0, EBX, 16, "avx512f"),
    (0x7, 0, EBX, 17, "avx512dq"),
    (0x7, 0, EBX, 18, "rdseed"),
    (0x7, 0, EBX, 19, "adx"),
    (0x7, 0, EBX, 20, "smap"),
    (0x7, 0, EBX, 21, "avx512ifma"),
    (0x7, 0, EBX, 23, "clflushopt"),
    (0x7, 0, EBX, 24, "clwb"),
    (0x7, 0, EBX, 28, "avx512cd"),
    (0x7, 0, EBX, 29, "sha_ni"),
    (0x7, 0, EBX, 30, "avx512bw"),
    (0x7, 0, EBX, 31, "avx512vl"),
    (0x7, 0, ECX, 1, "avx512vbmi"),
    (0x7, 0, ECX, 2, "umip"),
    (0x7, 0, ECX, 3, "pku"),
    (0x7, 0, ECX, 5, "waitpkg"),
    (0x7, 0, ECX, 6, "avx512_vbmi2"),
    (0x7, 0, ECX, 8, "gfni"),
    (0x7, 0, ECX, 9, "vaes"),
    (0x7, 0, ECX, 10, "vpclmulqdq"),
    (0x7, 0, ECX, 11, "avx512_vnni"),
    (0x7, 0, ECX, 12, "avx512_bitalg"),
    (0x7, 0, ECX, 14, "avx512_vpopcntdq"),
    (0x7, 0, ECX, 16, "la57"),
    (0x7, 0, ECX, 22, "rdpid"),
    (0x7, 0, ECX, 25, "cldemote"),
    (0x7, 0, ECX, 27, "movdiri"),
    (0x7, 0, ECX, 28, "movdir64b"),
    (0x7, 0, EDX, 4, "fsrm"),
    (0x7, 0, EDX, 8, "avx512_vp2intersect"),
    (0x7, 0, EDX, 10, "md_clear"),
    (0x7, 0, EDX, 14, "serialize"),
    (0x7, 0, EDX, 22, "amx_bf16"),
    (0x7, 0, EDX, 23, "avx512_fp16"),
    (0x7, 0, EDX, 24, "amx_tile"),
    (0x7, 0, EDX, 25, "amx_int8"),
    (0x7, 0, EDX, 26, "spec_ctrl"),
    (0x7, 0, EDX, 27, "stibp"),
    (0x7, 0, EDX, 29, "arch_capabilities"),
    (0x7, 0, EDX, 31, "ssbd"),
    (0x7, 1, EAX, 4, "avx_vnni"),
    (0x7, 1, EAX, 5, "avx512_bf16"),
    (0xd, 1, EAX, 0, "xsaveopt"),
    (0xd, 1, EAX, 1, "xsavec"),
    (0xd, 1, EAX, 2, "xgetbv1"),
    (0xd, 1, EAX, 3, "xsaves"),
    (0x8000_0001, 0, ECX, 0, "lahf_lm"),
    (0x8000_0001, 0, ECX, 5, "abm"),
    (0x8000_0001, 0, ECX, 6, "sse4a"),
    (0x8000_0001, 0, ECX, 8, "3dnowprefetch"),
    (0x8000_0001, 0, EDX, 11, "syscall"),
    (0x8000_0001, 0, EDX, 20, "nx"),
    (0x8000_0001, 0, EDX, 26, "pdpe1gb"),
    (0x8000_0001, 0, EDX, 27, "rdtscp"),
    (0x8000_0001, 0, EDX, 29, "lm"),
    (0x8000_0008, 0, EBX, 0, "clzero"),
    (0x8000_0008, 0, EBX, 9, "wbnoinvd"),
];

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
/// A fingerprint from the host's vendor registers (CPUID 0 EBX, EDX, ECX),
/// its CPUID 1 EAX and 0x80000008 EAX, and what KVM supports.
fn x86(vendor: [u32; 3], signature: u32, address: u32, supported: &[(u32, u32, [u32; 4])]) -> Cpu {
    let vendor: Vec<u8> = vendor.iter().flat_map(|r| r.to_le_bytes()).collect();
    let base_family = (signature >> 8) & 0xf;
    let family = match base_family {
        0xf => base_family + ((signature >> 20) & 0xff),
        _ => base_family,
    };
    let model = match base_family {
        0x6 | 0xf => ((signature >> 12) & 0xf0) | ((signature >> 4) & 0xf),
        _ => (signature >> 4) & 0xf,
    };
    let mut features = Vec::new();
    for &(leaf, subleaf, register) in FEATURE_REGISTERS {
        let Some((_, _, registers)) = supported
            .iter()
            .find(|(function, index, _)| *function == leaf && *index == subleaf)
        else {
            continue;
        };
        for bit in 0..32 {
            if registers[register] & (1 << bit) == 0
                || IGNORED.contains(&(leaf, subleaf, register, bit))
            {
                continue;
            }
            features.push(
                NAMES
                    .iter()
                    .find(|n| (n.0, n.1, n.2, n.3) == (leaf, subleaf, register, bit))
                    .map_or_else(
                        || {
                            let name = ["eax", "ebx", "ecx", "edx"][register];
                            format!("cpuid.{leaf:#x}.{subleaf}.{name}.{bit}")
                        },
                        |n| n.4.to_string(),
                    ),
            );
        }
    }
    features.sort();
    Cpu {
        vendor: String::from_utf8_lossy(&vendor).into_owned(),
        family,
        model,
        features,
        physical_address_bits: address & 0xff,
    }
}

/// A fingerprint from MIDR_EL1, `/proc/cpuinfo` and KVM's IPA limit.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
fn aarch64(midr: u64, cpuinfo: &str, ipa_bits: u32) -> Cpu {
    let mut features: Vec<String> = cpuinfo
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "Features").then_some(value)
        })
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    features.sort();
    Cpu {
        vendor: format!("{:#04x}", (midr >> 24) & 0xff),
        family: ((midr >> 20) & 0xf) as u32,
        model: ((midr >> 4) & 0xfff) as u32,
        features,
        physical_address_bits: ipa_bits,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn x86_features_are_named_and_kernel_bits_left_out() {
        // "GenuineIntel", family 6 model 0x55 (Skylake-SP).
        let vendor = [0x756e_6547, 0x4965_6e69, 0x6c65_746e];
        let supported = [
            (0x1, 0, [0, 0, (1 << 28) | (1 << 27) | (1 << 31), 1 << 26]),
            (0x7, 0, [0, (1 << 5) | (1 << 16) | (1 << 12), 0, 0]),
        ];
        let cpu = super::x86(vendor, 0x0005_0654, 0x302e, &supported);
        assert_eq!(cpu.vendor, "GenuineIntel");
        assert_eq!((cpu.family, cpu.model), (6, 0x55));
        assert_eq!(cpu.physical_address_bits, 46);
        assert_eq!(
            cpu.features,
            ["avx", "avx2", "avx512f", "cpuid.0x7.0.ebx.12", "sse2"]
        );
    }

    #[test]
    fn aarch64_is_its_midr_hwcaps_and_ipa_size() {
        let cpuinfo = "processor\t: 0\nBogoMIPS\t: 50.00\nFeatures\t: fp asimd aes atomics\n";
        let cpu = super::aarch64(0x413f_d0c1, cpuinfo, 44);
        assert_eq!(cpu.vendor, "0x41");
        assert_eq!((cpu.family, cpu.model), (3, 0xd0c));
        assert_eq!(cpu.features, ["aes", "asimd", "atomics", "fp"]);
        assert_eq!(cpu.physical_address_bits, 44);
    }
}
