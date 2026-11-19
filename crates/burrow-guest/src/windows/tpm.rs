//! The guest's TPM, provisioned for the sandbox before anything uses it.
//!
//! A template carries the TPM ownership Windows recorded for the TPM it was
//! installed with: the storage root key's hash, the owner and lockout
//! authorizations, and that maintenance is done. Every sandbox gets a TPM of
//! its own, which Windows has to clear and take ownership of again, creating
//! a storage root key (SRK) at its persistent handle. Its `Tpm-Maintenance`
//! task does that at boot, but not always: it can fail with
//! `TBS_E_INTERNAL_ERROR` before it notices the TPM changed, and once it has
//! failed it keeps failing against the stale record. Even after it succeeds,
//! the Platform Crypto Provider takes the new SRK only from the next boot.
//!
//! So on a boot whose TPM has no SRK, the agent drops the stale record, runs
//! the task until the SRK exists, and has the guest restart, alongside the
//! restart that gives it its name where there is one.

#![allow(clippy::result_large_err)]

use std::os::windows::process::CommandExt as _;

use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS2,
    TBS_CONTEXT_PARAMS2_0, TBS_CONTEXT_VERSION_TWO, Tbsi_Context_Create, Tbsip_Context_Close,
    Tbsip_Submit_Command,
};

/// Where Windows keeps a storage root key.
const SRK_HANDLE: u32 = 0x8100_0001;
/// What TPM Base Services answers on a machine with no TPM.
const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400f;
/// What `TBS_CONTEXT_PARAMS2` says to talk to a TPM 2.0.
const INCLUDE_TPM20: u32 = 1 << 2;
/// How long provisioning gets before the handshake goes on without it.
const PROVISION_WAIT: std::time::Duration = std::time::Duration::from_secs(90);
const MAINTENANCE: &str = r"\Microsoft\Windows\TPM\Tpm-Maintenance";
const ADMIN_KEY: &str = r"SYSTEM\CurrentControlSet\Services\TPM\WMI\Admin";
const TASK_STATES_KEY: &str = r"SYSTEM\CurrentControlSet\Services\TPM\WMI\TaskStates";
/// The ownership Windows recorded for a TPM, which names the template's.
const STALE: [(&str, &str); 7] = [
    (ADMIN_KEY, "SRKPub"),
    (ADMIN_KEY, "OwnerAuthFull"),
    (ADMIN_KEY, "OwnerAuthStatus"),
    (ADMIN_KEY, "LockoutHash"),
    (ADMIN_KEY, "LastAuthLevel"),
    (ADMIN_KEY, "StorageOwnerAuth"),
    (TASK_STATES_KEY, "MaintenanceTaskComplete"),
];

/// `TPM2_ReadPublic` of `handle`, as the TPM takes it.
fn read_public(handle: u32) -> [u8; 14] {
    let mut command = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x73, 0, 0, 0, 0];
    command[10..].copy_from_slice(&handle.to_be_bytes());
    command
}

/// The response code of a TPM response.
fn response_code(response: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(response.get(6..10)?.try_into().ok()?))
}

/// Whether the TPM holds a storage root key: `None` with no TPM to ask. The
/// agent starts before TPM Base Services does, so a service not yet running
/// is waited for.
fn has_srk() -> Option<bool> {
    let params = TBS_CONTEXT_PARAMS2 {
        version: TBS_CONTEXT_VERSION_TWO,
        Anonymous: TBS_CONTEXT_PARAMS2_0 {
            asUINT32: INCLUDE_TPM20,
        },
    };
    let mut context = std::ptr::null_mut();
    let started = std::time::Instant::now();
    loop {
        // SAFETY: `params` outlives the call, which writes `context`.
        match unsafe { Tbsi_Context_Create((&raw const params).cast(), &mut context) } {
            0 => break,
            TBS_E_TPM_NOT_FOUND => return None,
            _ if started.elapsed() > PROVISION_WAIT => return None,
            _ => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
    }
    let command = read_public(SRK_HANDLE);
    let mut response = [0u8; 1024];
    let mut length = response.len() as u32;
    // SAFETY: both buffers are live and sized as passed; the context is
    // closed below and not used after.
    let submitted = unsafe {
        let submitted = Tbsip_Submit_Command(
            context,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL,
            command.as_ptr(),
            command.len() as u32,
            response.as_mut_ptr(),
            &mut length,
        );
        Tbsip_Context_Close(context);
        submitted
    };
    (submitted == 0).then(|| response_code(&response[..length as usize]) == Some(0))
}

/// Provisions a TPM that has no storage root key, and says whether the guest
/// has to restart for the Platform Crypto Provider to use it. A guest with no
/// TPM, or one already provisioned, has nothing to do.
pub fn provision() -> bool {
    if has_srk() != Some(false) {
        return false;
    }
    for (key, value) in STALE {
        crate::windows::machine::delete_value(key, value);
    }
    let started = std::time::Instant::now();
    while started.elapsed() < PROVISION_WAIT {
        let _ = std::process::Command::new("schtasks")
            .args(["/Run", "/TN", MAINTENANCE])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if has_srk() == Some(true) {
                tracing::info!(
                    took_ms = started.elapsed().as_millis() as u64,
                    "provisioned the TPM; restarting for it"
                );
                return true;
            }
        }
    }
    tracing::warn!("the TPM has no storage root key; TPM-backed keys will not work");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_srk_is_read_by_its_persistent_handle() {
        assert_eq!(
            read_public(SRK_HANDLE),
            [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x73, 0x81, 0, 0, 0x01]
        );
        assert_eq!(
            response_code(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0]),
            Some(0)
        );
        assert_eq!(
            response_code(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x8b]),
            Some(0x18b)
        );
        assert_eq!(response_code(&[0x80]), None);
    }
}
