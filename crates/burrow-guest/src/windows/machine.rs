//! The machine itself: its name, Remote Desktop, its license.

#![allow(clippy::result_large_err)]

use std::os::windows::process::CommandExt as _;

use tonic::Status;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::windows::win;

/// Turns the Remote Desktop listener on (`fDenyTSConnections` 0, which
/// Terminal Services reads live), opens the Remote Desktop firewall rules,
/// and lets `user` log on through it when one is named.
pub async fn enable_remote_desktop(user: String) -> Result<(), Status> {
    tokio::task::spawn_blocking(move || {
        set_dword(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
            0,
        )?;
        // The rule group by its resource name, which every language shares.
        netsh(&[
            "advfirewall",
            "firewall",
            "set",
            "rule",
            "group=@FirewallAPI.dll,-28752",
            "new",
            "enable=yes",
        ])?;
        if !user.is_empty() {
            crate::windows::users::allow_remote_desktop(&user)?;
        }
        Ok(())
    })
    .await
    .map_err(|err| Status::internal(format!("enabling remote desktop did not run: {err}")))?
}

/// Sets a DWORD under HKEY_LOCAL_MACHINE.
pub fn set_dword(key: &str, value: &str, data: u32) -> Result<(), Status> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_DWORD, RegSetKeyValueW};
    let (key_w, value_w) = (win::wide(key), win::wide(value));
    // SAFETY: both names are NUL-terminated and `data` outlives the call.
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            key_w.as_ptr(),
            value_w.as_ptr(),
            REG_DWORD,
            (&raw const data).cast(),
            4,
        )
    };
    if rc != 0 {
        return Err(Status::internal(format!(
            "setting {key}\\{value}: {}",
            std::io::Error::from_raw_os_error(rc as i32)
        )));
    }
    Ok(())
}

/// Deletes a value under HKEY_LOCAL_MACHINE; one that is not there is
/// already gone.
pub fn delete_value(key: &str, value: &str) {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegDeleteKeyValueW};
    let (key_w, value_w) = (win::wide(key), win::wide(value));
    // SAFETY: both names are NUL-terminated.
    unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key_w.as_ptr(), value_w.as_ptr()) };
}

fn netsh(args: &[&str]) -> Result<(), Status> {
    let output = std::process::Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| Status::internal(format!("running netsh: {err}")))?;
    if !output.status.success() {
        return Err(Status::internal(format!(
            "netsh {} exited {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout).trim()
        )));
    }
    Ok(())
}

/// `ComputerNamePhysicalDnsHostname`: the DNS host name, whose first 15
/// characters Windows makes the NetBIOS name.
const DNS_HOSTNAME: i32 = 5;

/// The name the running system booted under.
fn computer_name() -> std::io::Result<String> {
    use windows_sys::Win32::System::SystemInformation::GetComputerNameExW;
    let mut buf = vec![0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` characters.
    win::check(unsafe { GetComputerNameExW(DNS_HOSTNAME, buf.as_mut_ptr(), &mut len) })?;
    Ok(win::from_wide(&buf[..len as usize]))
}

/// Where the agent notes the name it restarted for, so a name that did not
/// take is not restarted for again and again.
fn restarted_for() -> std::path::PathBuf {
    win::state_dir().join("restarted-for-name")
}

/// Gives the machine `name` from its next boot, through
/// `SetComputerNameExW`, the supported way to rename. Windows applies a new
/// computer name only at boot, so whether the guest should restart to take
/// it is returned: a running name that differs, unless this agent already
/// restarted once for this name and it did not take.
pub fn rename(name: &str) -> std::io::Result<bool> {
    use windows_sys::Win32::System::SystemInformation::SetComputerNameExW;
    if computer_name()?.eq_ignore_ascii_case(name) {
        let _ = std::fs::remove_file(restarted_for());
        return Ok(false);
    }
    let wide = win::wide(name);
    // SAFETY: `wide` is NUL-terminated.
    win::check(unsafe { SetComputerNameExW(DNS_HOSTNAME, wide.as_ptr()) })?;
    if std::fs::read_to_string(restarted_for()).is_ok_and(|done| done == name) {
        tracing::error!(name, "the computer name did not take after a restart");
        return Ok(false);
    }
    std::fs::create_dir_all(win::state_dir())?;
    std::fs::write(restarted_for(), name)?;
    Ok(true)
}

static RESTARTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this agent has started a restart, after which it renames nothing.
pub fn is_restarting() -> bool {
    RESTARTING.load(std::sync::atomic::Ordering::Relaxed)
}

/// Restarts the machine once the handshake's answer has had time to go out.
pub fn restart_soon() {
    RESTARTING.store(true, std::sync::atomic::Ordering::Relaxed);
    std::thread::spawn(|| {
        use windows_sys::Win32::System::Shutdown::{
            InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED,
            SHTDN_REASON_MAJOR_OPERATINGSYSTEM, SHTDN_REASON_MINOR_RECONFIG,
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        // SAFETY: no strings; restarts this machine, forcing applications.
        let ok = unsafe {
            InitiateSystemShutdownExW(
                std::ptr::null(),
                std::ptr::null(),
                0,
                1,
                1,
                SHTDN_REASON_MAJOR_OPERATINGSYSTEM
                    | SHTDN_REASON_MINOR_RECONFIG
                    | SHTDN_REASON_FLAG_PLANNED,
            )
        };
        if ok == 0 {
            tracing::error!(err = %win::last_io_error(), "could not restart to take the new name");
        }
    });
}

/// A product key as Windows takes one: five groups of five letters and
/// digits.
pub fn is_product_key(key: &str) -> bool {
    let groups: Vec<&str> = key.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .all(|group| group.len() == 5 && group.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// A KMS host as slmgr takes one: a name or address, and a port.
pub fn is_kms_host(host: &str) -> bool {
    (1..=255).contains(&host.len())
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

/// Installs `product_key` and points the guest at `kms_host` when given,
/// then activates. slmgr does the work, as the supported tool; its output
/// goes back with the key cut out of it.
pub async fn activate(
    req: burrow_proto::guest::v1::ActivateRequest,
) -> Result<burrow_proto::guest::v1::ActivateResponse, Status> {
    if !req.product_key.is_empty() && !is_product_key(&req.product_key) {
        return Err(Status::invalid_argument("not a product key"));
    }
    if !req.kms_host.is_empty() && !is_kms_host(&req.kms_host) {
        return Err(Status::invalid_argument(format!(
            "{:?} is not a KMS host",
            req.kms_host
        )));
    }
    tokio::task::spawn_blocking(move || {
        let key = req.product_key;
        if !key.is_empty() {
            let (ok, out) = slmgr(&["/ipk", &key], &key)?;
            if !ok {
                return Ok(burrow_proto::guest::v1::ActivateResponse {
                    is_activated: false,
                    status: format!("installing the product key: {out}"),
                });
            }
        }
        if !req.kms_host.is_empty() {
            let (ok, out) = slmgr(&["/skms", &req.kms_host], &key)?;
            if !ok {
                return Ok(burrow_proto::guest::v1::ActivateResponse {
                    is_activated: false,
                    status: format!("setting the KMS host: {out}"),
                });
            }
        }
        let (_, attempt) = slmgr(&["/ato"], &key)?;
        let (is_activated, state) = license_state()?;
        let status = match is_activated {
            true => state,
            false => format!("{state}: {attempt}"),
        };
        Ok(burrow_proto::guest::v1::ActivateResponse {
            is_activated,
            status,
        })
    })
    .await
    .map_err(|err| Status::internal(format!("activation did not run: {err}")))?
}

/// Runs slmgr under cscript, answering whether it succeeded and what it
/// printed, with `secret` replaced wherever it appears.
fn slmgr(args: &[&str], secret: &str) -> Result<(bool, String), Status> {
    let script = format!(r"{}:\Windows\System32\slmgr.vbs", win::system_drive());
    let output = std::process::Command::new("cscript.exe")
        .arg("//nologo")
        .arg(&script)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| Status::internal(format!("running slmgr: {err}")))?;
    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !secret.is_empty() {
        text = text.replace(secret, "<product key>");
    }
    // slmgr exits 0 whatever happened and says so in words.
    let ok = output.status.success() && !text.contains("Error:");
    Ok((ok, text.split_whitespace().collect::<Vec<_>>().join(" ")))
}

/// Whether Windows itself is licensed, and its state as `LicenseStatus` and
/// the license's description name it.
fn license_state() -> Result<(bool, String), Status> {
    const QUERY: &str = "$p = Get-CimInstance SoftwareLicensingProduct -Filter \"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL\" | Select-Object -First 1; if ($p) { \"$($p.LicenseStatus)|$($p.Description)\" }";
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", QUERY])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| Status::internal(format!("reading the license state: {err}")))?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let (code, description) = text
        .split_once('|')
        .unwrap_or(("", "no installed product key"));
    let state = match code {
        "0" => "unlicensed",
        "1" => "licensed",
        "2" => "out-of-box grace",
        "3" => "out-of-tolerance grace",
        "4" => "non-genuine grace",
        "5" => "notification",
        "6" => "extended grace",
        _ => "unknown",
    };
    Ok((code == "1", format!("{state} ({description})")))
}

/// Whether Windows Setup has finished with this install. A generalized image
/// runs specialize and OOBE on its first boot, restarting in between, and an
/// agent that answered meanwhile would be handshaken and then lose its
/// connection to Setup's restart. No `ImageState` is an install Setup never
/// generalized.
pub fn is_setup_complete() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    let key = win::wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State");
    let value = win::wide("ImageState");
    let mut buf = vec![0u16; 64];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: `buf` holds `len` bytes; both names are NUL-terminated.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    rc != 0 || win::from_wide(&buf) == "IMAGE_STATE_COMPLETE"
}
