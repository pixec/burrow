//! The machine itself: its name.

#![allow(clippy::result_large_err)]

use crate::windows::win;

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
