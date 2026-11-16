//! A guest's TPM 2.0, from an swtpm process of its own beside its VMM.
//!
//! The emulator is started before the VMM, which connects to its control
//! socket, and outlives a VMM that exits so that its state can be saved. A
//! boot starts it with its permanent state alone, so the firmware's
//! `TPM2_Startup` begins a fresh boot; a restore keeps the volatile state a
//! kill saved, which the emulator resumes from when the restored VMM
//! initialises it. Stopping the VMM saves that volatile state and stops the
//! emulator.

use std::path::{Path, PathBuf};

use crate::TpmSpec;
use crate::error::{Error, Result};

pub(crate) const SOCKET: &str = "swtpm.sock";
const PID: &str = "swtpm.pid";
const LOG: &str = "swtpm.log";
const VOLATILE: &str = "tpm2-00.volatilestate";

/// swtpm's control channel commands, from its `tpm_ioctl.h`.
const CMD_SHUTDOWN: u32 = 3;
const CMD_STORE_VOLATILE: u32 = 10;

/// The socket as the VM config names it: relative to the working directory
/// when the state is in it, so a jailed VMM finds it there too.
pub(crate) fn socket(tpm: &TpmSpec, workdir: &Path) -> PathBuf {
    let socket = tpm.dir.join(SOCKET);
    match socket.strip_prefix(workdir) {
        Ok(relative) => relative.to_path_buf(),
        Err(_) => socket,
    }
}

/// Starts the emulator, after stopping one a VMM that ended left running.
/// `is_fresh` drops saved volatile state, for a boot.
///
/// A jailed VMM runs as another uid, so the socket is left open to every uid
/// and what guards it is the directory: closed to all but root when the VMM
/// reaches the socket through a bind mount of it alone, and only passable
/// inside the working directory, which is the jail's own. Handing the socket
/// to the jail's uid instead breaks Ubuntu's AppArmor profile for swtpm,
/// which lets it write only to files it owns.
pub(crate) async fn start(
    tpm: &TpmSpec,
    workdir: &Path,
    is_fresh: bool,
    is_jailed: bool,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::create_dir_all(&tpm.dir).await?;
    let dir_mode = match is_jailed && tpm.dir.starts_with(workdir) {
        true => 0o711,
        false => 0o700,
    };
    tokio::fs::set_permissions(&tpm.dir, std::fs::Permissions::from_mode(dir_mode)).await?;
    stop(tpm, false).await;
    if is_fresh {
        let _ = tokio::fs::remove_file(tpm.dir.join(VOLATILE)).await;
    }
    let mode = if is_jailed { "0666" } else { "0600" };
    let ctrl = format!(
        "type=unixio,path={},mode={mode}",
        tpm.dir.join(SOCKET).display()
    );
    let output = tokio::process::Command::new(&tpm.swtpm)
        .arg("socket")
        .arg("--tpm2")
        .arg("--tpmstate")
        .arg(format!("dir={}", tpm.dir.display()))
        .arg("--ctrl")
        .arg(ctrl)
        .arg("--pid")
        .arg(format!("file={}", tpm.dir.join(PID).display()))
        .arg("--log")
        .arg(format!("file={},level=1", tpm.dir.join(LOG).display()))
        .arg("--daemon")
        .output()
        .await
        .map_err(|err| Error::Tpm(format!("starting {}: {err}", tpm.swtpm.display())))?;
    if !output.status.success() {
        return Err(Error::Tpm(format!(
            "{} exited {}: {}",
            tpm.swtpm.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Stops the emulator, first having it save its volatile state when
/// `is_saved`, for a restore to resume from.
pub(crate) async fn stop(tpm: &TpmSpec, is_saved: bool) {
    let socket = tpm.dir.join(SOCKET);
    let commands: &[u32] = match is_saved {
        true => &[CMD_STORE_VOLATILE, CMD_SHUTDOWN],
        false => &[CMD_SHUTDOWN],
    };
    if let Err(err) = control(&socket, commands).await
        && is_saved
    {
        tracing::warn!(dir = %tpm.dir.display(), %err, "could not save the TPM's volatile state");
    }
    // A shutdown the emulator never heard, from one hung or gone.
    if let Ok(pid) = tokio::fs::read_to_string(tpm.dir.join(PID)).await
        && let Ok(pid) = pid.trim().parse::<i32>()
    {
        // SAFETY: a plain signal to the pid swtpm recorded.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let _ = tokio::fs::remove_file(tpm.dir.join(PID)).await;
    let _ = tokio::fs::remove_file(&socket).await;
}

/// Sends control commands, each a big-endian code answered by a big-endian
/// result, 0 for success.
async fn control(socket: &Path, commands: &[u32]) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::UnixStream::connect(socket),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    for command in commands {
        stream.write_all(&command.to_be_bytes()).await?;
        let mut result = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut result),
        )
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        if u32::from_be_bytes(result) != 0 {
            return Err(std::io::Error::other(format!(
                "swtpm answered command {command} with {}",
                u32::from_be_bytes(result)
            )));
        }
    }
    Ok(())
}
