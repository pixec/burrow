//! A guest's TPM 2.0, from an swtpm process of its own beside its VMM.
//!
//! The emulator is started before the VMM, which connects to its control
//! socket, and outlives a VMM that exits so that its state can be saved. A
//! boot starts it with its permanent state alone, so the firmware's
//! `TPM2_Startup` begins a fresh boot; a restore keeps the volatile state a
//! kill saved, which the emulator resumes from when the restored VMM
//! initialises it. Stopping the VMM saves that volatile state and stops the
//! emulator.
//!
//! The state is kept outside the VM's working directory, which a jailed VMM
//! owns, in a directory only the emulator's own uid can enter, and a jailed
//! VMM is shown the socket alone. swtpm runs as a uid of its sandbox's own,
//! under its own seccomp filter, in the VM's cgroup. It is not chrooted:
//! Ubuntu's AppArmor profile for it refuses `CAP_SYS_CHROOT`.
//!
//! A copy of the guest carries the emulator's state files, packed into one
//! ([`pack`]) and unpacked into the copy's own directory ([`unpack`]). They
//! are what swtpm's own state blobs hold, read from its directory once the
//! emulator has stored its volatile state and stopped, with the VM paused or
//! gone, so nothing moves under them.

use std::path::{Path, PathBuf};

use crate::TpmSpec;
use crate::error::{Error, Result};

const SOCKET: &str = "swtpm.sock";
const PID: &str = "swtpm.pid";
const LOG: &str = "swtpm.log";
const PERMANENT: &str = "tpm2-00.permall";
const VOLATILE: &str = "tpm2-00.volatilestate";
/// What a packed state starts with.
const MAGIC: &[u8; 8] = b"BTPMST01";

/// swtpm's control channel commands, from its `tpm_ioctl.h`.
const CMD_SHUTDOWN: u32 = 3;
const CMD_STORE_VOLATILE: u32 = 10;

/// The socket the VM config names, which a jail binds in by this path.
pub(crate) fn socket(tpm: &TpmSpec) -> PathBuf {
    tpm.dir.join(SOCKET)
}

/// Starts the emulator, after stopping one a VMM that ended left running.
/// `is_fresh` drops saved volatile state, for a boot.
///
/// The socket is open to every uid: a jailed VMM runs as another uid, and
/// swtpm, never root, cannot give it to that uid's group. What
/// guards it is its directory, 0700 to the emulator's uid, which the VMM
/// reaches only through a bind mount of the socket itself.
pub(crate) async fn start(tpm: &TpmSpec, is_fresh: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    stop(tpm, false).await;
    if let Some(parent) = tpm.dir.parent() {
        tokio::fs::create_dir_all(parent).await?;
        // Passable, not listable, to the uid the emulator runs as.
        tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o711)).await?;
    }
    tokio::fs::create_dir_all(&tpm.dir).await?;
    let (uid, gid) = (tpm.uid, tpm.uid);
    let dir = tpm.dir.clone();
    tokio::task::spawn_blocking(move || {
        std::os::unix::fs::lchown(&dir, Some(uid), Some(gid))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(&dir)? {
            std::os::unix::fs::lchown(entry?.path(), Some(uid), Some(gid))?;
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(std::io::Error::other)??;
    if is_fresh {
        let _ = tokio::fs::remove_file(tpm.dir.join(VOLATILE)).await;
    }
    let mut command = tokio::process::Command::new(&tpm.swtpm);
    command
        .arg("socket")
        .arg("--tpm2")
        .arg("--tpmstate")
        .arg(format!("dir={}", tpm.dir.display()))
        .arg("--ctrl")
        .arg(format!(
            "type=unixio,path={},mode=0666",
            socket(tpm).display()
        ))
        .arg("--pid")
        .arg(format!("file={}", tpm.dir.join(PID).display()))
        .arg("--log")
        .arg(format!("file={},level=1", tpm.dir.join(LOG).display()))
        .arg("--seccomp")
        .arg("action=kill")
        .arg("--daemon")
        // Not `--runas`, which leaves root's supplementary groups on a uid
        // with no passwd entry; dropping to a uid clears them.
        .uid(uid)
        .gid(gid);
    let output = command
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

/// The emulator's pid, when the pid file names a live swtpm serving this
/// state directory: the file is in a directory the emulator's uid writes.
pub(crate) fn pid(tpm: &TpmSpec) -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(tpm.dir.join(PID))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if exe != std::fs::canonicalize(&tpm.swtpm).ok()? {
        return None;
    }
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let state = format!("dir={}", tpm.dir.display());
    cmdline
        .split(|b| *b == 0)
        .any(|arg| arg == state.as_bytes())
        .then_some(pid)
}

/// Stops the emulator, first having it save its volatile state when
/// `is_saved`, for a restore to resume from. Signalled only when it does not
/// answer its control socket.
pub(crate) async fn stop(tpm: &TpmSpec, is_saved: bool) {
    let socket = socket(tpm);
    let commands: &[u32] = match is_saved {
        true => &[CMD_STORE_VOLATILE, CMD_SHUTDOWN],
        false => &[CMD_SHUTDOWN],
    };
    let running = pid(tpm);
    if let Err(err) = control(&socket, commands).await {
        if is_saved {
            tracing::warn!(dir = %tpm.dir.display(), %err, "could not save the TPM's volatile state");
        }
        // Checked again now: the control socket can take seconds to fail.
        if let Some(pid) = pid(tpm) {
            // SAFETY: a plain signal to a process just checked to be this
            // TPM's swtpm.
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        }
    }
    // Gone before the VM's cgroup, which it is in, is removed.
    if let Some(pid) = running {
        for _ in 0..40 {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
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

/// Packs the emulator's state in `dir` into the file `dest`, readable by root
/// alone. The emulator must have stopped, having stored its volatile state
/// where the guest's memory needs it.
pub async fn pack(dir: &Path, dest: &Path) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let mut packed = MAGIC.to_vec();
    for name in [PERMANENT, VOLATILE] {
        let bytes = match tokio::fs::read(dir.join(name)).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && name == VOLATILE => continue,
            Err(err) => {
                return Err(Error::Tpm(format!(
                    "reading {}: {err}",
                    dir.join(name).display()
                )));
            }
        };
        packed.push(name.len() as u8);
        packed.extend_from_slice(name.as_bytes());
        packed.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        packed.extend_from_slice(&bytes);
    }
    let next = dest.with_extension("next");
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&next)
        .await?;
    file.write_all(&packed).await?;
    file.sync_all().await?;
    tokio::fs::rename(&next, dest).await?;
    Ok(())
}

/// Unpacks state [`pack`] wrote into `dir`, replacing whatever was there. The
/// emulator's start gives the files to its uid.
pub async fn unpack(src: &Path, dir: &Path) -> Result<()> {
    let packed = tokio::fs::read(src).await?;
    let files = parse(&packed)?;
    if !files.iter().any(|(name, _)| *name == PERMANENT) {
        return Err(Error::Tpm(format!(
            "{} holds no permanent state",
            src.display()
        )));
    }
    let _ = tokio::fs::remove_dir_all(dir).await;
    tokio::fs::create_dir_all(dir).await?;
    for (name, bytes) in files {
        tokio::fs::write(dir.join(name), bytes).await?;
    }
    Ok(())
}

/// The files a packed state holds, by the names swtpm gives them.
fn parse(mut packed: &[u8]) -> Result<Vec<(&'static str, &[u8])>> {
    let bad = |why: &str| Error::Tpm(format!("packed TPM state: {why}"));
    packed = packed.strip_prefix(MAGIC).ok_or_else(|| bad("not one"))?;
    let mut files = Vec::new();
    while let Some((&len, rest)) = packed.split_first() {
        let (name, rest) = rest
            .split_at_checked(usize::from(len))
            .ok_or_else(|| bad("truncated"))?;
        let name = [PERMANENT, VOLATILE]
            .into_iter()
            .find(|known| known.as_bytes() == name)
            .ok_or_else(|| bad("an unknown file"))?;
        let (size, rest) = rest.split_at_checked(8).ok_or_else(|| bad("truncated"))?;
        let size = u64::from_le_bytes(size.try_into().unwrap());
        let (bytes, rest) = usize::try_from(size)
            .ok()
            .and_then(|size| rest.split_at_checked(size))
            .ok_or_else(|| bad("truncated"))?;
        if files.iter().any(|(known, _)| *known == name) {
            return Err(bad("a file twice"));
        }
        files.push((name, bytes));
        packed = rest;
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_packed_state_unpacks_to_the_same_files() {
        let root = std::env::temp_dir().join(format!("burrow-tpm-{}", std::process::id()));
        let (from, to) = (root.join("a"), root.join("b"));
        std::fs::create_dir_all(&from).unwrap();
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(from.join(PERMANENT), b"permanent").unwrap();
        std::fs::write(from.join(VOLATILE), b"volatile").unwrap();
        std::fs::write(from.join(LOG), b"not carried").unwrap();
        std::fs::write(to.join("stale"), b"gone").unwrap();
        let packed = root.join("tpm.state");
        pack(&from, &packed).await.unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&packed).unwrap().permissions().mode() & 0o777,
            0o600
        );
        unpack(&packed, &to).await.unwrap();
        assert_eq!(std::fs::read(to.join(PERMANENT)).unwrap(), b"permanent");
        assert_eq!(std::fs::read(to.join(VOLATILE)).unwrap(), b"volatile");
        assert!(!to.join(LOG).exists());
        assert!(!to.join("stale").exists());

        std::fs::remove_file(from.join(VOLATILE)).unwrap();
        pack(&from, &packed).await.unwrap();
        unpack(&packed, &to).await.unwrap();
        assert!(!to.join(VOLATILE).exists());
        std::fs::remove_file(from.join(PERMANENT)).unwrap();
        assert!(pack(&from, &packed).await.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_packed_state_names_only_swtpms_files() {
        let entry = |name: &str, bytes: &[u8]| {
            let mut out = vec![name.len() as u8];
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes);
            out
        };
        let good = [MAGIC.to_vec(), entry(PERMANENT, b"p")].concat();
        assert_eq!(parse(&good).unwrap(), vec![(PERMANENT, &b"p"[..])]);
        assert!(parse(&[MAGIC.to_vec(), entry("../../etc/passwd", b"x")].concat()).is_err());
        assert!(parse(&[good.clone(), entry(PERMANENT, b"q")].concat()).is_err());
        assert!(parse(&good[..good.len() - 1]).is_err());
        assert!(parse(b"BTPMST02").is_err());
    }
}
