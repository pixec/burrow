//! `burrow-guest install`: puts the agent where its LaunchDaemon runs it from
//! and loads the daemon.
//!
//! Run once, as root, while a template is built (see deploy/macos/README.md).
//! Running it again replaces the binary and restarts the daemon.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

/// launchd's name for the agent, and its plist's.
pub const LABEL: &str = "dev.burrow.guest";
/// Where the daemon runs the agent from. `/usr/local` is on the data volume,
/// which a sealed system leaves writable.
pub const INSTALL_PATH: &str = "/usr/local/libexec/burrow-guest";
const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.burrow.guest.plist";
const PLIST: &str = include_str!("burrow-guest.plist");

pub fn run() -> anyhow::Result<()> {
    // SAFETY: a plain getter.
    anyhow::ensure!(
        unsafe { nix::libc::geteuid() } == 0,
        "install needs root: sudo burrow-guest install"
    );
    let exe = std::env::current_exe()?;
    let target = Path::new(INSTALL_PATH);
    if std::fs::canonicalize(&exe).ok() != std::fs::canonicalize(target).ok() {
        std::fs::create_dir_all(target.parent().expect("an absolute path"))?;
        // Beside the target and renamed over it, so a running agent keeps the
        // inode it runs from and launchd never starts a half-copied one.
        let temp = target.with_extension("new");
        std::fs::copy(&exe, &temp)?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))?;
        std::os::unix::fs::chown(&temp, Some(0), Some(0))?;
        std::fs::rename(&temp, target)?;
    }
    std::fs::write(PLIST_PATH, PLIST)?;
    std::fs::set_permissions(PLIST_PATH, std::fs::Permissions::from_mode(0o644))?;
    std::os::unix::fs::chown(PLIST_PATH, Some(0), Some(0))?;

    let service = format!("system/{LABEL}");
    // Not loaded yet on a first install, which is all its failure means.
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &service])
        .stderr(std::process::Stdio::null())
        .status();
    launchctl(&["enable", &service])?;
    // launchd finishes a bootout after returning from it, and a bootstrap
    // that lands before then fails with an I/O error.
    let mut attempts = 0;
    while let Err(err) = launchctl(&["bootstrap", "system", PLIST_PATH]) {
        attempts += 1;
        if attempts == 10 {
            return Err(err);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    println!("installed {INSTALL_PATH} and loaded {service}");
    Ok(())
}

fn launchctl(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("/bin/launchctl")
        .args(args)
        .status()?;
    anyhow::ensure!(
        status.success(),
        "launchctl {} failed: {status}",
        args.join(" ")
    );
    Ok(())
}
