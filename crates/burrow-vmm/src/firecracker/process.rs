//! Spawning a `firecracker` process, jailed or not.

use std::path::{Path, PathBuf};

use tokio::net::unix::pipe;

use crate::cgroup::Cgroup;
use crate::error::{Error, Result};
use crate::jail::JailLayout;
use crate::process::{Output, VmmProcess};

/// Removes the device nodes the jailer creates.
///
/// The jailer `mknod`s `/dev/kvm` and `/dev/net/tun` inside the chroot
/// unconditionally and fails with `EEXIST` if they are already there. A chroot
/// is reused every time a sandbox resumes, so without this the first resume
/// after a suspend fails outright.
async fn clear_jail_devices(workdir: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(workdir.join("dev")).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// How firecracker is confined, if at all.
///
/// The jailer chroots the VMM into its own working directory and drops it to an
/// unprivileged uid, so a firecracker compromised out of its seccomp filter
/// still holds no root and can see no filesystem but the one sandbox's. Without
/// it firecracker runs as root with the whole host visible, which is a large
/// amount of trust to place in one process supervising untrusted guests.
#[derive(Debug, Clone)]
pub struct Jail {
    pub jailer: PathBuf,
    pub layout: JailLayout,
}

/// Spawns firecracker with its working directory set to `workdir`, so every
/// path handed to the API can stay relative, and in `cgroup` from before it
/// execs. Returns the process once it listens on `api_sock`, and its stdin,
/// which is wired to the guest serial port.
///
/// Guest serial output arrives on the process's stdout, so both stdout and
/// stderr are captured to the bounded console log inside the workdir.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn(
    binary: &Path,
    vm_id: &str,
    workdir: &Path,
    api_sock: &str,
    jail: Option<&Jail>,
    enable_pci: bool,
    cgroup: Option<Cgroup>,
    phases: &mut crate::Phases,
) -> Result<(VmmProcess, pipe::Sender)> {
    if !binary.exists() {
        return Err(Error::BinaryNotFound(binary.to_path_buf()));
    }
    if let Some(jail) = jail
        && !jail.jailer.exists()
    {
        return Err(Error::BinaryNotFound(jail.jailer.clone()));
    }
    tokio::fs::create_dir_all(workdir).await?;

    // Firecracker refuses to start if the socket path already exists.
    let sock_path = workdir.join(api_sock);
    if tokio::fs::try_exists(&sock_path).await.unwrap_or(false) {
        tokio::fs::remove_file(&sock_path).await?;
    }

    if jail.is_some() {
        clear_jail_devices(workdir).await?;
        // The jailer copies firecracker in each time; an existing copy is
        // simply overwritten, but a stale pid file confuses nothing and is
        // tidier gone.
        let _ = tokio::fs::remove_file(workdir.join("firecracker.pid")).await;
    }

    phases.mark("prespawn");
    let id = crate::jail::sanitize_vm_id(vm_id);
    let mut args: Vec<std::ffi::OsString> = Vec::new();
    let program = match jail {
        None => {
            args.extend(["--api-sock", api_sock, "--id", &id].map(Into::into));
            binary
        }
        Some(jail) => {
            // Everything the VM needs is already inside the chroot, and
            // every path handed to the API is relative, so firecracker's
            // view of them is unchanged by the pivot. v2 with no --cgroup
            // has the jailer touch no cgroup: the VMM is cloned into its
            // own already.
            args.extend([
                "--id".into(),
                id.into(),
                "--exec-file".into(),
                binary.into(),
                "--uid".into(),
                jail.layout.uid.to_string().into(),
                "--gid".into(),
                jail.layout.gid.to_string().into(),
                "--chroot-base-dir".into(),
                jail.layout.chroot_base.clone().into(),
            ]);
            args.extend(["--cgroup-version", "2", "--", "--api-sock", api_sock].map(Into::into));
            &jail.jailer
        }
    };
    if enable_pci {
        args.push("--enable-pci".into());
    }
    // The jailer execs firecracker in place, so what is cloned into the
    // cgroup here is firecracker itself.
    let spawned =
        crate::child::spawn(program, &args, workdir, cgroup.as_ref().map(Cgroup::path)).await?;

    let outputs: Vec<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = vec![
        Box::new(pipe::Receiver::from_owned_fd(spawned.stdout)?),
        Box::new(pipe::Receiver::from_owned_fd(spawned.stderr)?),
    ];
    let mut process = VmmProcess::new(
        spawned.child,
        Output::Console(workdir.to_path_buf()),
        cgroup,
    );
    crate::console::capture(workdir, outputs)?;
    phases.mark("spawn");
    let console_in = pipe::Sender::from_owned_fd(spawned.stdin)?;
    process.wait_for_socket(&sock_path).await?;
    phases.mark("api_ready");
    Ok((process, console_in))
}
