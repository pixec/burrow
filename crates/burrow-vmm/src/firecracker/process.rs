//! Spawning a `firecracker` process, jailed or not.

use std::path::{Path, PathBuf};

use tokio::net::unix::pipe;

use crate::cgroup::Cgroup;
use crate::error::{Error, Result};
use crate::process::{ChildProcess, Output, VmmProcess};

/// Firecracker accepts only alphanumerics and hyphens in `--id`, and panics
/// on anything else. Burrow's own ids use underscores (`sbx_1a2b…`), so they
/// are mapped here rather than constraining the id format everywhere else.
/// The value is only used in firecracker's own logs and metrics.
fn sanitize_vm_id(id: &str) -> String {
    let mapped: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(64)
        .collect();
    if mapped.is_empty() {
        "burrow-vm".to_string()
    } else {
        mapped
    }
}

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
    pub uid: u32,
    pub gid: u32,
    /// Every jailed VM's files are under `<base>/<hypervisor>/<id>/root`.
    pub chroot_base: PathBuf,
}

impl Jail {
    /// The chroot a VM under `hypervisor` runs in, which is also the working
    /// directory its files must be staged into.
    pub fn chroot_for(&self, hypervisor: crate::Hypervisor, vm_id: &str) -> PathBuf {
        self.dir_for(hypervisor, vm_id).join("root")
    }

    /// The directory one level above a VM's chroot.
    ///
    /// Firecracker's is the one its jailer builds, `<base>/<exec file
    /// name>/<id>`, and the binary is `firecracker`. Cloud Hypervisor's is
    /// laid out the same way under its own name.
    ///
    /// Named by the jailer's own sanitised id rather than the sandbox id: `_`
    /// is not alphanumeric, so `sbx_1234` lives in `sbx-1234`. Anything
    /// matching directories on this base against sandbox ids has to come
    /// through here, or it concludes that every jailed sandbox is an orphan.
    pub fn dir_for(&self, hypervisor: crate::Hypervisor, vm_id: &str) -> PathBuf {
        self.hypervisor_dir(hypervisor).join(sanitize_vm_id(vm_id))
    }

    /// Where every jailed VM under `hypervisor` has its directory.
    pub fn hypervisor_dir(&self, hypervisor: crate::Hypervisor) -> PathBuf {
        self.chroot_base.join(hypervisor.as_str())
    }

    /// What to remove to tear down the VM whose working directory is
    /// `workdir`: its whole directory when `workdir` is a chroot on this
    /// base, `workdir` alone otherwise. Decided on the path alone, so it
    /// never reaches outside the base or through a link.
    pub fn tree_of<'a>(&self, workdir: &'a Path) -> &'a Path {
        let is_chroot = workdir.strip_prefix(&self.chroot_base).is_ok_and(|rest| {
            let parts: Vec<_> = rest.components().collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
                && parts[2].as_os_str() == "root"
        });
        match workdir.parent() {
            Some(dir) if is_chroot => dir,
            _ => workdir,
        }
    }
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
    let id = sanitize_vm_id(vm_id);
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
                jail.uid.to_string().into(),
                "--gid".into(),
                jail.gid.to_string().into(),
                "--chroot-base-dir".into(),
                jail.chroot_base.clone().into(),
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
        ChildProcess::Cloned(spawned.child),
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

#[cfg(test)]
mod tests {
    use super::sanitize_vm_id;

    #[test]
    fn maps_characters_firecracker_rejects() {
        assert_eq!(sanitize_vm_id("sbx_1a2b"), "sbx-1a2b");
        assert_eq!(sanitize_vm_id("a.b/c"), "a-b-c");
        assert_eq!(sanitize_vm_id("plain123"), "plain123");
    }

    #[test]
    fn always_produces_a_usable_id() {
        assert_eq!(sanitize_vm_id(""), "burrow-vm");
        assert_eq!(sanitize_vm_id(&"x".repeat(100)).len(), 64);
    }

    fn jail() -> super::Jail {
        super::Jail {
            jailer: "/usr/local/bin/jailer".into(),
            uid: 65534,
            gid: 65534,
            chroot_base: std::path::PathBuf::from("/var/lib/burrow/jail"),
        }
    }

    /// A jailed sandbox's directory is not named after its id, so anything
    /// looking one up by id finds nothing. That once made every live jailed
    /// sandbox read as an orphan, and its state was deleted on every restart.
    #[test]
    fn a_jail_directory_is_not_named_after_the_sandbox() {
        let jail = jail();
        let id = "sbx_1a2b";

        let dir = jail.dir_for(crate::Hypervisor::Firecracker, id);
        assert_eq!(
            dir,
            std::path::Path::new("/var/lib/burrow/jail/firecracker/sbx-1a2b")
        );
        assert_ne!(dir.file_name().unwrap(), id, "the id is not the directory");
        assert_eq!(
            jail.chroot_for(crate::Hypervisor::Firecracker, id),
            dir.join("root")
        );
        assert_eq!(
            jail.dir_for(crate::Hypervisor::CloudHypervisor, id),
            std::path::Path::new("/var/lib/burrow/jail/cloud-hypervisor/sbx-1a2b")
        );
    }

    /// Removing only the chroot left `<base>/<hypervisor>/<id>` behind empty
    /// for every VM the node ever ran.
    #[test]
    fn a_teardown_takes_the_vm_directory_and_nothing_above_it() {
        let jail = jail();
        let path = std::path::Path::new;
        for hypervisor in [
            crate::Hypervisor::Firecracker,
            crate::Hypervisor::CloudHypervisor,
        ] {
            let chroot = jail.chroot_for(hypervisor, "sbx_1");
            assert_eq!(jail.tree_of(&chroot), jail.dir_for(hypervisor, "sbx_1"));
        }
        for workdir in [
            "/var/lib/burrow/sandboxes/sbx_1",
            "/var/lib/burrow/jail/firecracker/root",
            "/var/lib/burrow/jail/firecracker/sbx-1/root/root",
            "/var/lib/burrow/jail/firecracker/sbx-1/other",
            "/var/lib/burrow/jail/../sandboxes/sbx-1/root",
            "/var/lib/burrow/jail/firecracker/../root",
        ] {
            assert_eq!(jail.tree_of(path(workdir)), path(workdir), "{workdir}");
        }
    }
}
