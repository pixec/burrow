//! Where jailed VMs live and which uid they run as, shared by Firecracker's
//! jailer and Cloud Hypervisor's helper.

use std::path::{Path, PathBuf};

/// The chroot layout and identity every jailed VM on a node shares.
#[derive(Debug, Clone)]
pub struct JailLayout {
    pub uid: u32,
    pub gid: u32,
    /// Every jailed VM's files are under `<base>/<hypervisor>/<id>/root`.
    pub chroot_base: PathBuf,
}

impl JailLayout {
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

/// Firecracker accepts only alphanumerics and hyphens in `--id`, and panics
/// on anything else. Burrow's own ids use underscores (`sbx_1a2b…`), so they
/// are mapped here rather than constraining the id format everywhere else.
/// The value is only used in firecracker's own logs and metrics.
pub(crate) fn sanitize_vm_id(id: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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

    fn jail() -> JailLayout {
        JailLayout {
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
