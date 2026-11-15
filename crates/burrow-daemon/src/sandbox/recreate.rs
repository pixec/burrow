//! Replacing a sandbox's root disk under the same id, address, volumes and
//! settings, without losing the sandbox when the replacement cannot be made.
//!
//! The replacement is staged beside the sandbox's directory while the old
//! guest still runs: the template's files and a fresh root disk, in
//! `<dir>.next`. Only once that exists is the old guest halted, its
//! directory moved to `<dir>.prev` and the staged one moved into its place,
//! and the new disk booted on the same lease and tap. A failure from the halt
//! to the end of what runs inside the new guest (what `--keep` carries, a
//! Kit's hooks) moves the old directory back and boots it again if it was
//! running.
//!
//! From the halt until the new sandbox is committed, a journal under the data
//! directory names both directories and holds the old record, so a node that
//! dies in between comes back to the old sandbox, stopped on its own disk.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tonic::Status;

use burrow_proto::common::v1 as common;
use burrow_vmm::HypervisorExt;

use super::{
    ENDED_FAILED, RunningSandbox, SandboxManager, TEMPLATE_ROOTFS, charge_of, pin_boot_memory,
    prepare_workdir, require_min_machine, require_nested_kernel, seal_secrets, settled,
};

/// What a sandbox is recreated as.
pub struct Replacement {
    pub template: String,
    pub policy: common::Policy,
    /// Paths carried from the old root disk to the new one.
    pub keep: Vec<String>,
}

/// Where the replacement is made before it takes the sandbox's directory.
fn staged(tree: &Path) -> PathBuf {
    sibling(tree, "next")
}

/// Where the old directory waits until the replacement is committed.
fn retired(tree: &Path) -> PathBuf {
    sibling(tree, "prev")
}

fn sibling(tree: &Path, suffix: &str) -> PathBuf {
    let mut name = tree.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    tree.with_file_name(name)
}

/// `workdir`'s place inside `tree`, moved to `base`.
fn within(base: &Path, tree: &Path, workdir: &Path) -> PathBuf {
    base.join(workdir.strip_prefix(tree).unwrap_or(Path::new("")))
}

/// Which of the two renames that put the replacement in place were made.
#[derive(Debug, Clone, Copy, Default)]
struct Moved {
    /// The old directory to its retired place.
    old: bool,
    /// The staged directory to the sandbox's.
    new: bool,
}

impl Moved {
    /// What a recreate the node died in had done, read from what is on disk.
    /// The retired place is cleared before a journal is written, so a
    /// retired directory under a journal is that recreate's.
    async fn found(old_tree: &Path, tree: &Path) -> std::io::Result<Self> {
        let old = tokio::fs::try_exists(retired(old_tree)).await?;
        Ok(Self {
            old,
            new: old && tokio::fs::try_exists(tree).await?,
        })
    }
}

/// Undoes the renames in `moved` and removes the staged directory, so the
/// old directory is where it was and nothing of the replacement is left.
async fn restore_dirs(old_tree: &Path, tree: &Path, moved: Moved) -> std::io::Result<()> {
    if moved.new {
        tokio::fs::remove_dir_all(tree).await?;
    }
    if moved.old {
        tokio::fs::rename(retired(old_tree), old_tree).await?;
    }
    let next = staged(tree);
    if tokio::fs::try_exists(&next).await? {
        tokio::fs::remove_dir_all(&next).await?;
    }
    Ok(())
}

/// A recreate between the halt and the commit.
#[derive(Serialize, Deserialize)]
struct Journal {
    old_tree: PathBuf,
    tree: PathBuf,
    template: String,
    /// The record the store held before the halt, secrets sealed, base64.
    record: String,
}

impl Journal {
    fn dir(data_dir: &Path) -> PathBuf {
        data_dir.join("recreating")
    }

    fn path(data_dir: &Path, id: &str) -> PathBuf {
        Self::dir(data_dir).join(format!("{id}.json"))
    }

    async fn write(&self, data_dir: &Path, id: &str) -> std::io::Result<()> {
        tokio::fs::create_dir_all(Self::dir(data_dir)).await?;
        let path = Self::path(data_dir, id);
        let bytes = serde_json::to_vec(self)?;
        crate::fsync::replace(&path, &path.with_extension("pending"), bytes).await
    }

    async fn remove(data_dir: &Path, id: &str) -> std::io::Result<()> {
        tokio::fs::remove_file(Self::path(data_dir, id)).await?;
        crate::fsync::dir(&Self::dir(data_dir)).await
    }
}

impl SandboxManager {
    /// Replaces a sandbox's root disk with a fresh one from `replacement`'s
    /// template, keeping its id, address, tap, volumes, ports and name. Once
    /// the new guest is up, `keep` is carried into it and `ready` runs, and
    /// only when both succeed is the old disk let go. Any failure before
    /// then leaves the sandbox on its old disk, running if it was.
    pub async fn recreate<F, Fut>(
        &self,
        id: &str,
        replacement: Replacement,
        ready: F,
    ) -> Result<common::Sandbox, Status>
    where
        F: FnOnce(Arc<RunningSandbox>) -> Fut,
        Fut: std::future::Future<Output = Result<(), Status>>,
    {
        if !self.recreating.lock().unwrap().insert(id.to_string()) {
            return Err(Status::aborted(format!(
                "sandbox {id} is already being recreated"
            )));
        }
        let recreated = self.recreate_claimed(id, replacement, ready).await;
        self.recreating.lock().unwrap().remove(id);
        recreated
    }

    async fn recreate_claimed<F, Fut>(
        &self,
        id: &str,
        replacement: Replacement,
        ready: F,
    ) -> Result<common::Sandbox, Status>
    where
        F: FnOnce(Arc<RunningSandbox>) -> Fut,
        Fut: std::future::Future<Output = Result<(), Status>>,
    {
        let old = self.get(id).await?;
        if old.durable.is_fenced() {
            return Err(Status::unavailable(format!(
                "sandbox {id} has a checkpoint in the object store, and this node is waiting for \
                 the orchestrator to confirm it still holds it; try again shortly"
            )));
        }
        let Replacement {
            template,
            mut policy,
            keep,
        } = replacement;
        crate::template::validate_name(&template)?;
        let templates_dir = self.config.templates_dir();
        let environment = self.image_environment(&template).await;
        let (hypervisor, guest_os) = environment.machine()?;
        self.require_hypervisor(hypervisor)?;
        let mut resources = policy.resources.clone().unwrap_or_default();
        self.require_nested_virt(hypervisor, &resources)?;
        let kernel =
            crate::kernels::in_dir(&templates_dir.join(&template), &environment.kernel).await?;
        require_nested_kernel(&template, kernel.as_ref(), &resources)?;
        let capabilities = hypervisor.capabilities();
        if !capabilities.runs(guest_os) {
            return Err(Status::failed_precondition(format!(
                "template {template} is a {} guest, which {hypervisor} cannot run",
                guest_os.as_str()
            )));
        }
        if capabilities.is_tap_networked != old.hypervisor.capabilities().is_tap_networked {
            return Err(Status::failed_precondition(format!(
                "template {template} runs under {hypervisor}, which networks a guest differently \
                 from {}; create a new sandbox from it with the same volumes instead",
                old.hypervisor
            )));
        }
        require_min_machine(&template, guest_os, crate::warm::Shape::wanted(&resources))?;
        let keep = match keep.is_empty() {
            true => keep,
            false => crate::keep::check(&keep, &policy.volumes, old.guest_os(), guest_os)?,
        };
        let is_macos = crate::macnode::is_macos(guest_os);
        let disk_bytes = match crate::macnode::disk_file(guest_os) {
            Some(disk) => {
                let bytes =
                    crate::rootdisk::provisioned_bytes(&templates_dir.join(&template).join(disk));
                resources.disk_mib =
                    u32::try_from(bytes.div_ceil(burrow_common::disk::MIB)).unwrap_or(u32::MAX);
                bytes
            }
            None => {
                let image =
                    tokio::fs::metadata(templates_dir.join(&template).join(TEMPLATE_ROOTFS))
                        .await
                        .map_err(|err| {
                            Status::failed_precondition(format!(
                                "template {template} is not on this node: {err}"
                            ))
                        })?;
                resources.disk_mib = crate::rootdisk::disk_mib(resources.disk_mib, image.len())?;
                u64::from(resources.disk_mib) * burrow_common::disk::MIB
            }
        };
        pin_boot_memory(&mut resources, hypervisor, guest_os)?;
        policy.resources = Some(resources.clone());
        crate::volume::validate_mounts(&policy.volumes)?;
        self.require_volumes(&policy.volumes)?;
        let node_id = old.record().node_id;
        let _disk = self
            .admit_disk(&node_id, "recreate a sandbox", disk_bytes)
            .await?;
        // The old sandbox stays registered, and charged, until the new one
        // takes its place, so only what the new one needs beyond it is held.
        let _cpu = self
            .hold_cpu(charge_of(&resources).saturating_sub(old.cpu_charge_millis()))
            .await?;

        let old_tree = self.config.tree_of(&old.workdir).to_path_buf();
        let workdir = self.config.sandbox_dir(id, hypervisor);
        let tree = self.config.tree_of(&workdir).to_path_buf();
        let next = staged(&tree);
        let staged_workdir = within(&next, &tree, &workdir);
        let made = async {
            // Left by an earlier recreate that could not finish removing
            // them, and nothing this one may take for its own.
            for leftover in [&next, &retired(&old_tree)] {
                if tokio::fs::try_exists(leftover).await.unwrap_or(false) {
                    tokio::fs::remove_dir_all(leftover).await.map_err(|err| {
                        Status::internal(format!("clearing {}: {err}", leftover.display()))
                    })?;
                }
            }
            let template_dir = templates_dir.join(&template);
            if is_macos {
                let root = self.inspection_ca_for(&policy);
                crate::macnode::prepare(&template_dir, &staged_workdir, &root)
                    .await
                    .map_err(|err| {
                        Status::failed_precondition(format!("template {template:?}: {err}"))
                    })?;
                return Ok(());
            }
            prepare_workdir(&template_dir, &staged_workdir, guest_os)
                .await
                .map_err(|err| {
                    Status::failed_precondition(format!("template {template:?}: {err}"))
                })?;
            let disk = staged_workdir.join(crate::rootdisk::ROOT_DISK);
            self.spares
                .take(&templates_dir, &template, &disk)
                .await
                .map_err(|err| Status::internal(format!("making the root disk: {err}")))?;
            crate::rootdisk::grow(&disk, resources.disk_mib)
                .await
                .map(drop)
        }
        .await;
        if let Err(err) = made {
            let _ = tokio::fs::remove_dir_all(&next).await;
            return Err(err);
        }

        let mut sealed = old.base_record.lock().unwrap().clone();
        sealed.state = old.record().state;
        if let Err(err) = seal_secrets(&self.vault, &mut sealed) {
            let _ = tokio::fs::remove_dir_all(&next).await;
            return Err(Status::internal(format!("sealing the record: {err}")));
        }
        let journal = Journal {
            old_tree: old_tree.clone(),
            tree: tree.clone(),
            template: old.template.clone(),
            record: base64::engine::general_purpose::STANDARD
                .encode(prost::Message::encode_to_vec(&sealed)),
        };
        if let Err(err) = journal.write(&self.config.data_dir, id).await {
            let _ = tokio::fs::remove_dir_all(&next).await;
            return Err(Status::internal(format!("journaling the recreate: {err}")));
        }

        let was_running = old.is_running() || old.is_suspended();
        if was_running && let Err(err) = self.halt(&old, true).await {
            let _ = tokio::fs::remove_dir_all(&next).await;
            let _ = Journal::remove(&self.config.data_dir, id).await;
            return Err(err);
        }

        let mut moved = Moved::default();
        let switched = async {
            self.claim_volumes(id, &policy.volumes, guest_os).await?;
            let linked = async {
                let sources = self.volume_sources(id, &mut policy.volumes, false).await?;
                self.finish_workdir(
                    &staged_workdir,
                    hypervisor,
                    false,
                    &policy.volumes,
                    &sources,
                )
                .await?;
                let io = |err: std::io::Error| {
                    Status::internal(format!("moving the new root disk into place: {err}"))
                };
                tokio::fs::rename(&old_tree, retired(&old_tree))
                    .await
                    .map_err(io)?;
                moved.old = true;
                tokio::fs::rename(&next, &tree).await.map_err(io)?;
                moved.new = true;
                Ok(())
            }
            .await;
            if linked.is_err() {
                self.volumes.release_all(id);
            }
            linked
        }
        .await;
        if let Err(err) = switched {
            return Err(self
                .roll_back(&old, None, &tree, moved, was_running, err)
                .await);
        }

        let mut record = old.base_record.lock().unwrap().clone();
        record.template.clone_from(&template);
        record.hypervisor = hypervisor.to_string();
        record.guest_os = guest_os.as_str().to_string();
        record.kernel = kernel;
        record.policy = Some(policy);
        record.state = common::SandboxState::Stopped as i32;
        record.state_reason.clear();
        // A Kit's are set again by its `ready`; a plain template has none.
        record.kit = None;
        record.env.clear();
        record.kit_credentials.clear();
        record.kit_selection.clear();
        let new = Arc::new(RunningSandbox {
            id: id.to_string(),
            template,
            hypervisor,
            base_record: std::sync::Mutex::new(record),
            state: std::sync::atomic::AtomicI32::new(common::SandboxState::Stopped as i32),
            vm: tokio::sync::Mutex::new(None),
            spec: std::sync::Mutex::new(old.spec.lock().unwrap().clone()),
            agent_channel: tokio::sync::Mutex::new(None),
            agent_features: tokio::sync::Mutex::new(None),
            agent_timeout: self.config.agent_timeout(guest_os),
            handshake: settled(),
            memory_chain: tokio::sync::Mutex::new(Vec::new()),
            durable: Default::default(),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            suspended_at: std::sync::atomic::AtomicI64::new(0),
            usage: std::sync::Mutex::new(*old.usage.lock().unwrap()),
            session: std::sync::Mutex::new(None),
            workdir,
            logs: Arc::clone(&old.logs),
            lease: old.lease,
            tap: old.tap.clone(),
        });
        self.sandboxes
            .lock()
            .await
            .insert(id.to_string(), Arc::clone(&new));

        let booted = async {
            self.sync_firewall().await?;
            self.start_now(id, true).await?;
            if !keep.is_empty() {
                let old_disk = within(&retired(&old_tree), &old_tree, &old.workdir)
                    .join(crate::rootdisk::ROOT_DISK);
                crate::keep::carry(&new, &old_disk, &keep).await?;
            }
            ready(Arc::clone(&new)).await
        }
        .await;
        if let Err(err) = booted {
            return Err(self
                .roll_back(&old, Some(&new), &tree, moved, was_running, err)
                .await);
        }

        if !self.holds(&new).await {
            return Err(self.abandon(id, &old_tree, &tree, moved).await);
        }
        self.persist(&new).await;
        if let Err(err) = Journal::remove(&self.config.data_dir, id).await {
            tracing::error!(sandbox = id, %err, "could not remove the recreate's journal");
        }
        if let Err(err) = tokio::fs::remove_dir_all(retired(&old_tree)).await {
            tracing::warn!(sandbox = id, %err, "could not remove the old root disk");
        }
        tracing::info!(sandbox = id, template = new.template(), "sandbox recreated");
        Ok(new.record())
    }

    /// Puts `old` back on its own disk after a recreate that failed with
    /// `err`, taking down `new` if it got as far as existing, and boots `old`
    /// again if it was running.
    #[allow(clippy::too_many_arguments)]
    async fn roll_back(
        &self,
        old: &Arc<RunningSandbox>,
        new: Option<&Arc<RunningSandbox>>,
        tree: &Path,
        moved: Moved,
        was_running: bool,
        err: Status,
    ) -> Status {
        let id = old.id();
        let old_tree = self.config.tree_of(&old.workdir).to_path_buf();
        if let Some(new) = new
            && !self.holds(new).await
        {
            self.abandon(id, &old_tree, tree, moved).await;
            return err;
        }
        if let Some(new) = new {
            let _ = new.shutdown().await;
            self.volumes.release_all(id);
            self.close_session(new, ENDED_FAILED).await;
            self.sandboxes
                .lock()
                .await
                .insert(id.to_string(), Arc::clone(old));
            if let Err(err) = self.sync_firewall().await {
                tracing::error!(sandbox = id, err = err.message(), "restoring the old rules");
            }
        }
        if let Err(io) = restore_dirs(&old_tree, tree, moved).await {
            tracing::error!(sandbox = id, err = %io, "could not put the old root disk back");
            return Status::new(
                err.code(),
                format!(
                    "{}; the old root disk could not be put back ({io}), and is restored when \
                     the node restarts",
                    err.message()
                ),
            );
        }
        self.persist(old).await;
        if let Err(err) = Journal::remove(&self.config.data_dir, id).await {
            tracing::error!(sandbox = id, %err, "could not remove the recreate's journal");
        }
        let restarted = match was_running {
            true => match self.start_now(id, true).await {
                Ok(_) => crate::kit::restart(self, id).await.err(),
                Err(err) => Some(err),
            },
            false => None,
        };
        let message = match restarted {
            None => format!("{}; sandbox {id} is unchanged", err.message()),
            Some(again) => format!(
                "{}; sandbox {id} is back on its old disk but did not boot again: {}",
                err.message(),
                again.message()
            ),
        };
        Status::new(err.code(), message)
    }

    /// Whether `new` is still the sandbox this node holds under its id. Only
    /// a lifecycle call that should have been refused could have changed it.
    async fn holds(&self, new: &Arc<RunningSandbox>) -> bool {
        self.sandboxes
            .lock()
            .await
            .get(new.id())
            .is_some_and(|held| Arc::ptr_eq(held, new))
    }

    /// Lets go of a recreate whose sandbox was taken out from under it: what
    /// it left on disk goes, and nothing is put back or recorded.
    async fn abandon(&self, id: &str, old_tree: &Path, tree: &Path, moved: Moved) -> Status {
        tracing::error!(sandbox = id, "a recreate's sandbox went away under it");
        if moved.old {
            let _ = tokio::fs::remove_dir_all(retired(old_tree)).await;
        }
        let _ = tokio::fs::remove_dir_all(staged(tree)).await;
        let _ = Journal::remove(&self.config.data_dir, id).await;
        Status::aborted(format!(
            "sandbox {id} was removed while it was being recreated"
        ))
    }

    /// Every directory a recreate journal still names or implies, under any
    /// hypervisor: kept out of the orphan sweep while a journal recovery
    /// could not undo is waiting for someone to look at it.
    pub(super) async fn journaled_dirs(&self) -> std::collections::HashSet<PathBuf> {
        let mut dirs = std::collections::HashSet::new();
        let Ok(mut entries) = tokio::fs::read_dir(Journal::dir(&self.config.data_dir)).await else {
            return dirs;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            for hypervisor in burrow_vmm::Hypervisor::ALL {
                let tree = self
                    .config
                    .tree_of(&self.config.sandbox_dir(id, hypervisor))
                    .to_path_buf();
                dirs.insert(staged(&tree));
                dirs.insert(retired(&tree));
                dirs.insert(tree);
            }
        }
        dirs
    }

    /// Undoes recreates a previous run of this node left between the halt and
    /// the commit: the old directory goes back, the replacement goes, and the
    /// store gets the old record back. `rows` is the store as read before.
    pub(super) async fn undo_recreations(
        &self,
        mut rows: Vec<burrow_store::SandboxRow>,
    ) -> Vec<burrow_store::SandboxRow> {
        let dir = Journal::dir(&self.config.data_dir);
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
            return rows;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let Some(id) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".json"))
                .map(str::to_string)
            else {
                let _ = tokio::fs::remove_file(&path).await;
                continue;
            };
            let journal = match tokio::fs::read(&path).await.map(|bytes| {
                serde_json::from_slice::<Journal>(&bytes).map_err(std::io::Error::other)
            }) {
                Ok(Ok(journal)) => journal,
                Ok(Err(err)) | Err(err) => {
                    tracing::error!(sandbox = id, %err, "unreadable recreate journal; leaving it");
                    continue;
                }
            };
            let moved = match Moved::found(&journal.old_tree, &journal.tree).await {
                Ok(moved) => moved,
                Err(err) => {
                    tracing::error!(sandbox = id, %err, "could not read an interrupted recreate");
                    continue;
                }
            };
            // Neither the retired nor the staged directory: the recreate got
            // past its commit, or its rollback did, and only the journal's
            // removal failed. The store already matches the disk.
            if !moved.old
                && !tokio::fs::try_exists(staged(&journal.tree))
                    .await
                    .unwrap_or(true)
            {
                let _ = Journal::remove(&self.config.data_dir, &id).await;
                continue;
            }
            if let Err(err) = restore_dirs(&journal.old_tree, &journal.tree, moved).await {
                tracing::error!(sandbox = id, %err, "could not undo an interrupted recreate");
                continue;
            }
            let Ok(record) = base64::engine::general_purpose::STANDARD.decode(&journal.record)
            else {
                tracing::error!(
                    sandbox = id,
                    "the recreate journal's record does not decode"
                );
                continue;
            };
            if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                row.record = record;
                row.template = journal.template;
                if let Err(err) = self.store.put_sandbox(row).await {
                    tracing::error!(sandbox = id, %err, "could not restore the record");
                    continue;
                }
            }
            let _ = Journal::remove(&self.config.data_dir, &id).await;
            tracing::warn!(
                sandbox = id,
                "undid a recreate the node stopped in the middle of"
            );
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::tests::{recovering, running, under_fake_vmm};
    use burrow_vmm::Hypervisor;

    fn replacement(template: &str) -> Replacement {
        Replacement {
            template: template.to_string(),
            policy: Default::default(),
            keep: Vec::new(),
        }
    }

    async fn template(data_dir: &Path, name: &str, rootfs: Option<&[u8]>) {
        let dir = data_dir.join("images").join(name);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut kernel = vec![0u8; 64];
        kernel[56..60].copy_from_slice(b"ARM\x64");
        kernel.extend_from_slice(b"Linux version 6.1.141 #1\0");
        tokio::fs::write(dir.join(super::super::TEMPLATE_KERNEL), kernel)
            .await
            .unwrap();
        match rootfs {
            Some(bytes) => tokio::fs::write(dir.join(TEMPLATE_ROOTFS), bytes)
                .await
                .unwrap(),
            None => tokio::fs::create_dir_all(dir.join(TEMPLATE_ROOTFS))
                .await
                .unwrap(),
        }
    }

    async fn assert_untouched(manager: &SandboxManager, old: &Arc<RunningSandbox>, disk: &[u8]) {
        let held = manager.get(old.id()).await.unwrap();
        assert!(
            Arc::ptr_eq(&held, old),
            "the old sandbox is still the one held"
        );
        let root = old.workdir.join(crate::rootdisk::ROOT_DISK);
        assert_eq!(tokio::fs::read(&root).await.unwrap(), disk);
        let tree = manager
            .config
            .sandbox_dir(old.id(), Hypervisor::Firecracker);
        assert!(!staged(&tree).exists());
        assert!(!retired(&old.workdir).exists());
        assert!(!Journal::path(&manager.config.data_dir, old.id()).exists());
        assert!(!manager.recreating.lock().unwrap().contains(old.id()));
    }

    /// A plain recreate on a node that has lost the template used to delete
    /// the sandbox and then fail to create its replacement. It is refused
    /// with the running guest untouched.
    #[tokio::test]
    async fn a_recreate_onto_a_template_the_node_lacks_changes_nothing() {
        let (manager, data_dir) = recovering("recreate-absent").await;
        let (old, workdir) = under_fake_vmm(&manager, 0).await;
        tokio::fs::write(workdir.join(crate::rootdisk::ROOT_DISK), b"old")
            .await
            .unwrap();

        let err = manager
            .recreate(old.id(), replacement("absent"), |_| async { Ok(()) })
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message().contains("not on this node"),
            "{}",
            err.message()
        );
        assert!(old.is_running());
        assert!(old.vm.lock().await.is_some());
        assert_untouched(&manager, &old, b"old").await;
        if let Some(vm) = old.vm.lock().await.take() {
            let _ = vm.kill().await;
        }
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A new disk that cannot be made fails the recreate before the old guest
    /// is stopped.
    #[tokio::test]
    async fn a_recreate_whose_disk_cannot_be_made_changes_nothing() {
        let (manager, data_dir) = recovering("recreate-disk").await;
        template(&data_dir, "broken", None).await;
        let (old, workdir) = under_fake_vmm(&manager, 0).await;
        tokio::fs::write(workdir.join(crate::rootdisk::ROOT_DISK), b"old")
            .await
            .unwrap();

        let err = manager
            .recreate(old.id(), replacement("broken"), |_| async { Ok(()) })
            .await
            .unwrap_err();

        assert!(
            err.message().contains("template \"broken\""),
            "{}",
            err.message()
        );
        assert!(old.is_running());
        assert!(old.vm.lock().await.is_some());
        assert_untouched(&manager, &old, b"old").await;
        if let Some(vm) = old.vm.lock().await.take() {
            let _ = vm.kill().await;
        }
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A path a recreate cannot keep is refused before anything is made.
    #[tokio::test]
    async fn a_path_that_cannot_be_kept_changes_nothing() {
        let (manager, data_dir) = recovering("recreate-keep").await;
        template(&data_dir, "fresh", Some(b"new")).await;
        let (old, workdir) = under_fake_vmm(&manager, 0).await;
        tokio::fs::write(workdir.join(crate::rootdisk::ROOT_DISK), b"old")
            .await
            .unwrap();
        let mut keeping = replacement("fresh");
        keeping.keep = vec!["/proc/self".into()];

        let err = manager
            .recreate(old.id(), keeping, |_| async { Ok(()) })
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(old.is_running());
        assert_untouched(&manager, &old, b"old").await;
        if let Some(vm) = old.vm.lock().await.take() {
            let _ = vm.kill().await;
        }
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A replacement that is made but does not boot puts the old disk back,
    /// and the record the store holds is the old one. A retired directory an
    /// earlier recreate left behind is cleared first rather than mistaken
    /// for this one's.
    #[tokio::test]
    async fn a_recreate_whose_guest_does_not_boot_puts_the_old_disk_back() {
        let (manager, data_dir) = recovering("recreate-boot").await;
        template(&data_dir, "fresh", Some(b"new")).await;
        let old = running("sbx_recreate_boot");
        old.set_state(common::SandboxState::Stopped);
        old.base_record.lock().unwrap().template = "default".into();
        tokio::fs::create_dir_all(&old.workdir).await.unwrap();
        tokio::fs::write(old.workdir.join(crate::rootdisk::ROOT_DISK), b"old")
            .await
            .unwrap();
        let stale = retired(&old.workdir);
        tokio::fs::create_dir_all(&stale).await.unwrap();
        tokio::fs::write(stale.join(crate::rootdisk::ROOT_DISK), b"stale")
            .await
            .unwrap();
        manager
            .sandboxes
            .lock()
            .await
            .insert(old.id().to_string(), Arc::clone(&old));

        manager
            .recreate(old.id(), replacement("fresh"), |_| async { Ok(()) })
            .await
            .unwrap_err();

        assert_eq!(old.record().state, common::SandboxState::Stopped as i32);
        assert_untouched(&manager, &old, b"old").await;
        assert!(
            !manager
                .config
                .sandbox_dir(old.id(), Hypervisor::Firecracker)
                .exists()
        );
        let rows = manager.store.list_sandboxes().await.unwrap();
        assert_eq!(rows[0].template, "default");
        let _ = tokio::fs::remove_dir_all(&old.workdir).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A running guest is halted only once the replacement exists; when that
    /// does not boot, the old one is put back and booted again.
    #[tokio::test]
    async fn a_running_sandbox_whose_replacement_does_not_boot_is_booted_again() {
        let (manager, data_dir) = recovering("recreate-rerun").await;
        template(&data_dir, "fresh", Some(b"new")).await;
        let (old, workdir) = under_fake_vmm(&manager, 0).await;
        tokio::fs::write(workdir.join(crate::rootdisk::ROOT_DISK), b"old")
            .await
            .unwrap();

        let err = manager
            .recreate(old.id(), replacement("fresh"), |_| async { Ok(()) })
            .await
            .unwrap_err();

        // The node's own firecracker does not exist here, so the old guest
        // cannot come back either, and the caller is told so.
        assert!(
            err.message().contains("did not boot again"),
            "{}",
            err.message()
        );
        assert_untouched(&manager, &old, b"old").await;
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// Nothing else may change a sandbox while it is recreated: a delete
    /// would tear down the new instance's tap and lease, and the recreate
    /// would then put the old one back on an address no longer its own.
    #[tokio::test]
    async fn lifecycle_calls_wait_for_a_recreate() {
        let manager = crate::sandbox::tests::manager().await;
        let sandbox = running("sbx_recreate_busy");
        let id = sandbox.id().to_string();
        manager
            .sandboxes
            .lock()
            .await
            .insert(id.clone(), Arc::clone(&sandbox));
        manager.recreating.lock().unwrap().insert(id.clone());

        let refused = [
            manager.delete(&id).await.err(),
            manager.stop(&id).await.err(),
            manager.start(&id, false).await.err(),
            manager.pause(&id).await.err(),
            manager.resume(&id).await.err(),
            manager.release(&id).await.err(),
        ];
        for err in refused {
            let err = err.expect("refused");
            assert_eq!(err.code(), tonic::Code::Aborted);
            assert!(
                err.message().contains("being recreated"),
                "{}",
                err.message()
            );
        }
        let again = manager
            .recreate(&id, replacement("fresh"), |_| async { Ok(()) })
            .await
            .unwrap_err();
        assert_eq!(again.code(), tonic::Code::Aborted);
        assert!(manager.get(&id).await.is_ok());
    }

    /// A recreate whose sandbox was removed under it anyway does not put the
    /// old one back or record it: it removes what it left and says so.
    #[tokio::test]
    async fn a_recreate_whose_sandbox_was_removed_lets_go() {
        let (manager, data_dir) = recovering("recreate-gone").await;
        let old = running("sbx_recreate_gone");
        let new = running("sbx_recreate_gone");
        let old_tree = old.workdir.clone();
        std::fs::create_dir_all(retired(&old_tree)).unwrap();
        Journal {
            old_tree: old_tree.clone(),
            tree: old_tree.clone(),
            template: "default".into(),
            record: String::new(),
        }
        .write(&data_dir, old.id())
        .await
        .unwrap();
        let moved = Moved {
            old: true,
            new: true,
        };

        let err = manager
            .roll_back(
                &old,
                Some(&new),
                &old_tree,
                moved,
                true,
                Status::internal("keep failed"),
            )
            .await;

        assert_eq!(err.message(), "keep failed");
        assert!(
            manager.get(old.id()).await.is_err(),
            "the old sandbox is not put back"
        );
        assert!(manager.store.list_sandboxes().await.unwrap().is_empty());
        assert!(!retired(&old_tree).exists());
        assert!(!Journal::path(&data_dir, old.id()).exists());
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A journal whose recreate got past its commit, or its rollback, before
    /// the node died leaves neither directory behind; the store already
    /// matches the disk, so the journal goes and nothing is restored.
    #[tokio::test]
    async fn a_journal_outliving_its_recreate_is_dropped() {
        let (manager, data_dir) = recovering("recreate-done").await;
        let id = "sbx_recreate_done";
        let tree = manager.config.sandbox_dir(id, Hypervisor::Firecracker);
        std::fs::create_dir_all(&tree).unwrap();
        Journal {
            old_tree: tree.clone(),
            tree: tree.clone(),
            template: "before".into(),
            record: String::new(),
        }
        .write(&data_dir, id)
        .await
        .unwrap();
        assert!(manager.journaled_dirs().await.contains(&retired(&tree)));
        let mut row = crate::sandbox::tests::row(id, common::SandboxState::Stopped, 1);
        row.template = "after".into();
        manager.store.put_sandbox(&row).await.unwrap();

        let rows = manager
            .undo_recreations(manager.store.list_sandboxes().await.unwrap())
            .await;

        assert_eq!(rows[0].template, "after");
        assert!(tree.exists());
        assert!(!Journal::path(&data_dir, id).exists());
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A node that died between the halt and the commit comes back to the
    /// old sandbox: its directory back in place, the replacement gone, and
    /// the store holding the old record.
    #[tokio::test]
    async fn a_recreate_the_node_died_in_is_undone_on_recovery() {
        let (manager, data_dir) = recovering("recreate-undo").await;
        let id = "sbx_recreate_undo";
        let tree = manager.config.sandbox_dir(id, Hypervisor::Firecracker);
        std::fs::create_dir_all(retired(&tree)).unwrap();
        std::fs::write(retired(&tree).join(crate::rootdisk::ROOT_DISK), b"old").unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join(crate::rootdisk::ROOT_DISK), b"new").unwrap();
        let old = common::Sandbox {
            id: id.into(),
            template: "before".into(),
            ..Default::default()
        };
        Journal {
            old_tree: tree.clone(),
            tree: tree.clone(),
            template: "before".into(),
            record: base64::engine::general_purpose::STANDARD
                .encode(prost::Message::encode_to_vec(&old)),
        }
        .write(&data_dir, id)
        .await
        .unwrap();
        let mut row = crate::sandbox::tests::row(id, common::SandboxState::Running, 1);
        row.template = "after".into();
        manager.store.put_sandbox(&row).await.unwrap();

        let rows = manager
            .undo_recreations(manager.store.list_sandboxes().await.unwrap())
            .await;

        assert_eq!(rows[0].template, "before");
        let stored = manager.store.list_sandboxes().await.unwrap();
        assert_eq!(stored[0].template, "before");
        let record: common::Sandbox = prost::Message::decode(&stored[0].record[..]).unwrap();
        assert_eq!(record.template, "before");
        assert_eq!(
            std::fs::read(tree.join(crate::rootdisk::ROOT_DISK)).unwrap(),
            b"old"
        );
        assert!(!retired(&tree).exists());
        assert!(!Journal::path(&data_dir, id).exists());
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }
}
