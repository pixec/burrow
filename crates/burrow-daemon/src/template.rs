//! Building guest images.
//!
//! A template is built by running the requested steps inside a throwaway
//! sandbox and then capturing the filesystem it ended up with. The guest
//! already presents a merged view of the read-only base plus its own writable
//! overlay, so the capture is a tar of `/` taken from inside, with no loop
//! mounts and no reaching into overlay internals from the host.
//!
//! The tar is unpacked on the node and turned into a fresh ext4 with
//! `mkfs.ext4 -d`, which populates an image from a directory without mounting
//! it. The build sandbox is destroyed either way.

#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;
use tonic::Status;

use burrow_proto::api::v1 as api;
use burrow_proto::common::v1 as common;

use crate::sandbox::SandboxManager;

/// Written inside the guest, then excluded from its own tar.
const EXPORT_PATH: &str = "/.burrow-export.tar";

/// Top-level entries kept out of a built image: kernel-populated
/// pseudo-filesystems, per-boot scratch space, and the archive itself.
/// `/scratch` in particular holds the overlay's own upper and work
/// directories, so including it would nest a copy of the filesystem inside
/// itself.
///
/// Applied as an include-list at capture time rather than passed to
/// `tar --exclude`: busybox is frequently built without exclude support, and
/// deciding what goes *in* fails safe if a future image grows a mount point
/// nobody remembered to exclude.
const SKIP_TOPLEVEL: [&str; 7] = [
    "proc",
    "sys",
    "dev",
    "run",
    "tmp",
    "scratch",
    ".burrow-export.tar",
];

/// Ceiling on the archive a build sandbox may stream back to the node.
///
/// The guest chooses how many bytes it sends, and nothing else stops it: a
/// build step that writes forever fills the node's data directory and takes
/// every other sandbox on the host down with it. Eight gibibytes is far above
/// any real image and far below a disk.
const MAX_EXPORT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Slack added to the measured content size when sizing the new image, so the
/// filesystem has room for metadata and for whatever the sandbox writes later.
const IMAGE_SLACK_MIB: u64 = 256;

type LogTx = mpsc::Sender<Result<api::BuildLog, Status>>;

fn event(event: api::build_log::Event) -> Result<api::BuildLog, Status> {
    Ok(api::BuildLog { event: Some(event) })
}

pub fn templates_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("images")
}

/// The kernel this node boots guests with, set once from `--guest-kernel`.
///
/// Held here rather than threaded through every build because it is decided at
/// startup and never changes, and the alternative is an extra parameter on
/// five functions that care about nothing else.
static GUEST_KERNEL: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub fn set_guest_kernel(path: PathBuf) {
    let _ = GUEST_KERNEL.set(path);
}

/// Gives a freshly built template its own kernel.
///
/// An OCI image carries a userland and no kernel, so the node supplies one.
/// Hard-linked rather than copied: it is the same bytes for every template,
/// and a sandbox hard-links both artifacts out of one directory.
async fn link_kernel(data_dir: &Path, target: &Path) -> Result<(), Status> {
    let kernel = target.join("vmlinux");
    if tokio::fs::try_exists(&kernel).await.unwrap_or(false) {
        return Ok(());
    }
    let configured = GUEST_KERNEL.get().cloned();
    // The `default` template is the fallback for nodes set up before there was
    // a flag for this, where the kernel arrived as part of that template.
    let legacy = templates_dir(data_dir).join("default").join("vmlinux");
    let mut candidates = Vec::new();
    candidates.extend(configured);
    candidates.push(legacy);

    for source in &candidates {
        if !tokio::fs::try_exists(source).await.unwrap_or(false) {
            continue;
        }
        // Across filesystems a link is refused, and a copy is still correct.
        if tokio::fs::hard_link(source, &kernel).await.is_ok()
            || tokio::fs::copy(source, &kernel).await.is_ok()
        {
            return Ok(());
        }
    }
    Err(Status::failed_precondition(format!(
        "no guest kernel on this node: looked in {}. Point --guest-kernel at a \
         vmlinux, or put one at <data-dir>/vmlinux",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

pub async fn list(data_dir: &Path) -> Vec<api::TemplateInfo> {
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(templates_dir(data_dir)).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rootfs = entry.path().join("rootfs.ext4");
        let Ok(meta) = tokio::fs::metadata(&rootfs).await else {
            // A directory without a rootfs is not a usable template.
            continue;
        };
        let warm = crate::warm::is_warm(&templates_dir(data_dir), &name).await;
        out.push(api::TemplateInfo {
            name,
            size_bytes: meta.len(),
            warm,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub async fn delete(data_dir: &Path, name: &str) -> Result<(), Status> {
    validate_name(name)?;
    let dir = templates_dir(data_dir).join(name);
    // Held across the removal: a warm build of this template that is already
    // running publishes its snapshot under the lock, and would otherwise
    // recreate the directory this call just deleted. One queued behind the
    // delete finds no rootfs and stops.
    let _no_builds = crate::warm::hold_builds().await;
    if !tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        return Err(Status::not_found(format!("no template {name}")));
    }
    tokio::fs::remove_dir_all(&dir)
        .await
        .map_err(|err| Status::internal(format!("removing template: {err}")))?;
    Ok(())
}

/// Template names become directory names, so they must not be able to escape
/// the images directory or collide with path syntax.
pub(crate) fn validate_name(name: &str) -> Result<(), Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("template name is required"));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.');
    if !ok {
        return Err(Status::invalid_argument(
            "template name may contain only letters, digits, '-', '_', '.' and may not start with '.'",
        ));
    }
    Ok(())
}

/// Runs a build and streams its logs.
///
/// Spawned as a task by the caller; every exit path removes the build sandbox,
/// including failures, so a broken build leaves nothing running.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    manager: SandboxManager,
    data_dir: PathBuf,
    node_id: String,
    request: api::BuildTemplateRequest,
    agent_binary: PathBuf,
    credentials: crate::oci::auth::Store,
    insecure: Vec<String>,
    tx: LogTx,
) {
    let result = run_build(
        &manager,
        &data_dir,
        &node_id,
        &request,
        &agent_binary,
        &credentials,
        &insecure,
        &tx,
    )
    .await;
    if let Err(status) = result {
        let _ = tx.send(Err(status)).await;
        return;
    }
    // Any snapshot here was captured on the rootfs this build just replaced.
    manager.invalidate_warm(&request.name).await;
    // Whoever just built a template is about to create from it, and a template
    // with no snapshot cold-boots.
    manager.warm_in_background(request.name.clone(), Default::default());
}

#[allow(clippy::too_many_arguments)]
async fn run_build(
    manager: &SandboxManager,
    data_dir: &Path,
    node_id: &str,
    request: &api::BuildTemplateRequest,
    agent_binary: &Path,
    credentials: &crate::oci::auth::Store,
    insecure: &[String],
    tx: &LogTx,
) -> Result<(), Status> {
    validate_name(&request.name)?;

    // An OCI base has to be converted into a template before anything can be
    // run in it. With no steps that is the whole build; with steps, the
    // converted image becomes the base they run on.
    let from_owned;
    let from = if !request.from_image.is_empty() {
        let base = if request.steps.is_empty() {
            request.name.clone()
        } else {
            // A scratch name, so a failed build cannot publish a half-finished
            // template under the name the caller asked for.
            format!("{}-base", request.name)
        };
        from_image::import(
            data_dir,
            &base,
            &request.from_image,
            agent_binary,
            credentials,
            insecure,
            tx,
        )
        .await?;
        if request.steps.is_empty() {
            return Ok(());
        }
        from_owned = base;
        &from_owned
    } else if request.from.is_empty() {
        "default"
    } else {
        &request.from
    };
    if !tokio::fs::try_exists(templates_dir(data_dir).join(from).join("rootfs.ext4"))
        .await
        .unwrap_or(false)
    {
        return Err(Status::not_found(format!("no base template {from}")));
    }

    // Builds fetch packages, so they need egress. An explicit domain list
    // narrows that; an empty one means the caller accepts unrestricted access
    // for the duration of the build.
    let network = if request.allow_domains.is_empty() {
        common::NetworkPolicy {
            mode: common::NetworkMode::Open as i32,
            ..Default::default()
        }
    } else {
        common::NetworkPolicy {
            mode: common::NetworkMode::Allowlist as i32,
            allow_domains: request.allow_domains.clone(),
            ..Default::default()
        }
    };

    // The base's rootfs digest is half the layer key: the same steps on a
    // different base produce a different image.
    let base_rootfs =
        crate::blobs::hash_file(&templates_dir(data_dir).join(from).join("rootfs.ext4"))
            .await
            .map_err(|err| Status::internal(format!("hashing base template: {err}")))?;
    let commands: Vec<String> = request
        .steps
        .iter()
        .map(|step| step.run.trim().to_string())
        .filter(|run| !run.is_empty())
        .collect();
    let (cached_steps, seed) = layers::resume_point(data_dir, &base_rootfs, &commands).await;
    if cached_steps > 0 {
        let _ = tx
            .send(event(api::build_log::Event::Step(format!(
                "reusing {cached_steps} cached step(s)"
            ))))
            .await;
        tracing::info!(
            template = request.name,
            cached_steps,
            total = commands.len(),
            "resuming a build from cached layers"
        );
    }

    let build_id = format!("bld_{}", burrow_core::SandboxId::generate());
    let policy = common::Policy {
        resources: Some(common::ResourcePolicy {
            vcpus: request.vcpus.max(1),
            mem_mib: if request.mem_mib == 0 {
                1024
            } else {
                request.mem_mib
            },
            ..Default::default()
        }),
        network: Some(network),
        ..Default::default()
    };

    manager
        .create_seeded(
            build_id.clone(),
            from.to_string(),
            policy,
            Default::default(),
            node_id.to_string(),
            seed.as_deref(),
            // A build sandbox is internal and short-lived; naming it would
            // spend a name from a namespace the caller owns.
            String::new(),
        )
        .await?;

    // From here on the sandbox exists and must be cleaned up on every path.
    let outcome = build_in_sandbox(
        manager,
        data_dir,
        &build_id,
        request,
        tx,
        &base_rootfs,
        &commands,
        cached_steps,
    )
    .await;
    if let Err(err) = manager.delete(&build_id).await {
        tracing::warn!(build = build_id, %err, "could not remove build sandbox");
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn build_in_sandbox(
    manager: &SandboxManager,
    data_dir: &Path,
    build_id: &str,
    request: &api::BuildTemplateRequest,
    tx: &LogTx,
    base_rootfs: &crate::blobs::Digest,
    commands: &[String],
    cached_steps: usize,
) -> Result<(), Status> {
    for (index, run) in commands.iter().enumerate() {
        // Steps the cache already covers are represented by the seeded scratch
        // disk; re-running them would produce the same filesystem more slowly.
        if index < cached_steps {
            continue;
        }
        let _ = tx
            .send(event(api::build_log::Event::Step(run.clone())))
            .await;

        let exit = exec_streaming(manager, build_id, run, tx).await?;
        if exit != 0 {
            return Err(Status::failed_precondition(format!(
                "build step failed with exit {exit}: {run}"
            )));
        }

        if let Err(err) = cache_layer(
            manager,
            data_dir,
            build_id,
            tx,
            base_rootfs,
            &commands[..=index],
        )
        .await
        {
            // A build that succeeded must not fail because caching did; the
            // cost is a slower rebuild, not a wrong image.
            tracing::warn!(build = build_id, %err, "could not cache a build layer");
        }
    }

    let _ = tx
        .send(event(api::build_log::Event::Step(
            "exporting filesystem".into(),
        )))
        .await;

    // Capture from inside the guest, where the overlay is already merged.
    // Written as POSIX sh so it does not depend on which busybox applets the
    // base image happens to have been built with.
    let skip = SKIP_TOPLEVEL.join("|");
    let tar_cmd = format!(
        r#"cd / && set -e && include="" && for entry in $(ls -A /); do
             case "$entry" in
               {skip}) ;;
               *) include="$include $entry" ;;
             esac
           done && tar -cf {EXPORT_PATH} $include"#
    );
    let exit = exec_streaming(manager, build_id, &tar_cmd, tx).await?;
    if exit != 0 {
        return Err(Status::internal(format!(
            "could not archive the build filesystem (tar exited {exit})"
        )));
    }

    let staging = data_dir.join("build").join(build_id);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|err| Status::internal(format!("staging dir: {err}")))?;

    let tar_path = staging.join("rootfs.tar");
    let bytes = download_to(manager, build_id, EXPORT_PATH, &tar_path).await?;
    tracing::info!(build = build_id, bytes, "captured build filesystem");

    let result = assemble_image(data_dir, &staging, &tar_path, &request.name, bytes).await;
    let _ = tokio::fs::remove_dir_all(&staging).await;
    let size_bytes = result?;

    let _ = tx
        .send(event(api::build_log::Event::Done(api::BuildDone {
            template: request.name.clone(),
            size_bytes,
        })))
        .await;
    Ok(())
}

/// Unpacks the captured tar and turns it into a bootable image.
async fn assemble_image(
    data_dir: &Path,
    staging: &Path,
    tar_path: &Path,
    name: &str,
    tar_bytes: u64,
) -> Result<u64, Status> {
    let rootdir = staging.join("root");
    tokio::fs::create_dir_all(&rootdir)
        .await
        .map_err(|err| Status::internal(format!("staging root: {err}")))?;

    // This tar comes out of the build sandbox, produced by whatever tar the
    // (possibly hostile) base image shipped: arbitrary bytes, extracted as
    // root. A symlink member followed by an entry under it (`x -> /etc`, then
    // `x/passwd`) is a root write to the host under any extractor that
    // follows links, so it goes through the same in-process unpacker the OCI
    // layer path already trusts for equally hostile bytes, entry-count and
    // expansion budgets included.
    let unpack_into = rootdir.clone();
    let archive = tar_path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::oci::unpack_layers(&[archive], &unpack_into))
        .await
        .map_err(|err| Status::internal(format!("unpack did not run: {err}")))?
        .map_err(|err| Status::internal(format!("unpacking build filesystem: {err}")))?;

    // Pseudo-filesystem mount points are excluded from the tar but must exist
    // in the image: the agent cannot create them on a read-only root.
    for dir in ["proc", "sys", "dev", "tmp", "run", "scratch"] {
        let _ = tokio::fs::create_dir_all(rootdir.join(dir)).await;
    }

    // Bounded by MAX_EXPORT_BYTES: without that cap a guest could pick the
    // size of the filesystem the node then builds for it.
    let size_mib = (tar_bytes / (1024 * 1024)) * 2 + IMAGE_SLACK_MIB;
    let target = templates_dir(data_dir).join(name);
    tokio::fs::create_dir_all(&target)
        .await
        .map_err(|err| Status::internal(format!("template dir: {err}")))?;

    // Built beside the destination and renamed, so a failed build never
    // leaves a half-written image where a usable one is expected.
    let pending = target.join("rootfs.ext4.building");
    let _ = tokio::fs::remove_file(&pending).await;
    run(
        "mkfs.ext4",
        &[
            "-q",
            "-F",
            "-L",
            "burrow-root",
            "-b",
            "4096",
            "-d",
            &path(&rootdir),
            &path(&pending),
            &format!("{size_mib}M"),
        ],
    )
    .await?;

    link_kernel(data_dir, &target).await?;

    let final_path = target.join("rootfs.ext4");
    tokio::fs::rename(&pending, &final_path)
        .await
        .map_err(|err| Status::internal(format!("publishing image: {err}")))?;

    let size = tokio::fs::metadata(&final_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(size)
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

pub async fn run(program: &str, args: &[&str]) -> Result<(), Status> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|err| Status::internal(format!("{program}: {err}")))?;
    if !output.status.success() {
        return Err(Status::internal(format!(
            "{program} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Runs one command in the build sandbox, forwarding its output to the caller.
async fn exec_streaming(
    manager: &SandboxManager,
    sandbox_id: &str,
    command: &str,
    tx: &LogTx,
) -> Result<i32, Status> {
    use burrow_proto::agent::v1 as agentpb;
    use tokio_stream::StreamExt;

    let sandbox = manager.get(sandbox_id).await?;
    let mut agent = sandbox.agent().await?;

    let start = agentpb::ExecInput {
        input: Some(agentpb::exec_input::Input::Start(agentpb::ExecStart {
            cmd: vec!["/bin/sh".into(), "-c".into(), command.to_string()],
            env: Default::default(),
            cwd: String::new(),
            pty: false,
            rows: 0,
            cols: 0,
            // The node's own housekeeping, which is root's.
            user: String::new(),
        })),
    };

    let mut stream = agent
        .exec(tokio_stream::iter(vec![start]))
        .await?
        .into_inner();

    let mut exit = 0;
    while let Some(msg) = stream.next().await {
        match msg?.output {
            Some(agentpb::exec_output::Output::Stdout(b)) => {
                let _ = tx.send(event(api::build_log::Event::Stdout(b))).await;
            }
            Some(agentpb::exec_output::Output::Stderr(b)) => {
                let _ = tx.send(event(api::build_log::Event::Stderr(b))).await;
            }
            Some(agentpb::exec_output::Output::ExitCode(code)) => exit = code,
            // A build step is watched to completion here; there is nothing to
            // come back to it for.
            Some(agentpb::exec_output::Output::CommandId(_)) | None => {}
        }
    }
    Ok(exit)
}

/// Streams a file out of the build sandbox onto the node's disk.
async fn download_to(
    manager: &SandboxManager,
    sandbox_id: &str,
    guest_path: &str,
    dest: &Path,
) -> Result<u64, Status> {
    use burrow_proto::agent::v1 as agentpb;
    use tokio::io::AsyncWriteExt;
    use tokio_stream::StreamExt;

    let sandbox = manager.get(sandbox_id).await?;
    let mut agent = sandbox.agent().await?;

    let mut stream = agent
        .download_file(agentpb::DownloadRequest {
            path: guest_path.to_string(),
        })
        .await?
        .into_inner();

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|err| Status::internal(format!("creating {}: {err}", dest.display())))?;

    let mut total = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        total += chunk.data.len() as u64;
        // Checked before the write, and the partial file removed: the guest
        // decides how much it sends, so an unbounded stream is a way to fill
        // the node's disk from inside a sandbox.
        if total > MAX_EXPORT_BYTES {
            drop(file);
            let _ = tokio::fs::remove_file(dest).await;
            return Err(Status::resource_exhausted(format!(
                "exported filesystem exceeds {MAX_EXPORT_BYTES} bytes"
            )));
        }
        file.write_all(&chunk.data)
            .await
            .map_err(|err| Status::internal(format!("writing archive: {err}")))?;
    }
    file.flush()
        .await
        .map_err(|err| Status::internal(format!("flushing archive: {err}")))?;
    Ok(total)
}

/// Template distribution: naming a template's artifacts by content, serving
/// them to peers, and pulling them from one.
///
/// A template built on one node cannot run anywhere else, so without this a
/// fleet whose only copy of an image sits on a busy node has nowhere to put
/// work.
pub mod distribute {
    use std::path::Path;

    use tonic::Status;

    use crate::blobs::{BlobStore, Digest};
    use burrow_proto::node::v1 as nodepb;

    /// Artifacts that travel as blobs. The warm snapshot does not: it is tied
    /// to the host that took it, so a receiving node warms the template
    /// itself.
    ///
    /// `image.json` is not here either, but for the opposite reason: it is
    /// small enough to travel inside the manifest, and it must travel. See
    /// [`IMAGE_CONFIG`].
    const ARTIFACTS: [&str; 2] = ["vmlinux", "rootfs.ext4"];

    /// The environment an imported image declared, as written by the importer.
    ///
    /// Metadata rather than an artifact, but a template that arrives without it
    /// is not the same template: the receiving node runs its sandboxes with no
    /// `PATH` and no `WORKDIR`. The trust bundles an image names live here too,
    /// so without it the inspection CA reaches the system store only, leaving
    /// an image like `curlimages/curl` (which reads `$CURL_CA_BUNDLE`, not
    /// `/etc/ssl/certs`) unable to verify anything.
    const IMAGE_CONFIG: &str = "image.json";

    /// Describes a local template by content, storing its artifacts as blobs
    /// on the way so a later fetch has something to serve.
    pub async fn manifest(data_dir: &Path, name: &str) -> Result<nodepb::TemplateManifest, Status> {
        let dir = super::templates_dir(data_dir).join(name);
        if !tokio::fs::try_exists(dir.join("rootfs.ext4"))
            .await
            .unwrap_or(false)
        {
            return Err(Status::not_found(format!("no template {name}")));
        }
        let store = BlobStore::new(data_dir);

        let mut digests = Vec::new();
        for artifact in ARTIFACTS {
            let path = dir.join(artifact);
            let digest = store
                .insert(&path)
                .await
                .map_err(|err| Status::internal(format!("hashing {artifact} of {name}: {err}")))?;
            digests.push(digest);
        }
        let rootfs_bytes = tokio::fs::metadata(dir.join("rootfs.ext4"))
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        // Absent for templates built the old way, which is not an error: the
        // receiving node then has exactly what this one has.
        let image_config = tokio::fs::read_to_string(dir.join(IMAGE_CONFIG))
            .await
            .unwrap_or_default();

        Ok(nodepb::TemplateManifest {
            name: name.to_string(),
            kernel_digest: digests[0].to_string(),
            rootfs_digest: digests[1].to_string(),
            rootfs_bytes,
            image_config,
        })
    }

    /// Writes the image config that came with a manifest beside the template.
    ///
    /// A manifest carrying none leaves nothing behind, and clears a stale one:
    /// after a pull the template is the source's, and a leftover config
    /// describing the image that used to have this name would be applied to
    /// the one that now does.
    async fn install_image_config(dir: &Path, config: &str) -> Result<(), Status> {
        let path = dir.join(IMAGE_CONFIG);
        if config.is_empty() {
            let _ = tokio::fs::remove_file(&path).await;
            return Ok(());
        }
        tokio::fs::write(&path, config)
            .await
            .map_err(|err| Status::internal(format!("installing {IMAGE_CONFIG}: {err}")))
    }

    /// Opens a stored blob for streaming to a peer.
    pub async fn open_blob(data_dir: &Path, digest: &str) -> Result<tokio::fs::File, Status> {
        // Parsed, not trusted: the digest names a path, and an unchecked one
        // would let a peer ask for any file on this node.
        let digest = Digest::parse(digest)
            .ok_or_else(|| Status::invalid_argument("not a sha-256 digest"))?;
        let store = BlobStore::new(data_dir);
        tokio::fs::File::open(store.path(&digest))
            .await
            .map_err(|_| Status::not_found(format!("no blob {digest}")))
    }

    /// Fetches whatever this node is missing and installs the template.
    ///
    /// Returns `(bytes_transferred, blobs_reused)`. A node that already has an
    /// artifact, say a shared kernel or a retried pull, transfers nothing for
    /// it, which is the whole reason artifacts are named by content.
    pub async fn pull(
        data_dir: &Path,
        source_address: &str,
        manifest: &nodepb::TemplateManifest,
        token: Option<&str>,
    ) -> Result<(u64, u32), Status> {
        // A compromised peer controls this manifest verbatim (it travels
        // from the source node through the orchestrator unmodified), and a
        // name like `..` would have `materialise` write `vmlinux` and
        // `rootfs.ext4` into `data_dir` itself, so it gets the same
        // validation `build` and `delete` already require of a template name.
        super::validate_name(&manifest.name)?;
        let store = BlobStore::new(data_dir);
        let wanted = [
            ("vmlinux", &manifest.kernel_digest),
            ("rootfs.ext4", &manifest.rootfs_digest),
        ];

        let mut transferred = 0;
        let mut reused = 0;
        let mut client = None;

        for (artifact, digest) in wanted {
            let digest = Digest::parse(digest).ok_or_else(|| {
                Status::invalid_argument(format!("{artifact}: not a sha-256 digest"))
            })?;
            if store.has(&digest).await {
                reused += 1;
                continue;
            }
            // Connected lazily: a pull where everything is already present
            // should not need the peer at all.
            if client.is_none() {
                client = Some(connect(source_address, token).await?);
            }
            transferred += fetch_blob(client.as_mut().expect("connected"), &store, &digest).await?;
        }

        // Only once every artifact is present and verified is the template
        // assembled, so a failed pull never leaves a half-built image that
        // placement would treat as runnable.
        let dir = super::templates_dir(data_dir).join(&manifest.name);
        for (artifact, digest) in wanted {
            let digest = Digest::parse(digest).expect("validated above");
            store
                .materialise(&digest, &dir.join(artifact))
                .await
                .map_err(|err| Status::internal(format!("installing {artifact}: {err}")))?;
        }
        // Last, like the artifacts: a template is only assembled once every
        // part of it is present.
        install_image_config(&dir, &manifest.image_config).await?;

        tracing::info!(
            template = manifest.name,
            source = source_address,
            transferred,
            reused,
            "template pulled from peer"
        );
        Ok((transferred, reused))
    }

    /// Presents the cluster token when dialling a peer node.
    #[derive(Clone)]
    pub struct PeerAuth(Option<String>);

    impl tonic::service::Interceptor for PeerAuth {
        fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
            if let Some(token) = &self.0 {
                let value = format!("Bearer {token}")
                    .parse()
                    .map_err(|_| Status::internal("malformed node token"))?;
                req.metadata_mut().insert("authorization", value);
            }
            Ok(req)
        }
    }

    type PeerClient = nodepb::node_service_client::NodeServiceClient<
        tonic::service::interceptor::InterceptedService<tonic::transport::Channel, PeerAuth>,
    >;

    async fn connect(address: &str, token: Option<&str>) -> Result<PeerClient, Status> {
        let endpoint = if address.starts_with("http") {
            address.to_string()
        } else {
            format!("http://{address}")
        };
        let channel = tonic::transport::Endpoint::try_from(endpoint)
            .map_err(|err| Status::invalid_argument(format!("source address: {err}")))?
            .connect()
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach {address}: {err}")))?;

        Ok(
            nodepb::node_service_client::NodeServiceClient::with_interceptor(
                channel,
                PeerAuth(token.map(str::to_string)),
            ),
        )
    }

    async fn fetch_blob(
        client: &mut PeerClient,
        store: &BlobStore,
        digest: &Digest,
    ) -> Result<u64, Status> {
        let mut stream = client
            .fetch_blob(nodepb::BlobRequest {
                digest: digest.to_string(),
            })
            .await?
            .into_inner();

        let mut writer = store
            .receive(digest.clone())
            .await
            .map_err(|err| Status::internal(format!("staging blob: {err}")))?;
        let mut bytes = 0u64;
        while let Some(chunk) = stream.message().await? {
            bytes += chunk.data.len() as u64;
            writer
                .write(&chunk.data)
                .await
                .map_err(|err| Status::internal(format!("writing blob: {err}")))?;
        }
        // Rejects a peer that served the wrong bytes rather than installing
        // them as the image everyone runs.
        writer
            .finish()
            .await
            .map_err(|err| Status::data_loss(err.to_string()))?;
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const CONFIG: &str =
            r#"{"env":["PATH=/usr/bin","CURL_CA_BUNDLE=/cacert.pem"],"working_dir":"/app"}"#;

        async fn template(data_dir: &Path, name: &str, config: Option<&str>) {
            let dir = super::super::templates_dir(data_dir).join(name);
            tokio::fs::create_dir_all(&dir).await.unwrap();
            tokio::fs::write(dir.join("vmlinux"), b"kernel")
                .await
                .unwrap();
            tokio::fs::write(dir.join("rootfs.ext4"), b"rootfs")
                .await
                .unwrap();
            if let Some(config) = config {
                tokio::fs::write(dir.join(IMAGE_CONFIG), config)
                    .await
                    .unwrap();
            }
        }

        fn scratch(name: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("burrow-distribute-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// The regression this exists for: when only `vmlinux` and
        /// `rootfs.ext4` travelled, a distributed template arrived with no
        /// image config, so sandboxes ran with none of the image's environment
        /// and none of the trust bundles it names. `curl` in an image that sets
        /// `CURL_CA_BUNDLE` then verified against a store the CA was never
        /// installed into.
        #[tokio::test]
        async fn a_template_carries_its_image_config_to_the_node_that_pulls_it() {
            let source = scratch("source");
            let dest = scratch("dest");
            template(&source, "curlh2", Some(CONFIG)).await;

            let manifest = manifest(&source, "curlh2").await.unwrap();
            assert_eq!(manifest.image_config, CONFIG);

            // What `pull` does once the artifacts are in place.
            let dir = super::super::templates_dir(&dest).join(&manifest.name);
            tokio::fs::create_dir_all(&dir).await.unwrap();
            install_image_config(&dir, &manifest.image_config)
                .await
                .unwrap();

            let environment = crate::oci::image_environment(&dest, "curlh2").await;
            assert_eq!(environment.working_dir, "/app");
            let bundles = environment.trust_bundles();
            assert_eq!(bundles.len(), 1, "the bundle did not survive the pull");
            assert_eq!(bundles[0].path, "/cacert.pem");

            let _ = std::fs::remove_dir_all(&source);
            let _ = std::fs::remove_dir_all(&dest);
        }

        /// A template built the old way has no image config, and a pull of it
        /// must clear whatever the name used to mean on the receiving node
        /// rather than leaving another image's environment behind.
        #[tokio::test]
        async fn a_template_without_one_leaves_none_behind() {
            let source = scratch("plain");
            let dest = scratch("plain-dest");
            template(&source, "default", None).await;
            template(&dest, "default", Some(CONFIG)).await;

            let manifest = manifest(&source, "default").await.unwrap();
            assert!(manifest.image_config.is_empty());

            let dir = super::super::templates_dir(&dest).join("default");
            install_image_config(&dir, &manifest.image_config)
                .await
                .unwrap();
            assert!(!dir.join(IMAGE_CONFIG).exists());
            assert!(
                crate::oci::image_environment(&dest, "default")
                    .await
                    .env
                    .is_empty()
            );

            let _ = std::fs::remove_dir_all(&source);
            let _ = std::fs::remove_dir_all(&dest);
        }

        /// A compromised peer controls the manifest verbatim, and a name
        /// like `..` resolves to the data dir itself, where `materialise`
        /// would then write `vmlinux`/`rootfs.ext4` — the default guest
        /// kernel location every template on the node links against.
        #[tokio::test]
        async fn a_manifest_naming_a_path_escape_is_refused() {
            let dest = scratch("escape-dest");
            for name in ["..", ".", "", "a/b", ".hidden"] {
                let manifest = nodepb::TemplateManifest {
                    name: name.to_string(),
                    kernel_digest: String::new(),
                    rootfs_digest: String::new(),
                    rootfs_bytes: 0,
                    image_config: String::new(),
                };
                let result = pull(&dest, "unused:0", &manifest, None).await;
                assert!(result.is_err(), "{name:?} should be refused");
            }
            assert!(
                !dest.join("vmlinux").exists(),
                "a rejected pull must not touch the data dir"
            );
            let _ = std::fs::remove_dir_all(&dest);
        }
    }
}

/// Snapshots the build sandbox's scratch disk as the layer for `steps`.
///
/// The guest is told to `sync` first: its writes reach the scratch file
/// through virtio, and copying a disk with dirty guest page cache behind it
/// would cache a filesystem that never existed.
async fn cache_layer(
    manager: &SandboxManager,
    data_dir: &Path,
    build_id: &str,
    tx: &LogTx,
    base_rootfs: &crate::blobs::Digest,
    steps: &[String],
) -> Result<(), Status> {
    let exit = exec_streaming(manager, build_id, "sync", tx).await?;
    if exit != 0 {
        return Err(Status::internal(format!("sync exited {exit}")));
    }

    let scratch = manager.get(build_id).await?.scratch_path();
    let key = layers::key(base_rootfs, steps);
    layers::record(data_dir, &key, &scratch)
        .await
        .map_err(|err| Status::internal(format!("recording layer: {err}")))
}

/// Caching build steps, so a rebuild only re-runs what changed.
///
/// A build's writes land in an overlay scratch disk, and that disk *is* the
/// layer: it holds exactly what the steps changed. So caching a layer is
/// copying one file, rather than exporting and rebuilding an image per step,
/// which would cost more than the steps it saves.
///
/// A layer is keyed by everything that could change its contents: the base
/// template's rootfs digest, and every step command up to and including it.
/// Changing step three leaves layers one and two valid and invalidates
/// everything after, as a Dockerfile would.
pub mod layers {
    use std::path::{Path, PathBuf};

    use sha2::{Digest as _, Sha256};

    use crate::blobs::{BlobStore, Digest};

    /// Bumped when the meaning of a key changes: a cached layer from an older
    /// scheme is unrelated rather than wrong, and reusing it would produce an
    /// image nobody asked for.
    const KEY_VERSION: &str = "burrow-layer-v1";

    fn index_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("layers")
    }

    /// The key for the layer produced by running `steps` in order on `base`.
    pub fn key(base_rootfs: &Digest, steps: &[String]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(KEY_VERSION.as_bytes());
        hasher.update(base_rootfs.as_str().as_bytes());
        for step in steps {
            // Length-prefixed so ["a", "bc"] and ["ab", "c"] cannot collide.
            hasher.update((step.len() as u64).to_be_bytes());
            hasher.update(step.as_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The cached scratch disk for `key`, if this node has one.
    pub async fn lookup(data_dir: &Path, key: &str) -> Option<PathBuf> {
        let recorded = tokio::fs::read_to_string(index_dir(data_dir).join(key))
            .await
            .ok()?;
        let digest = Digest::parse(recorded.trim())?;
        let store = BlobStore::new(data_dir);
        // The index can outlive the blob it names, since a blob store may be
        // pruned, so the file has to be there rather than merely recorded.
        store.has(&digest).await.then(|| store.path(&digest))
    }

    /// Records the scratch disk at `scratch` as the layer for `key`.
    ///
    /// Stored content-addressed, so two builds whose steps differ but whose
    /// filesystems end up identical share one copy.
    pub async fn record(data_dir: &Path, key: &str, scratch: &Path) -> std::io::Result<()> {
        let store = BlobStore::new(data_dir);
        let digest = store.insert(scratch).await?;
        let index = index_dir(data_dir);
        tokio::fs::create_dir_all(&index).await?;
        // Written via a temporary and renamed: a half-written index entry
        // would name a digest that does not exist.
        let temp = index.join(format!(".{key}.tmp"));
        tokio::fs::write(&temp, digest.to_string()).await?;
        tokio::fs::rename(&temp, index.join(key)).await
    }

    /// How many leading steps are already cached, and the disk to resume from.
    ///
    /// Returns the *longest* cached prefix, because layers are cumulative:
    /// having the layer for steps 1..3 makes 1..2 redundant.
    pub async fn resume_point(
        data_dir: &Path,
        base_rootfs: &Digest,
        steps: &[String],
    ) -> (usize, Option<PathBuf>) {
        let mut best = (0, None);
        for taken in 1..=steps.len() {
            let key = key(base_rootfs, &steps[..taken]);
            match lookup(data_dir, &key).await {
                Some(path) => best = (taken, Some(path)),
                // Layers are chained, so the first gap ends the run: a later
                // hit would have been produced from a base we do not have.
                None => break,
            }
        }
        best
    }
}

#[cfg(test)]
mod layer_tests {
    use super::layers;
    use crate::blobs::Digest;

    fn base(seed: char) -> Digest {
        Digest::parse(&seed.to_string().repeat(64)).expect("a digest")
    }

    fn steps(commands: &[&str]) -> Vec<String> {
        commands.iter().map(|c| (*c).to_string()).collect()
    }

    #[test]
    fn the_same_steps_on_the_same_base_key_the_same() {
        let a = layers::key(&base('a'), &steps(&["apk add curl", "echo hi"]));
        let b = layers::key(&base('a'), &steps(&["apk add curl", "echo hi"]));
        assert_eq!(a, b);
    }

    /// The base is half the identity: the same steps on a different image
    /// produce a different filesystem.
    #[test]
    fn a_different_base_keys_differently() {
        let steps = steps(&["apk add curl"]);
        assert_ne!(
            layers::key(&base('a'), &steps),
            layers::key(&base('b'), &steps)
        );
    }

    #[test]
    fn a_prefix_keys_differently_from_the_whole() {
        let all = steps(&["one", "two", "three"]);
        assert_ne!(
            layers::key(&base('a'), &all[..1]),
            layers::key(&base('a'), &all)
        );
        assert_ne!(
            layers::key(&base('a'), &all[..2]),
            layers::key(&base('a'), &all)
        );
    }

    /// Length-prefixing is what stops ["ab","c"] and ["a","bc"] colliding: they
    /// are different builds and must not share a layer.
    #[test]
    fn step_boundaries_are_part_of_the_key() {
        assert_ne!(
            layers::key(&base('a'), &steps(&["ab", "c"])),
            layers::key(&base('a'), &steps(&["a", "bc"]))
        );
    }

    #[test]
    fn changing_a_step_leaves_earlier_keys_alone() {
        let before = steps(&["one", "two", "three"]);
        let after = steps(&["one", "two", "CHANGED"]);
        assert_eq!(
            layers::key(&base('a'), &before[..2]),
            layers::key(&base('a'), &after[..2]),
            "an unchanged prefix must keep its key"
        );
        assert_ne!(
            layers::key(&base('a'), &before),
            layers::key(&base('a'), &after)
        );
    }

    #[tokio::test]
    async fn a_recorded_layer_is_found_again() {
        let dir = std::env::temp_dir().join(format!("burrow-layers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let scratch = dir.join("scratch.ext4");
        tokio::fs::write(&scratch, b"layer contents").await.unwrap();
        let key = layers::key(&base('a'), &steps(&["one"]));

        assert!(layers::lookup(&dir, &key).await.is_none());
        layers::record(&dir, &key, &scratch).await.unwrap();
        let found = layers::lookup(&dir, &key).await.expect("recorded layer");
        assert_eq!(tokio::fs::read(&found).await.unwrap(), b"layer contents");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Layers are cumulative, so the longest cached prefix is the one to resume
    /// from, and a gap ends the run because a later layer was built from a base
    /// this node does not have.
    #[tokio::test]
    async fn the_resume_point_is_the_longest_cached_prefix() {
        let dir = std::env::temp_dir().join(format!("burrow-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let scratch = dir.join("scratch.ext4");
        tokio::fs::write(&scratch, b"x").await.unwrap();

        let all = steps(&["one", "two", "three"]);
        assert_eq!(layers::resume_point(&dir, &base('a'), &all).await.0, 0);

        layers::record(&dir, &layers::key(&base('a'), &all[..1]), &scratch)
            .await
            .unwrap();
        layers::record(&dir, &layers::key(&base('a'), &all[..2]), &scratch)
            .await
            .unwrap();
        let (taken, path) = layers::resume_point(&dir, &base('a'), &all).await;
        assert_eq!(taken, 2);
        assert!(path.is_some());

        // A third layer cached without the second would be unusable; the run
        // still stops at the gap.
        let gapped = steps(&["one", "CHANGED", "three"]);
        assert_eq!(layers::resume_point(&dir, &base('a'), &gapped).await.0, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An index entry can outlive the blob it names.
    #[tokio::test]
    async fn a_layer_whose_blob_is_gone_is_not_offered() {
        let dir = std::env::temp_dir().join(format!("burrow-pruned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let scratch = dir.join("scratch.ext4");
        tokio::fs::write(&scratch, b"y").await.unwrap();

        let key = layers::key(&base('a'), &steps(&["one"]));
        layers::record(&dir, &key, &scratch).await.unwrap();
        let blob = layers::lookup(&dir, &key).await.unwrap();
        std::fs::remove_file(&blob).unwrap();

        assert!(layers::lookup(&dir, &key).await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Converting an OCI image into a burrow template, which is how every template
/// a node holds comes to exist.
pub mod from_image {
    use std::path::Path;

    use tonic::Status;

    use super::{IMAGE_SLACK_MIB, LogTx, event, path, run, templates_dir, validate_name};
    use burrow_proto::api::v1 as api;

    /// Directories the guest needs that an image will not contain.
    ///
    /// The root is mounted read-only and the agent cannot create them itself,
    /// so they have to exist in the image. `/scratch` in particular is where
    /// the writable overlay is assembled.
    const REQUIRED_DIRS: [&str; 7] = ["proc", "sys", "dev", "tmp", "run", "scratch", "usr/bin"];

    /// Pulls an image, converts it, and publishes it as a template.
    #[allow(clippy::too_many_arguments)]
    pub async fn import(
        data_dir: &Path,
        name: &str,
        image: &str,
        agent_binary: &Path,
        credentials: &crate::oci::auth::Store,
        insecure: &[String],
        tx: &LogTx,
    ) -> Result<(), Status> {
        validate_name(name)?;
        let reference = crate::oci::Reference::parse(image)?;

        if !tokio::fs::try_exists(agent_binary).await.unwrap_or(false) {
            return Err(Status::failed_precondition(format!(
                "the guest agent is not at {}; set --agent-binary",
                agent_binary.display()
            )));
        }

        let mut progress = |line: String| {
            let _ = tx.try_send(event(api::build_log::Event::Step(line)));
        };
        let pulled =
            crate::oci::pull(&reference, data_dir, credentials, insecure, &mut progress).await?;

        let staging = data_dir.join("build").join(format!("import-{name}"));
        let _ = tokio::fs::remove_dir_all(&staging).await;
        let rootdir = staging.join("root");
        tokio::fs::create_dir_all(&rootdir)
            .await
            .map_err(|err| Status::internal(format!("staging: {err}")))?;

        let _ = tx
            .send(event(api::build_log::Event::Step(format!(
                "unpacking {} layer(s)",
                pulled.layers.len()
            ))))
            .await;
        // Blocking file work, and a large image is a lot of it.
        let layers = pulled.layers.clone();
        let unpack_into = rootdir.clone();
        tokio::task::spawn_blocking(move || crate::oci::unpack_layers(&layers, &unpack_into))
            .await
            .map_err(|err| Status::internal(format!("unpack did not run: {err}")))?
            .map_err(|err| Status::internal(format!("unpacking image: {err}")))?;

        for dir in REQUIRED_DIRS {
            let _ = tokio::fs::create_dir_all(rootdir.join(dir)).await;
        }
        // Without this the VM boots an image with no init and panics.
        tokio::fs::copy(agent_binary, rootdir.join("usr/bin/burrow-agent"))
            .await
            .map_err(|err| Status::internal(format!("installing the agent: {err}")))?;
        set_executable(&rootdir.join("usr/bin/burrow-agent")).await?;

        let outcome = assemble(data_dir, &rootdir, name, &pulled.environment, tx).await;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        outcome
    }

    async fn set_executable(path: &Path) -> Result<(), Status> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .await
                .map_err(|err| Status::internal(format!("agent permissions: {err}")))?;
        }
        Ok(())
    }

    async fn assemble(
        data_dir: &Path,
        rootdir: &Path,
        name: &str,
        environment: &crate::oci::ImageEnvironment,
        tx: &LogTx,
    ) -> Result<(), Status> {
        let content_bytes = directory_size(rootdir).await;
        // Images are sized by their contents, plus room for what the sandbox
        // writes later and for filesystem metadata.
        let size_mib = (content_bytes / (1024 * 1024)) + IMAGE_SLACK_MIB;

        let target = templates_dir(data_dir).join(name);
        tokio::fs::create_dir_all(&target)
            .await
            .map_err(|err| Status::internal(format!("template dir: {err}")))?;

        let _ = tx
            .send(event(api::build_log::Event::Step(format!(
                "building a {size_mib}MiB rootfs"
            ))))
            .await;
        let pending = target.join("rootfs.ext4.building");
        let _ = tokio::fs::remove_file(&pending).await;
        run(
            "mkfs.ext4",
            &[
                "-q",
                "-F",
                "-L",
                "burrow-root",
                "-b",
                "4096",
                "-d",
                &path(rootdir),
                &path(&pending),
                &format!("{size_mib}M"),
            ],
        )
        .await?;

        super::link_kernel(data_dir, &target).await?;

        // The image's environment and working directory are what a shell in
        // the sandbox would otherwise get wrong.
        let config = serde_json::to_vec_pretty(environment)
            .map_err(|err| Status::internal(format!("image config: {err}")))?;
        tokio::fs::write(target.join("image.json"), config)
            .await
            .map_err(|err| Status::internal(format!("writing image config: {err}")))?;

        tokio::fs::rename(&pending, target.join("rootfs.ext4"))
            .await
            .map_err(|err| Status::internal(format!("publishing image: {err}")))?;

        let size_bytes = tokio::fs::metadata(target.join("rootfs.ext4"))
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let _ = tx
            .send(event(api::build_log::Event::Done(api::BuildDone {
                template: name.to_string(),
                size_bytes,
            })))
            .await;
        Ok(())
    }

    /// Apparent size of a directory tree, for sizing the filesystem.
    async fn directory_size(root: &Path) -> u64 {
        let root = root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            fn walk(dir: &Path) -> u64 {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return 0;
                };
                entries
                    .flatten()
                    // symlink_metadata: a layer symlink like `a -> .` or
                    // `a -> /` must be counted as a link, never followed.
                    .map(|entry| match std::fs::symlink_metadata(entry.path()) {
                        Ok(meta) if meta.is_dir() => walk(&entry.path()),
                        Ok(meta) => meta.len(),
                        Err(_) => 0,
                    })
                    .sum()
            }
            walk(&root)
        })
        .await
        .unwrap_or(0)
    }
}
