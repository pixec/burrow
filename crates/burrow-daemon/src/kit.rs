//! Docker Sandbox Kits on a node: importing a set as one template and
//! provisioning a sandbox the way its descriptors ask.
//!
//! The grammar and the merge rules live in `burrow-kit`; this module is the
//! I/O around them. An import pulls every Kit, reads the descriptor out of
//! each manifest, judges the set and records the result in the template's
//! `image.json`, so a create needs no registry. A create then expands those
//! records with the caller's args and environment, turns the composition
//! into a network policy per phase, volumes and a sandbox environment, and
//! once the VM is up walks the lifecycle: files, install hooks under the
//! install-phase policy, the swap to the runtime policy, startup hooks and
//! the workload's entrypoint.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};

use burrow_kit::{HookPhase, Phase};
use burrow_proto::common::v1 as common;
use burrow_proto::guest::v1 as guestpb;
use serde::{Deserialize, Serialize};
use tonic::Status;

use crate::oci::{ImageEnvironment, PulledImage};
use crate::sandbox::{RunningSandbox, SandboxManager};

/// The capability types this node answers.
pub const CLAIMED: &[&str] = burrow_kit::KNOWN_TYPES;

/// Label on a Kit volume naming the sandbox it belongs to.
pub const LABEL_SANDBOX: &str = "burrow.kit/sandbox";
/// Label on a Kit volume naming the path it mounts at.
pub const LABEL_PATH: &str = "burrow.kit/path";
/// Labels a recreation compares against the storage it would reattach.
const LABEL_SIZE: &str = "burrow.kit/size";
const LABEL_MODE: &str = "burrow.kit/mode";

const DEFAULT_VOLUME_MIB: u64 = 1024;
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SENTINEL_PREFIX: &str = "burrow-sentinel-";
/// How much of a failed hook's output its error carries.
const HOOK_OUTPUT_TAIL: usize = 2000;

/// Why a Kit, or a set of them, cannot be used. The RPC boundary turns it
/// into the status code the adapter contract expects.
#[derive(Debug)]
pub enum Error {
    /// The set or an input, as `burrow-kit` judged it.
    Kit(burrow_kit::Error),
    /// A pulled image that cannot be read as a Kit at all.
    NotAKit(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kit(burrow_kit::Error::Refused(m)) => write!(f, "kit refused: {m}"),
            Self::Kit(burrow_kit::Error::Invalid(m)) => write!(f, "kit: {m}"),
            Self::NotAKit(m) => f.write_str(m),
        }
    }
}

impl From<burrow_kit::Error> for Error {
    fn from(err: burrow_kit::Error) -> Self {
        Self::Kit(err)
    }
}

/// A refusal is FAILED_PRECONDITION and bad input INVALID_ARGUMENT, the two
/// codes the adapter contract keeps apart.
impl From<Error> for Status {
    fn from(err: Error) -> Self {
        let message = err.to_string();
        match err {
            Error::Kit(burrow_kit::Error::Refused(_)) => Status::failed_precondition(message),
            Error::Kit(burrow_kit::Error::Invalid(_)) | Error::NotAKit(_) => {
                Status::invalid_argument(message)
            }
        }
    }
}

/// A Kit as the import recorded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KitImage {
    pub reference: String,
    pub digest: String,
    /// The published descriptor, as the manifest annotation carried it.
    pub descriptor: serde_json::Value,
    pub config: burrow_kit::ImageConfig,
    pub layers: Vec<String>,
}

impl From<burrow_kit::Loaded> for KitImage {
    fn from(kit: burrow_kit::Loaded) -> Self {
        Self {
            reference: kit.reference,
            digest: kit.digest,
            descriptor: kit.descriptor.raw,
            config: kit.image_config,
            layers: kit.layers,
        }
    }
}

impl KitImage {
    fn to_loaded(&self) -> burrow_kit::Result<burrow_kit::Loaded> {
        Ok(burrow_kit::Loaded {
            reference: self.reference.clone(),
            digest: self.digest.clone(),
            descriptor: burrow_kit::Descriptor::from_value(self.descriptor.clone())?,
            image_config: self.config.clone(),
            layers: self.layers.clone(),
        })
    }
}

impl From<&ImageEnvironment> for burrow_kit::ImageConfig {
    fn from(env: &ImageEnvironment) -> Self {
        Self {
            entrypoint: env.entrypoint.clone(),
            cmd: env.cmd.clone(),
            env: env.env.clone(),
            user: env.user.clone(),
            working_dir: env.working_dir.clone(),
        }
    }
}

/// The composition a template was imported from, in composition order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KitTemplate {
    pub kits: Vec<KitImage>,
    pub workload: usize,
    pub lock: String,
}

impl KitTemplate {
    pub fn template_name(&self) -> String {
        template_name(&self.lock)
    }

    fn resolved(&self) -> burrow_kit::Result<burrow_kit::Resolved> {
        let kits = self
            .kits
            .iter()
            .map(KitImage::to_loaded)
            .collect::<burrow_kit::Result<Vec<_>>>()?;
        burrow_kit::resolve(kits)
    }

    /// The `image.json` a Kit template carries: the merged config, with the
    /// composition recorded beside it.
    pub fn environment(&self) -> ImageEnvironment {
        let workload = &self.kits[self.workload].config;
        let mixins: Vec<&burrow_kit::ImageConfig> = self
            .kits
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.workload)
            .map(|(_, k)| &k.config)
            .collect();
        let merged = burrow_kit::merge_image_configs(workload, &mixins);
        ImageEnvironment {
            env: merged.env,
            working_dir: merged.working_dir,
            entrypoint: merged.entrypoint,
            cmd: merged.cmd,
            user: merged.user,
            kit: Some(self.clone()),
            systemd: false,
        }
    }
}

fn template_name(lock: &str) -> String {
    format!("kit-{}", &lock[..16])
}

/// Whether a pulled image is a Kit: its manifest carries the descriptor.
pub fn is_kit(pulled: &PulledImage) -> bool {
    pulled
        .annotations
        .contains_key(burrow_kit::DESCRIPTOR_ANNOTATION)
}

/// Reads a pulled Kit's descriptor and runtime contract.
pub fn load(reference: &str, pulled: &PulledImage) -> Result<burrow_kit::Loaded, Error> {
    let Some(text) = pulled.annotations.get(burrow_kit::DESCRIPTOR_ANNOTATION) else {
        return Err(Error::NotAKit(format!(
            "{reference} is not a sandbox kit: its manifest carries no {} annotation",
            burrow_kit::DESCRIPTOR_ANNOTATION
        )));
    };
    let descriptor = burrow_kit::Descriptor::parse(text)
        .map_err(|e| Error::NotAKit(format!("{reference}: {e}")))?;
    Ok(burrow_kit::Loaded {
        reference: reference.to_string(),
        digest: pulled.digest.clone(),
        descriptor,
        image_config: (&pulled.environment).into(),
        layers: pulled.layer_digests.clone(),
    })
}

/// Pulls every Kit named, judges the set and returns it with the layer blobs
/// to unpack, in composition order.
pub async fn load_set(
    refs: &[String],
    data_dir: &Path,
    credentials: &crate::oci::auth::Store,
    insecure: &[String],
    progress: &mut impl FnMut(String),
) -> Result<(KitTemplate, Vec<PathBuf>), Status> {
    if refs.is_empty() {
        return Err(Status::invalid_argument(
            "a kit composition names at least one kit",
        ));
    }
    let mut loaded = Vec::with_capacity(refs.len());
    let mut blobs = HashMap::new();
    for reference in refs {
        let parsed = crate::oci::Reference::parse(reference)?;
        let pulled = crate::oci::pull(&parsed, data_dir, credentials, insecure, progress).await?;
        loaded.push(load(reference, &pulled)?);
        blobs.insert(pulled.digest, pulled.layers);
    }
    Ok(assemble(loaded, blobs, progress)?)
}

/// Judges a loaded set and lays its layers out in composition order.
pub fn assemble(
    loaded: Vec<burrow_kit::Loaded>,
    blobs: HashMap<String, Vec<PathBuf>>,
    progress: &mut impl FnMut(String),
) -> Result<(KitTemplate, Vec<PathBuf>), Error> {
    let resolved = burrow_kit::resolve(loaded)?;
    let lock = burrow_kit::lock_digest(&resolved);
    let references: Vec<&str> = resolved.kits.iter().map(|k| k.reference.as_str()).collect();
    progress(format!(
        "composing {} as {}",
        references.join(" + "),
        template_name(&lock)
    ));
    let layers = resolved
        .kits
        .iter()
        .flat_map(|kit| blobs[&kit.digest].iter().cloned())
        .collect();
    let template = KitTemplate {
        kits: resolved.kits.into_iter().map(KitImage::from).collect(),
        workload: resolved.workload,
        lock,
    };
    Ok((template, layers))
}

/// Everything a create has to do for a Kit sandbox, worked out before any
/// resource is taken.
pub struct Plan {
    pub composition: burrow_kit::Composition,
    /// What every process in the sandbox gets on top of the image's env,
    /// sentinels included.
    pub env: BTreeMap<String, String>,
    pub install_network: common::NetworkPolicy,
    pub runtime_network: common::NetworkPolicy,
    pub resources: common::ResourcePolicy,
    /// The selection records and permission surface, as the record keeps
    /// them.
    pub selection: String,
    /// Sentinel values by variable name for each phase.
    install_sentinels: BTreeMap<String, String>,
    runtime_sentinels: BTreeMap<String, String>,
}

/// Composes a template's Kits with the caller's inputs and renders the plan.
pub fn plan(
    template: &KitTemplate,
    spec: &common::KitSpec,
    credentials: &HashMap<String, String>,
    requested: &common::ResourcePolicy,
) -> Result<Plan, Error> {
    let resolved = template.resolved()?;
    let inputs = burrow_kit::Inputs {
        args: spec.args.clone().into_iter().collect(),
        env: spec.env.clone().into_iter().collect(),
    };
    let bound: BTreeSet<String> = credentials.keys().cloned().collect();
    let host = burrow_kit::Host {
        claimed: CLAIMED,
        bound_services: &bound,
        rejected: &spec.reject_types,
    };
    let composition = burrow_kit::compose(&resolved, &inputs, &host)?;

    let (install_sentinels, runtime_sentinels) = sentinels(&composition, credentials);
    let mut env = composition.env.clone();
    env.extend(runtime_sentinels.clone());

    let mut install_network = render_network(&composition, Phase::Install, credentials);
    let runtime_network = render_network(&composition, Phase::Runtime, credentials);
    // Inspection is settled at creation, when the guest is handed the CA, so
    // a runtime phase that needs it asks for it from the first boot.
    install_network.is_tls_inspected |= runtime_network.is_tls_inspected;
    Ok(Plan {
        env,
        install_network,
        runtime_network,
        resources: fit_resources(*requested, &composition.resources),
        selection: selection_record(&composition),
        install_sentinels,
        runtime_sentinels,
        composition,
    })
}

impl Plan {
    /// The environment one hook runs with: the baseline, plus the variables
    /// it declared, taken from the sandbox environment and the sentinels of
    /// the phase it runs in. An install hook never sees a runtime-only
    /// sentinel.
    fn hook_env(
        &self,
        hook: &burrow_kit::Hook,
        baseline: &BTreeMap<String, String>,
    ) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = baseline.clone().into_iter().collect();
        for name in &hook.env {
            let value = match hook.phase {
                HookPhase::Install => self.install_sentinels.get(name).or_else(|| {
                    self.env
                        .get(name)
                        .filter(|_| !self.runtime_sentinels.contains_key(name))
                }),
                HookPhase::Startup => self.env.get(name),
            };
            if let Some(value) = value {
                env.insert(name.clone(), value.clone());
            }
        }
        env
    }

    fn hooks(&self, phase: HookPhase) -> impl Iterator<Item = &burrow_kit::Hook> {
        self.composition
            .hooks
            .iter()
            .filter(move |h| h.phase == phase)
    }
}

/// The value each credential variable carries in each phase: a sentinel the
/// proxy swaps for the secret when the proxy manages it, the secret itself
/// otherwise.
fn sentinels(
    composition: &burrow_kit::Composition,
    credentials: &HashMap<String, String>,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut install = BTreeMap::new();
    let mut runtime = BTreeMap::new();
    for cred in &composition.credentials {
        let Some(var) = &cred.variable else { continue };
        let value = if cred.is_proxy_managed {
            format!("{SENTINEL_PREFIX}{}", uuid::Uuid::new_v4().simple())
        } else {
            credentials[&cred.service].clone()
        };
        if cred.phases.is_install_active {
            install.insert(var.clone(), value.clone());
        }
        if cred.phases.is_runtime_active {
            runtime.insert(var.clone(), value);
        }
    }
    (install, runtime)
}

/// Raises the caller's resources to what the composition asks for.
fn fit_resources(
    mut resources: common::ResourcePolicy,
    wanted: &burrow_kit::Resources,
) -> common::ResourcePolicy {
    if let Some(cpu) = wanted.cpu {
        let vcpus = cpu.ceil() as u32;
        if vcpus > 0 {
            resources.vcpus = resources.vcpus.max(vcpus);
        }
    }
    if let Some(mem) = wanted.memory_mib {
        resources.mem_mib = resources.mem_mib.max(mem as u32);
    }
    resources
}

fn selection_record(composition: &burrow_kit::Composition) -> String {
    serde_json::json!({
        "selection": {
            "capabilities": [],
            "selected": composition.selection.selected,
            "skipped": composition.selection.skipped,
        },
        "surface": composition.surface,
    })
    .to_string()
}

/// Renders one phase of the composition's network policy as the node
/// enforces it: outright hosts to the allowlist, HTTP entries to rules, and
/// the phase's credentials to header injections. Inspection is on whenever
/// a request has to be read.
fn render_network(
    composition: &burrow_kit::Composition,
    phase: Phase,
    credentials: &HashMap<String, String>,
) -> common::NetworkPolicy {
    let allow_domains = composition.allowed_hosts(phase);
    let deny_domains = composition.denied_hosts(phase);
    let http_rules: Vec<common::HttpRule> = composition
        .http_entries(phase)
        .into_iter()
        .map(|e| common::HttpRule {
            hosts: e.hosts,
            methods: e.methods,
            paths: e.paths,
            is_denied: e.is_denying,
        })
        .collect();
    let rules: Vec<common::RequestRule> = composition
        .credentials
        .iter()
        .filter(|c| c.phases.is_active_in(phase))
        .flat_map(|cred| {
            let secret = &credentials[&cred.service];
            cred.inject
                .iter()
                .filter_map(move |inject| inject_rule(inject, secret))
        })
        .collect();
    let mode = if composition.network.is_declared
        && (!allow_domains.is_empty() || !http_rules.is_empty())
    {
        common::NetworkMode::Allowlist
    } else {
        common::NetworkMode::None
    };
    let inspect_tls =
        mode == common::NetworkMode::Allowlist && (!http_rules.is_empty() || !rules.is_empty());
    common::NetworkPolicy {
        mode: mode as i32,
        allow_domains,
        deny_domains,
        http_rules,
        is_tls_inspected: inspect_tls,
        rules,
        ..Default::default()
    }
}

/// The header rule one injection asks for: a formatted header, or Basic
/// auth when it names a scheme instead.
fn inject_rule(inject: &burrow_kit::Inject, secret: &str) -> Option<common::RequestRule> {
    let value = match (&inject.header, &inject.scheme) {
        (Some(_), _) => inject
            .format
            .as_deref()
            .unwrap_or("%s")
            .replacen("%s", secret, 1),
        (None, Some(_)) => {
            use base64::Engine as _;
            let user = inject.username.as_deref().unwrap_or_default();
            let token =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"));
            format!("Basic {token}")
        }
        (None, None) => return None,
    };
    let name = inject
        .header
        .clone()
        .unwrap_or_else(|| "Authorization".into());
    Some(common::RequestRule {
        domain: inject.domain.clone(),
        r#match: None,
        action: Some(common::request_rule::Action::SetHeaders(
            common::SetHeaders {
                headers: vec![common::HeaderValue { name, value }],
            },
        )),
    })
}

/// The volume a Kit path is backed by on this node.
pub fn volume_name(sandbox_id: &str, path: &str) -> String {
    let hex = crate::oci::sha256_hex(path.as_bytes());
    format!("kit-{}-{}", sandbox_id.replace('_', "-"), &hex[..12])
}

fn is_owned_by(volume: &common::Volume, sandbox_id: &str) -> bool {
    volume
        .labels
        .get(LABEL_SANDBOX)
        .is_some_and(|s| s == sandbox_id)
}

/// Allocates or reattaches the block volumes a plan asks for, and refuses a
/// request that disagrees with retained storage at the same path. Returns
/// the mounts in request order.
pub async fn prepare_volumes(
    manager: &SandboxManager,
    sandbox_id: &str,
    plan: &Plan,
) -> Result<Vec<common::VolumeMount>, Status> {
    let store = manager.volumes();
    let retained: HashMap<String, common::Volume> = store
        .list()
        .await
        .into_iter()
        .filter(|v| is_owned_by(v, sandbox_id))
        .map(|v| (v.name.clone(), v))
        .collect();
    let mut mounts = Vec::with_capacity(plan.composition.volumes.len());
    for request in &plan.composition.volumes {
        let cfg = &request.config;
        let mode = cfg.mode.clone().unwrap_or_default();
        if cfg.is_tmpfs {
            mounts.push(common::VolumeMount {
                path: cfg.path.clone(),
                is_tmpfs: true,
                size_mib: cfg.size.map_or(0, |s| s.mib_ceil()),
                mode,
                ..Default::default()
            });
            continue;
        }
        let name = volume_name(sandbox_id, &cfg.path);
        let size = cfg.size.map(|s| s.0.to_string()).unwrap_or_default();
        match retained.get(&name) {
            Some(volume) => {
                let same = volume.labels.get(LABEL_SIZE) == Some(&size)
                    && volume.labels.get(LABEL_MODE) == Some(&mode);
                if !same {
                    return Err(Status::failed_precondition(format!(
                        "kit refused: volume at {} differs from the storage retained there; recreation keeps the previous composition",
                        cfg.path
                    )));
                }
            }
            None => {
                let size_mib = cfg.size.map_or(DEFAULT_VOLUME_MIB, |s| s.mib_ceil()).max(1);
                let labels = HashMap::from([
                    (LABEL_SANDBOX.to_string(), sandbox_id.to_string()),
                    (LABEL_PATH.to_string(), cfg.path.clone()),
                    (LABEL_SIZE.to_string(), size),
                    (LABEL_MODE.to_string(), mode.clone()),
                ]);
                store.create(&name, size_mib, labels).await?;
            }
        }
        mounts.push(common::VolumeMount {
            volume: name,
            path: cfg.path.clone(),
            mode,
            ..Default::default()
        });
    }
    Ok(mounts)
}

/// Deletes every volume that belongs to a sandbox.
pub async fn remove_volumes(manager: &SandboxManager, sandbox_id: &str) {
    let store = manager.volumes();
    for volume in store.list().await {
        if is_owned_by(&volume, sandbox_id)
            && let Err(err) = store.delete(&volume.name).await
        {
            tracing::warn!(sandbox = sandbox_id, volume = volume.name, %err, "could not remove kit volume");
        }
    }
}

/// Which boots run which hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boot {
    /// The first boot: install hooks under the install policy, then the
    /// swap to the runtime policy.
    Create,
    /// Every later boot, a recreation included: startup only.
    Restart,
}

/// Walks the lifecycle inside a running sandbox.
pub async fn provision(
    manager: &SandboxManager,
    sandbox: &RunningSandbox,
    plan: &Plan,
    boot: Boot,
) -> Result<(), Status> {
    let image = manager.image_environment(sandbox.template()).await;
    let baseline = baseline_env(&image);

    write_files(
        sandbox,
        &plan.composition.files,
        plan.composition.agent_user(),
    )
    .await?;

    if boot == Boot::Create {
        run_hooks(
            sandbox,
            plan,
            HookPhase::Install,
            &baseline,
            &image.working_dir,
        )
        .await?;
        manager
            .update_network_policy(sandbox.id(), plan.runtime_network.clone())
            .await?;
    }
    run_hooks(
        sandbox,
        plan,
        HookPhase::Startup,
        &baseline,
        &image.working_dir,
    )
    .await?;

    launch_entrypoint(sandbox, &image, plan).await
}

/// The platform baseline a hook sees, derived from the image and the
/// sandbox rather than the host's environment.
fn baseline_env(image: &ImageEnvironment) -> BTreeMap<String, String> {
    let path = image
        .as_map()
        .remove("PATH")
        .unwrap_or_else(|| DEFAULT_PATH.to_string());
    BTreeMap::from([
        ("PATH".to_string(), path),
        ("TERM".to_string(), "dumb".to_string()),
    ])
}

/// An exec as the node's lifecycle work issues it: a clean environment,
/// and root expressed as the agent's default user.
fn lifecycle_exec(
    cmd: Vec<String>,
    env: HashMap<String, String>,
    cwd: String,
    user: &str,
) -> guestpb::ExecStart {
    guestpb::ExecStart {
        cmd,
        env,
        cwd,
        is_pty: false,
        rows: 0,
        cols: 0,
        user: if user == "root" {
            String::new()
        } else {
            user.to_string()
        },
        is_env_cleared: true,
        log_max_bytes: 0,
        log_max_files: 0,
    }
}

async fn run_hooks(
    sandbox: &RunningSandbox,
    plan: &Plan,
    phase: HookPhase,
    baseline: &BTreeMap<String, String>,
    working_dir: &str,
) -> Result<(), Status> {
    for hook in plan.hooks(phase) {
        run_hook(sandbox, hook, plan.hook_env(hook, baseline), working_dir).await?;
    }
    Ok(())
}

async fn run_hook(
    sandbox: &RunningSandbox,
    hook: &burrow_kit::Hook,
    env: HashMap<String, String>,
    working_dir: &str,
) -> Result<(), Status> {
    let label = format!("{} hook {} ({:?})", hook.kit, hook.index, hook.phase);
    let in_context = |e: Status| Status::internal(format!("{label}: {e}"));
    // A non-root hook starts in its user's home, which the agent picks.
    let cwd = if hook.user == "root" {
        working_dir.to_string()
    } else {
        String::new()
    };
    let start = lifecycle_exec(hook.argv.clone(), env, cwd, &hook.user);
    if hook.is_background {
        crate::guestconn::spawn_detached(sandbox, start)
            .await
            .map_err(in_context)?;
        return Ok(());
    }
    let outcome = crate::guestconn::run_to_completion(sandbox, start)
        .await
        .map_err(in_context)?;
    if outcome.exit_code != 0 {
        return Err(Status::failed_precondition(format!(
            "{label} exited with status {}:\n{}",
            outcome.exit_code,
            tail(&String::from_utf8_lossy(&outcome.output), HOOK_OUTPUT_TAIL)
        )));
    }
    Ok(())
}

/// The last `chars` characters of `text`.
fn tail(text: &str, chars: usize) -> &str {
    let skip = text.chars().count().saturating_sub(chars);
    text.char_indices()
        .nth(skip)
        .map_or("", |(start, _)| &text[start..])
}

async fn write_files(
    sandbox: &RunningSandbox,
    files: &[burrow_kit::FileEntry],
    owner: &str,
) -> Result<(), Status> {
    for file in files {
        let mode = file
            .mode
            .as_deref()
            .and_then(|m| u32::from_str_radix(m, 8).ok())
            .unwrap_or(DEFAULT_FILE_MODE);
        crate::guestconn::upload(
            sandbox,
            &file.path,
            file.content.as_bytes(),
            mode,
            owner,
            !file.is_overwriting,
        )
        .await
        .map_err(|e| Status::internal(format!("{}: writing {}: {e}", file.kit, file.path)))?;
    }
    Ok(())
}

/// Starts the workload the way the image config says, as the image's user
/// in its working directory, under bash so `BASH_ENV` applies.
async fn launch_entrypoint(
    sandbox: &RunningSandbox,
    image: &ImageEnvironment,
    plan: &Plan,
) -> Result<(), Status> {
    if image.entrypoint.is_empty() && image.cmd.is_empty() {
        return Ok(());
    }
    let cmd = ["/bin/bash", "-c", "exec \"$@\"", "entrypoint"]
        .into_iter()
        .map(str::to_string)
        .chain(image.entrypoint.iter().cloned())
        .chain(image.cmd.iter().cloned())
        .collect();
    let mut env = image.as_map();
    env.extend(plan.env.clone());
    let start = lifecycle_exec(
        cmd,
        env,
        image.working_dir.clone(),
        plan.composition.agent_user(),
    );
    crate::guestconn::spawn_detached(sandbox, start)
        .await
        .map(drop)
        .map_err(|e| Status::internal(format!("launching the workload: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_names_are_valid_and_stable() {
        let name = volume_name(
            "sbx_0123456789abcdef0123456789abcdef",
            "/var/tmp/kit-tck-volume",
        );
        crate::volume::validate_name(&name).unwrap();
        assert_eq!(
            name,
            volume_name(
                "sbx_0123456789abcdef0123456789abcdef",
                "/var/tmp/kit-tck-volume"
            )
        );
        assert_ne!(
            name,
            volume_name("sbx_0123456789abcdef0123456789abcdef", "/var/tmp/other")
        );
    }

    #[test]
    fn a_tail_keeps_the_last_characters() {
        assert_eq!(tail("abcdef", 3), "def");
        assert_eq!(tail("ab", 3), "ab");
        assert_eq!(tail("héllo", 4), "éllo");
    }
}
