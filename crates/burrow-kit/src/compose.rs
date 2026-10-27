//! Selection and composition (SPEC-v3 §7, §9.5): expanding each Kit with
//! the installer's inputs, deciding which of its requests the runtime
//! answers, and reconciling the selected requests into one plan.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{
    CredentialConfig, HostEntry, LifecycleConfig, NetworkPolicyConfig, PortConfig, ResourcesConfig,
    VolumeConfig, require_no_config,
};
use crate::descriptor::{CapType, Descriptor, Entry, Item};
use crate::expand::{ContainerEnv, expand_args, expand_env, resolve_args};
use crate::image::ImageConfig;
use crate::resolve::{Loaded, Resolved};
use crate::surface::{Surface, service_entry};
use crate::{Result, invalid, refused};
use burrow_common::glob::is_host_match;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Install,
    Runtime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPhase {
    pub allow: Vec<HostEntry>,
    pub deny: Vec<HostEntry>,
}

impl NetworkPhase {
    /// Whether `host` is granted by an unbounded allow entry.
    pub fn is_granted_outright(&self, host: &str) -> bool {
        self.allow
            .iter()
            .any(|e| !e.is_bounded() && e.hosts.iter().any(|p| is_host_match(p, host)))
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        self.allow
            .iter()
            .any(|e| e.hosts.iter().any(|p| is_host_match(p, host)))
    }

    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub install: NetworkPhase,
    pub runtime: NetworkPhase,
    /// Whether any Kit declared a network policy at all. Without one a
    /// sandbox has no egress in either phase.
    pub is_declared: bool,
}

impl NetworkPolicy {
    pub fn phase(&self, phase: Phase) -> &NetworkPhase {
        match phase {
            Phase::Install => &self.install,
            Phase::Runtime => &self.runtime,
        }
    }
}

/// An HTTP-level entry as the proxy enforces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEntry {
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub is_denying: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inject {
    pub domain: String,
    pub header: Option<String>,
    pub format: Option<String>,
    pub scheme: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialPhase {
    pub is_install_active: bool,
    pub is_runtime_active: bool,
}

impl CredentialPhase {
    pub fn is_active_in(&self, phase: Phase) -> bool {
        match phase {
            Phase::Install => self.is_install_active,
            Phase::Runtime => self.is_runtime_active,
        }
    }

    /// The phases included, install first.
    pub fn iter(self) -> impl Iterator<Item = Phase> {
        [Phase::Install, Phase::Runtime]
            .into_iter()
            .filter(move |p| self.is_active_in(*p))
    }
}

/// A selected, bound credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub service: String,
    pub phases: CredentialPhase,
    /// The in-container variable that carries a sentinel, when named.
    pub variable: Option<String>,
    pub is_proxy_managed: bool,
    pub inject: Vec<Inject>,
    pub kit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRequest {
    pub config: VolumeConfig,
    pub kit: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPhase {
    Install,
    Startup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub phase: HookPhase,
    pub argv: Vec<String>,
    /// Login name to run as.
    pub user: String,
    /// Variables the hook may see beyond the platform baseline.
    pub env: Vec<String>,
    pub is_background: bool,
    pub description: Option<String>,
    pub kit: String,
    pub index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub content: String,
    pub mode: Option<String>,
    pub is_overwriting: bool,
    pub kit: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Resources {
    pub cpu: Option<f64>,
    pub memory_mib: Option<u64>,
    pub gpu: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRequest {
    pub name: Option<String>,
    pub container: u16,
    pub transport: String,
}

/// Where a declaration came from: the Kit's consumption reference and its
/// path in that descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    pub kit: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    #[serde(rename = "accepted")]
    pub is_accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One declaration's selection outcome: an ordinary entry, or a group with
/// its members, in the spec library's record shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionRecord {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub source: Source,
    pub members: Vec<String>,
    pub member_sources: Vec<Source>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<String>,
    pub decisions: Vec<Decision>,
}

/// The create-time decisions, kept apart from the merged grants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Selection {
    pub selected: Vec<SelectionRecord>,
    pub skipped: Vec<SelectionRecord>,
}

/// A request the composition proceeds without.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub kit: String,
    pub path: String,
    pub type_: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct Composition {
    /// The workload's config with its mixins' env merged in.
    pub image: ImageConfig,
    /// Arg exports and overrides: what every process gets on top of the
    /// image's environment.
    pub env: BTreeMap<String, String>,
    pub network: NetworkPolicy,
    pub credentials: Vec<Credential>,
    pub volumes: Vec<VolumeRequest>,
    pub hooks: Vec<Hook>,
    pub files: Vec<FileEntry>,
    pub interactive: Option<Vec<String>>,
    pub resources: Resources,
    pub ports: Vec<PortRequest>,
    pub is_long_running: bool,
    pub is_sbx_requested: bool,
    pub selection: Selection,
    pub skipped: Vec<Skipped>,
    pub surface: Surface,
}

impl Composition {
    /// The login name files and startup hooks default to: the image's user,
    /// or the platform floor's `agent`.
    pub fn agent_user(&self) -> &str {
        let name = self.image.user_name();
        if name.is_empty() { "agent" } else { name }
    }

    /// The HTTP rules a phase's policy renders to, deny entries first.
    pub fn http_entries(&self, phase: Phase) -> Vec<HttpEntry> {
        let lists = self.network.phase(phase);
        let deny = lists.deny.iter().map(|e| (e, true));
        let allow = lists.allow.iter().map(|e| (e, false));
        deny.chain(allow)
            .filter(|(e, _)| e.is_bounded())
            .map(|(e, deny)| HttpEntry {
                hosts: e.hosts.clone(),
                methods: e.methods.clone(),
                paths: e.paths.clone(),
                is_denying: deny,
            })
            .collect()
    }

    /// Hosts granted outright in a phase.
    pub fn allowed_hosts(&self, phase: Phase) -> Vec<String> {
        outright_hosts(&self.network.phase(phase).allow)
    }

    /// Hosts refused outright in a phase.
    pub fn denied_hosts(&self, phase: Phase) -> Vec<String> {
        outright_hosts(&self.network.phase(phase).deny)
    }
}

/// The hosts of a list's unbounded entries, sorted and distinct.
fn outright_hosts(entries: &[HostEntry]) -> Vec<String> {
    let hosts: BTreeSet<&String> = entries
        .iter()
        .filter(|e| !e.is_bounded())
        .flat_map(|e| &e.hosts)
        .collect();
    hosts.into_iter().cloned().collect()
}

/// What the runtime brings to selection.
#[derive(Debug, Clone)]
pub struct Host<'a> {
    /// Capability types the runtime implements.
    pub claimed: &'a [&'a str],
    /// Credential services that have a binding.
    pub bound_services: &'a BTreeSet<String>,
    /// Types the host declines for this create, however well it implements
    /// them: the operator's answer rather than the runtime's.
    pub rejected: &'a [String],
}

/// Create-time inputs.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub args: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
}

/// A Kit's descriptor after expansion, with the label its messages carry.
struct Decoded<'a> {
    kit: &'a Loaded,
    label: String,
    descriptor: Descriptor,
}

pub fn compose(resolved: &Resolved, inputs: &Inputs, host: &Host<'_>) -> Result<Composition> {
    let mut image = resolved.image_config();

    // Args first: their exports are part of the environment `kit.env`
    // resolves against.
    let mut exports = BTreeMap::new();
    let arg_expanded = resolved
        .kits
        .iter()
        .map(|kit| {
            expand_kit_args(kit, &inputs.args, &mut exports).map_err(|e| e.prefixed(&kit.label()))
        })
        .collect::<Result<Vec<_>>>()?;
    let undeclared = inputs.args.keys().find(|name| {
        !resolved
            .kits
            .iter()
            .any(|k| k.descriptor.args.contains_key(*name))
    });
    if let Some(name) = undeclared {
        return Err(invalid(format!(
            "arg {name:?} is declared by no kit in the set"
        )));
    }

    let container_env = ContainerEnv::compose(&image.env, &exports, &inputs.env);
    let mut env = exports;
    env.extend(inputs.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    for (k, v) in &env {
        image.set_env(k, v);
    }

    let decoded = resolved
        .kits
        .iter()
        .zip(arg_expanded)
        .map(|(kit, raw)| {
            let label = kit.label();
            match decode_kit(&raw, &container_env) {
                Ok(descriptor) => Ok(Decoded {
                    kit,
                    label,
                    descriptor,
                }),
                Err(e) => Err(e.prefixed(&label)),
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let mut out = Composition {
        image,
        env,
        ..Default::default()
    };
    let selected = select(&decoded, host, &mut out)?;
    Merge::default().run(&mut out, &selected)?;
    let services = selected
        .iter()
        .filter_map(|(_, e)| service_entry(e))
        .collect();
    out.surface = Surface::of(&out, services);
    Ok(out)
}

/// Resolves a Kit's args, records the ones it exports, and expands its
/// descriptor with them.
fn expand_kit_args(
    kit: &Loaded,
    supplied: &BTreeMap<String, String>,
    exports: &mut BTreeMap<String, String>,
) -> Result<Value> {
    let descriptor = &kit.descriptor;
    let values = resolve_args(descriptor, supplied)?;
    for (name, value) in &values {
        if let Some(var) = &descriptor.args[name].env {
            exports.insert(var.clone(), value.clone());
        }
    }
    expand_args(&descriptor.raw, &descriptor.args, &values)
}

/// Expands `kit.env` and re-reads the result. Every declaration validates
/// here, selected or not.
fn decode_kit(raw: &Value, env: &ContainerEnv) -> Result<Descriptor> {
    let descriptor = Descriptor::from_value(expand_env(raw, env)?)?;
    validate_blocks(&descriptor)?;
    descriptor.entries().try_for_each(validate_entry)?;
    Ok(descriptor)
}

/// Decides every declaration, recording each outcome, and returns the
/// selected entries with their Kits' labels. A required declaration the
/// host rejects refuses the whole composition.
fn select<'a>(
    decoded: &'a [Decoded<'_>],
    host: &Host<'_>,
    out: &mut Composition,
) -> Result<Vec<(&'a str, &'a Entry)>> {
    let mut selected = Vec::new();
    for d in decoded {
        let reference = &d.kit.reference;
        for item in &d.descriptor.capabilities {
            let (path, name, optional) = match item {
                Item::Entry(e) => (&e.path, &e.name, e.is_optional),
                Item::Group(g) => (&g.path, &g.name, g.is_optional),
            };
            let members = item.members();
            let decisions: Vec<Option<String>> = members.iter().map(|m| decide(m, host)).collect();
            let reasons: Vec<String> = members
                .iter()
                .zip(&decisions)
                .filter_map(|(m, dec)| {
                    dec.as_ref()
                        .map(|r| format!("{} ({}): {r}", m.path, m.type_))
                })
                .collect();
            let record = SelectionRecord {
                path: path.clone(),
                name: name.clone(),
                source: Source {
                    kit: reference.clone(),
                    path: path.clone(),
                },
                members: members.iter().map(|m| m.path.clone()).collect(),
                member_sources: members
                    .iter()
                    .map(|m| Source {
                        kit: reference.clone(),
                        path: m.path.clone(),
                    })
                    .collect(),
                rejected: members
                    .iter()
                    .zip(&decisions)
                    .filter(|(_, d)| d.is_some())
                    .map(|(m, _)| m.path.clone())
                    .collect(),
                decisions: decisions
                    .into_iter()
                    .map(|message| Decision {
                        is_accepted: message.is_none(),
                        message,
                    })
                    .collect(),
            };
            if reasons.is_empty() {
                selected.extend(members.iter().map(|m| (d.label.as_str(), m)));
                out.selection.selected.push(record);
                continue;
            }
            let reason = reasons.join("; ");
            if !optional {
                let what = match item {
                    Item::Entry(_) => String::new(),
                    Item::Group(g) => format!(" group {:?}", g.name.as_deref().unwrap_or("group")),
                };
                return Err(refused(format!(
                    "{}: {path}{what} is required: {reason}",
                    d.label
                )));
            }
            out.skipped.extend(members.iter().map(|m| Skipped {
                kit: d.label.clone(),
                path: m.path.clone(),
                type_: m.type_.to_string(),
                reason: reason.clone(),
            }));
            out.selection.skipped.push(record);
        }
    }
    Ok(selected)
}

fn is_singleton(t: &CapType) -> bool {
    t.namespace == crate::NAMESPACE
        && matches!(
            t.name.as_str(),
            "network-policy"
                | "resources"
                | "privileged"
                | "kit-registry"
                | "agent-sessions"
                | "agent-interactive-sessions"
                | "lifecycle"
                | "sbx"
                | "long-running"
                | "git-identity"
        )
}

/// Singleton and duplicate constraints hold within each declaration block:
/// the ordinary top-level entries together, and each group on its own.
fn validate_blocks(descriptor: &Descriptor) -> Result<()> {
    let mut blocks: Vec<Vec<&Entry>> = vec![Vec::new()];
    for item in &descriptor.capabilities {
        match item {
            Item::Entry(e) => blocks[0].push(e),
            Item::Group(g) => blocks.push(g.members.iter().collect()),
        }
    }
    blocks.iter().try_for_each(|block| validate_block(block))
}

fn validate_block(block: &[&Entry]) -> Result<()> {
    let mut seen_exact = BTreeSet::new();
    let mut seen_singletons = BTreeSet::new();
    let mut network_version = None;
    for e in block {
        if !seen_exact.insert((&e.type_, e.is_optional, e.config.to_string())) {
            return Err(invalid(format!(
                "{}: duplicates an earlier {} entry",
                e.path, e.type_
            )));
        }
        if is_singleton(&e.type_) && !seen_singletons.insert(&e.type_) {
            return Err(invalid(format!("{}: {} may appear once", e.path, e.type_)));
        }
        if (e.type_.is("network-policy", 1) || e.type_.is("network-policy", 2))
            && *network_version.get_or_insert(e.type_.version) != e.type_.version
        {
            return Err(invalid(format!(
                "{}: network-policy@1 and @2 are exclusive",
                e.path
            )));
        }
    }
    Ok(())
}

fn validate_entry(entry: &Entry) -> Result<()> {
    let t = &entry.type_;
    if t.namespace != crate::NAMESPACE {
        return Ok(());
    }
    match (t.name.as_str(), t.version) {
        ("network-policy", 1 | 2) => NetworkPolicyConfig::decode(entry).map(drop),
        ("credential", 1) => CredentialConfig::decode(entry).map(drop),
        ("volume", 1) => VolumeConfig::decode(entry).map(drop),
        ("lifecycle", 1) => LifecycleConfig::decode(entry).map(drop),
        ("resources", 1) => ResourcesConfig::decode(entry).map(drop),
        ("port", 1) => PortConfig::decode(entry).map(drop),
        ("long-running" | "sbx" | "privileged" | "kit-registry" | "git-identity", 1) => {
            require_no_config(entry)
        }
        _ => Ok(()),
    }
}

/// `None` accepts the entry; `Some(reason)` rejects it.
fn decide(entry: &Entry, host: &Host<'_>) -> Option<String> {
    let type_name = entry.type_.to_string();
    if !host.claimed.contains(&type_name.as_str()) {
        return Some(format!(
            "capability type {type_name} is not supported by this runtime"
        ));
    }
    if host.rejected.contains(&type_name) {
        return Some(format!(
            "capability type {type_name} is rejected by host policy"
        ));
    }
    if entry.type_.is("credential", 1) {
        let cfg = CredentialConfig::decode(entry).ok()?;
        if cfg.oauth.is_some() {
            return Some("OAuth credentials are not supported by this runtime".into());
        }
        if !host.bound_services.contains(&cfg.service) {
            return Some(format!(
                "no credential is bound for service {:?}",
                cfg.service
            ));
        }
    }
    None
}

/// Reconciles the selected entries into the composition, tracking which Kit
/// owns each thing only one may own.
#[derive(Default)]
struct Merge<'s> {
    credential_owners: BTreeMap<(String, Phase), &'s str>,
    volumes: BTreeMap<String, VolumeRequest>,
    /// File path to its owner's label and declaration path.
    files: BTreeMap<String, (&'s str, &'s str)>,
    /// The interactive tail's owner label and declaration path.
    interactive_owner: Option<(&'s str, &'s str)>,
    hook_index: BTreeMap<&'s str, usize>,
}

impl<'s> Merge<'s> {
    fn run(mut self, out: &mut Composition, selected: &[(&'s str, &'s Entry)]) -> Result<()> {
        for &(label, entry) in selected {
            let t = &entry.type_;
            if t.namespace != crate::NAMESPACE {
                continue;
            }
            match (t.name.as_str(), t.version) {
                ("network-policy", 1 | 2) => {
                    let cfg = NetworkPolicyConfig::decode(entry)?;
                    out.network.is_declared = true;
                    union_phase(
                        &mut out.network.install,
                        cfg.install.allow,
                        cfg.install.deny,
                    );
                    union_phase(
                        &mut out.network.runtime,
                        cfg.runtime.allow,
                        cfg.runtime.deny,
                    );
                }
                ("credential", 1) => {
                    self.credential(out, label, CredentialConfig::decode(entry)?)?
                }
                ("volume", 1) => self.volume(label, VolumeConfig::decode(entry)?)?,
                ("lifecycle", 1) => self.lifecycle(out, label, entry)?,
                ("resources", 1) => {
                    merge_resources(&mut out.resources, ResourcesConfig::decode(entry)?)
                }
                ("port", 1) => merge_port(&mut out.ports, PortConfig::decode(entry)?),
                ("long-running", 1) => out.is_long_running = true,
                ("sbx", 1) => out.is_sbx_requested = true,
                _ => {}
            }
        }
        out.volumes = self.volumes.into_values().collect();
        check_injections(out)
    }

    fn credential(
        &mut self,
        out: &mut Composition,
        label: &'s str,
        cfg: CredentialConfig,
    ) -> Result<()> {
        for phase in cfg.phases.iter() {
            if let Some(owner) = self
                .credential_owners
                .insert((cfg.service.clone(), phase), label)
            {
                return Err(refused(format!(
                    "{label}: credential {:?} in phase {phase:?} is already requested by {owner}; one owner per service and phase",
                    cfg.service
                )));
            }
        }
        let key = cfg
            .api_key
            .expect("selection rejects credentials without an apiKey");
        out.credentials.push(Credential {
            service: cfg.service,
            phases: cfg.phases,
            variable: (!key.name.is_empty()).then_some(key.name),
            is_proxy_managed: key.is_proxy_managed,
            inject: key.inject,
            kit: label.to_string(),
        });
        Ok(())
    }

    fn volume(&mut self, label: &str, cfg: VolumeConfig) -> Result<()> {
        match self.volumes.get(&cfg.path) {
            Some(existing) if existing.config != cfg => Err(refused(format!(
                "{label}: volume at {} differs from the one {} declared; two storage configurations at one path cannot merge",
                cfg.path, existing.kit
            ))),
            Some(_) => Ok(()),
            None => {
                self.volumes.insert(
                    cfg.path.clone(),
                    VolumeRequest {
                        config: cfg,
                        kit: label.to_string(),
                    },
                );
                Ok(())
            }
        }
    }

    fn lifecycle(&mut self, out: &mut Composition, label: &'s str, entry: &'s Entry) -> Result<()> {
        let cfg = LifecycleConfig::decode(entry)?;
        let next = self.hook_index.entry(label).or_insert(0);
        let install = cfg.install.into_iter().map(|h| (HookPhase::Install, h));
        let startup = cfg.startup.into_iter().map(|h| (HookPhase::Startup, h));
        for (phase, hook) in install.chain(startup) {
            let user = hook.user.unwrap_or_else(|| match phase {
                HookPhase::Install => "root".into(),
                HookPhase::Startup => out.agent_user().to_string(),
            });
            out.hooks.push(Hook {
                phase,
                argv: hook.command.into_argv(),
                user,
                env: hook.env,
                is_background: hook.is_background,
                description: hook.description,
                kit: label.to_string(),
                index: *next,
            });
            *next += 1;
        }
        for file in cfg.files {
            if let Some((owner, at)) = self.files.insert(file.path.clone(), (label, &entry.path)) {
                return Err(refused(format!(
                    "file {} is written by both {owner} ({at}) and {label} ({}); two declarations cannot own one path",
                    file.path, entry.path
                )));
            }
            out.files.push(FileEntry {
                path: file.path,
                content: file.content,
                mode: file.mode.map(|m| m.0),
                is_overwriting: file.overwrite.unwrap_or(true),
                kit: label.to_string(),
            });
        }
        if let Some(tail) = cfg.interactive {
            if let Some((owner, at)) = self.interactive_owner.replace((label, &entry.path)) {
                return Err(refused(format!(
                    "interactive is declared by both {owner} ({at}) and {label} ({}); it replaces the launch argv, so only one declaration can own it",
                    entry.path
                )));
            }
            out.interactive = Some(tail);
        }
        Ok(())
    }
}

fn merge_resources(resources: &mut Resources, cfg: ResourcesConfig) {
    if let Some(cpu) = cfg.cpu {
        resources.cpu = Some(resources.cpu.map_or(cpu, |c| c.max(cpu)));
    }
    if let Some(memory) = cfg.memory {
        let mib = memory.mib_ceil();
        resources.memory_mib = Some(resources.memory_mib.map_or(mib, |m| m.max(mib)));
    }
    if cfg.gpu.is_some() {
        resources.gpu = cfg.gpu;
    }
}

fn merge_port(ports: &mut Vec<PortRequest>, cfg: PortConfig) {
    match ports
        .iter_mut()
        .find(|p| p.container == cfg.container && p.transport == cfg.transport)
    {
        Some(existing) => {
            if existing.name.is_none() {
                existing.name = cfg.name;
            }
        }
        None => ports.push(PortRequest {
            name: cfg.name,
            container: cfg.container,
            transport: cfg.transport,
        }),
    }
}

/// Every injection target must be reachable in each phase its credential
/// is present in.
fn check_injections(out: &Composition) -> Result<()> {
    for cred in &out.credentials {
        for inject in &cred.inject {
            for phase in cred.phases.iter() {
                if !out.network.phase(phase).is_host_allowed(&inject.domain) {
                    return Err(refused(format!(
                        "{}: credential {:?} injects into {} but the {phase:?} network policy does not allow that host",
                        cred.kit, cred.service, inject.domain
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Unions one Kit's lists into a phase. A bounded allow entry whose hosts are
/// all granted outright adds nothing and is dropped.
fn union_phase(phase: &mut NetworkPhase, allow: Vec<HostEntry>, deny: Vec<HostEntry>) {
    for e in allow {
        if !phase.allow.contains(&e) {
            phase.allow.push(e);
        }
    }
    for e in deny {
        if !phase.deny.contains(&e) {
            phase.deny.push(e);
        }
    }
    let unbounded: Vec<HostEntry> = phase
        .allow
        .iter()
        .filter(|e| !e.is_bounded())
        .cloned()
        .collect();
    phase.allow.retain(|e| {
        !e.is_bounded()
            || !e.hosts.iter().all(|h| {
                unbounded
                    .iter()
                    .any(|u| u.hosts.iter().any(|p| is_host_match(p, h)))
            })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{Loaded, resolve};

    fn kit(reference: &str, kind: &str, body: &str) -> Loaded {
        let json = format!(r#"{{"schemaVersion":"3","kind":"{kind}",{body}}}"#);
        Loaded {
            reference: reference.into(),
            digest: format!("sha256:{reference}"),
            descriptor: Descriptor::parse(&json).unwrap(),
            image_config: ImageConfig {
                env: vec![
                    "PATH=/bin".into(),
                    "HOME=/home/agent".into(),
                    "KIT_GREETING=image".into(),
                ],
                user: "agent".into(),
                ..Default::default()
            },
            layers: vec![],
        }
    }

    fn host<'a>(claimed: &'a [&'a str], bound: &'a BTreeSet<String>) -> Host<'a> {
        Host {
            claimed,
            bound_services: bound,
            rejected: &[],
        }
    }

    #[test]
    fn network_policies_union_and_bounded_entries_drop_under_outright_grants() {
        let w = kit(
            "w",
            "workload",
            r#""capabilities":[{"type":"com.docker.sandbox/network-policy@1","config":{"runtime":{"allow":["api.github.com"]}}}]"#,
        );
        let m = kit(
            "m",
            "mixin",
            r#""capabilities":[{"type":"com.docker.sandbox/network-policy@2","config":{"install":{"allow":["example.net"]},"runtime":{"allow":[{"hosts":["api.github.com"],"methods":["GET"]},{"hosts":["example.com"],"methods":["GET"],"paths":["/allowed/**"]}],"deny":[{"hosts":["api.github.com"],"methods":["DELETE"]}]}}}]"#,
        );
        let resolved = resolve(vec![w, m]).unwrap();
        let bound = BTreeSet::new();
        let c = compose(
            &resolved,
            &Inputs::default(),
            &host(crate::KNOWN_TYPES, &bound),
        )
        .unwrap();
        assert_eq!(c.allowed_hosts(Phase::Install), vec!["example.net"]);
        assert_eq!(c.allowed_hosts(Phase::Runtime), vec!["api.github.com"]);
        let http = c.http_entries(Phase::Runtime);
        assert_eq!(http.len(), 2);
        assert!(http[0].is_denying && http[0].hosts == vec!["api.github.com"]);
        assert!(!http[1].is_denying && http[1].hosts == vec!["example.com"]);
    }

    #[test]
    fn required_unclaimed_refuses_and_optional_skips() {
        let w = kit(
            "w",
            "workload",
            r#""capabilities":[{"type":"com.docker.sandbox/usb-device@1","optional":true,"config":{"vendorId":"1"}}]"#,
        );
        let m = kit(
            "m",
            "mixin",
            r#""capabilities":[{"type":"com.example/thing@1"}]"#,
        );
        let bound = BTreeSet::new();
        let resolved = resolve(vec![w.clone(), m]).unwrap();
        let err = compose(
            &resolved,
            &Inputs::default(),
            &host(crate::KNOWN_TYPES, &bound),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Refused(m) if m.contains("com.example/thing@1")));
        let resolved = resolve(vec![w]).unwrap();
        let c = compose(
            &resolved,
            &Inputs::default(),
            &host(crate::KNOWN_TYPES, &bound),
        )
        .unwrap();
        assert_eq!(c.skipped.len(), 1);
    }

    #[test]
    fn groups_select_atomically() {
        let w = kit(
            "w",
            "workload",
            r#""capabilities":[
            {"type":"com.docker.sandbox/lifecycle@1","config":{"startup":[{"command":"printf base > /var/tmp/o"}]}},
            {"group":{"name":"Feature","optional":true,"capabilities":[{"type":"com.docker.sandbox/usb-device@1","config":{}},{"type":"com.docker.sandbox/lifecycle@1","config":{"files":[{"path":"/var/tmp/f","content":"x"}]}}]}},
            {"group":{"name":"Other","capabilities":[{"type":"com.docker.sandbox/lifecycle@1","config":{"startup":[{"command":["sh","-c","true"]}]}}]}}]"#,
        );
        let bound = BTreeSet::new();
        let resolved = resolve(vec![w]).unwrap();
        let c = compose(
            &resolved,
            &Inputs::default(),
            &host(crate::KNOWN_TYPES, &bound),
        )
        .unwrap();
        assert_eq!(c.hooks.len(), 2);
        assert!(c.files.is_empty());
        assert_eq!(c.skipped.len(), 2);
        assert_eq!(c.hooks[0].user, "agent");
        assert_eq!(c.selection.selected.len(), 2);
        let skipped = &c.selection.skipped[0];
        assert_eq!(skipped.path, "capabilities[1]");
        assert_eq!(
            skipped.rejected,
            vec!["capabilities[1].group.capabilities[0]"]
        );
        assert_eq!(skipped.members.len(), 2);
        assert_eq!(skipped.source.kit, "w");
        assert!(c.surface.storage_paths.is_empty());

        let rejected = ["com.docker.sandbox/lifecycle@1".to_string()];
        let host = Host {
            claimed: crate::KNOWN_TYPES,
            bound_services: &bound,
            rejected: &rejected,
        };
        let err = compose(&resolved, &Inputs::default(), &host).unwrap_err();
        assert!(matches!(err, crate::Error::Refused(m) if m.contains("rejected by host policy")));
    }

    #[test]
    fn args_and_env_expand_into_files() {
        let w = kit(
            "w",
            "workload",
            r#""args":{"greeting":{"default":"unset","env":"KIT_GREETING"}},"capabilities":[{"type":"com.docker.sandbox/lifecycle@1","config":{"files":[{"path":"/home/agent/.config/kit-written","content":"${{ kit.args.greeting }}"},{"path":"${{ kit.env.HOME }}/.config/env-written","content":"${{ kit.env.KIT_GREETING }}"}]}}]"#,
        );
        let bound = BTreeSet::new();
        let resolved = resolve(vec![w]).unwrap();
        let mut inputs = Inputs::default();
        inputs.args.insert("greeting".into(), "hello".into());
        let c = compose(&resolved, &inputs, &host(crate::KNOWN_TYPES, &bound)).unwrap();
        assert_eq!(c.files[0].content, "hello");
        assert_eq!(c.files[1].path, "/home/agent/.config/env-written");
        assert_eq!(c.files[1].content, "hello");
        assert_eq!(c.env.get("KIT_GREETING").unwrap(), "hello");
        inputs.env.insert("KIT_GREETING".into(), "".into());
        let c = compose(&resolved, &inputs, &host(crate::KNOWN_TYPES, &bound)).unwrap();
        assert_eq!(c.files[1].content, "");
        let mut bad = Inputs::default();
        bad.args.insert("nope".into(), "1".into());
        assert!(compose(&resolved, &bad, &host(crate::KNOWN_TYPES, &bound)).is_err());
    }

    #[test]
    fn credentials_need_bindings_and_allowed_domains() {
        let w = kit(
            "w",
            "workload",
            r#""capabilities":[
            {"type":"com.docker.sandbox/network-policy@1","config":{"runtime":{"allow":["example.com"]}}},
            {"type":"com.docker.sandbox/credential@1","config":{"service":"kit-tck","phase":"runtime","apiKey":{"name":"KIT_TCK_TOKEN","proxyManaged":true,"inject":[{"domain":"example.com","header":"Authorization","format":"Bearer %s"}]}}}]"#,
        );
        let resolved = resolve(vec![w]).unwrap();
        let none = BTreeSet::new();
        assert!(
            compose(
                &resolved,
                &Inputs::default(),
                &host(crate::KNOWN_TYPES, &none)
            )
            .is_err()
        );
        let bound: BTreeSet<String> = ["kit-tck".to_string()].into();
        let c = compose(
            &resolved,
            &Inputs::default(),
            &host(crate::KNOWN_TYPES, &bound),
        )
        .unwrap();
        assert_eq!(c.credentials[0].variable.as_deref(), Some("KIT_TCK_TOKEN"));
        assert!(
            c.credentials[0].phases.is_runtime_active && !c.credentials[0].phases.is_install_active
        );

        let bad = kit(
            "b",
            "workload",
            r#""capabilities":[
            {"type":"com.docker.sandbox/credential@1","config":{"service":"kit-tck","phase":"runtime","apiKey":{"name":"T","inject":[{"domain":"example.com","header":"Authorization"}]}}}]"#,
        );
        let resolved = resolve(vec![bad]).unwrap();
        assert!(
            compose(
                &resolved,
                &Inputs::default(),
                &host(crate::KNOWN_TYPES, &bound)
            )
            .is_err()
        );
    }

    #[test]
    fn volumes_merge_when_equal_and_conflict_otherwise() {
        let w = kit(
            "w",
            "workload",
            r#""capabilities":[{"type":"com.docker.sandbox/volume@1","config":{"path":"/data","size":"1g"}}]"#,
        );
        let same = kit(
            "s",
            "mixin",
            r#""capabilities":[{"type":"com.docker.sandbox/volume@1","config":{"path":"/data/","size":"1024m"}}]"#,
        );
        let diff = kit(
            "d",
            "mixin",
            r#""capabilities":[{"type":"com.docker.sandbox/volume@1","config":{"path":"/data","size":"2g"}}]"#,
        );
        let bound = BTreeSet::new();
        let c = compose(
            &resolve(vec![w.clone(), same]).unwrap(),
            &Inputs::default(),
            &host(crate::KNOWN_TYPES, &bound),
        )
        .unwrap();
        assert_eq!(c.volumes.len(), 1);
        assert!(
            compose(
                &resolve(vec![w, diff]).unwrap(),
                &Inputs::default(),
                &host(crate::KNOWN_TYPES, &bound)
            )
            .is_err()
        );
    }
}
