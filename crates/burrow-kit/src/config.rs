//! Typed configs of the well-known capability types this crate composes.
//! Each decodes strictly from an expanded entry's `config`.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::compose::{CredentialPhase, Inject};
use crate::descriptor::Entry;
use crate::names::is_kebab;
use crate::{Result, invalid};

fn decode<T: DeserializeOwned>(entry: &Entry) -> Result<T> {
    let decoded = if entry.config.is_null() {
        T::deserialize(&Value::Object(Map::new()))
    } else {
        T::deserialize(&entry.config)
    };
    decoded.map_err(|e| invalid(format!("{} ({}): {e}", entry.path, entry.type_)))
}

/// A string that may have arrived as a number through whole-value arg
/// expansion: `size: ${{ kit.args.size }}` with a value of `1024`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Text(pub String);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        match v {
            Value::String(s) => Ok(Text(s)),
            Value::Number(n) => Ok(Text(n.to_string())),
            other => Err(serde::de::Error::custom(format!(
                "expected a string, got {other}"
            ))),
        }
    }
}

/// An entry of a network-policy allow or deny list: a bare host, or an
/// object bounding hosts to HTTP methods and paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub hosts: Vec<String>,
    /// Empty means every method.
    pub methods: Vec<String>,
    /// Empty means every path.
    pub paths: Vec<String>,
}

impl HostEntry {
    pub fn is_bounded(&self) -> bool {
        !self.methods.is_empty() || !self.paths.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBounded {
    hosts: Vec<String>,
    methods: Option<Vec<String>>,
    paths: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for HostEntry {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let v = Value::deserialize(d)?;
        match v {
            Value::String(host) => Ok(HostEntry {
                hosts: vec![host],
                methods: vec![],
                paths: vec![],
            }),
            Value::Object(_) => {
                let raw: RawBounded = serde_json::from_value(v).map_err(D::Error::custom)?;
                if raw.hosts.is_empty() {
                    return Err(D::Error::custom("hosts must be non-empty"));
                }
                if raw.methods.as_ref().is_some_and(Vec::is_empty) {
                    return Err(D::Error::custom("methods must be non-empty when stated"));
                }
                if raw.paths.as_ref().is_some_and(Vec::is_empty) {
                    return Err(D::Error::custom("paths must be non-empty when stated"));
                }
                let methods = raw.methods.unwrap_or_default();
                let paths = raw.paths.unwrap_or_default();
                if !paths.is_empty() && methods.is_empty() {
                    return Err(D::Error::custom("paths requires methods"));
                }
                for m in &methods {
                    let ok = !m.is_empty()
                        && m.bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
                    if !ok {
                        return Err(D::Error::custom(format!(
                            "method {m:?} is not an uppercase token"
                        )));
                    }
                }
                if methods.iter().any(|m| m == "ANY") && methods.len() > 1 {
                    return Err(D::Error::custom("ANY must be the only method"));
                }
                for p in &paths {
                    if !p.starts_with('/') {
                        return Err(D::Error::custom(format!("path {p:?} must start with '/'")));
                    }
                }
                Ok(HostEntry {
                    hosts: raw.hosts,
                    methods,
                    paths,
                })
            }
            other => Err(D::Error::custom(format!(
                "expected a host or an entry object, got {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseLists {
    #[serde(default)]
    pub allow: Vec<HostEntry>,
    #[serde(default)]
    pub deny: Vec<HostEntry>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyConfig {
    #[serde(default)]
    pub install: PhaseLists,
    #[serde(default)]
    pub runtime: PhaseLists,
}

impl NetworkPolicyConfig {
    pub fn decode(entry: &Entry) -> Result<Self> {
        let cfg: Self = decode(entry)?;
        let v1 = entry.type_.version == 1;
        for phase in [&cfg.install, &cfg.runtime] {
            for e in phase.allow.iter().chain(&phase.deny) {
                if v1 && e.is_bounded() {
                    return Err(invalid(format!(
                        "{}: network-policy@1 entries are bare hosts",
                        entry.path
                    )));
                }
            }
            for e in &phase.allow {
                if e.is_bounded() && e.hosts.iter().any(|h| h.contains('*')) {
                    return Err(invalid(format!(
                        "{}: a bounded allow entry must name its hosts literally",
                        entry.path
                    )));
                }
            }
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApiKeyConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    #[serde(rename = "proxyManaged")]
    pub is_proxy_managed: bool,
    #[serde(default)]
    pub inject: Vec<Inject>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawCredential {
    service: String,
    phase: OneOrMany,
    api_key: Option<ApiKeyConfig>,
    oauth: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct CredentialConfig {
    pub service: String,
    pub phases: CredentialPhase,
    pub api_key: Option<ApiKeyConfig>,
    pub oauth: Option<Value>,
}

impl CredentialConfig {
    pub fn decode(entry: &Entry) -> Result<Self> {
        let raw: RawCredential = decode(entry)?;
        if !is_kebab(&raw.service) {
            return Err(invalid(format!(
                "{}: service {:?} must be lowercase kebab-case",
                entry.path, raw.service
            )));
        }
        let listed = match raw.phase {
            OneOrMany::One(p) => vec![p],
            OneOrMany::Many(ps) => ps,
        };
        if listed.is_empty() {
            return Err(invalid(format!("{}: phase must be non-empty", entry.path)));
        }
        let mut phases = CredentialPhase {
            is_install_active: false,
            is_runtime_active: false,
        };
        for p in &listed {
            let slot = match p.as_str() {
                "install" => &mut phases.is_install_active,
                "runtime" => &mut phases.is_runtime_active,
                _ => {
                    return Err(invalid(format!(
                        "{}: phase {p:?} is not install or runtime",
                        entry.path
                    )));
                }
            };
            if std::mem::replace(slot, true) {
                return Err(invalid(format!(
                    "{}: phase {p:?} is listed twice",
                    entry.path
                )));
            }
        }
        if raw.api_key.is_none() && raw.oauth.is_none() {
            return Err(invalid(format!(
                "{}: one of apiKey or oauth must be declared",
                entry.path
            )));
        }
        if let Some(key) = &raw.api_key {
            if key.name.is_empty() && key.inject.is_empty() {
                return Err(invalid(format!(
                    "{}: apiKey needs a name or inject rules",
                    entry.path
                )));
            }
            for rule in &key.inject {
                if rule.domain.is_empty() {
                    return Err(invalid(format!(
                        "{}: inject domain is required",
                        entry.path
                    )));
                }
                let has_header = rule.header.is_some();
                let has_scheme = rule.scheme.is_some();
                if has_header == has_scheme {
                    return Err(invalid(format!(
                        "{}: an inject rule sets a header or a scheme",
                        entry.path
                    )));
                }
            }
        }
        Ok(Self {
            service: raw.service,
            phases,
            api_key: raw.api_key,
            oauth: raw.oauth,
        })
    }
}

/// A byte size such as `512m`, `2g` or `1gib`; suffixes are powers of 1024.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn parse(text: &str) -> Result<Self> {
        let t = text.trim().to_ascii_lowercase();
        let digits_end = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
        let (num, unit) = t.split_at(digits_end);
        let n: u64 = num
            .parse()
            .map_err(|_| invalid(format!("byte size {text:?} has no number")))?;
        let unit = unit.trim_end_matches('b').trim_end_matches('i');
        let mult: u64 = match unit {
            "" => 1,
            "k" => 1 << 10,
            "m" => 1 << 20,
            "g" => 1 << 30,
            "t" => 1 << 40,
            _ => return Err(invalid(format!("byte size {text:?} has an unknown unit"))),
        };
        n.checked_mul(mult)
            .map(ByteSize)
            .ok_or_else(|| invalid(format!("byte size {text:?} overflows")))
    }

    pub fn mib_ceil(self) -> u64 {
        self.0.div_ceil(1 << 20)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVolume {
    path: String,
    size: Option<Text>,
    #[serde(default)]
    #[serde(rename = "tmpfs")]
    is_tmpfs: bool,
    mode: Option<Text>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VolumeConfig {
    pub path: String,
    pub size: Option<ByteSize>,
    pub is_tmpfs: bool,
    /// Octal permissions as written, e.g. `1777`.
    pub mode: Option<String>,
}

impl VolumeConfig {
    pub fn decode(entry: &Entry) -> Result<Self> {
        let raw: RawVolume = decode(entry)?;
        let path = clean_path(&raw.path).ok_or_else(|| {
            invalid(format!(
                "{}: path {:?} must be absolute",
                entry.path, raw.path
            ))
        })?;
        let size = raw.size.map(|s| ByteSize::parse(&s.0)).transpose()?;
        let mode = raw.mode.map(|m| parse_mode(&m.0)).transpose()?;
        Ok(Self {
            path,
            size,
            is_tmpfs: raw.is_tmpfs,
            mode,
        })
    }
}

pub fn parse_mode(text: &str) -> Result<String> {
    let digits = text
        .strip_prefix('0')
        .filter(|rest| rest.len() >= 3)
        .unwrap_or(text);
    let ok = (3..=4).contains(&digits.len()) && digits.bytes().all(|b| (b'0'..=b'7').contains(&b));
    if !ok {
        return Err(invalid(format!("mode {text:?} is not octal")));
    }
    Ok(digits.to_string())
}

/// A cleaned absolute path: no `.` or `..` segments, no doubled or trailing
/// separators. `None` when the path is not absolute or is `/`.
pub fn clean_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains('\0') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("/{}", parts.join("/")))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Command {
    Shell(String),
    Argv(Vec<String>),
}

impl Command {
    /// The argv to exec. A string runs via `sh -c`.
    pub fn into_argv(self) -> Vec<String> {
        match self {
            Command::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s],
            Command::Argv(a) => a,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    pub command: Command,
    pub user: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub description: Option<String>,
    #[serde(default)]
    #[serde(rename = "background")]
    pub is_background: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub path: String,
    #[serde(default)]
    pub content: String,
    /// Normalized by [`parse_mode`] once decoded.
    pub mode: Option<Text>,
    pub overwrite: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleConfig {
    #[serde(default)]
    pub install: Vec<HookConfig>,
    #[serde(default)]
    pub startup: Vec<HookConfig>,
    #[serde(default)]
    pub files: Vec<FileConfig>,
    pub interactive: Option<Vec<String>>,
}

impl LifecycleConfig {
    pub fn decode(entry: &Entry) -> Result<Self> {
        let mut cfg: Self = decode(entry)?;
        if cfg.install.iter().any(|h| h.is_background) {
            return Err(invalid(format!(
                "{}: install hooks cannot run in the background",
                entry.path
            )));
        }
        for hook in cfg.install.iter().chain(&cfg.startup) {
            if matches!(&hook.command, Command::Argv(a) if a.is_empty()) {
                return Err(invalid(format!(
                    "{}: a hook command must not be empty",
                    entry.path
                )));
            }
        }
        for file in &mut cfg.files {
            if !file.path.starts_with('/') {
                return Err(invalid(format!(
                    "{}: file path {:?} must be absolute",
                    entry.path, file.path
                )));
            }
            if let Some(m) = &mut file.mode {
                m.0 = parse_mode(&m.0)?;
            }
        }
        Ok(cfg)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResources {
    cpu: Option<f64>,
    memory: Option<Text>,
    gpu: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResourcesConfig {
    pub cpu: Option<f64>,
    pub memory: Option<ByteSize>,
    pub gpu: Option<String>,
}

impl ResourcesConfig {
    pub fn decode(entry: &Entry) -> Result<Self> {
        let raw: RawResources = decode(entry)?;
        if raw.cpu.is_some_and(|c| c < 0.0 || !c.is_finite()) {
            return Err(invalid(format!("{}: cpu must be non-negative", entry.path)));
        }
        let memory = raw.memory.map(|m| ByteSize::parse(&m.0)).transpose()?;
        Ok(Self {
            cpu: raw.cpu,
            memory,
            gpu: raw.gpu,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPort {
    name: Option<String>,
    container: u32,
    #[serde(default)]
    transport: String,
}

#[derive(Debug, Clone)]
pub struct PortConfig {
    pub name: Option<String>,
    pub container: u16,
    pub transport: String,
}

impl PortConfig {
    pub fn decode(entry: &Entry) -> Result<Self> {
        let raw: RawPort = decode(entry)?;
        let container = u16::try_from(raw.container)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| {
                invalid(format!(
                    "{}: container port {} is out of range",
                    entry.path, raw.container
                ))
            })?;
        let transport = if raw.transport.is_empty() {
            "tcp".into()
        } else {
            raw.transport
        };
        if transport != "tcp" && transport != "udp" {
            return Err(invalid(format!(
                "{}: transport {transport:?} is not tcp or udp",
                entry.path
            )));
        }
        Ok(Self {
            name: raw.name,
            container,
            transport,
        })
    }
}

/// Config-less types reject every config value, an empty map included.
pub fn require_no_config(entry: &Entry) -> Result<()> {
    if entry.config.is_null() {
        return Ok(());
    }
    Err(invalid(format!(
        "{}: {} takes no config",
        entry.path, entry.type_
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes() {
        assert_eq!(ByteSize::parse("512m").unwrap().0, 512 << 20);
        assert_eq!(
            ByteSize::parse("2g").unwrap(),
            ByteSize::parse("2GiB").unwrap()
        );
        assert_eq!(ByteSize::parse("1024").unwrap().0, 1024);
        assert_eq!(ByteSize::parse("1gib").unwrap().mib_ceil(), 1024);
        assert!(ByteSize::parse("1x").is_err());
    }

    #[test]
    fn paths_and_modes() {
        assert_eq!(clean_path("/a//b/./c/").unwrap(), "/a/b/c");
        assert!(clean_path("/a/../b").is_none());
        assert!(clean_path("/").is_none());
        assert!(clean_path("a").is_none());
        assert_eq!(parse_mode("0755").unwrap(), "755");
        assert_eq!(parse_mode("1777").unwrap(), "1777");
        assert!(parse_mode("999").is_err());
    }

    #[test]
    fn host_entries() {
        let e: HostEntry = serde_json::from_str(r#""example.com""#).unwrap();
        assert!(!e.is_bounded());
        let e: HostEntry =
            serde_json::from_str(r#"{"hosts":["a.com"],"methods":["GET"],"paths":["/x/**"]}"#)
                .unwrap();
        assert!(e.is_bounded());
        assert!(
            serde_json::from_str::<HostEntry>(r#"{"hosts":["a.com"],"paths":["/x"]}"#).is_err()
        );
        assert!(
            serde_json::from_str::<HostEntry>(r#"{"hosts":["a.com"],"methods":["get"]}"#).is_err()
        );
        assert!(serde_json::from_str::<HostEntry>(r#"{"hosts":["a.com"],"methods":[]}"#).is_err());
        assert!(
            serde_json::from_str::<HostEntry>(r#"{"hosts":["a.com"],"methods":["ANY","GET"]}"#)
                .is_err()
        );
    }
}
