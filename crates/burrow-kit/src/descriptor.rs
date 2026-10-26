//! The descriptor grammar (SPEC-v3 §4, §6, §7).
//!
//! A descriptor is decoded from the JSON the manifest annotation carries.
//! Decoding is strict: an unknown key anywhere in the grammar is an error,
//! because a permission silently dropped is indistinguishable from one never
//! requested. Capability configs are kept as values here; the typed decode
//! happens in [`crate::config`] after arg expansion, since a parameterized
//! config is only judged once its placeholders are gone.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::names::{CapName, Constraint, Provide, is_kebab};
use crate::{Result, invalid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Workload,
    Mixin,
}

/// `<namespace>/<name>@<version>`: the identity of a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapType {
    pub namespace: String,
    pub name: String,
    pub version: u32,
}

impl CapType {
    pub fn parse(text: &str) -> Result<Self> {
        let err = || {
            invalid(format!(
                "capability type {text:?} is not <namespace>/<name>@<version>"
            ))
        };
        let (path, version) = text.rsplit_once('@').ok_or_else(err)?;
        let (namespace, name) = path.rsplit_once('/').ok_or_else(err)?;
        let ns_ok = !namespace.is_empty()
            && namespace.split('.').all(|l| {
                !l.is_empty()
                    && l.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            });
        let version: u32 = version.parse().map_err(|_| err())?;
        if !ns_ok || !is_kebab(name) {
            return Err(err());
        }
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version,
        })
    }

    pub fn is(&self, name: &str, version: u32) -> bool {
        self.namespace == crate::NAMESPACE && self.name == name && self.version == version
    }
}

impl fmt::Display for CapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}@{}", self.namespace, self.name, self.version)
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArgDecl {
    pub default: Option<String>,
    #[serde(default)]
    #[serde(rename = "required")]
    pub is_required: bool,
    pub description: Option<String>,
    #[serde(rename = "enum")]
    pub enum_: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub env: Option<String>,
    pub build_arg: Option<String>,
}

/// One ordinary capability request.
#[derive(Debug, Clone)]
pub struct Entry {
    pub type_: CapType,
    pub name: Option<String>,
    pub is_optional: bool,
    pub config: Value,
    pub declaration_blocks: Vec<String>,
    /// `capabilities[i]` or `capabilities[i].group.capabilities[j]`.
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: Option<String>,
    pub is_optional: bool,
    pub members: Vec<Entry>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub enum Item {
    Entry(Entry),
    Group(Group),
}

impl Item {
    /// The entries this declaration selects or skips together.
    pub fn members(&self) -> &[Entry] {
        match self {
            Item::Entry(e) => std::slice::from_ref(e),
            Item::Group(g) => &g.members,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Descriptor {
    pub kind: Kind,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub provides: Vec<Provide>,
    pub requires: Vec<Constraint>,
    pub integrates: Vec<Constraint>,
    pub conflicts: Vec<CapName>,
    pub args: BTreeMap<String, ArgDecl>,
    pub capabilities: Vec<Item>,
    /// The decoded document, kept so expansion can work structurally on it.
    pub raw: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawDescriptor {
    schema_version: String,
    kind: String,
    display_name: Option<String>,
    #[allow(dead_code)]
    author: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    #[allow(dead_code)]
    source_url: Option<String>,
    #[allow(dead_code)]
    icon_url: Option<String>,
    version: Option<String>,
    #[allow(dead_code)]
    licenses: Option<Vec<String>>,
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    integrates: Vec<String>,
    #[serde(default)]
    conflicts: Vec<String>,
    #[serde(default)]
    capabilities: Vec<Value>,
    #[serde(default)]
    args: BTreeMap<String, ArgDecl>,
    #[allow(dead_code)]
    build: Option<String>,
    #[allow(dead_code)]
    dockerfile: Option<String>,
    #[allow(dead_code)]
    kits: Option<Vec<Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawEntry {
    #[serde(rename = "type")]
    type_: String,
    name: Option<String>,
    optional: Option<bool>,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    config: Value,
    #[allow(dead_code)]
    source: Option<Value>,
    declaration_blocks: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroupItem {
    group: RawGroup,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawGroup {
    name: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    #[serde(rename = "optional")]
    is_optional: bool,
    capabilities: Vec<Value>,
}

impl Descriptor {
    /// Decodes the published descriptor as the annotation carries it.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: Value = serde_json::from_str(text)
            .map_err(|e| invalid(format!("kit descriptor is not JSON: {e}")))?;
        Self::from_value(raw)
    }

    pub fn from_value(raw: Value) -> Result<Self> {
        let d = RawDescriptor::deserialize(&raw)
            .map_err(|e| invalid(format!("kit descriptor: {e}")))?;
        if d.schema_version != "3" {
            return Err(invalid(format!(
                "kit descriptor schemaVersion {:?} is not \"3\"",
                d.schema_version
            )));
        }
        let kind = match d.kind.as_str() {
            "workload" | "sandbox" => Kind::Workload,
            "mixin" => Kind::Mixin,
            "set" => {
                return Err(invalid(
                    "kit descriptor kind \"set\" is an authoring form, not a published one",
                ));
            }
            other => return Err(invalid(format!("kit descriptor kind {other:?} is unknown"))),
        };
        for (key, decl) in &d.args {
            validate_arg_decl(key, decl)?;
        }
        let provides = parse_all(&d.provides, Provide::parse)?;
        let requires = parse_all(&d.requires, Constraint::parse)?;
        let integrates = parse_all(&d.integrates, Constraint::parse)?;
        let conflicts = parse_all(&d.conflicts, CapName::parse)?;
        let templated = [&d.requires, &d.integrates, &d.conflicts]
            .into_iter()
            .flatten()
            .find(|s| s.contains("${{"));
        if let Some(s) = templated {
            return Err(invalid(format!(
                "{s:?}: requires, integrates and conflicts must stay literal"
            )));
        }
        let capabilities = parse_items(&d.capabilities)?;
        Ok(Self {
            kind,
            display_name: d.display_name,
            version: d.version,
            provides,
            requires,
            integrates,
            conflicts,
            args: d.args,
            capabilities,
            raw,
        })
    }

    /// Every ordinary entry, group members included, in declaration order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.capabilities.iter().flat_map(Item::members)
    }

    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or("kit")
    }
}

fn validate_arg_decl(key: &str, decl: &ArgDecl) -> Result<()> {
    let key_ok = {
        let b = key.as_bytes();
        !b.is_empty()
            && (b[0].is_ascii_alphabetic() || b[0] == b'_')
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
    };
    if !key_ok {
        return Err(invalid(format!(
            "arg name {key:?} must match ^[A-Za-z_][A-Za-z0-9_]*$"
        )));
    }
    if decl.is_required && decl.default.is_some() {
        return Err(invalid(format!(
            "arg {key:?}: default and required are mutually exclusive"
        )));
    }
    if decl.enum_.is_some() && decl.pattern.is_some() {
        return Err(invalid(format!(
            "arg {key:?}: enum and pattern are mutually exclusive"
        )));
    }
    if decl.env.is_some() && decl.build_arg.is_some() {
        return Err(invalid(format!(
            "arg {key:?}: env and buildArg are mutually exclusive"
        )));
    }
    if let Some(p) = &decl.pattern {
        regex::Regex::new(p)
            .map_err(|e| invalid(format!("arg {key:?}: pattern does not compile: {e}")))?;
    }
    Ok(())
}

fn parse_all<T>(texts: &[String], parse: impl Fn(&str) -> Result<T>) -> Result<Vec<T>> {
    texts.iter().map(|s| parse(s)).collect()
}

fn parse_items(items: &[Value]) -> Result<Vec<Item>> {
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let path = format!("capabilities[{i}]");
            if item.get("group").is_some() {
                parse_group(item, path).map(Item::Group)
            } else {
                parse_entry(item, path).map(|(entry, _)| Item::Entry(entry))
            }
        })
        .collect()
}

fn parse_group(item: &Value, path: String) -> Result<Group> {
    let RawGroupItem { group } =
        RawGroupItem::deserialize(item).map_err(|e| invalid(format!("{path}: {e}")))?;
    if group.capabilities.is_empty() {
        return Err(invalid(format!("{path}: a group must have members")));
    }
    let mut members = Vec::with_capacity(group.capabilities.len());
    for (j, m) in group.capabilities.iter().enumerate() {
        let member_path = format!("{path}.group.capabilities[{j}]");
        if m.get("group").is_some() {
            return Err(invalid(format!("{member_path}: groups do not nest")));
        }
        let (entry, stated_optional) = parse_entry(m, member_path)?;
        if stated_optional {
            return Err(invalid(format!(
                "{}: group members cannot state optional",
                entry.path
            )));
        }
        if !entry.declaration_blocks.is_empty() {
            return Err(invalid(format!(
                "{}: group members cannot state declarationBlocks",
                entry.path
            )));
        }
        members.push(entry);
    }
    Ok(Group {
        name: group.name,
        is_optional: group.is_optional,
        members,
        path,
    })
}

/// Returns the entry and whether `optional` was stated at all, which a group
/// member may not do even as false.
fn parse_entry(value: &Value, path: String) -> Result<(Entry, bool)> {
    let e = RawEntry::deserialize(value).map_err(|e| invalid(format!("{path}: {e}")))?;
    let type_ = CapType::parse(&e.type_).map_err(|err| err.prefixed(&path))?;
    let blocks = e.declaration_blocks.unwrap_or_default();
    if blocks.iter().any(|b| b.is_empty()) {
        return Err(invalid(format!(
            "{path}: declarationBlocks entries must be nonempty"
        )));
    }
    let mut seen = BTreeSet::new();
    if !blocks.iter().all(|b| seen.insert(b)) {
        return Err(invalid(format!(
            "{path}: declarationBlocks entries must be distinct"
        )));
    }
    let entry = Entry {
        type_,
        name: e.name.filter(|n| !n.is_empty()),
        is_optional: e.optional.unwrap_or(false),
        config: e.config,
        declaration_blocks: blocks,
        path,
    };
    Ok((entry, e.optional.is_some()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_published_descriptor() {
        let d = Descriptor::parse(
            r#"{"schemaVersion":"3","kind":"mixin","displayName":"GitHub CLI","provides":["gh@2.101.0"],
            "capabilities":[{"type":"com.docker.sandbox/network-policy@2","config":{"runtime":{"allow":["github.com"]}}},
            {"type":"com.docker.sandbox/credential@1","optional":true,"config":{"service":"github","phase":["runtime"]}}]}"#,
        )
        .unwrap();
        assert_eq!(d.kind, Kind::Mixin);
        assert_eq!(d.entries().count(), 2);
        assert!(d.entries().nth(1).unwrap().is_optional);
        assert_eq!(d.entries().next().unwrap().path, "capabilities[0]");
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(Descriptor::parse(r#"{"schemaVersion":"3","kind":"mixin","bogus":1}"#).is_err());
        assert!(Descriptor::parse(r#"{"schemaVersion":"2","kind":"mixin"}"#).is_err());
        assert!(Descriptor::parse(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[{"type":"com.docker.sandbox/sbx@1","extra":true}]}"#
        )
        .is_err());
    }

    #[test]
    fn groups() {
        let d = Descriptor::parse(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[
              {"type":"com.docker.sandbox/lifecycle@1","config":{}},
              {"group":{"name":"Feature","optional":true,"capabilities":[{"type":"com.docker.sandbox/volume@1","config":{"path":"/v"}}]}}]}"#,
        )
        .unwrap();
        assert_eq!(d.entries().count(), 2);
        assert_eq!(
            d.entries().nth(1).unwrap().path,
            "capabilities[1].group.capabilities[0]"
        );
        assert!(Descriptor::parse(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[{"group":{"capabilities":[{"type":"com.docker.sandbox/sbx@1","optional":false}]}}]}"#
        )
        .is_err());
        assert!(Descriptor::parse(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[{"group":{"capabilities":[]}}]}"#
        )
        .is_err());
    }

    #[test]
    fn cap_types() {
        let t = CapType::parse("com.docker.sandbox/network-policy@2").unwrap();
        assert!(t.is("network-policy", 2));
        assert_eq!(t.to_string(), "com.docker.sandbox/network-policy@2");
        assert!(CapType::parse("network-policy@2").is_err());
        assert!(CapType::parse("com.docker.sandbox/Network@1").is_err());
    }
}
