//! The permission surface (SPEC-v3 §7.4): everything a composition asks the
//! host to grant, normalized so two compositions compare as sets. The field
//! names and entry spellings follow the spec library's `Surface`, which is
//! what the conformance suite decodes.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::compose::{Composition, Phase};
use crate::config::HostEntry;
use crate::descriptor::Entry;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Surface {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_install_allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_install_deny: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_runtime_allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_runtime_deny: Vec<String>,
    #[serde(
        rename = "networkInstallHTTPAllow",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_install_http_allow: Vec<String>,
    #[serde(
        rename = "networkInstallHTTPDeny",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_install_http_deny: Vec<String>,
    #[serde(
        rename = "networkRuntimeHTTPAllow",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_runtime_http_allow: Vec<String>,
    #[serde(
        rename = "networkRuntimeHTTPDeny",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub network_runtime_http_deny: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credentials_install: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credentials_runtime: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub storage_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(rename = "privileged")]
    pub is_privileged: bool,
    /// One entry per other selected request: the type, with a digest of
    /// its config when it has one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
}

/// Types that run on the entrypoint's trust plane and grant nothing.
fn is_inert(entry: &Entry) -> bool {
    let t = &entry.type_;
    t.namespace == crate::NAMESPACE
        && matches!(
            (t.name.as_str(), t.version),
            ("network-policy", 1 | 2)
                | ("credential", 1)
                | ("volume", 1)
                | ("port", 1)
                | ("resources", 1)
                | ("lifecycle", 1)
                | ("agent-context", 1 | 2)
                | ("agent-sessions", 1)
                | ("agent-interactive-sessions", 1)
                | ("acp", 1)
                | ("sbx", 1)
                | ("long-running", 1)
        )
}

/// What one selected entry of an "other" type renders as.
pub fn service_entry(entry: &Entry) -> Option<String> {
    if is_inert(entry) {
        return None;
    }
    if entry.type_.is("privileged", 1) {
        return None;
    }
    if entry.config.is_null() || entry.config.as_object().is_some_and(|o| o.is_empty()) {
        return Some(entry.type_.to_string());
    }
    let canonical = serde_json::to_vec(&entry.config).unwrap_or_default();
    let digest = Sha256::digest(&canonical);
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    Some(format!("{}+{hex}", entry.type_))
}

/// One atomic grant per method, host and path. An unbounded entry is every
/// method on every path, and `ANY` stays the wildcard it is.
fn http_entries(entries: &[HostEntry]) -> Vec<String> {
    let mut out = Vec::new();
    for e in entries {
        let methods: Vec<&str> = if e.methods.is_empty() || e.methods.iter().any(|m| m == "ANY") {
            vec!["ANY"]
        } else {
            e.methods.iter().map(String::as_str).collect()
        };
        let paths: Vec<&str> = if e.paths.is_empty() {
            vec!["/**"]
        } else {
            e.paths.iter().map(String::as_str).collect()
        };
        for host in &e.hosts {
            for m in &methods {
                for p in &paths {
                    out.push(format!("{m} {host}{p}"));
                }
            }
        }
    }
    out
}

fn normalized(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

impl Surface {
    pub fn of(composition: &Composition, selected_services: Vec<String>) -> Self {
        let install = composition.network.phase(Phase::Install);
        let runtime = composition.network.phase(Phase::Runtime);
        let mut credentials_install = Vec::new();
        let mut credentials_runtime = Vec::new();
        for cred in &composition.credentials {
            if cred.phases.is_install_active {
                credentials_install.push(cred.service.clone());
            }
            if cred.phases.is_runtime_active {
                credentials_runtime.push(cred.service.clone());
            }
        }
        Self {
            network_install_allow: composition.allowed_hosts(Phase::Install),
            network_install_deny: composition.denied_hosts(Phase::Install),
            network_runtime_allow: composition.allowed_hosts(Phase::Runtime),
            network_runtime_deny: composition.denied_hosts(Phase::Runtime),
            network_install_http_allow: normalized(http_entries(&install.allow)),
            network_install_http_deny: normalized(http_entries(&install.deny)),
            network_runtime_http_allow: normalized(http_entries(&runtime.allow)),
            network_runtime_http_deny: normalized(http_entries(&runtime.deny)),
            credentials_install: normalized(credentials_install),
            credentials_runtime: normalized(credentials_runtime),
            storage_paths: normalized(
                composition
                    .volumes
                    .iter()
                    .map(|v| v.config.path.clone())
                    .collect(),
            ),
            ports: normalized(
                composition
                    .ports
                    .iter()
                    .map(|p| format!("{}/{}", p.container, p.transport))
                    .collect(),
            ),
            is_privileged: false,
            services: normalized(selected_services),
        }
    }
}
