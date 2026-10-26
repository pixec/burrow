//! Docker Sandbox Kits: OCI images whose manifest annotation carries a
//! descriptor saying what the image needs from the runtime that composes it.
//!
//! This crate is the part of that contract with no I/O in it. A node reads
//! descriptors out of the manifests it pulls and hands them here to be
//! judged ([`resolve`]), expanded with the installer's inputs ([`expand`])
//! and merged into one [`Composition`] it then provisions. Everything the
//! spec calls a refusal, a Kit the runtime must not run, comes back as
//! [`Error::Refused`], and everything malformed as [`Error::Invalid`], so
//! callers can keep the two apart the way the conformance suite requires.
//!
//! The grammar is SPEC-v3 of <https://github.com/docker/sandbox-kit-spec>.

mod compose;
mod config;
mod descriptor;
mod expand;
mod image;
mod names;
mod resolve;
mod surface;

use std::collections::BTreeSet;

use serde_json::Value;

pub use compose::{
    Composition, Credential, CredentialPhase, Decision, FileEntry, Hook, HookPhase, Host,
    HttpEntry, Inject, Inputs, NetworkPhase, NetworkPolicy, Phase, PortRequest, Resources,
    Selection, SelectionRecord, Skipped, Source, VolumeRequest, compose,
};
pub use config::{ByteSize, HostEntry, VolumeConfig};
pub use descriptor::{ArgDecl, CapType, Descriptor, Entry, Group, Item, Kind};
pub use expand::{ContainerEnv, expand_args, expand_env, resolve_args};
pub use image::{ImageConfig, merge_image_configs};
pub use names::{CapName, Constraint, Provide, Version};
pub use resolve::{Loaded, Resolved, lock_digest, resolve};
pub use surface::Surface;

/// The manifest annotation a Kit's descriptor rides in.
pub const DESCRIPTOR_ANNOTATION: &str = "vnd.docker.sandbox.kit.descriptor";
/// The annotation naming the descriptor's schema version.
pub const SCHEMA_VERSION_ANNOTATION: &str = "vnd.docker.sandbox.kit.schema-version";

/// The namespace of the capability types the spec itself defines.
pub const NAMESPACE: &str = "com.docker.sandbox";

/// The capability types this crate knows how to compose. A runtime claims a
/// subset of these; anything else a Kit requires is refused by name.
pub const KNOWN_TYPES: &[&str] = &[
    "com.docker.sandbox/network-policy@1",
    "com.docker.sandbox/network-policy@2",
    "com.docker.sandbox/credential@1",
    "com.docker.sandbox/volume@1",
    "com.docker.sandbox/port@1",
    "com.docker.sandbox/resources@1",
    "com.docker.sandbox/lifecycle@1",
    "com.docker.sandbox/long-running@1",
    "com.docker.sandbox/sbx@1",
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The runtime declines a Kit it understood: a required capability it
    /// does not provide, an incoherent set, a composition conflict.
    #[error("{0}")]
    Refused(String),
    /// A descriptor or an input that does not satisfy the grammar.
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The same error with `context: ` before its message.
    pub(crate) fn prefixed(self, context: &str) -> Self {
        match self {
            Error::Refused(m) => Error::Refused(format!("{context}: {m}")),
            Error::Invalid(m) => Error::Invalid(format!("{context}: {m}")),
        }
    }
}

fn refused(msg: impl Into<String>) -> Error {
    Error::Refused(msg.into())
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

/// The credential services the descriptors recorded in a Kit template's
/// `image.json` request, for a control plane deciding which secrets to hand
/// to a node. The input is the file's text; anything unreadable yields none.
pub fn credential_services(image_json: &str) -> Vec<String> {
    let Ok(mut value) = serde_json::from_str::<Value>(image_json) else {
        return Vec::new();
    };
    let Some(kits) = value.pointer_mut("/kit/kits").and_then(Value::as_array_mut) else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    for kit in kits {
        let Some(raw) = kit.get_mut("descriptor").map(Value::take) else {
            continue;
        };
        let Ok(descriptor) = Descriptor::from_value(raw) else {
            continue;
        };
        out.extend(
            descriptor
                .entries()
                .filter(|e| e.type_.is("credential", 1))
                .filter_map(|e| e.config.get("service")?.as_str())
                .map(str::to_string),
        );
    }
    out.into_iter().collect()
}
