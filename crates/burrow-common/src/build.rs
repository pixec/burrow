//! Template builds: their digests, the references that name them, and the
//! manifest a digest is taken of.
//!
//! A build is immutable and named by the SHA-256 of its canonical manifest,
//! written `sha256:<hex>`. A template is a name; `name` means `name:latest`,
//! `name:tag` resolves to the newest ready build assigned to that tag, and
//! `name@sha256:<hex>` or a bare `sha256:<hex>` names one build exactly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const DIGEST_PREFIX: &str = "sha256:";
pub const DEFAULT_TAG: &str = "latest";

/// A build digest. Holds the lowercase hex; displays as `sha256:<hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    /// `sha256:<64 lowercase hex>`, or the hex alone.
    pub fn parse(text: &str) -> Option<Self> {
        let hex = text.strip_prefix(DIGEST_PREFIX).unwrap_or(text);
        let valid = hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        valid.then(|| Self(hex.to_string()))
    }

    pub fn of(bytes: &[u8]) -> Self {
        Self(hex(&Sha256::digest(bytes)))
    }

    pub fn hex(&self) -> &str {
        &self.0
    }

    /// The first 12 hex digits, for display.
    pub fn short(&self) -> &str {
        &self.0[..12]
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{DIGEST_PREFIX}{}", self.0)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `sha256:<12 hex>` for a digest string, or the string as it is.
pub fn short(digest: &str) -> String {
    match Digest::parse(digest) {
        Some(digest) => format!("{DIGEST_PREFIX}{}", digest.short()),
        None => digest.to_string(),
    }
}

/// What a caller names a template by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateRef {
    Tag {
        name: String,
        tag: String,
    },
    Build {
        name: Option<String>,
        digest: Digest,
    },
}

impl TemplateRef {
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.starts_with(DIGEST_PREFIX) {
            return Ok(Self::Build {
                name: None,
                digest: parse_digest(text)?,
            });
        }
        if let Some((name, digest)) = text.split_once('@') {
            // A tag beside a digest says nothing more; the digest names the
            // build.
            let name = match name.split_once(':') {
                Some((name, tag)) => {
                    validate_tag(tag)?;
                    name
                }
                None => name,
            };
            validate_name(name)?;
            return Ok(Self::Build {
                name: Some(name.to_string()),
                digest: parse_digest(digest)?,
            });
        }
        let (name, tag) = text.split_once(':').unwrap_or((text, DEFAULT_TAG));
        validate_name(name)?;
        validate_tag(tag)?;
        Ok(Self::Tag {
            name: name.to_string(),
            tag: tag.to_string(),
        })
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Tag { name, .. } => Some(name),
            Self::Build { name, .. } => name.as_deref(),
        }
    }
}

impl std::fmt::Display for TemplateRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tag { name, tag } if tag == DEFAULT_TAG => f.write_str(name),
            Self::Tag { name, tag } => write!(f, "{name}:{tag}"),
            Self::Build {
                name: Some(name),
                digest,
            } => write!(f, "{name}@{digest}"),
            Self::Build { name: None, digest } => write!(f, "{digest}"),
        }
    }
}

fn parse_digest(text: &str) -> Result<Digest, String> {
    if !text.starts_with(DIGEST_PREFIX) {
        return Err(format!("{text:?} is not a sha256:<hex> digest"));
    }
    Digest::parse(text).ok_or_else(|| format!("{text:?} is not a sha256:<hex> digest"))
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

/// A template name: letters, digits, `-`, `_` and `.`, not starting with
/// `.`, at most 128 characters.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("template name is required".into());
    }
    if name.len() > 128 || !name.chars().all(is_name_char) || name.starts_with('.') {
        return Err(format!(
            "template name {name:?} may contain only letters, digits, '-', '_', '.', may not \
             start with '.' and is at most 128 characters"
        ));
    }
    Ok(())
}

/// A tag, under the same rules as a name.
pub fn validate_tag(tag: &str) -> Result<(), String> {
    if tag.is_empty() || tag.len() > 128 || !tag.chars().all(is_name_char) || tag.starts_with('.') {
        return Err(format!(
            "tag {tag:?} may contain only letters, digits, '-', '_', '.', may not start with \
             '.' and is at most 128 characters"
        ));
    }
    Ok(())
}

/// Everything a build is: what its digest is taken of.
///
/// Artifact digests are bare SHA-256 hex, as the node's blob store and the
/// object store's `images/` name them. `start`, `ready` and `prefetch_trace`
/// are empty until builds record them.
///
/// Every field but `version` and `rootfs` is left out of the JSON while
/// empty, and a field added later must be too, so a manifest written before
/// it existed keeps its digest.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub rootfs: Artifact,
    /// Empty for a guest booted from firmware or installed whole.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kernel: String,
    /// Other files of the build by name, such as a macOS machine's auxiliary
    /// storage and identity.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// The image config: environment, working directory, user, init mode and
    /// what the image was built for.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub config: serde_json::Value,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hypervisor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub guest_os: String,
    /// The guest agent installed in it. Empty when not known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub start: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ready: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefetch_trace: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// The file's name in the build: `rootfs.ext4`, or `disk.img` for macOS.
    pub file: String,
    pub digest: String,
    pub bytes: u64,
}

pub const MANIFEST_VERSION: u32 = 1;

impl Manifest {
    /// The manifest as its digest is taken: JSON with every object's keys
    /// sorted and no whitespace.
    pub fn canonical(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("a manifest serializes");
        serde_json::to_vec(&value).expect("a value serializes")
    }

    pub fn digest(&self) -> Digest {
        Digest::of(&self.canonical())
    }

    /// Parses a manifest, refusing one whose bytes do not hash to
    /// `expected` or are not in canonical form. The digest is checked over
    /// the bytes as received, so a manifest with fields this build does not
    /// know still verifies.
    pub fn verified(json: &str, expected: &Digest) -> Result<Self, String> {
        let actual = Digest::of(json.as_bytes());
        if &actual != expected {
            return Err(format!("build manifest hashes as {actual}, not {expected}"));
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|err| format!("build manifest: {err}"))?;
        if serde_json::to_vec(&value).map_err(|err| err.to_string())? != json.as_bytes() {
            return Err("build manifest is not in canonical form".into());
        }
        serde_json::from_value(value).map_err(|err| format!("build manifest: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn references_parse_and_print_back() {
        let digest = format!("sha256:{}", hex64('a'));
        for (text, printed) in [
            ("python", "python"),
            ("python:latest", "python"),
            ("python:3.12", "python:3.12"),
        ] {
            assert_eq!(TemplateRef::parse(text).unwrap().to_string(), printed);
        }
        let tagged = TemplateRef::parse(&format!("python:3.12@{digest}")).unwrap();
        assert_eq!(tagged.to_string(), format!("python@{digest}"));
        assert!(TemplateRef::parse(&format!("python:@{digest}")).is_err());
        let by_build = TemplateRef::parse(&format!("python@{digest}")).unwrap();
        assert_eq!(by_build.name(), Some("python"));
        assert_eq!(by_build.to_string(), format!("python@{digest}"));
        let bare = TemplateRef::parse(&digest).unwrap();
        assert_eq!(bare.name(), None);
        for bad in [
            "",
            ".hidden",
            "a/b",
            "py:",
            "py@sha256:zz",
            &format!("py@{}", hex64('a')),
            "sha256:abc",
            &format!("sha256:{}", hex64('A')),
        ] {
            assert!(TemplateRef::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_digest_covers_every_field_and_ignores_key_order() {
        let mut manifest = Manifest {
            version: MANIFEST_VERSION,
            rootfs: Artifact {
                file: "rootfs.ext4".into(),
                digest: hex64('a'),
                bytes: 10,
            },
            kernel: hex64('b'),
            config: serde_json::json!({"working_dir": "/", "env": ["A=1"]}),
            ..Default::default()
        };
        let first = manifest.digest();
        let reordered: Manifest = serde_json::from_str(
            &serde_json::to_string(&serde_json::json!({
                "version": 1,
                "config": {"env": ["A=1"], "working_dir": "/"},
                "kernel": hex64('b'),
                "rootfs": {"bytes": 10, "digest": hex64('a'), "file": "rootfs.ext4"},
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reordered.digest(), first);
        manifest.agent = hex64('c');
        assert_ne!(manifest.digest(), first);
        let json = String::from_utf8(manifest.canonical()).unwrap();
        assert!(Manifest::verified(&json, &manifest.digest()).is_ok());
        assert!(Manifest::verified(&json, &first).is_err());
        let spaced = json.replace(',', ", ");
        assert!(Manifest::verified(&spaced, &Digest::of(spaced.as_bytes())).is_err());
    }

    /// A field a later build adds is left out while empty, so manifests
    /// written before keep their digests, and one carrying a field this
    /// build does not know still verifies.
    #[test]
    fn manifests_stay_verifiable_across_fields() {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            ..Default::default()
        };
        let json = String::from_utf8(manifest.canonical()).unwrap();
        assert_eq!(
            json,
            r#"{"rootfs":{"bytes":0,"digest":"","file":""},"version":1}"#
        );
        let newer = r#"{"later":"x","rootfs":{"bytes":0,"digest":"","file":""},"version":1}"#;
        assert!(Manifest::verified(newer, &Digest::of(newer.as_bytes())).is_ok());
    }
}
