//! The OCI image config fields a Kit's runtime contract lives in (SPEC-v3
//! §8, §10).

use serde::{Deserialize, Serialize};

/// What an image config says about how its workload runs. For a mixin the
/// config records only what its recipe stated over its base, so the
/// additive fields merge and the contract fields are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    /// `KEY=value` pairs.
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub working_dir: String,
}

impl ImageConfig {
    pub fn env_value(&self, key: &str) -> Option<&str> {
        self.env.iter().rev().find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == key).then_some(v)
        })
    }

    pub(crate) fn set_env(&mut self, key: &str, value: &str) {
        if let Some(slot) = self
            .env
            .iter_mut()
            .find(|kv| kv.split_once('=').map(|(k, _)| k) == Some(key))
        {
            *slot = format!("{key}={value}");
        } else {
            self.env.push(format!("{key}={value}"));
        }
    }

    /// The user's login name, with any `:group` suffix removed.
    pub fn user_name(&self) -> &str {
        self.user
            .split_once(':')
            .map(|(u, _)| u)
            .unwrap_or(&self.user)
    }
}

/// Composes the workload's config with its mixins', in composition order.
/// Env merges additively with later values replacing earlier ones, except
/// `PATH`, whose elements append; entrypoint, cmd, user and workdir are the
/// workload's alone.
pub fn merge_image_configs(workload: &ImageConfig, mixins: &[&ImageConfig]) -> ImageConfig {
    let mut out = workload.clone();
    for mixin in mixins {
        for kv in &mixin.env {
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            if k == "PATH" {
                let mut elements: Vec<&str> = out
                    .env_value("PATH")
                    .unwrap_or("")
                    .split(':')
                    .filter(|e| !e.is_empty())
                    .collect();
                for e in v.split(':').filter(|e| !e.is_empty()) {
                    if !elements.contains(&e) {
                        elements.push(e);
                    }
                }
                let joined = elements.join(":");
                out.set_env("PATH", &joined);
            } else {
                out.set_env(k, v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixins_merge_env_and_append_path() {
        let workload = ImageConfig {
            entrypoint: vec!["run".into()],
            env: vec!["PATH=/usr/bin:/bin".into(), "A=1".into()],
            user: "agent".into(),
            ..Default::default()
        };
        let mixin = ImageConfig {
            entrypoint: vec!["other".into()],
            env: vec!["PATH=/opt/gh/bin:/bin".into(), "A=2".into(), "B=3".into()],
            user: "root".into(),
            ..Default::default()
        };
        let merged = merge_image_configs(&workload, &[&mixin]);
        assert_eq!(merged.entrypoint, vec!["run"]);
        assert_eq!(merged.user, "agent");
        assert_eq!(merged.env_value("PATH"), Some("/usr/bin:/bin:/opt/gh/bin"));
        assert_eq!(merged.env_value("A"), Some("2"));
        assert_eq!(merged.env_value("B"), Some("3"));
    }
}
