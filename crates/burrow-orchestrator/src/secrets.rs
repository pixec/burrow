//! Credentials Kits ask for by service name, and that policies name as
//! `${secret:<name>}`, sealed at rest by [`burrow_common::vault::Vault`].
//!
//! A secret may be scoped to the sandboxes allowed to use it. The scope is
//! stored beside the sealed value and bound into the value's sealing context,
//! so a row whose scope is rewritten in the store no longer unseals: widening
//! who may use a credential takes the key, not just the database.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use burrow_common::vault::Vault;
use serde::{Deserialize, Serialize};

/// Most entries in either list of a scope.
pub const MAX_SCOPE_ENTRIES: usize = 64;

/// Who may use a secret. Empty, the default, is everyone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Sandbox ids or names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandboxes: Vec<String>,
    /// Tags as `key=value`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// The sandbox a secret is being resolved for.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    pub id: &'a str,
    /// Empty when the sandbox has none.
    pub name: &'a str,
    pub tags: &'a HashMap<String, String>,
}

impl Scope {
    pub fn new(mut sandboxes: Vec<String>, mut tags: Vec<String>) -> Self {
        // Canonical, so the same scope always seals under the same context.
        sandboxes.sort();
        sandboxes.dedup();
        tags.sort();
        tags.dedup();
        Self { sandboxes, tags }
    }

    pub fn is_unscoped(&self) -> bool {
        self.sandboxes.is_empty() && self.tags.is_empty()
    }

    /// Whether `subject` may use a secret with this scope: any sandbox when
    /// unscoped, otherwise one named by id or name, or carrying a listed tag.
    pub fn admits(&self, subject: &Subject<'_>) -> bool {
        self.is_unscoped()
            || self.sandboxes.iter().any(|entry| {
                entry == subject.id || (!subject.name.is_empty() && entry == subject.name)
            })
            || self.tags.iter().any(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(key, value)| subject.tags.get(key).is_some_and(|v| v == value))
            })
    }

    /// As stored: empty when unscoped, which is also every row from before
    /// scopes existed.
    fn encode(&self) -> String {
        if self.is_unscoped() {
            String::new()
        } else {
            serde_json::to_string(self).unwrap_or_default()
        }
    }

    fn decode(text: &str) -> anyhow::Result<Self> {
        if text.is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(text).context("reading a secret's scope")
    }
}

/// The context a value is sealed under: the name alone for an unscoped
/// secret, so rows from before scopes still unseal, and the name with the
/// scope otherwise.
fn context(name: &str, scope: &str) -> String {
    if scope.is_empty() {
        name.to_string()
    } else {
        format!("{name}\n{scope}")
    }
}

/// A secret's value and who may use it.
#[derive(Debug, Clone)]
pub struct Secret {
    pub value: String,
    pub scope: Scope,
}

pub struct Secrets {
    store: Arc<burrow_store::Store>,
    vault: Vault,
}

impl Secrets {
    pub fn open(store: Arc<burrow_store::Store>, key_path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            store,
            vault: Vault::open(key_path)?,
        })
    }

    pub async fn set(&self, name: &str, value: &str) -> anyhow::Result<()> {
        self.set_scoped(name, value, &Scope::default()).await
    }

    pub async fn set_scoped(&self, name: &str, value: &str, scope: &Scope) -> anyhow::Result<()> {
        let scope = scope.encode();
        let sealed = self
            .vault
            .seal(&context(name, &scope), value)
            .context("sealing secret")?;
        self.store
            .put_secret_scoped(name, &sealed, &scope)
            .await
            .context("storing secret")
    }

    pub async fn get(&self, name: &str) -> anyhow::Result<Option<String>> {
        Ok(self.get_scoped(name).await?.map(|secret| secret.value))
    }

    pub async fn get_scoped(&self, name: &str) -> anyhow::Result<Option<Secret>> {
        let Some((sealed, scope)) = self
            .store
            .get_secret_scoped(name)
            .await
            .with_context(|| format!("reading secret {name}"))?
        else {
            return Ok(None);
        };
        Ok(Some(Secret {
            value: self.vault.unseal(&context(name, &scope), &sealed)?,
            scope: Scope::decode(&scope)?,
        }))
    }

    pub async fn list(&self) -> anyhow::Result<Vec<String>> {
        self.store
            .list_secret_names()
            .await
            .context("listing secrets")
    }

    /// Every secret's name and scope. A scope that does not read back is
    /// reported as unreadable rather than as unscoped, since unscoped would
    /// claim more than is known.
    pub async fn list_scoped(&self) -> anyhow::Result<Vec<(String, Scope)>> {
        self.store
            .list_secret_scopes()
            .await
            .context("listing secrets")?
            .into_iter()
            .map(|(name, scope)| Ok((name, Scope::decode(&scope)?)))
            .collect()
    }

    pub async fn delete(&self, name: &str) -> anyhow::Result<bool> {
        self.store
            .delete_secret(name)
            .await
            .context("deleting secret")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn secrets() -> Secrets {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("burrow-secrets-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store: Arc<burrow_store::Store> =
            Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        Secrets::open(store, &dir.join("secrets.key")).unwrap()
    }

    #[tokio::test]
    async fn round_trips_and_stores_ciphertext() {
        let secrets = secrets().await;
        secrets.set("github", "ghp_value").await.unwrap();
        assert_eq!(
            secrets.get("github").await.unwrap().as_deref(),
            Some("ghp_value")
        );
        let raw = secrets.store.get_secret("github").await.unwrap().unwrap();
        assert!(!raw.contains("ghp_value"));
        assert_eq!(secrets.list().await.unwrap(), vec!["github"]);
        assert!(secrets.delete("github").await.unwrap());
        assert!(secrets.get("github").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_row_cannot_be_renamed_into_another_service() {
        let secrets = secrets().await;
        secrets.set("github", "ghp_value").await.unwrap();
        let raw = secrets.store.get_secret("github").await.unwrap().unwrap();
        secrets.store.put_secret("other", &raw).await.unwrap();
        assert!(secrets.get("other").await.is_err());
    }

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_unscoped_secret_admits_everyone_and_a_scoped_one_only_whom_it_names() {
        let none = tags(&[]);
        let anyone = Subject {
            id: "sbx_1",
            name: "",
            tags: &none,
        };
        assert!(Scope::default().admits(&anyone));

        let scope = Scope::new(
            vec!["sbx_2".into(), "builder".into()],
            vec!["team=ml".into()],
        );
        assert!(!scope.admits(&anyone));
        assert!(scope.admits(&Subject {
            id: "sbx_2",
            ..anyone
        }));
        assert!(scope.admits(&Subject {
            name: "builder",
            ..anyone
        }));
        let ml = tags(&[("team", "ml")]);
        assert!(scope.admits(&Subject {
            tags: &ml,
            ..anyone
        }));
        // A tag is its key and its value: the key alone, or another value,
        // is not the tag.
        let other = tags(&[("team", "web")]);
        assert!(!scope.admits(&Subject {
            tags: &other,
            ..anyone
        }));
    }

    #[tokio::test]
    async fn a_scope_round_trips_and_cannot_be_rewritten_in_the_store() {
        let secrets = secrets().await;
        let scope = Scope::new(vec!["sbx_2".into()], vec![]);
        secrets.set_scoped("api", "token", &scope).await.unwrap();
        let back = secrets.get_scoped("api").await.unwrap().unwrap();
        assert_eq!(back.value, "token");
        assert_eq!(back.scope, scope);
        assert_eq!(
            secrets.list_scoped().await.unwrap(),
            vec![("api".to_string(), scope)]
        );

        // Widening the scope behind the vault's back leaves a row that no
        // longer unseals, rather than a credential anyone may now use.
        let (sealed, _) = secrets
            .store
            .get_secret_scoped("api")
            .await
            .unwrap()
            .unwrap();
        secrets
            .store
            .put_secret_scoped("api", &sealed, "")
            .await
            .unwrap();
        assert!(secrets.get_scoped("api").await.is_err());

        // Setting it unscoped clears the scope with the value.
        secrets.set("api", "token2").await.unwrap();
        let back = secrets.get_scoped("api").await.unwrap().unwrap();
        assert!(back.scope.is_unscoped());
        assert_eq!(back.value, "token2");
    }
}
