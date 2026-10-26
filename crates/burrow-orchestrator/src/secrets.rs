//! Credentials Kits ask for by service name, sealed at rest by
//! [`burrow_core::vault::Vault`] with the service name as the context.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use burrow_core::vault::Vault;

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

    pub fn set(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let sealed = self.vault.seal(name, value).context("sealing secret")?;
        self.store
            .put_secret(name, &sealed)
            .context("storing secret")
    }

    pub fn get(&self, name: &str) -> anyhow::Result<Option<String>> {
        let Some(sealed) = self
            .store
            .get_secret(name)
            .with_context(|| format!("reading secret {name}"))?
        else {
            return Ok(None);
        };
        Ok(Some(self.vault.unseal(name, &sealed)?))
    }

    pub fn list(&self) -> anyhow::Result<Vec<String>> {
        self.store.list_secret_names().context("listing secrets")
    }

    pub fn delete(&self, name: &str) -> anyhow::Result<bool> {
        self.store.delete_secret(name).context("deleting secret")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> Secrets {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("burrow-secrets-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(burrow_store::Store::open_in_memory().unwrap());
        Secrets::open(store, &dir.join("secrets.key")).unwrap()
    }

    #[test]
    fn round_trips_and_stores_ciphertext() {
        let secrets = secrets();
        secrets.set("github", "ghp_value").unwrap();
        assert_eq!(secrets.get("github").unwrap().as_deref(), Some("ghp_value"));
        let raw = secrets.store.get_secret("github").unwrap().unwrap();
        assert!(!raw.contains("ghp_value"));
        assert_eq!(secrets.list().unwrap(), vec!["github"]);
        assert!(secrets.delete("github").unwrap());
        assert!(secrets.get("github").unwrap().is_none());
    }

    #[test]
    fn a_row_cannot_be_renamed_into_another_service() {
        let secrets = secrets();
        secrets.set("github", "ghp_value").unwrap();
        let raw = secrets.store.get_secret("github").unwrap().unwrap();
        secrets.store.put_secret("other", &raw).unwrap();
        assert!(secrets.get("other").is_err());
    }
}
