//! Secrets at rest.
//!
//! Both daemons keep credentials on disk: the orchestrator the ones Kits ask
//! for by service name, a node the header values and tokens its proxy
//! brokers for a sandbox. What is on disk is sealed with AES-256-GCM under a
//! key file beside the database, generated on first use and readable by the
//! daemon's user alone, so a copy of the database without the key file says
//! nothing. The context a value belongs to is the associated data, so a
//! sealed value cannot be moved under another name.

use std::path::Path;

use base64::Engine as _;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Key(String),
    #[error("no entropy")]
    Entropy,
    #[error("sealed value for {0} does not open with this key")]
    Open(String),
}

pub struct Vault {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl Vault {
    /// Opens the key at `path`, creating a fresh one when there is none.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let io_err = |err: std::io::Error| Error::Key(format!("{}: {err}", path.display()));
        let raw = match std::fs::read(path) {
            Ok(bytes) if bytes.len() == KEY_BYTES => bytes,
            Ok(_) => {
                return Err(Error::Key(format!(
                    "{} is not a {KEY_BYTES}-byte key",
                    path.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut bytes = vec![0u8; KEY_BYTES];
                rng.fill(&mut bytes).map_err(|_| Error::Entropy)?;
                write_private(path, &bytes).map_err(io_err)?;
                tracing::info!(path = %path.display(), "generated a secrets key");
                bytes
            }
            Err(err) => return Err(io_err(err)),
        };
        let key = UnboundKey::new(&AES_256_GCM, &raw)
            .map_err(|_| Error::Key("bad secrets key".into()))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            rng,
        })
    }

    /// Seals `value` for `context`, as base64 of nonce and ciphertext.
    pub fn seal(&self, context: &str, value: &str) -> Result<String, Error> {
        let mut nonce = [0u8; NONCE_BYTES];
        self.rng.fill(&mut nonce).map_err(|_| Error::Entropy)?;
        let mut buf = value.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context.as_bytes()),
                &mut buf,
            )
            .map_err(|_| Error::Entropy)?;
        let mut record = nonce.to_vec();
        record.extend(buf);
        Ok(base64::engine::general_purpose::STANDARD.encode(record))
    }

    pub fn unseal(&self, context: &str, sealed: &str) -> Result<String, Error> {
        let refused = || Error::Open(context.to_owned());
        let mut record = base64::engine::general_purpose::STANDARD
            .decode(sealed)
            .map_err(|_| refused())?;
        if record.len() < NONCE_BYTES {
            return Err(refused());
        }
        let (nonce, body) = record.split_at_mut(NONCE_BYTES);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| refused())?;
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(context.as_bytes()), body)
            .map_err(|_| refused())?;
        String::from_utf8(plain.to_vec()).map_err(|_| refused())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_path() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("burrow-vault-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("secrets.key")
    }

    #[test]
    fn round_trips_and_binds_the_context() {
        let vault = Vault::open(&key_path()).unwrap();
        let sealed = vault.seal("github", "ghp_value").unwrap();
        assert!(!sealed.contains("ghp_value"));
        assert_eq!(vault.unseal("github", &sealed).unwrap(), "ghp_value");
        assert!(vault.unseal("other", &sealed).is_err());
    }

    #[test]
    fn the_key_persists_and_is_private() {
        let path = key_path();
        let sealed = Vault::open(&path).unwrap().seal("svc", "v").unwrap();
        assert_eq!(
            Vault::open(&path).unwrap().unseal("svc", &sealed).unwrap(),
            "v"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
