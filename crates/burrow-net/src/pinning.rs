//! Pinning mesh peer keys, so the orchestrator cannot silently redirect traffic.
//!
//! Nodes learn each other's WireGuard public keys from the orchestrator, so an
//! orchestrator that substituted a key it held the private half of would sit in
//! the middle of every cross-node private network with nothing downstream the
//! wiser: the tunnel comes up and traffic flows either way.
//!
//! A peer's key is therefore recorded the first time it is seen and is then
//! immutable; a later heartbeat naming a different key for the same node is
//! refused. The orchestrator can still introduce new nodes, which it must be
//! able to do, but it cannot change the identity of one that exists.
//!
//! Trust-on-first-use, with its usual caveat: the first key is taken on faith.
//! Operator-written pins take precedence over anything learned.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A peer's key, and where the pin came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub public_key: String,
    /// Operator-provided pins are never overwritten and never learned over.
    pub explicit: bool,
}

/// Keys this node has committed to, per peer node id.
#[derive(Debug, Default)]
pub struct PinnedKeys {
    pins: HashMap<String, Pin>,
    path: Option<PathBuf>,
}

/// What happened when a reported key was checked against the pins.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Matches what was already pinned.
    Known,
    /// Not seen before; now pinned to this key.
    Learned,
    /// Contradicts the pin. The peer is refused.
    Conflict { pinned: String },
}

impl PinnedKeys {
    /// Loads pins from disk, treating everything in `explicit` as operator
    /// intent that learning must not override.
    pub async fn load(path: &Path, explicit: &Path) -> Self {
        let mut pins = HashMap::new();

        if let Ok(text) = tokio::fs::read_to_string(path).await {
            for (node_id, key) in parse(&text) {
                pins.insert(
                    node_id,
                    Pin {
                        public_key: key,
                        explicit: false,
                    },
                );
            }
        }
        // Applied second so an operator pin replaces anything learned earlier.
        if let Ok(text) = tokio::fs::read_to_string(explicit).await {
            for (node_id, key) in parse(&text) {
                pins.insert(
                    node_id,
                    Pin {
                        public_key: key,
                        explicit: true,
                    },
                );
            }
        }

        Self {
            pins,
            path: Some(path.to_path_buf()),
        }
    }

    /// In-memory only, for tests.
    pub fn in_memory(pins: impl IntoIterator<Item = (String, Pin)>) -> Self {
        Self {
            pins: pins.into_iter().collect(),
            path: None,
        }
    }

    pub fn get(&self, node_id: &str) -> Option<&Pin> {
        self.pins.get(node_id)
    }

    /// Checks a reported key, pinning it if the peer is new.
    pub fn check(&mut self, node_id: &str, public_key: &str) -> Verdict {
        match self.pins.get(node_id) {
            Some(pin) if pin.public_key == public_key => Verdict::Known,
            Some(pin) => Verdict::Conflict {
                pinned: pin.public_key.clone(),
            },
            None => {
                self.pins.insert(
                    node_id.to_string(),
                    Pin {
                        public_key: public_key.to_string(),
                        explicit: false,
                    },
                );
                Verdict::Learned
            }
        }
    }

    /// Writes learned pins back, so they survive a restart.
    ///
    /// Explicit pins are not written: they belong to whoever wrote the file,
    /// and copying them here would blur which pins were chosen and which were
    /// merely observed.
    pub async fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut lines: Vec<String> = self
            .pins
            .iter()
            .filter(|(_, pin)| !pin.explicit)
            .map(|(node_id, pin)| format!("{node_id} {}", pin.public_key))
            .collect();
        lines.sort();

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temp = path.with_extension("tmp");
        tokio::fs::write(&temp, lines.join("\n") + "\n").await?;
        tokio::fs::rename(&temp, path).await
    }
}

/// Parses `<node-id> <public-key>` lines, ignoring blanks and `#` comments.
fn parse(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let (node_id, key) = line.split_once(char::is_whitespace)?;
            let key = key.trim();
            (!node_id.is_empty() && !key.is_empty()).then(|| (node_id.to_string(), key.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(node_id: &str, key: &str, explicit: bool) -> (String, Pin) {
        (
            node_id.to_string(),
            Pin {
                public_key: key.to_string(),
                explicit,
            },
        )
    }

    #[test]
    fn an_unknown_peer_is_learned() {
        let mut pins = PinnedKeys::default();
        assert_eq!(pins.check("node-a", "keyA"), Verdict::Learned);
        assert_eq!(pins.check("node-a", "keyA"), Verdict::Known);
    }

    /// The whole point: the orchestrator may add nodes, but it may not change
    /// the identity of one that already exists.
    #[test]
    fn a_changed_key_is_a_conflict_not_an_update() {
        let mut pins = PinnedKeys::in_memory([pinned("node-a", "keyA", false)]);
        assert_eq!(
            pins.check("node-a", "attacker-key"),
            Verdict::Conflict {
                pinned: "keyA".into()
            }
        );
        // And the pin is unchanged, so a retry does not wear it down.
        assert_eq!(pins.get("node-a").unwrap().public_key, "keyA");
        assert_eq!(pins.check("node-a", "keyA"), Verdict::Known);
    }

    #[test]
    fn learning_one_peer_does_not_affect_another() {
        let mut pins = PinnedKeys::default();
        assert_eq!(pins.check("node-a", "keyA"), Verdict::Learned);
        assert_eq!(pins.check("node-b", "keyB"), Verdict::Learned);
        assert_eq!(pins.check("node-a", "keyA"), Verdict::Known);
    }

    #[test]
    fn pin_files_parse_with_comments_and_blanks() {
        let parsed = parse("# a comment\n\nnode-a keyA\n  node-b   keyB  \n\n");
        assert_eq!(
            parsed,
            vec![
                ("node-a".to_string(), "keyA".to_string()),
                ("node-b".to_string(), "keyB".to_string())
            ]
        );
    }

    #[test]
    fn malformed_pin_lines_are_ignored_rather_than_guessed_at() {
        assert!(parse("justonefield\n").is_empty());
        assert!(parse("   \n").is_empty());
        assert!(parse("#node-a keyA\n").is_empty());
    }

    #[tokio::test]
    async fn learned_pins_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("burrow-pins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mesh-pins");
        let explicit = dir.join("absent");

        let mut pins = PinnedKeys::load(&path, &explicit).await;
        assert_eq!(pins.check("node-a", "keyA"), Verdict::Learned);
        pins.save().await.unwrap();

        let mut reloaded = PinnedKeys::load(&path, &explicit).await;
        assert_eq!(reloaded.check("node-a", "keyA"), Verdict::Known);
        assert!(matches!(
            reloaded.check("node-a", "other"),
            Verdict::Conflict { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An operator pin is the stronger statement and must win over whatever a
    /// node happened to observe first.
    #[tokio::test]
    async fn an_explicit_pin_overrides_a_learned_one() {
        let dir = std::env::temp_dir().join(format!("burrow-pins-x-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let learned = dir.join("mesh-pins");
        let explicit = dir.join("operator-pins");

        tokio::fs::write(&learned, "node-a learned-key\n")
            .await
            .unwrap();
        tokio::fs::write(&explicit, "node-a operator-key\n")
            .await
            .unwrap();

        let mut pins = PinnedKeys::load(&learned, &explicit).await;
        assert!(pins.get("node-a").unwrap().explicit);
        assert!(matches!(
            pins.check("node-a", "learned-key"),
            Verdict::Conflict { .. }
        ));
        assert_eq!(pins.check("node-a", "operator-key"), Verdict::Known);

        // Saving must not launder an operator pin into a learned one.
        pins.save().await.unwrap();
        let text = tokio::fs::read_to_string(&learned).await.unwrap();
        assert!(
            !text.contains("operator-key"),
            "explicit pins must not be rewritten: {text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
