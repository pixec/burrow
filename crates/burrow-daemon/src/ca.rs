//! `burrowd ca`: the fleet's TLS inspection root and the intermediates nodes
//! sign with, made offline as files so an operator needs no openssl.
//!
//! The root's key signs node intermediates and nothing else; it belongs on
//! the operator's machine, not on a node. Each node gets its own intermediate
//! and key, and the root's certificate, which is all its guests are told to
//! trust.

use std::path::{Path, PathBuf};

use burrow_proxy::inspect;

#[derive(clap::Subcommand)]
pub enum CaCommand {
    /// Create the fleet's inspection root: `root.pem` and `root.key`.
    Init {
        /// Directory the root is written to. Existing files are never
        /// replaced.
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// The root's common name.
        #[arg(long, default_value = "burrow fleet inspection root")]
        name: String,
        #[arg(long, default_value_t = 3650)]
        days: u64,
    },
    /// Issue a node's inspection CA under the root: `<node>.pem` and
    /// `<node>.key`, for `burrowd serve --inspect-ca-cert/--inspect-ca-key`.
    Issue {
        /// The node id it is for, as given to `burrowd serve --node-id`.
        #[arg(long)]
        node: String,
        #[arg(long, default_value = "root.pem")]
        root_cert: PathBuf,
        #[arg(long, default_value = "root.key")]
        root_key: PathBuf,
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        #[arg(long, default_value_t = inspect::NODE_CA_LIFETIME.as_secs() / 86400)]
        days: u64,
    },
}

pub fn run(command: CaCommand) -> anyhow::Result<()> {
    match command {
        CaCommand::Init {
            out_dir,
            name,
            days,
        } => {
            let (cert, key) =
                inspect::create_root(&name, days_of(days)).map_err(anyhow::Error::msg)?;
            let cert_path = write_pair(&out_dir, "root", &cert, &key)?;
            println!(
                "fleet root {} in {}\nkeep root.key off the nodes; give each node root.pem and \
                 its own `burrowd ca issue --node <id>`",
                inspect::pem_fingerprint(&cert),
                cert_path.display()
            );
        }
        CaCommand::Issue {
            node,
            root_cert,
            root_key,
            out_dir,
            days,
        } => {
            anyhow::ensure!(
                !node.is_empty() && !node.contains(['/', '\\']) && node != "." && node != "..",
                "--node must be a node id, not a path"
            );
            let root = read(&root_cert)?;
            let (cert, key) =
                inspect::issue_node_ca(&root, &read(&root_key)?, &node, days_of(days))
                    .map_err(anyhow::Error::msg)?;
            let cert_path = write_pair(&out_dir, &node, &cert, &key)?;
            println!(
                "node CA for {node} in {}, valid {days} days, under root {}\n\
                 start the node with --inspect-ca-cert {} --inspect-ca-key {} --inspect-root-cert {}",
                cert_path.display(),
                inspect::pem_fingerprint(&root),
                cert_path.display(),
                out_dir.join(format!("{node}.key")).display(),
                root_cert.display()
            );
        }
    }
    Ok(())
}

fn days_of(days: u64) -> std::time::Duration {
    std::time::Duration::from_secs(days * 86400)
}

fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("reading {}: {err}", path.display()))
}

/// Writes `<stem>.pem` and `<stem>.key`, the key readable by its owner only,
/// refusing to replace either.
fn write_pair(dir: &Path, stem: &str, cert: &str, key: &str) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join(format!("{stem}.pem"));
    let key_path = dir.join(format!("{stem}.key"));
    for path in [&cert_path, &key_path] {
        anyhow::ensure!(
            !path.exists(),
            "{} exists; refusing to replace it",
            path.display()
        );
    }
    inspect::write_private(&key_path, key)
        .map_err(|err| anyhow::anyhow!("writing {}: {err}", key_path.display()))?;
    std::fs::write(&cert_path, cert)
        .map_err(|err| anyhow::anyhow!("writing {}: {err}", cert_path.display()))?;
    Ok(cert_path)
}
