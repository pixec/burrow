use std::process::Command;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

const BINARIES: &[&str] = &["burrow-orchestrator", "burrowd", "burrow"];

#[derive(Parser)]
#[command(name = "xtask", about = "Burrow dev tasks")]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Cross-compile for Linux and rsync binaries to the dev box.
    Deploy {
        /// SSH destination, e.g. root@devbox or an ssh-config alias.
        #[arg(long, env = "BURROW_DEVBOX")]
        host: String,
        /// Remote directory for the binaries.
        #[arg(long, default_value = "/usr/local/bin")]
        dest: String,
        /// Cross-compilation target (OVH boxes are x86_64).
        #[arg(long, default_value = "x86_64-unknown-linux-musl")]
        target: String,
    },
    /// Cross-compile the Linux binaries without deploying.
    Build {
        /// Cross-compilation target (the local docker harness is aarch64).
        #[arg(long, default_value = "aarch64-unknown-linux-musl")]
        target: String,
    },
    /// Copy the protos into the SDKs.
    ///
    /// The SDKs are published and cannot reach into this workspace, so each
    /// needs its own copies. A test in `burrow-proto` fails when they fall
    /// behind, so this is the thing to run after changing a `.proto`. The
    /// Python SDK additionally commits code generated from its copies:
    /// regenerate with `python sdk/python/scripts/genproto.py`.
    Protos {
        /// Report drift and exit non-zero instead of fixing it.
        #[arg(long)]
        check: bool,
    },
}

/// Protos the SDK carries. `node` and `agent` are unused by it today, but a
/// stale copy is a trap for whoever reaches for one next.
const SHIPPED_PROTOS: &[&str] = &["common", "api", "node", "agent"];

fn sync_protos(check: bool) -> anyhow::Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?
        .to_path_buf();
    let source = root.join("crates/burrow-proto/proto");
    let sdks = [
        root.join("sdk/typescript/proto"),
        root.join("sdk/python/src/burrow/proto"),
    ];

    let mut stale = Vec::new();
    for sdk in &sdks {
        for name in SHIPPED_PROTOS {
            let file = format!("{name}.proto");
            let from = source.join(&file);
            let to = sdk.join(&file);
            let want = std::fs::read_to_string(&from)
                .with_context(|| format!("reading {}", from.display()))?;
            let have = std::fs::read_to_string(&to).unwrap_or_default();
            if want == have {
                continue;
            }
            stale.push(to.strip_prefix(&root).unwrap_or(&to).display().to_string());
            if !check {
                std::fs::write(&to, &want).with_context(|| format!("writing {}", to.display()))?;
            }
        }
    }

    match (check, stale.is_empty()) {
        (_, true) => {
            println!("sdk protos are in sync");
            Ok(())
        }
        (true, false) => bail!(
            "sdk protos have drifted: {}. Run `cargo xtask protos`.",
            stale.join(", ")
        ),
        (false, false) => {
            println!("updated {}", stale.join(", "));
            Ok(())
        }
    }
}

fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let desc = format!("{cmd:?}");
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn {desc}"))?;
    if !status.success() {
        bail!("command failed ({status}): {desc}");
    }
    Ok(())
}

fn zigbuild(target: &str) -> anyhow::Result<()> {
    if Command::new("cargo")
        .args(["zigbuild", "--help"])
        .output()
        .is_ok_and(|o| !o.status.success())
    {
        bail!(
            "cargo-zigbuild not found; install with: cargo install cargo-zigbuild (and `brew install zig`)"
        );
    }
    run(Command::new("rustup").args(["target", "add", target]))?;
    run(Command::new("cargo").args([
        "zigbuild",
        "--release",
        "--target",
        target,
        "-p",
        "burrow-orchestrator",
        "-p",
        "burrow-daemon",
        "-p",
        "burrow-cli",
        // Guest binary: not deployed to hosts, but it must land in
        // target/<triple>/release so the rootfs build can pick it up.
        "-p",
        "burrow-agent",
    ]))
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Cmd::Build { target } => zigbuild(&target),
        Cmd::Protos { check } => sync_protos(check),
        Cmd::Deploy { host, dest, target } => {
            zigbuild(&target)?;
            let paths: Vec<String> = BINARIES
                .iter()
                .map(|b| format!("target/{target}/release/{b}"))
                .collect();
            let mut rsync = Command::new("rsync");
            rsync
                .args(["-avz", "--progress"])
                .args(&paths)
                .arg(format!("{host}:{dest}/"));
            run(&mut rsync)?;
            println!("deployed {} to {host}:{dest}", BINARIES.join(", "));
            Ok(())
        }
    }
}
