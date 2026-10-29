mod access;
mod blobs;
mod chunks;
mod cmdlogs;
mod delivery;
mod devvm;
mod durable;
mod edge;
mod guestconn;
mod kit;
mod macnode;
mod metrics;
mod nodeapi;
mod objstore;
mod oci;
mod sandbox;
mod sandboxproxy;
mod serve;
mod share;
mod snapshot;
mod staged;
mod template;
mod volume;
mod warm;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "burrowd", about = "Burrow node daemon")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run the node daemon: serve the node API and register with the orchestrator.
    Serve(serve::ServeArgs),
    /// Development commands for the microVM layer.
    #[command(subcommand)]
    Vm(VmCommand),
    /// Build a macOS template from a restore image, on a Mac node.
    #[cfg(target_os = "macos")]
    VzTemplate(macnode::TemplateArgs),
}

#[derive(Subcommand)]
enum VmCommand {
    /// Boot a microVM from local images and report boot latency.
    Boot(devvm::VmBootArgs),
    /// Boot, snapshot, restore, and verify the guest kept its state.
    Snapshot(devvm::VmBootArgs),
    /// Measure time to usable userspace with no distro init in the way.
    Floor(devvm::VmBootArgs),
    /// Boot the agent rootfs and talk to the guest agent over vsock.
    Agent(devvm::VmBootArgs),
    /// Restore two sandboxes from one snapshot and check RNG divergence.
    Clones(devvm::VmBootArgs),
    /// Boot an agent sandbox and run a command in it.
    Exec {
        #[command(flatten)]
        boot: devvm::VmBootArgs,
        /// Command and arguments, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    // Before the runtime starts a thread: the helper that jails Cloud
    // Hypervisor unshares its mount namespace, which a threaded process
    // cannot.
    burrow_vmm::cloud_hypervisor::jail::run_if_helper();
    tokio::runtime::Runtime::new()?.block_on(daemon())
}

async fn daemon() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut telemetry = burrow_common::telemetry::init(
        "burrowd",
        match &args.command {
            Command::Serve(serve) => serve.otlp_endpoint.as_deref(),
            _ => None,
        },
    );
    // Read on the reaper's period, which is how often the totals move.
    telemetry.export_metrics(std::time::Duration::from_secs(serve::REAP_INTERVAL_SECS));

    let result = run(args).await;
    // Spans from the shutdown path are the ones worth not losing.
    telemetry.shutdown();
    result
}

async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Serve(args) => serve::run(args).await,
        Command::Vm(VmCommand::Boot(args)) => devvm::run(args).await,
        #[cfg(target_os = "macos")]
        Command::VzTemplate(args) => macnode::build_template(args).await,
        Command::Vm(VmCommand::Snapshot(args)) => devvm::snapshot_roundtrip(args).await,
        Command::Vm(VmCommand::Floor(args)) => devvm::boot_floor(args).await,
        Command::Vm(VmCommand::Agent(args)) => devvm::agent_boot(args).await,
        Command::Vm(VmCommand::Exec { boot, cmd }) => devvm::agent_exec(boot, cmd).await,
        Command::Vm(VmCommand::Clones(args)) => devvm::clone_divergence(args).await,
    }
}
