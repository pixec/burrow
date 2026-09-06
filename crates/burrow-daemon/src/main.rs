mod agentconn;
mod blobs;
mod devvm;
mod edge;
mod nodeapi;
mod oci;
mod sandbox;
mod sandboxproxy;
mod serve;
mod snapshot;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let telemetry = burrow_core::telemetry::init(
        "burrowd",
        match &args.command {
            Command::Serve(serve) => serve.otlp_endpoint.as_deref(),
            _ => None,
        },
    );

    let result = run(args).await;
    // Spans from the shutdown path are the ones worth not losing.
    telemetry.shutdown();
    result
}

async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Serve(args) => serve::run(args).await,
        Command::Vm(VmCommand::Boot(args)) => devvm::run(args).await,
        Command::Vm(VmCommand::Snapshot(args)) => devvm::snapshot_roundtrip(args).await,
        Command::Vm(VmCommand::Floor(args)) => devvm::boot_floor(args).await,
        Command::Vm(VmCommand::Agent(args)) => devvm::agent_boot(args).await,
        Command::Vm(VmCommand::Exec { boot, cmd }) => devvm::agent_exec(boot, cmd).await,
        Command::Vm(VmCommand::Clones(args)) => devvm::clone_divergence(args).await,
    }
}
