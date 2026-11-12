use std::io::{IsTerminal, Write};

use clap::{Args as ClapArgs, Parser, Subcommand};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use burrow_proto::api::v1 as api;
use burrow_proto::api::v1::burrow_client::BurrowClient;
use burrow_proto::common::v1 as common;

mod term;

type Client = BurrowClient<
    tonic::service::interceptor::InterceptedService<tonic::transport::Channel, BearerAuth>,
>;
type AccessClient = api::access_client::AccessClient<
    tonic::service::interceptor::InterceptedService<tonic::transport::Channel, BearerAuth>,
>;

/// Where a sandbox's exec, attach and file calls go: the node that holds it,
/// called with a token the orchestrator issues, or the orchestrator, which
/// relays them. Both serve the same calls.
enum Passage {
    Direct(AccessClient),
    Relay(Client),
}

impl Passage {
    async fn exec(
        &mut self,
        input: impl tonic::IntoStreamingRequest<Message = api::ExecInput>,
    ) -> Result<tonic::Response<tonic::Streaming<api::ExecOutput>>, tonic::Status> {
        match self {
            Self::Direct(client) => client.exec(input).await,
            Self::Relay(client) => client.exec(input).await,
        }
    }

    async fn attach(
        &mut self,
        input: impl tonic::IntoStreamingRequest<Message = api::AttachInput>,
    ) -> Result<tonic::Response<tonic::Streaming<api::ExecOutput>>, tonic::Status> {
        match self {
            Self::Direct(client) => client.attach(input).await,
            Self::Relay(client) => client.attach(input).await,
        }
    }

    async fn fs(
        &mut self,
        req: api::FsRequest,
    ) -> Result<tonic::Response<api::FsResponse>, tonic::Status> {
        match self {
            Self::Direct(client) => client.fs(req).await,
            Self::Relay(client) => client.fs(req).await,
        }
    }
}

/// One sandbox's calls and the reference they carry: the id a token names
/// when direct, which the node matches exactly, or what the caller gave the
/// orchestrator, which resolves names.
struct Route {
    client: Passage,
    sandbox_id: String,
}

/// `--insecure`, which governs the node a token goes to as much as the
/// orchestrator, set once from the command line.
static INSECURE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
/// Whether `--route orchestrator` was asked for, set once like `INSECURE`.
static RELAYED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

async fn route(client: &Client, sandbox: &str) -> anyhow::Result<Route> {
    if *RELAYED.get().unwrap_or(&false) {
        return Ok(Route {
            client: Passage::Relay(client.clone()),
            sandbox_id: sandbox.to_string(),
        });
    }
    let grant = client
        .clone()
        .issue_access(api::IssueAccessRequest {
            sandbox_id: sandbox.to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    let channel = connect(&grant.endpoint, *INSECURE.get().unwrap_or(&false)).await?;
    Ok(Route {
        client: Passage::Direct(api::access_client::AccessClient::with_interceptor(
            channel,
            BearerAuth(Some(grant.token)),
        )),
        sandbox_id: grant.sandbox_id,
    })
}

/// Attaches the bearer token, when one is configured.
#[derive(Clone)]
struct BearerAuth(Option<String>);

impl tonic::service::Interceptor for BearerAuth {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(token) = &self.0 {
            let value = format!("Bearer {token}")
                .parse()
                .map_err(|_| tonic::Status::internal("malformed token"))?;
            req.metadata_mut().insert("authorization", value);
        }
        Ok(req)
    }
}

#[derive(Parser)]
#[command(name = "burrow", about = "Burrow sandbox CLI")]
struct Args {
    /// Orchestrator gRPC endpoint.
    #[arg(
        long,
        global = true,
        default_value = "http://127.0.0.1:7070",
        env = "BURROW_ORCHESTRATOR"
    )]
    orchestrator: String,
    /// Bearer token, when the orchestrator requires one.
    #[arg(long, global = true, env = "BURROW_API_KEY")]
    api_key: Option<String>,
    /// Read the bearer token from a file instead: the first non-blank,
    /// non-`#` line. Preferred on a shared machine, where a token on the
    /// command line is visible in `ps` to every user on the host.
    #[arg(long, global = true, env = "BURROW_API_KEY_FILE")]
    api_key_file: Option<std::path::PathBuf>,
    /// Allow a plaintext `http://` endpoint that is not on this machine.
    ///
    /// The api key travels in a header, so plaintext to a remote orchestrator
    /// hands it to anything on the path.
    #[arg(long = "insecure", global = true, env = "BURROW_INSECURE")]
    is_insecure: bool,
    /// Where exec, attach and file traffic goes. `direct`, the default, calls
    /// the node holding the sandbox with a short-lived token from the
    /// orchestrator, which the node has to be reachable for. `orchestrator`
    /// sends it through the orchestrator, which relays it. Neither falls back
    /// to the other.
    #[arg(
        long,
        global = true,
        default_value = "direct",
        value_parser = ["direct", "orchestrator"],
        env = "BURROW_ROUTE"
    )]
    route: String,
    #[command(subcommand)]
    command: Command,
}

/// Loads the bearer token from `--api-key` or `--api-key-file`.
///
/// The file is read the way the daemons read theirs: the first non-blank,
/// non-`#` line, so a token file can be annotated. A file that cannot be read
/// is an error, not a silent fall back to calling unauthenticated.
fn load_api_key(
    inline: Option<&str>,
    path: Option<&std::path::Path>,
) -> anyhow::Result<Option<String>> {
    if let Some(value) = inline {
        return Ok(Some(value.to_string()));
    }
    let Some(path) = path else {
        return Ok(None);
    };
    let contents = std::fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("cannot read --api-key-file {}: {err}", path.display()))?;
    let token = contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("--api-key-file {} holds no token", path.display()))?;
    Ok(Some(token))
}

/// Builds the channel to the orchestrator, refusing to leak the api key.
///
/// `https://` gets TLS against the platform's CA store. Plaintext is allowed
/// only to this machine, where there is no network to eavesdrop on; anywhere
/// else it needs `--insecure`, because the bearer token goes out in a header
/// on every call. An endpoint with no scheme counts as plaintext, which is
/// what tonic makes of it.
async fn connect(endpoint: &str, insecure: bool) -> anyhow::Result<tonic::transport::Channel> {
    let uri: tonic::transport::Uri = endpoint
        .parse()
        .map_err(|err| anyhow::anyhow!("{endpoint} is not a URL: {err}"))?;
    let mut builder = tonic::transport::Endpoint::from(uri.clone());

    if uri.scheme_str() == Some("https") {
        builder = builder.tls_config(
            tonic::transport::ClientTlsConfig::new()
                .with_native_roots()
                .with_enabled_roots(),
        )?;
    } else if !insecure && !is_loopback(uri.host().unwrap_or_default()) {
        anyhow::bail!(
            "refusing to send a bearer token in plaintext to {}: use https://, or pass \
             --insecure if the endpoint is reached over a network you trust",
            uri.host().unwrap_or(endpoint)
        );
    }

    Ok(builder.connect().await?)
}

/// Whether a host names this machine, where plaintext has no network to cross.
fn is_loopback(host: &str) -> bool {
    // A URL's v6 literal keeps its brackets; the address inside is what parses.
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

#[derive(Subcommand)]
enum Command {
    /// Check orchestrator health.
    Health,
    /// Node operations.
    #[command(subcommand)]
    Nodes(NodesCommand),
    /// Create a sandbox.
    Create {
        #[command(flatten)]
        create: CreateFlags,
        /// Open an interactive shell in the sandbox once it is running.
        #[arg(long = "connect")]
        is_connecting: bool,
    },
    /// List sandboxes.
    ///
    /// Running sandboxes only, as `docker ps` does. Everything the fleet holds,
    /// suspended and lost records included, needs --all.
    #[command(visible_aliases = ["list", "ls"])]
    Ps {
        /// Include sandboxes that are not running: stopped, suspended, failed
        /// and lost ones.
        #[arg(long = "all", short = 'a')]
        is_all_shown: bool,
        /// Show only sandboxes carrying this key=value tag.
        #[arg(long)]
        tag: Option<String>,
    },
    /// List the commands a sandbox has run, running and finished alike.
    Top { id: String },
    /// Print one sandbox's whole record.
    Inspect {
        id: String,
        /// Emit the record as JSON instead of the readable field list.
        #[arg(long = "json")]
        is_json_requested: bool,
    },
    /// Show what sandboxes have consumed.
    Stats {
        /// Sandbox to report on. Omitted covers every sandbox.
        id: Option<String>,
        /// Include sandboxes that are not running.
        #[arg(long = "all", short = 'a')]
        is_all_shown: bool,
    },
    /// List templates.
    Images,
    /// Import an OCI image as a template, e.g. `python:3.12-slim`.
    Pull {
        /// Image references: [registry/]repository[:tag|@digest]. Several
        /// are a Docker Sandbox Kit set, composed into one template.
        #[arg(required = true)]
        images: Vec<String>,
        /// Template name. Defaults to the image's repository name, or for a
        /// kit set to one derived from its digests.
        #[arg(long)]
        name: Option<String>,
        /// Boot the image's own systemd under the agent. The image has to
        /// ship systemd.
        #[arg(long)]
        systemd: bool,
        /// Hypervisor every sandbox from the template runs under:
        /// `firecracker` or `cloud-hypervisor`. Defaults to Firecracker.
        #[arg(long)]
        hypervisor: Option<String>,
    },
    /// Save a sandbox's state as a snapshot. The sandbox keeps running.
    Commit {
        /// Sandbox to snapshot, by id or name.
        sandbox: String,
        /// Seconds from last use before the snapshot is swept. Omitted falls
        /// back to the sandbox's --snapshot-expiration-secs, and to no expiry
        /// when that is unset too.
        #[arg(long, default_value_t = 0)]
        expiration_secs: u64,
    },
    /// Create a sandbox from another's current state.
    Fork {
        /// Sandbox to fork. It keeps running.
        id: String,
        /// Name for the child, usable in place of its id from then on. A fork
        /// never inherits its source's name: names are unique.
        #[arg(long)]
        name: Option<String>,
        /// Egress policy for the child. Without any network flag it inherits
        /// the source's.
        #[command(flatten)]
        network: NetworkFlags,
        /// Exec and file access for the child. Without any of these flags it
        /// inherits the source's.
        #[command(flatten)]
        access: AccessFlags,
        /// Require the source's node to carry this key=value label. A fork is
        /// built where its source is, so a mismatch is refused rather than
        /// moved. Repeatable.
        #[arg(long = "node-label")]
        node_labels: Vec<String>,
    },
    /// Move a sandbox to another node through the object store. A running
    /// sandbox is suspended, carried over and resumed; it keeps its id, name
    /// and policy, and gets a new address on the new node. Needs the nodes
    /// to share an object store. Volumes do not move.
    Move {
        id: String,
        /// The node to move to; omitted places it like a create.
        #[arg(long)]
        node: Option<String>,
        /// Require the destination to carry this key=value label, when no
        /// node is named. Repeatable.
        #[arg(long = "node-label")]
        node_labels: Vec<String>,
    },
    /// Run a command in an existing sandbox.
    Exec {
        id: String,
        #[command(flatten)]
        exec: ExecFlags,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Open an interactive shell in a sandbox.
    #[command(visible_aliases = ["ssh", "shell"])]
    Connect {
        id: String,
        /// Guest user to run the shell as. Defaults to root.
        #[arg(long = "user", short = 'u')]
        user: Option<String>,
        /// Shell to start. Defaults to /bin/sh.
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Replay and follow a command's output.
    ///
    /// Every byte is kept on the node until `burrow prune`, so this replays
    /// from the start unless the command asked for its log to rotate.
    Logs {
        id: String,
        /// Command to follow, from `burrow top`. Required: burrow's logs belong
        /// to a command, not to the sandbox as a whole.
        command_id: Option<String>,
    },
    /// Remove finished commands and their output logs, as `docker container
    /// prune`. Running commands are left alone.
    Prune { id: String },
    /// Signal a running command.
    Kill {
        id: String,
        /// Command to signal, from `burrow top`. Required: `kill` ends one
        /// command, never the sandbox.
        command_id: Option<String>,
        /// Signal number. Defaults to 9 (SIGKILL).
        #[arg(long, default_value_t = 9)]
        signal: i32,
    },
    /// Guest user operations.
    #[command(subcommand)]
    User(UserCommand),
    /// Guest group operations.
    #[command(subcommand)]
    Group(GroupCommand),
    /// Create a sandbox, run a command in it, and leave it running.
    ///
    /// With --name this is get-or-create: the named sandbox is reused when it
    /// exists, resumed when it is suspended, and created when it is not there.
    Run {
        #[command(flatten)]
        create: CreateFlags,
        #[command(flatten)]
        exec: ExecFlags,
        /// Suspend the sandbox once the command exits.
        #[arg(long = "stop", conflicts_with = "is_removed_after")]
        is_suspended_after: bool,
        /// Delete the sandbox once the command exits.
        #[arg(long = "rm")]
        is_removed_after: bool,
        /// Start the command and return, printing the sandbox id. The command
        /// keeps running; follow it with `burrow logs`.
        #[arg(long = "detach", short = 'd', conflicts_with_all = ["is_suspended_after", "is_removed_after"])]
        is_detached: bool,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Copy a file between the local filesystem and a sandbox.
    ///
    /// Exactly one side is a sandbox path, written as <id>:<path>. A local
    /// destination of - writes the file to stdout.
    #[command(visible_alias = "cp")]
    Copy { src: String, dst: String },
    /// Snapshot sandboxes to disk and stop their VMs.
    #[command(visible_alias = "pause")]
    Stop {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Restore a stopped sandbox from its snapshot.
    #[command(visible_alias = "resume")]
    Start { id: String },
    /// Shut a sandbox's VM down, keeping its disks. Unlike `stop`, nothing
    /// in memory survives: `boot` starts the image's init again on the same
    /// writable disk, and a kit's startup hooks run again.
    Shutdown {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Cold-boot a shut-down sandbox on its existing disks.
    Boot { id: String },
    /// Replace a sandbox's root disk, discarding everything written to it,
    /// while keeping its id, name and volumes.
    Recreate {
        id: String,
        /// Template for the new disk; omitted keeps the current one.
        #[arg(long)]
        template: Option<String>,
        /// Kit arg values replacing the recorded ones by name.
        #[arg(long = "arg")]
        kit_args: Vec<String>,
        /// Environment overrides replacing the recorded ones by name.
        #[arg(long = "kit-env")]
        kit_env: Vec<String>,
        /// Capability types to decline, replacing the recorded list. Passing
        /// none clears it.
        #[arg(long = "reject-capability")]
        reject_capabilities: Vec<String>,
    },
    /// Credentials kits ask for by service name.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// List the VMs a sandbox has run, newest first.
    Sessions { id: String },
    /// Tokens for calling a sandbox's node directly, without the orchestrator.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Destroy sandboxes.
    #[command(visible_alias = "rm")]
    Remove {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Read and replace a sandbox's configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Publish a guest port on the node's address.
    Expose {
        id: String,
        guest_port: u32,
        /// Preferred host port; omitted lets the node pick.
        #[arg(long, default_value_t = 0)]
        host_port: u32,
        /// Forward UDP rather than TCP. Publishing both takes two mappings.
        #[arg(long = "udp")]
        is_udp: bool,
    },
    /// List published ports for a sandbox.
    #[command(visible_alias = "ports")]
    Port { id: String },
    /// Withdraw a published port.
    Unexpose { id: String, host_port: u32 },
    /// Share a sandbox through a tailcat address: a WireGuard tunnel over a
    /// DERP relay that any `tailcat` client can dial, with no host port and
    /// no edge. The address is the credential, so treat it as a secret.
    Share {
        id: String,
        /// Guest TCP port reachable through the share. Repeatable; omitted
        /// shares every port.
        #[arg(long = "port", value_delimiter = ',')]
        ports: Vec<u32>,
        /// Client node key admitted, as `nodekey:<hex>`. Repeatable; omitted
        /// admits anyone holding the address.
        #[arg(long = "allow")]
        allowed_clients: Vec<String>,
        /// Issue new keys, and so a new address, to an existing share.
        #[arg(long = "rotate")]
        is_rotating: bool,
        /// Source connections from the gateway instead of from the client's
        /// own address, which is what the guest sees by default.
        #[arg(long = "no-transparent-ip")]
        is_transparent_ip_disabled: bool,
        /// Guest UDP port reachable through the share, or `all`. Repeatable;
        /// omitted shares no UDP.
        #[arg(long = "udp-port", value_delimiter = ',')]
        udp_ports: Vec<String>,
        /// Print the existing share without changing it.
        #[arg(long = "show", conflicts_with_all = ["ports", "allowed_clients", "is_rotating", "udp_ports", "is_transparent_ip_disabled"])]
        is_showing: bool,
    },
    /// Revoke a sandbox's share.
    Unshare { id: String },
    /// List a directory inside a sandbox.
    Dir { id: String, path: String },
    /// Template operations.
    #[command(subcommand, visible_alias = "template")]
    Templates(TemplatesCommand),
    /// Snapshot operations.
    #[command(subcommand, visible_alias = "snapshots")]
    Snapshot(SnapshotCommand),
    /// Volume operations.
    #[command(subcommand, visible_alias = "volumes")]
    Volume(VolumeCommand),
    /// Dedicated public IPs: allocate, attach, release, reverse DNS, pools.
    #[command(subcommand, visible_alias = "ips")]
    Ip(IpCommand),
    /// Show what happened to sandboxes, in order, and optionally follow it.
    Events {
        /// Restrict to one sandbox.
        #[arg(long)]
        sandbox: Option<String>,
        /// Start after this position, from a previous listing's SEQ column.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Keep printing new events as they happen.
        #[arg(long, short = 'f')]
        follow: bool,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Show what sandboxes consumed, from the usage ledger, including
    /// sandboxes that no longer exist.
    Usage {
        /// Start of the window, UTC: `2026-10-01` or `2026-10-01T12:00:00Z`.
        /// An interval belongs to the window it started in.
        #[arg(long)]
        from: Option<String>,
        /// End of the window, exclusive, in the same form.
        #[arg(long)]
        to: Option<String>,
        /// Restrict to one sandbox, by id or by the name of one that exists.
        #[arg(long)]
        sandbox: Option<String>,
        /// Only sandboxes that carried this key=value tag. Repeatable.
        #[arg(long = "tag", value_name = "KEY=VALUE")]
        tags: Vec<String>,
        /// Sum by `sandbox`, `template`, `node`, `state` or `tag:<key>`, per
        /// state. Omitted lists the intervals themselves.
        #[arg(long)]
        group_by: Option<String>,
        #[arg(long, value_enum, default_value_t = UsageFormat::Table)]
        format: UsageFormat,
        /// Leave out the stretch since each open interval began.
        #[arg(long = "closed")]
        is_closed_only: bool,
        /// Continue an export after this interval id, from a previous
        /// page's `next_after`. Open intervals are never included with one.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Intervals per page; sums are never paged.
        #[arg(long, default_value_t = 1000)]
        limit: u32,
    },
    /// Show recorded egress attempts and DNS lookups.
    Audit {
        /// Restrict to one sandbox.
        #[arg(long)]
        sandbox: Option<String>,
        /// Only attempts the proxy refused.
        #[arg(long = "denied")]
        is_denied_only: bool,
        /// UTC lower bound, e.g. 2026-08-27 or 2026-08-27T00:00:00Z.
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum UsageFormat {
    Table,
    Json,
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user with a private home directory.
    Create { id: String, name: String },
    /// Delete a user that `user create` could have made. The home is kept,
    /// handed to root, unless --remove-home.
    Delete {
        id: String,
        name: String,
        #[arg(long = "remove-home")]
        is_home_removed: bool,
    },
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Create a group with a shared directory.
    Create { id: String, name: String },
    /// Add a user to a group.
    Add {
        id: String,
        user: String,
        group: String,
    },
    /// Remove a user from a group.
    Remove {
        id: String,
        user: String,
        group: String,
    },
    /// Delete a group that `group create` could have made. Its shared
    /// directory is kept, handed to root, unless --remove-shared-dir.
    Delete {
        id: String,
        name: String,
        #[arg(long = "remove-shared-dir")]
        is_shared_dir_removed: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print a sandbox's current configuration. Same output as `burrow
    /// inspect`.
    List {
        id: String,
        /// Emit the record as JSON instead of the readable field list.
        #[arg(long = "json")]
        is_json_requested: bool,
    },
    /// Replace a running sandbox's egress policy.
    NetworkPolicy {
        id: String,
        #[command(flatten)]
        network: NetworkFlags,
    },
    /// Move a sandbox's lifetime clocks and snapshot retention. A flag you
    /// leave out is left as it is; 0 is unlimited, as on a create.
    #[command(alias = "lifetimes")]
    Lifetime {
        id: String,
        /// Destroy the sandbox this many seconds after it was created.
        #[arg(long, alias = "max-lifetime")]
        max_lifetime_secs: Option<u64>,
        /// Suspend it after this many idle seconds.
        #[arg(long, alias = "idle-suspend")]
        idle_suspend_secs: Option<u64>,
        /// Delete it once it has been suspended this long.
        #[arg(long, alias = "suspended-ttl")]
        suspended_ttl_secs: Option<u64>,
        /// Sweep a snapshot this long after it was last used.
        #[arg(long)]
        snapshot_expiration_secs: Option<u64>,
        /// Keep only this many snapshots, evicting the oldest.
        #[arg(long)]
        keep_last_snapshots: Option<u32>,
        /// Let an evicted snapshot expire on its own instead of being deleted.
        #[arg(long)]
        keep_evicted_snapshots: Option<bool>,
    },
    /// Change a sandbox's vCPUs, memory and root disk.
    ///
    /// A running sandbox takes what its hypervisor can hotplug: a bigger disk
    /// under Firecracker and Cloud Hypervisor, and vCPUs under Cloud
    /// Hypervisor on x86_64. A shut-down one (`burrow shutdown`) takes everything: vCPUs
    /// and memory on its next `boot`, and its disk at once, shrunk by a helper
    /// VM that checks the filesystem first and refuses a size below what it
    /// needs. A suspended sandbox takes none of it. A macOS sandbox's disk
    /// grows while it is shut down and shrinks while it runs, and its guest
    /// finishes either on its next boot. Each change is reported as live, next
    /// boot, offline or refused with the reason; any refusal exits non-zero.
    Resources {
        id: String,
        #[arg(long)]
        vcpus: Option<u32>,
        /// Memory in MiB, or a number with m or g.
        #[arg(long = "mem-mib", alias = "mem", value_parser = parse_size_mib)]
        mem_mib: Option<u32>,
        /// Root disk: MiB, or a number with m or g, e.g. 20g.
        #[arg(long = "disk-mib", alias = "disk", value_parser = parse_size_mib)]
        disk_mib: Option<u32>,
    },
    /// Grow or shrink a sandbox's root disk: `config resources --disk-mib`.
    Disk {
        id: String,
        /// The disk's new size: MiB, or a number with m or g, e.g. 20g.
        #[arg(value_parser = parse_size_mib)]
        mib: u32,
    },
    /// Replace a running sandbox's exec and file policies.
    ///
    /// A section you name is replaced wholesale; a section you do not name is
    /// left exactly as it is, so tightening files cannot re-open exec. Within
    /// the fs section every field is replaced together: restate the parts you
    /// want kept.
    Access {
        id: String,
        #[command(flatten)]
        access: AccessUpdateFlags,
    },
    /// Replace a sandbox's tags. Passing none clears them.
    Tags {
        id: String,
        /// Tag as key=value. Repeatable; replaces the whole set.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Replace a sandbox's published ports. Passing none closes them all.
    Ports {
        id: String,
        /// Guest port to publish. Repeatable; replaces the whole set.
        #[arg(long = "port", short = 'p')]
        ports: Vec<u32>,
    },
}

/// Everything `create` needs, shared with `run` so a sandbox made either way
/// is configured by the same flags.
#[derive(ClapArgs)]
struct CreateFlags {
    /// An allocated public IP to attach once the sandbox is up, from
    /// `burrow ip allocate`. A static address places the sandbox on its node.
    /// Repeatable.
    #[arg(long = "ip")]
    ips: Vec<String>,
    /// Name for the sandbox, usable anywhere its id is. 1-63 characters of
    /// lowercase letters, digits and '-'. Unique across the fleet, and fixed
    /// once the sandbox exists.
    #[arg(long)]
    name: Option<String>,
    /// Template to boot, as imported by `burrow pull`. Required unless
    /// `--snapshot` is given, which carries its own. A template pulled from
    /// Docker Sandbox Kits is provisioned the way their descriptors ask.
    #[arg(long)]
    template: Option<String>,
    /// Create-phase value for a kit template's arg, as name=value.
    /// Repeatable.
    #[arg(long = "arg")]
    kit_args: Vec<String>,
    /// Environment override for a kit template's processes, as NAME=value.
    /// Repeatable.
    #[arg(long = "kit-env")]
    kit_env: Vec<String>,
    /// Capability type to decline for this sandbox, by full name. A kit
    /// requiring it is refused; one asking optionally does without.
    /// Repeatable.
    #[arg(long = "reject-capability")]
    reject_capabilities: Vec<String>,
    /// Snapshot to start from. The sandbox restores that state instead of
    /// booting, and takes its template and machine shape from the snapshot,
    /// so --template, --vcpus and --mem-mib may not disagree with it.
    #[arg(long)]
    snapshot: Option<String>,
    /// vCPUs. Defaults to 1.
    #[arg(long)]
    vcpus: Option<u32>,
    /// Guest memory in MiB. Defaults to 512.
    #[arg(long)]
    mem_mib: Option<u32>,
    /// Root disk in MiB, as the guest sees it: at least the template's image.
    /// Defaults to the image plus 1024. Resized later with `burrow config
    /// resources --disk-mib`.
    #[arg(long = "disk-mib")]
    disk_mib: Option<u32>,
    /// Destroy the sandbox this many seconds after it is created.
    /// 0 (default) lets it live until something deletes it.
    #[arg(long, default_value_t = 0)]
    max_lifetime_secs: u64,
    /// Suspend the sandbox after this many seconds unused; `resume` brings it
    /// back where it left off. 0 (default) never suspends it.
    #[arg(long, default_value_t = 0)]
    idle_suspend_secs: u64,
    /// Delete the sandbox once it has been suspended this long, releasing
    /// its disk and address. 0 (default) keeps it suspended indefinitely.
    #[arg(long, default_value_t = 0)]
    suspended_ttl_secs: u64,
    /// Sweep snapshots of this sandbox this many seconds after they were last
    /// used, where a use is a sandbox created from one. 0 (default) keeps them
    /// until something deletes them.
    #[arg(long, default_value_t = 0)]
    snapshot_expiration_secs: u64,
    /// Keep only this many snapshots of the sandbox, evicting the oldest as a
    /// new one is taken. 1-10; 0 (default) is unlimited.
    #[arg(long, default_value_t = 0)]
    keep_last_snapshots: u32,
    /// Let a snapshot that --keep-last-snapshots evicts live out its
    /// expiration instead of being deleted at once. Needs both
    /// --keep-last-snapshots and --snapshot-expiration-secs.
    #[arg(long = "keep-evicted-snapshots")]
    is_evicted_snapshots_kept: bool,
    /// Mount a volume, as `name:/path` or `name:/path:ro`, or a tmpfs as
    /// `tmpfs:/path[:size=512m][:mode=1777]`. Repeatable. A sandbox that
    /// mounts a volume is placed on the node holding it. Volumes are
    /// hotplugged onto a warm restore, or the sandbox boots cold where the
    /// hypervisor cannot hotplug drives.
    #[arg(long = "mount")]
    mounts: Vec<String>,
    /// Tag as key=value. Repeatable; at most 16.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Guest port to publish once the sandbox exists, as `expose` would.
    /// The host port is picked by the node. Repeatable.
    #[arg(long = "publish", short = 'p')]
    publish: Vec<u32>,
    /// Only place this sandbox on a node carrying this key=value label.
    /// Repeatable; every one must match. `burrow nodes ls` shows what each
    /// node carries.
    #[arg(long = "node-label")]
    node_labels: Vec<String>,
    #[command(flatten)]
    network: NetworkFlags,
    #[command(flatten)]
    access: AccessFlags,
    /// Private network to join; members can address each other. Repeatable.
    #[arg(long = "network")]
    networks: Vec<String>,
    /// Name this sandbox answers to on its networks, reachable from peers
    /// as `<alias>.<network>.internal`. Defaults to the sandbox id, which
    /// always works.
    #[arg(long)]
    alias: Option<String>,
}

impl CreateFlags {
    /// Whether the caller configured a sandbox beyond naming it.
    ///
    /// `run --name` may land on an existing sandbox, where none of these flags
    /// can be applied, and a silently ignored `--mem-mib` is worse than an
    /// error. `--name` and `--publish` are excluded: one is what was matched
    /// on, the other still applies to a sandbox that already exists.
    fn is_stated(&self) -> bool {
        self.template.is_some()
            || self.snapshot.is_some()
            || self.vcpus.is_some()
            || self.mem_mib.is_some()
            || self.disk_mib.is_some()
            || self.max_lifetime_secs != 0
            || self.idle_suspend_secs != 0
            || self.suspended_ttl_secs != 0
            || self.snapshot_expiration_secs != 0
            || self.keep_last_snapshots != 0
            || self.is_evicted_snapshots_kept
            || !self.mounts.is_empty()
            || !self.tags.is_empty()
            || !self.node_labels.is_empty()
            || !self.networks.is_empty()
            || self.alias.is_some()
            || self.network.is_stated()
            || self.access.is_stated()
    }
}

/// Exec and file access, shared by `create`, `run` and `fork`.
///
/// Every flag here takes something away. Naming none of them leaves the policy
/// sections unset, which is what a sandbox that may do anything looks like on
/// the wire, so an old client and a new one describe the same sandbox.
#[derive(ClapArgs)]
struct AccessFlags {
    /// Refuse `exec`, `run` and `connect` against this sandbox. It still
    /// boots, and its files can still be copied in and out.
    #[arg(long = "no-exec")]
    is_exec_denied: bool,
    /// Refuse uploads into this sandbox.
    #[arg(long = "no-upload")]
    is_upload_denied: bool,
    /// Refuse downloads out of this sandbox.
    #[arg(long = "no-download")]
    is_download_denied: bool,
    /// Absolute path uploads, downloads and listings are confined to, e.g.
    /// /work. Repeatable; at most 16. Without any, the whole filesystem is
    /// reachable.
    #[arg(long = "fs-scope")]
    fs_scopes: Vec<String>,
    /// Largest single upload accepted, in bytes. 0 (default) is unlimited.
    #[arg(long, default_value_t = 0)]
    max_upload_bytes: u64,
}

impl AccessFlags {
    fn is_stated(&self) -> bool {
        self.is_exec_denied
            || self.is_upload_denied
            || self.is_download_denied
            || !self.fs_scopes.is_empty()
            || self.max_upload_bytes != 0
    }

    /// The exec section, set only when the caller restricted exec.
    ///
    /// An absent section means "allowed" to the node, so sending one that says
    /// exactly that would be noise in every record.
    fn exec_policy(&self) -> Option<common::ExecPolicy> {
        self.is_exec_denied.then_some(common::ExecPolicy {
            is_exec_allowed: false,
        })
    }

    /// The fs section, set only when the caller restricted file access. One
    /// fs flag settles all four fields, since the message is enforced whole.
    fn fs_policy(&self) -> Option<common::FsPolicy> {
        let stated = self.is_upload_denied
            || self.is_download_denied
            || !self.fs_scopes.is_empty()
            || self.max_upload_bytes != 0;
        stated.then(|| common::FsPolicy {
            is_upload_allowed: !self.is_upload_denied,
            is_download_allowed: !self.is_download_denied,
            path_scopes: self.fs_scopes.clone(),
            max_upload_bytes: self.max_upload_bytes,
        })
    }
}

/// Exec and file access on a sandbox that already exists, for `config access`.
///
/// Separate from [`AccessFlags`] because the two mean different things by
/// silence: on a create, naming no flag leaves a section unset; here it leaves
/// the section as the node already has it, so tightening files need not restate
/// exec. Each allowance therefore has both spellings, and they conflict rather
/// than being resolved by argument order.
#[derive(ClapArgs)]
struct AccessUpdateFlags {
    /// Refuse `exec`, `run` and `connect` against this sandbox.
    #[arg(long = "no-exec", conflicts_with = "is_exec_allowed")]
    is_exec_denied: bool,
    /// Allow them again.
    #[arg(long = "allow-exec")]
    is_exec_allowed: bool,
    /// Refuse uploads into this sandbox.
    #[arg(long = "no-upload", conflicts_with = "is_upload_allowed")]
    is_upload_denied: bool,
    /// Allow uploads again.
    #[arg(long = "allow-upload")]
    is_upload_allowed: bool,
    /// Refuse downloads out of this sandbox.
    #[arg(long = "no-download", conflicts_with = "is_download_allowed")]
    is_download_denied: bool,
    /// Allow downloads again.
    #[arg(long = "allow-download")]
    is_download_allowed: bool,
    /// Absolute path uploads, downloads and listings are confined to.
    /// Repeatable; at most 16. Naming none while setting another fs flag
    /// reopens the whole filesystem, since the section is replaced whole.
    #[arg(long = "fs-scope")]
    fs_scopes: Vec<String>,
    /// Largest single upload accepted, in bytes. 0 is unlimited.
    #[arg(long)]
    max_upload_bytes: Option<u64>,
}

impl AccessUpdateFlags {
    /// The exec section, sent only when the caller said something about exec.
    fn exec_policy(&self) -> Option<common::ExecPolicy> {
        (self.is_exec_denied || self.is_exec_allowed).then_some(common::ExecPolicy {
            is_exec_allowed: !self.is_exec_denied,
        })
    }

    /// The fs section, sent only when the caller said something about files.
    /// One fs flag settles all four fields, because the node replaces the
    /// section whole.
    fn fs_policy(&self) -> Option<common::FsPolicy> {
        let stated = self.is_upload_denied
            || self.is_upload_allowed
            || self.is_download_denied
            || self.is_download_allowed
            || !self.fs_scopes.is_empty()
            || self.max_upload_bytes.is_some();
        stated.then(|| common::FsPolicy {
            is_upload_allowed: !self.is_upload_denied,
            is_download_allowed: !self.is_download_denied,
            path_scopes: self.fs_scopes.clone(),
            max_upload_bytes: self.max_upload_bytes.unwrap_or(0),
        })
    }
}

/// Everything an exec needs, shared by `exec`, `run` and `connect`.
#[derive(ClapArgs)]
struct ExecFlags {
    /// Allocate a pty, so the command sees a terminal.
    #[arg(long = "pty", short = 't', visible_alias = "tty")]
    is_pty_allocated: bool,
    /// Environment variable as key=value. Repeatable; wins over the image's
    /// own environment.
    #[arg(long = "env", short = 'e')]
    envs: Vec<String>,
    /// Directory to run in. Defaults to the image's WORKDIR, or the user's
    /// home when --user is given.
    #[arg(long = "workdir", short = 'w')]
    workdir: Option<String>,
    /// Guest user to run as. Defaults to root. Create one with
    /// `burrow user create`.
    #[arg(long = "user", short = 'u')]
    user: Option<String>,
    /// Rotate the command's output log once a file reaches this size, e.g.
    /// 20m, as Docker's `--log-opt max-size`. Unset keeps every byte.
    #[arg(long = "log-max-size", value_parser = parse_size)]
    log_max_size: Option<u64>,
    /// Log files kept once rotating, as Docker's `--log-opt max-file`.
    #[arg(long = "log-max-files", default_value_t = 1, requires = "log_max_size")]
    log_max_files: u32,
}

/// A size as Docker writes one: bytes, or a number with k, m or g.
fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim().to_ascii_lowercase();
    let (digits, scale) = match text.strip_suffix(['k', 'm', 'g']) {
        Some(digits) => (
            digits,
            match text.chars().last() {
                Some('k') => 1u64 << 10,
                Some('m') => 1 << 20,
                _ => 1 << 30,
            },
        ),
        None => (text.as_str(), 1),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a size like 20m"))?;
    match value.checked_mul(scale) {
        Some(0) | None => Err(format!("{text:?} is not a size above zero")),
        Some(bytes) => Ok(bytes),
    }
}

/// Egress policy, shared by `create`, `run` and `config network-policy` so they
/// cannot drift apart on what a flag means.
#[derive(ClapArgs)]
struct NetworkFlags {
    /// Egress policy: none (default), allowlist, or open.
    #[arg(long, default_value = "none", value_parser = ["none", "allowlist", "open"])]
    net: String,
    /// Domain the sandbox may reach in allowlist mode, e.g. pypi.org or
    /// *.pythonhosted.org. Repeatable.
    #[arg(long = "allow-domain")]
    allow_domains: Vec<String>,
    /// Extra destinations permitted at L3, e.g. 10.0.0.0/8. Bypasses the
    /// egress proxy entirely. Repeatable.
    #[arg(long = "allow-cidr")]
    allow_cidrs: Vec<String>,
    /// Ports the --allow-cidr allowance is limited to. Without this it
    /// covers every port and protocol on those addresses. Repeatable.
    #[arg(long = "allow-port")]
    allow_ports: Vec<u16>,
    /// Range the sandbox may never reach, e.g. 169.254.169.254/32. Beats every
    /// allowance, in every mode. Repeatable.
    #[arg(long = "deny-cidr")]
    deny_cidrs: Vec<String>,
    /// Domain the sandbox may never reach, e.g. *.internal.example. Beats
    /// every allowance, in every mode: not resolved, not connected to.
    /// Repeatable.
    #[arg(long = "deny-domain")]
    deny_domains: Vec<String>,
    /// Destination port the sandbox may never connect to, in every mode, as
    /// [tcp/|udp/]PORT[-END][@CIDR,...]: tcp/25, tcp/465-587, 5432@10.0.0.0/8.
    /// Without a protocol it covers both; without CIDRs every destination,
    /// over IPv4 and IPv6. Beats every allowance. Repeatable.
    #[arg(long = "deny-port")]
    deny_ports: Vec<String>,
    /// Refuse every IPv6 destination, in every mode. Without it each mode
    /// keeps its own IPv6 behaviour.
    #[arg(long = "deny-ipv6")]
    is_ipv6_denied: bool,
    /// What may reach the sandbox's public addresses (its dedicated IPs and
    /// its global IPv6 address), as PROTO[/PORTS][@SOURCES]: tcp/22,
    /// tcp/25,587, udp/27000-27015, tcp/22@203.0.113.0/24, icmp. Nothing is
    /// admitted without one. Repeatable.
    #[arg(long = "ingress")]
    ingress: Vec<String>,
    /// Terminate this sandbox's TLS so the host named inside the session
    /// is checked, not just the SNI. Closes domain fronting, at the cost
    /// of the proxy being able to read the payload. With --net open, only the
    /// hosts named by --rule and --inject-header are inspected; the rest of
    /// the sandbox's traffic is untouched. Only settable at creation, since
    /// it is what gives the guest the fleet inspection root; rules can change
    /// later.
    #[arg(long = "inspect-tls")]
    is_tls_inspected: bool,
    /// Credential the host adds to requests for a domain, as
    /// 'domain:Name=Value'. Requires --inspect-tls; the value never enters the
    /// guest. Repeatable.
    #[arg(long = "inject-header")]
    inject_headers: Vec<String>,
    /// Rule for inspected requests, as a JSON object: a domain, an optional
    /// match, and either setHeaders or forward, plus optionally expiresIn
    /// (seconds, or a number with s, m, h or d) or expiresAtUnixMs. Evaluated
    /// in order, and before every --inject-header. Requires --inspect-tls.
    /// Repeatable.
    ///
    /// {"domain":"api.example.com","match":{"path":{"startsWith":"/v1/"},
    /// "method":["GET"]},"setHeaders":{"Authorization":"Bearer t"},
    /// "expiresIn":"1h"}
    #[arg(long = "rule")]
    rules: Vec<String>,
}

impl NetworkFlags {
    /// Whether the caller named any egress flag at all.
    ///
    /// `--net` defaults to `none`, which is a real instruction on `create` and
    /// would be a silent lockdown on `fork`: a child given nothing should
    /// inherit its source's policy, not lose it.
    fn is_stated(&self) -> bool {
        self.net != "none"
            || self.is_tls_inspected
            || !self.allow_domains.is_empty()
            || !self.allow_cidrs.is_empty()
            || !self.allow_ports.is_empty()
            || !self.deny_cidrs.is_empty()
            || !self.deny_domains.is_empty()
            || !self.deny_ports.is_empty()
            || self.is_ipv6_denied
            || !self.ingress.is_empty()
            || !self.inject_headers.is_empty()
            || !self.rules.is_empty()
    }
}

/// Parses one `--deny-port`: `[tcp/|udp/]PORT[-END][@CIDR,...]`.
///
/// Only the shape is checked here. Ranges and CIDRs are validated by the node,
/// which is the one place every client's policy passes through.
fn parse_port_rule(spec: &str) -> anyhow::Result<common::PortRule> {
    let usage = || {
        anyhow::anyhow!(
            "--deny-port {spec:?}: expected [tcp/|udp/]PORT[-END][@CIDR,...], e.g. tcp/25 or tcp/465-587"
        )
    };
    let (ports, cidrs) = match spec.split_once('@') {
        Some((ports, cidrs)) => (
            ports,
            cidrs
                .split(',')
                .map(|cidr| cidr.trim().to_string())
                .collect::<Vec<_>>(),
        ),
        None => (spec, Vec::new()),
    };
    if cidrs.iter().any(String::is_empty) {
        return Err(usage());
    }
    let (protocol, ports) = if let Some(rest) = ports.strip_prefix("tcp/") {
        (common::PortProtocol::Tcp, rest)
    } else if let Some(rest) = ports.strip_prefix("udp/") {
        (common::PortProtocol::Udp, rest)
    } else {
        (common::PortProtocol::Unspecified, ports)
    };
    let number = |text: &str| -> anyhow::Result<u32> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(usage());
        }
        text.parse::<u32>().map_err(|_| usage())
    };
    let (port, port_end) = match ports.split_once('-') {
        Some((first, last)) => (number(first)?, number(last)?),
        None => (number(ports)?, 0),
    };
    Ok(common::PortRule {
        protocol: protocol as i32,
        port,
        port_end,
        cidrs,
    })
}

/// Parses one `--ingress`: `PROTO[/PORTS][@SOURCES]`, where PROTO is tcp,
/// udp, icmp or any, and PORTS a comma list of ports and ranges.
fn parse_ingress_rule(spec: &str) -> anyhow::Result<common::IngressRule> {
    let usage = || {
        anyhow::anyhow!(
            "--ingress {spec:?}: expected PROTO[/PORTS][@SOURCES], e.g. tcp/22, tcp/25,587, \
             udp/27000-27015, tcp/22@203.0.113.0/24 or icmp"
        )
    };
    let (head, sources) = match spec.split_once('@') {
        Some((head, sources)) => (
            head,
            sources
                .split(',')
                .map(|source| source.trim().to_string())
                .collect::<Vec<_>>(),
        ),
        None => (spec, Vec::new()),
    };
    if sources.iter().any(String::is_empty) {
        return Err(usage());
    }
    let (protocol, ports) = match head.split_once('/') {
        Some((protocol, ports)) => (protocol, Some(ports)),
        None => (head, None),
    };
    let protocol = match protocol {
        "tcp" => common::IngressProtocol::Tcp,
        "udp" => common::IngressProtocol::Udp,
        "icmp" => common::IngressProtocol::Icmp,
        "any" => common::IngressProtocol::Unspecified,
        _ => return Err(usage()),
    };
    let number = |text: &str| -> anyhow::Result<u32> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(usage());
        }
        text.parse::<u32>().map_err(|_| usage())
    };
    let ports = match ports {
        None => Vec::new(),
        Some(ports) => ports
            .split(',')
            .map(|range| match range.split_once('-') {
                Some((first, last)) => Ok(common::PortRange {
                    port: number(first)?,
                    port_end: number(last)?,
                }),
                None => Ok(common::PortRange {
                    port: number(range)?,
                    port_end: 0,
                }),
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    };
    if protocol == common::IngressProtocol::Icmp && !ports.is_empty() {
        anyhow::bail!("--ingress {spec:?}: icmp takes no ports");
    }
    Ok(common::IngressRule {
        protocol: protocol as i32,
        ports,
        sources,
    })
}

/// The `--ingress` spelling of a rule.
fn describe_ingress_rule(rule: &common::IngressRule) -> String {
    let mut text = match common::IngressProtocol::try_from(rule.protocol) {
        Ok(common::IngressProtocol::Tcp) => "tcp",
        Ok(common::IngressProtocol::Udp) => "udp",
        Ok(common::IngressProtocol::Icmp) => "icmp",
        _ => "any",
    }
    .to_string();
    if !rule.ports.is_empty() {
        let ports: Vec<String> = rule
            .ports
            .iter()
            .map(|range| match range.port_end {
                0 => range.port.to_string(),
                end => format!("{}-{end}", range.port),
            })
            .collect();
        text.push('/');
        text.push_str(&ports.join(","));
    }
    if !rule.sources.is_empty() {
        text.push('@');
        text.push_str(&rule.sources.join(","));
    }
    text
}

/// The `--deny-port` spelling of a port rule, for reading a policy back.
fn describe_port_rule(rule: &common::PortRule) -> String {
    let protocol = match common::PortProtocol::try_from(rule.protocol) {
        Ok(common::PortProtocol::Tcp) => "tcp/",
        Ok(common::PortProtocol::Udp) => "udp/",
        _ => "",
    };
    let mut text = format!("{protocol}{}", rule.port);
    if rule.port_end != 0 && rule.port_end != rule.port {
        text.push_str(&format!("-{}", rule.port_end));
    }
    if !rule.cidrs.is_empty() {
        text.push('@');
        text.push_str(&rule.cidrs.join(","));
    }
    text
}

/// Parses repeated `--mount name:/path[:ro|rw]` and
/// `--mount tmpfs:/path[:size=512m][:mode=1777]` flags.
///
/// The options are last so the common case reads as `name:/path`, and a path
/// may itself contain colons: the volume name is taken up to the first colon,
/// and a trailing `:ro`, `:rw`, `:size=` or `:mode=` off the end.
fn parse_mounts(mounts: &[String]) -> anyhow::Result<Vec<common::VolumeMount>> {
    let mut out = Vec::new();
    for raw in mounts {
        let (volume, rest) = raw.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("--mount {raw:?} must be name:/path, optionally with :ro or :rw")
        })?;
        if volume == "tmpfs" {
            out.push(parse_tmpfs_mount(raw, rest)?);
            continue;
        }
        let (path, read_only) = match rest.rsplit_once(':') {
            Some((path, "ro" | "read-only")) => (path, true),
            Some((path, "rw" | "read-write")) => (path, false),
            // No mode, or a colon that is part of the path.
            _ => (rest, false),
        };
        if volume.is_empty() || path.is_empty() {
            anyhow::bail!("--mount {raw:?} must be name:/path, optionally with :ro or :rw");
        }
        out.push(common::VolumeMount {
            volume: volume.to_string(),
            path: path.to_string(),
            is_read_only: read_only,
            ..Default::default()
        });
    }
    Ok(out)
}

/// The `/path[:size=512m][:mode=1777]` part of a tmpfs mount, in either order.
fn parse_tmpfs_mount(raw: &str, mut rest: &str) -> anyhow::Result<common::VolumeMount> {
    let usage = || {
        anyhow::anyhow!(
            "--mount {raw:?} must be tmpfs:/path, optionally with :size=512m or :mode=1777"
        )
    };
    let mut size_mib = 0;
    let mut mode = String::new();
    while let Some((path, option)) = rest.rsplit_once(':') {
        if let Some(size) = option.strip_prefix("size=") {
            size_mib = parse_mib(size).ok_or_else(usage)?;
        } else if let Some(octal) = option.strip_prefix("mode=") {
            mode = octal.to_string();
        } else {
            // A colon that is part of the path.
            break;
        }
        rest = path;
    }
    if rest.is_empty() {
        return Err(usage());
    }
    Ok(common::VolumeMount {
        path: rest.to_string(),
        is_tmpfs: true,
        size_mib,
        mode,
        ..Default::default()
    })
}

/// A size in MiB for `config resources`, as [`parse_mib`] reads one.
fn parse_size_mib(size: &str) -> Result<u32, String> {
    parse_mib(size)
        .and_then(|mib| u32::try_from(mib).ok())
        .ok_or_else(|| format!("{size:?} is not a size like 20g, 512m or 4096"))
}

/// Sends a resources update and prints what became of each field, failing
/// when any was refused.
async fn update_resources(
    client: &mut Client,
    id: String,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_mib: Option<u32>,
) -> anyhow::Result<()> {
    let updated = client
        .update_resources(api::UpdateResourcesRequest {
            sandbox_id: id,
            vcpus,
            mem_mib,
            disk_mib,
        })
        .await?
        .into_inner();
    let id = updated.sandbox.as_ref().map_or("", |s| &s.id);
    let lines = describe_update(&updated);
    for line in &lines {
        println!("{id} {line}");
    }
    if lines.iter().any(|line| line.contains(" refused: ")) {
        anyhow::bail!("not every change was applied");
    }
    Ok(())
}

/// What a resources update did, a line per field asked for.
fn describe_update(updated: &api::UpdateResourcesResponse) -> Vec<String> {
    let fields = [
        ("vcpus", "", &updated.vcpus),
        ("memory", " MiB", &updated.mem_mib),
        ("disk", " MiB", &updated.disk_mib),
    ];
    fields
        .into_iter()
        .filter_map(|(name, unit, outcome)| {
            let outcome = outcome.as_ref()?;
            let (from, to) = (outcome.previous, outcome.value);
            let filesystem = match (name, updated.filesystem_bytes) {
                ("disk", bytes) if bytes > 0 => format!(", filesystem {} MiB", bytes >> 20),
                _ => String::new(),
            };
            let change = api::ResourceChange::try_from(outcome.change).unwrap_or_default();
            let note = match change {
                api::ResourceChange::Refused => String::new(),
                _ if outcome.reason.is_empty() => String::new(),
                _ => format!("; {}", outcome.reason),
            };
            Some(
                match change {
                    api::ResourceChange::Unchanged => format!("{name} already {to}{unit}"),
                    api::ResourceChange::Live => {
                        format!("{name} {from} -> {to}{unit} live{filesystem}")
                    }
                    api::ResourceChange::NextBoot => {
                        format!("{name} {from} -> {to}{unit} on its next boot{filesystem}")
                    }
                    api::ResourceChange::Offline if to > from => format!(
                        "{name} {from} -> {to}{unit} while shut down; the guest fills it on its \
                         next boot"
                    ),
                    api::ResourceChange::Offline => {
                        format!("{name} {from} -> {to}{unit} offline{filesystem}")
                    }
                    _ => format!("{name} refused: {}", outcome.reason),
                } + &note,
            )
        })
        .collect()
}

/// `512m`, `2g` or a bare number of MiB.
fn parse_mib(size: &str) -> Option<u64> {
    let (digits, scale) = match size.as_bytes().last()? {
        b'm' | b'M' => (&size[..size.len() - 1], 1),
        b'g' | b'G' => (&size[..size.len() - 1], 1024),
        _ => (size, 1),
    };
    let n: u64 = digits.parse().ok().filter(|n| *n > 0)?;
    n.checked_mul(scale)
}

/// Parses repeated `key=value` flags.
///
/// Split on the first `=`, so a value may contain more. A flag with no `=`, or
/// an empty key, is refused rather than guessed at: a mistyped tag is a sandbox
/// the caller will not find again.
fn parse_pairs(
    flag: &str,
    specs: &[String],
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let mut pairs = std::collections::HashMap::new();
    for spec in specs {
        let (key, value) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{flag} {spec:?} is not key=value"))?;
        if key.is_empty() {
            anyhow::bail!("{flag} {spec:?} needs a key before the '='");
        }
        pairs.insert(key.to_string(), value.to_string());
    }
    Ok(pairs)
}

#[derive(Subcommand)]
enum TemplatesCommand {
    /// List templates, with the shapes (VCPUSxMEM_MIB) each is warm at.
    Ls {
        /// One row per warm snapshot instead: node, shape, disk and last use.
        #[arg(long)]
        warm: bool,
    },
    /// Import an OCI image as a template, e.g. `python:3.12-slim`.
    Import {
        /// Image references: [registry/]repository[:tag|@digest]. Several
        /// are a Docker Sandbox Kit set, composed into one template.
        #[arg(required = true)]
        images: Vec<String>,
        /// Template name. Defaults to the image's repository name, or for a
        /// kit set to one derived from its digests.
        #[arg(long)]
        name: Option<String>,
        /// Boot the image's own systemd under the agent. The image has to
        /// ship systemd.
        #[arg(long)]
        systemd: bool,
        /// Hypervisor every sandbox from the template runs under:
        /// `firecracker` or `cloud-hypervisor`. Defaults to Firecracker.
        #[arg(long)]
        hypervisor: Option<String>,
    },
    /// Build a template: steps run on another template, or macOS installed
    /// from a restore image on a Mac node.
    Build {
        /// Template name.
        name: String,
        /// Template to start from.
        #[arg(long, conflicts_with = "from_ipsw")]
        from: Option<String>,
        /// macOS restore image to install, as a path on the Mac node or
        /// `latest`, which the node downloads from Apple and keeps.
        #[arg(long)]
        from_ipsw: Option<String>,
        /// Shell command to run in the build, in order. Repeatable.
        #[arg(long = "step", conflicts_with = "from_ipsw")]
        steps: Vec<String>,
        /// Hypervisor every sandbox from the template runs under:
        /// `firecracker`, `cloud-hypervisor` or `vz`. Defaults to the base
        /// template's, and to `vz` for --from-ipsw.
        #[arg(long)]
        hypervisor: Option<String>,
        /// vCPUs of the build machine. Defaults to 1 for Linux and the
        /// restore image's minimum for macOS.
        #[arg(long, default_value_t = 0)]
        vcpus: u32,
        /// Memory of the build machine, in MiB. Defaults to 1024 for Linux
        /// and the restore image's minimum for macOS.
        #[arg(long = "mem", default_value_t = 0)]
        mem_mib: u32,
        /// Size of the build's root disk in MiB, which is the size of the image
        /// it makes. Defaults to the base image plus 1024. With --from-ipsw,
        /// the installed macOS disk: 65536 by default, and macOS needs 28672
        /// to install.
        #[arg(long, default_value_t = 0)]
        disk_mib: u32,
        /// Domain the build may reach. Repeatable; none means any.
        #[arg(long = "allow-domain")]
        allow_domains: Vec<String>,
    },
    /// Remove a template.
    Rm { name: String },
}

#[derive(Subcommand)]
enum SnapshotCommand {
    /// Save a sandbox's state as a snapshot. The sandbox keeps running.
    Create {
        /// Sandbox to snapshot, by id or name.
        sandbox: String,
        /// Seconds from last use before the snapshot is swept. Omitted falls
        /// back to the sandbox's --snapshot-expiration-secs, and to no expiry
        /// when that is unset too.
        #[arg(long, default_value_t = 0)]
        expiration_secs: u64,
    },
    /// List snapshots, newest first.
    #[command(alias = "list")]
    Ls {
        /// Only snapshots taken of this sandbox.
        sandbox: Option<String>,
    },
    /// Delete snapshots, freeing their disk on the node holding them.
    #[command(alias = "delete")]
    Rm {
        #[arg(required = true)]
        ids: Vec<String>,
    },
}

#[derive(Subcommand)]
enum VolumeCommand {
    /// Create a volume on one node, which is then where it lives.
    Create {
        name: String,
        /// Size in MiB.
        #[arg(long, default_value_t = 1024)]
        size_mib: u64,
        /// Labels the node holding it must carry, as key=value. Repeatable.
        /// A volume never moves, so this is the only chance to say where.
        #[arg(long = "node-label")]
        node_labels: Vec<String>,
    },
    /// List volumes.
    #[command(alias = "list")]
    Ls {
        /// Only volumes on this node.
        #[arg(long)]
        node: Option<String>,
        /// Emit the list as JSON, labels included.
        #[arg(long = "json")]
        is_json_requested: bool,
    },
    /// Show one volume, including which sandbox holds it writable.
    Inspect { name: String },
    /// Delete volumes and everything stored in them.
    #[command(alias = "delete")]
    Rm {
        #[arg(required = true)]
        names: Vec<String>,
    },
}

#[derive(Subcommand)]
enum IpCommand {
    /// Take an address from a pool, within this credential's quota.
    Allocate {
        /// The pool to take from; the first that can serve when left out.
        #[arg(long)]
        pool: Option<String>,
        /// An IPv6 subnet rather than an IPv4 address.
        #[arg(long = "v6")]
        is_v6: bool,
        /// Take one that reaches this sandbox's node, and attach it there.
        #[arg(long = "for")]
        sandbox: Option<String>,
    },
    /// Give an address back. It is quarantined before anyone gets it again.
    Release { address: String },
    /// Route an address to a sandbox.
    Attach { address: String, sandbox: String },
    /// Take an address off its sandbox, keeping it allocated.
    Detach { address: String },
    /// List the addresses this credential holds.
    #[command(alias = "list")]
    Ls {
        #[arg(long)]
        pool: Option<String>,
        /// Only those attached to this sandbox.
        #[arg(long)]
        sandbox: Option<String>,
        /// Quarantined addresses too (operators only).
        #[arg(long = "quarantined")]
        is_quarantine_included: bool,
        #[arg(long = "json")]
        is_json_requested: bool,
    },
    /// Address pools, operator credentials only.
    #[command(subcommand)]
    Pool(IpPoolCommand),
}

#[derive(Subcommand)]
enum IpPoolCommand {
    /// Define a pool on one node or on the nodes carrying a set of labels.
    Create(IpPoolFlags),
    /// Replace a pool's definition; its allocated addresses must stay in it.
    Update(IpPoolFlags),
    /// List pools with how much of each is allocated.
    #[command(alias = "list")]
    Ls {
        #[arg(long = "json")]
        is_json_requested: bool,
    },
    /// Remove a pool with nothing allocated from it.
    #[command(alias = "delete")]
    Rm { name: String },
}

#[derive(ClapArgs)]
struct IpPoolFlags {
    name: String,
    /// The one node the pool's addresses reach.
    #[arg(long)]
    node: Option<String>,
    /// Labels every node the pool covers carries, as key=value. Repeatable.
    #[arg(long = "node-label")]
    node_labels: Vec<String>,
    /// IPv4 addresses, as first-last. Repeatable.
    #[arg(long = "range")]
    ranges: Vec<String>,
    /// Single IPv4 addresses. Repeatable.
    #[arg(long = "address")]
    addresses: Vec<String>,
    /// The uplink gateway these addresses route through.
    #[arg(long)]
    gateway: Option<String>,
    /// The prefix of the gateway's network, e.g. 24.
    #[arg(long, default_value_t = 0)]
    prefix: u32,
    /// Resolvers to hand out with the addresses. Repeatable.
    #[arg(long = "nameserver")]
    nameservers: Vec<String>,
    /// An IPv6 prefix to carve per-sandbox subnets from, e.g. 2001:db8::/48.
    #[arg(long)]
    prefix6: Option<String>,
    /// The size of each sandbox's IPv6 share, e.g. 64 or 128.
    #[arg(long, default_value_t = 64)]
    per_sandbox: u32,
    /// The upstream looks addresses up on the uplink (ARP, NDP), so the node
    /// answers for them there.
    #[arg(long = "on-link")]
    is_on_link: bool,
    /// Allow outbound TCP 25 from these addresses.
    #[arg(long = "allow-smtp")]
    is_smtp_allowed: bool,
    /// Resume a suspended holder on its first admitted packet.
    #[arg(long = "wake-on-traffic")]
    is_wake_on_traffic: bool,
    /// Seconds a released address waits; the orchestrator's default when 0.
    #[arg(long, default_value_t = 0)]
    quarantine_secs: i64,
}

impl IpPoolFlags {
    fn pool(self) -> anyhow::Result<common::IpPool> {
        Ok(common::IpPool {
            name: self.name,
            node_id: self.node.unwrap_or_default(),
            node_labels: parse_pairs("--node-label", &self.node_labels)?,
            ranges: self.ranges,
            addresses: self.addresses,
            gateway: self.gateway.unwrap_or_default(),
            prefix_len: self.prefix,
            nameservers: self.nameservers,
            prefix6: self.prefix6.clone().unwrap_or_default(),
            per_sandbox: if self.prefix6.is_some() {
                self.per_sandbox
            } else {
                0
            },
            is_on_link: self.is_on_link,
            is_smtp_allowed: self.is_smtp_allowed,
            is_wake_on_traffic: self.is_wake_on_traffic,
            quarantine_secs: self.quarantine_secs,
            ..Default::default()
        })
    }
}

/// One address as `ip ls` prints it.
fn ip_line(ip: &common::PublicIp) -> String {
    let address = match ip.family {
        6 => format!("{}/{}", ip.address, ip.prefix_len),
        _ => ip.address.clone(),
    };
    let state = if ip.state() == common::PublicIpState::Quarantined {
        "quarantined"
    } else if ip.sandbox_id.is_empty() {
        "detached"
    } else {
        "attached"
    };
    format!(
        "{:<40} {:<14} {:<12} {:<20} {}",
        truncate(&address, 40),
        truncate(&ip.pool, 14),
        state,
        if ip.sandbox_id.is_empty() {
            "-"
        } else {
            &ip.sandbox_id
        },
        if ip.node_id.is_empty() {
            "-"
        } else {
            &ip.node_id
        },
    )
}

fn ip_json(ip: &common::PublicIp) -> serde_json::Value {
    serde_json::json!({
        "address": ip.address,
        "family": ip.family,
        "prefix_len": ip.prefix_len,
        "pool": ip.pool,
        "sandbox": ip.sandbox_id,
        "node": ip.node_id,
        "quarantined_until_unix_ms": ip.quarantined_until_unix_ms,
    })
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Issue a token and print it with the endpoint it works at.
    Issue {
        id: String,
        /// What it may do: exec, files:read or files:write. Repeatable; all
        /// three when left out.
        #[arg(long = "op")]
        ops: Vec<String>,
        /// Guest user every exec under it runs as, and every file transfer.
        #[arg(long)]
        user: Option<String>,
        /// Seconds it lasts, at most 3600. Five minutes when left out.
        #[arg(long, default_value_t = 0)]
        ttl: u32,
    },
    /// Refuse every token issued for a sandbox so far, and end the sessions
    /// they opened.
    Revoke { id: String },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store a secret. The value is read from --value, else from stdin.
    Set {
        /// Lowercase kebab-case, the `service` a kit credential names.
        name: String,
        #[arg(long)]
        value: Option<String>,
        /// Only this sandbox, by id or name, may use the secret. Repeatable;
        /// with no --allow-sandbox or --allow-tag, every sandbox may.
        #[arg(long = "allow-sandbox")]
        allowed_sandboxes: Vec<String>,
        /// Only sandboxes carrying this tag, as key=value, may use the secret.
        /// Repeatable.
        #[arg(long = "allow-tag")]
        allowed_tags: Vec<String>,
    },
    /// List secret names and their scopes. Values are never shown.
    #[command(visible_alias = "list")]
    Ls,
    /// Delete a secret.
    #[command(visible_alias = "remove")]
    Rm { name: String },
}

#[derive(Subcommand)]
enum NodesCommand {
    /// List registered nodes.
    Ls,
    /// Stop placing new sandboxes on a node. Refused while sandboxes on it
    /// hold public IPs, unless they are kept there.
    Drain {
        node_id: String,
        /// Also snapshot the sandboxes it is running.
        #[arg(long = "suspend")]
        suspend: bool,
        /// Drain although sandboxes here hold public IPs. They stay on this
        /// node and come back only here.
        #[arg(long = "keep-pinned")]
        is_pinned_kept: bool,
    },
    /// Resume placing sandboxes on a node.
    Undrain { node_id: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let api_key = load_api_key(args.api_key.as_deref(), args.api_key_file.as_deref())?;
    let _ = INSECURE.set(args.is_insecure);
    let _ = RELAYED.set(args.route == "orchestrator");
    let channel = connect(&args.orchestrator, args.is_insecure).await?;
    let mut client = BurrowClient::with_interceptor(channel, BearerAuth(api_key));

    match args.command {
        Command::Health => {
            let resp = client.health(api::HealthRequest {}).await?.into_inner();
            println!("ok (orchestrator v{})", resp.version);
        }
        Command::Nodes(NodesCommand::Ls) => list_nodes(&mut client).await?,
        Command::Nodes(NodesCommand::Drain {
            node_id,
            suspend,
            is_pinned_kept,
        }) => {
            let resp = client
                .drain_node(api::DrainNodeRequest {
                    node_id: node_id.clone(),
                    is_draining: true,
                    is_suspending: suspend,
                    is_pinned_kept,
                })
                .await?
                .into_inner();
            println!("draining {node_id} ({} suspended)", resp.suspended);
            if !resp.pinned_sandbox_ids.is_empty() {
                println!(
                    "kept on {node_id} by their public ips: {}",
                    resp.pinned_sandbox_ids.join(", ")
                );
            }
        }
        Command::Nodes(NodesCommand::Undrain { node_id }) => {
            client
                .drain_node(api::DrainNodeRequest {
                    node_id: node_id.clone(),
                    is_draining: false,
                    ..Default::default()
                })
                .await?;
            println!("{node_id} accepting sandboxes again");
        }
        Command::Create {
            create,
            is_connecting: connect,
        } => {
            let publish = create.publish.clone();
            let sandbox = client
                .create_sandbox(create_request(create)?)
                .await?
                .into_inner();
            if sandbox.name.is_empty() {
                println!("{}", sandbox.id);
            } else {
                println!("{} ({})", sandbox.id, sandbox.name);
            }
            // The sandbox is already there, so a port that could not be
            // published is a partial result, not a failed create: say which
            // one, keep the sandbox, and exit nonzero.
            if !publish_ports(&mut client, &sandbox.id, &publish).await? {
                std::process::exit(1);
            }
            if connect {
                let code = connect_shell(&client, &sandbox.id, None, Vec::new()).await?;
                if code != 0 {
                    std::process::exit(exit_status(code));
                }
            }
        }
        Command::Ps {
            is_all_shown: all,
            tag,
        } => list_sandboxes(&mut client, tag.unwrap_or_default(), all).await?,
        Command::Top { id } => list_commands(&mut client, &id).await?,
        Command::Inspect {
            id,
            is_json_requested: json,
        } => {
            let sandbox = client
                .get_sandbox(api::SandboxRef { sandbox_id: id })
                .await?
                .into_inner();
            if json {
                println!("{}", sandbox_json(&sandbox));
            } else {
                print_config(&sandbox);
            }
        }
        Command::Stats {
            id,
            is_all_shown: all,
        } => show_stats(&mut client, id, all).await?,
        Command::Images => list_templates(&mut client).await?,
        Command::Pull {
            images,
            name,
            systemd,
            hypervisor,
        } => import_template(&mut client, images, name, systemd, hypervisor).await?,
        Command::Commit {
            sandbox,
            expiration_secs,
        } => create_snapshot(&mut client, sandbox, expiration_secs).await?,
        Command::Fork {
            id,
            name,
            network,
            access,
            node_labels,
        } => {
            // Only an override the caller actually asked for: an unset flag
            // group means "inherit", not "no egress" and not "no access".
            let egress = network
                .is_stated()
                .then(|| network_policy(network))
                .transpose()?;
            let policy = (egress.is_some() || access.is_stated()).then(|| common::Policy {
                network: egress,
                exec: access.exec_policy(),
                fs: access.fs_policy(),
                ..Default::default()
            });
            let started = std::time::Instant::now();
            let sandbox = client
                .fork_sandbox(api::ForkSandboxRequest {
                    sandbox_id: id,
                    name: name.unwrap_or_default(),
                    policy,
                    node_labels: parse_pairs("--node-label", &node_labels)?,
                })
                .await?
                .into_inner();
            println!("{} in {}ms", sandbox.id, started.elapsed().as_millis());
        }
        Command::Move {
            id,
            node,
            node_labels,
        } => {
            let started = std::time::Instant::now();
            let sandbox = client
                .move_sandbox(api::MoveSandboxRequest {
                    sandbox_id: id,
                    node_id: node.unwrap_or_default(),
                    node_labels: parse_pairs("--node-label", &node_labels)?,
                })
                .await?
                .into_inner();
            println!(
                "{} on {} in {}ms",
                sandbox.id,
                sandbox.node_id,
                started.elapsed().as_millis()
            );
        }
        Command::Exec { id, exec, cmd } => {
            let mut node = route(&client, &id).await?;
            let code = run_exec(&mut node.client, &node.sandbox_id, &exec, cmd).await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
        }
        Command::Connect { id, user, cmd } => {
            let code = connect_shell(&client, &id, user, cmd).await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
        }
        Command::Logs { id, command_id } => {
            // The sandbox's own console log is written on the node and no RPC
            // reads it, so `logs <SANDBOX>` has nothing to show. Naming that
            // beats picking a command and calling it the sandbox's output.
            let Some(command_id) = command_id else {
                anyhow::bail!(
                    "burrow logs follows one command, so it needs a command id: \
                     `burrow logs {id} <COMMAND-ID>`. `burrow top {id}` lists them"
                );
            };
            let code = attach_command(&client, &id, &command_id).await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
        }
        Command::Prune { id } => {
            let pruned = client
                .prune_commands(api::PruneCommandsRequest { sandbox_id: id })
                .await?
                .into_inner();
            println!(
                "removed {} finished command(s), freed {} bytes",
                pruned.removed, pruned.freed_bytes
            );
        }
        Command::Kill {
            id,
            command_id,
            signal,
        } => {
            // Docker kills the container; burrow kills a command. Guessing
            // which one a bare id meant would either signal the wrong process
            // or destroy a sandbox nobody asked to lose.
            let Some(command_id) = command_id else {
                anyhow::bail!(
                    "burrow kill signals one command, so it needs a command id: \
                     `burrow kill {id} <COMMAND-ID>`. `burrow top {id}` lists them. \
                     To stop the sandbox use `burrow stop {id}`, to destroy it \
                     `burrow rm {id}`"
                );
            };
            client
                .signal_command(api::SignalCommandRequest {
                    sandbox_id: id,
                    command_id: command_id.clone(),
                    signal,
                })
                .await?;
            println!("signalled {command_id}");
        }
        Command::User(UserCommand::Create { id, name }) => {
            let resp = client
                .create_user(api::CreateUserRequest {
                    sandbox_id: id,
                    name,
                })
                .await?
                .into_inner();
            println!(
                "{} uid={} gid={} home={}",
                resp.username, resp.uid, resp.gid, resp.home
            );
        }
        Command::User(UserCommand::Delete {
            id,
            name,
            is_home_removed,
        }) => {
            let resp = client
                .delete_user(api::DeleteUserRequest {
                    sandbox_id: id,
                    name: name.clone(),
                    is_home_removed,
                })
                .await?
                .into_inner();
            match (resp.home.as_str(), resp.is_home_removed) {
                ("", _) => println!("deleted {name}"),
                (home, true) => println!("deleted {name}, removed {home}"),
                (home, false) => println!("deleted {name}, kept {home}"),
            }
        }
        Command::Group(GroupCommand::Create { id, name }) => {
            let resp = client
                .create_group(api::CreateGroupRequest {
                    sandbox_id: id,
                    name,
                })
                .await?
                .into_inner();
            println!(
                "{} gid={} dir={}",
                resp.groupname, resp.gid, resp.shared_dir
            );
        }
        Command::Group(GroupCommand::Add { id, user, group }) => {
            client
                .add_user_to_group(api::GroupMembershipRequest {
                    sandbox_id: id,
                    user: user.clone(),
                    group: group.clone(),
                })
                .await?;
            println!("{user} joined {group}");
        }
        Command::Group(GroupCommand::Remove { id, user, group }) => {
            client
                .remove_user_from_group(api::GroupMembershipRequest {
                    sandbox_id: id,
                    user: user.clone(),
                    group: group.clone(),
                })
                .await?;
            println!("{user} left {group}");
        }
        Command::Group(GroupCommand::Delete {
            id,
            name,
            is_shared_dir_removed,
        }) => {
            let resp = client
                .delete_group(api::DeleteGroupRequest {
                    sandbox_id: id,
                    name: name.clone(),
                    is_shared_dir_removed,
                })
                .await?
                .into_inner();
            match (resp.shared_dir.as_str(), resp.is_shared_dir_removed) {
                ("", _) => println!("deleted {name}"),
                (dir, true) => println!("deleted {name}, removed {dir}"),
                (dir, false) => println!("deleted {name}, kept {dir}"),
            }
        }
        Command::Run {
            create,
            exec,
            is_suspended_after,
            is_removed_after,
            is_detached,
            cmd,
        } => {
            let code = run_in_sandbox(
                &mut client,
                create,
                exec,
                is_suspended_after,
                is_removed_after,
                is_detached,
                cmd,
            )
            .await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
        }
        Command::Copy { src, dst } => copy(&client, &src, &dst).await?,
        Command::Stop { ids } => transition_each(&mut client, ids, Transition::Pause).await,
        Command::Start { id } => transition_timed(&mut client, id, Transition::Resume).await?,
        Command::Shutdown { ids } => transition_each(&mut client, ids, Transition::Stop).await,
        Command::Boot { id } => transition_timed(&mut client, id, Transition::Start).await?,
        Command::Recreate {
            id,
            template,
            kit_args,
            kit_env,
            reject_capabilities,
        } => {
            // Always sent: a recreation's reject list replaces the recorded
            // one, and an empty flag set is how it is cleared.
            let kit = kit_spec(&kit_args, &kit_env, reject_capabilities)?;
            let sandbox = client
                .recreate_sandbox(api::RecreateSandboxRequest {
                    sandbox_id: id,
                    kit: Some(kit),
                    template: template.unwrap_or_default(),
                })
                .await?
                .into_inner();
            println!("{} {}", sandbox.id, state_name(sandbox.state));
        }
        Command::Secret(SecretCommand::Set {
            name,
            value,
            allowed_sandboxes,
            allowed_tags,
        }) => {
            let value = match value {
                Some(value) => value,
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf.trim_end_matches(['\r', '\n']).to_string()
                }
            };
            client
                .set_secret(api::SetSecretRequest {
                    name: name.clone(),
                    value,
                    allowed_sandboxes,
                    allowed_tags,
                })
                .await?;
            println!("stored {name}");
        }
        Command::Secret(SecretCommand::Ls) => {
            let listed = client
                .list_secrets(api::ListSecretsRequest {})
                .await?
                .into_inner();
            for secret in listed.secrets {
                let scope: Vec<String> = secret
                    .allowed_sandboxes
                    .iter()
                    .map(|entry| format!("sandbox={entry}"))
                    .chain(
                        secret
                            .allowed_tags
                            .iter()
                            .map(|entry| format!("tag:{entry}")),
                    )
                    .collect();
                if scope.is_empty() {
                    println!("{}", secret.name);
                } else {
                    println!("{}\t{}", secret.name, scope.join(","));
                }
            }
        }
        Command::Secret(SecretCommand::Rm { name }) => {
            client
                .delete_secret(api::DeleteSecretRequest { name: name.clone() })
                .await?;
            println!("deleted {name}");
        }
        Command::Sessions { id } => list_sessions(&mut client, id).await?,
        Command::Token(TokenCommand::Issue { id, ops, user, ttl }) => {
            let grant = client
                .issue_access(api::IssueAccessRequest {
                    sandbox_id: id,
                    ops,
                    user: user.unwrap_or_default(),
                    ttl_secs: ttl,
                })
                .await?
                .into_inner();
            println!("endpoint  {}", sanitize(&grant.endpoint));
            println!("sandbox   {}", sanitize(&grant.sandbox_id));
            println!(
                "expires   {}",
                rfc3339_from_unix_ms(grant.expires_at_unix_ms)
            );
            println!("token     {}", sanitize(&grant.token));
        }
        Command::Token(TokenCommand::Revoke { id }) => {
            let revoked = client
                .revoke_access(api::SandboxRef {
                    sandbox_id: id.clone(),
                })
                .await?
                .into_inner();
            let revoked_ms = revoked.revoked_at_ms;
            println!(
                "revoked every token for {id} issued by {}; ended {} open session(s) and killed \
                 {} command(s)",
                rfc3339_from_unix_ms(revoked_ms),
                revoked.ended_sessions,
                revoked.killed_commands
            );
        }
        Command::Remove { ids } => {
            let mut failed = false;
            for id in ids {
                match client
                    .delete_sandbox(api::SandboxRef {
                        sandbox_id: id.clone(),
                    })
                    .await
                {
                    Ok(_) => println!("deleted {id}"),
                    Err(err) => {
                        eprintln!("{id}: {}", err.message());
                        failed = true;
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
        Command::Config(ConfigCommand::List {
            id,
            is_json_requested: json,
        }) => {
            let sandbox = client
                .get_sandbox(api::SandboxRef { sandbox_id: id })
                .await?
                .into_inner();
            if json {
                println!("{}", sandbox_json(&sandbox));
            } else {
                print_config(&sandbox);
            }
        }
        Command::Config(ConfigCommand::NetworkPolicy { id, network }) => {
            let sandbox = client
                .update_network_policy(api::UpdateNetworkPolicyRequest {
                    sandbox_id: id,
                    network: Some(network_policy(network)?),
                })
                .await?
                .into_inner();
            println!("{} network policy updated", sandbox.id);
        }
        Command::Config(ConfigCommand::Disk { id, mib }) => {
            update_resources(&mut client, id, None, None, Some(mib)).await?;
        }
        Command::Config(ConfigCommand::Resources {
            id,
            vcpus,
            mem_mib,
            disk_mib,
        }) => {
            update_resources(&mut client, id, vcpus, mem_mib, disk_mib).await?;
        }
        Command::Config(ConfigCommand::Lifetime {
            id,
            max_lifetime_secs,
            idle_suspend_secs,
            suspended_ttl_secs,
            snapshot_expiration_secs,
            keep_last_snapshots,
            keep_evicted_snapshots,
        }) => {
            let sandbox = client
                .update_lifetime(api::UpdateLifetimeRequest {
                    sandbox_id: id,
                    max_lifetime_secs,
                    idle_suspend_secs,
                    suspended_ttl_secs,
                    snapshot_expiration_secs,
                    snapshot_keep_last: keep_last_snapshots,
                    is_evicted_snapshot_kept: keep_evicted_snapshots,
                })
                .await?
                .into_inner();
            let lifetime = sandbox
                .policy
                .unwrap_or_default()
                .lifetime
                .unwrap_or_default();
            let clock = |secs: u64| match secs {
                0 => "unlimited".to_string(),
                secs => format!("{secs}s"),
            };
            println!(
                "{} max-lifetime {}, idle-suspend {}, suspended-ttl {}",
                sandbox.id,
                clock(lifetime.max_lifetime_secs),
                clock(lifetime.idle_suspend_secs),
                clock(lifetime.suspended_ttl_secs)
            );
        }
        Command::Config(ConfigCommand::Access { id, access }) => {
            let exec = access.exec_policy();
            let fs = access.fs_policy();
            if exec.is_none() && fs.is_none() {
                anyhow::bail!(
                    "name at least one of --no-exec/--allow-exec, --no-upload/--allow-upload, \
                     --no-download/--allow-download, --fs-scope or --max-upload-bytes"
                );
            }
            let sandbox = client
                .update_access_policy(api::UpdateAccessPolicyRequest {
                    sandbox_id: id,
                    exec,
                    fs,
                })
                .await?
                .into_inner();
            let policy = sandbox.policy.clone().unwrap_or_default();
            println!(
                "{} exec {} · upload {} · download {}",
                sandbox.id,
                // An absent section is no restriction, here as everywhere.
                match &policy.exec {
                    Some(exec) if !exec.is_exec_allowed => "denied",
                    _ => "allowed",
                },
                match &policy.fs {
                    Some(fs) if !fs.is_upload_allowed => "denied",
                    _ => "allowed",
                },
                match &policy.fs {
                    Some(fs) if !fs.is_download_allowed => "denied",
                    _ => "allowed",
                },
            );
        }
        Command::Config(ConfigCommand::Tags { id, tags }) => {
            let sandbox = client
                .update_tags(api::UpdateTagsRequest {
                    sandbox_id: id,
                    tags: parse_pairs("--tag", &tags)?,
                })
                .await?
                .into_inner();
            println!("{} now has {} tags", sandbox.id, sandbox.tags.len());
        }
        Command::Config(ConfigCommand::Ports { id, ports }) => {
            set_ports(&mut client, &id, &ports).await?
        }
        Command::Expose {
            id,
            guest_port,
            host_port,
            is_udp: udp,
        } => {
            let mapping = client
                .expose_port(api::ExposePortRequest {
                    sandbox_id: id,
                    guest_port,
                    host_port,
                    is_udp: udp,
                })
                .await?
                .into_inner();
            print_port(&mapping);
        }
        Command::Port { id } => {
            let resp = client
                .list_ports(api::SandboxRef { sandbox_id: id })
                .await?
                .into_inner();
            if resp.ports.is_empty() {
                println!("no published ports");
            }
            for mapping in &resp.ports {
                print_port(mapping);
            }
        }
        Command::Unexpose { id, host_port } => {
            client
                .close_port(api::ClosePortRequest {
                    sandbox_id: id,
                    host_port,
                })
                .await?;
            println!("closed {host_port}");
        }
        Command::Share {
            id,
            ports,
            allowed_clients,
            is_rotating,
            udp_ports,
            is_transparent_ip_disabled,
            is_showing,
        } => {
            let share = if is_showing {
                client
                    .get_share(api::SandboxRef { sandbox_id: id })
                    .await?
                    .into_inner()
            } else {
                let all_udp = udp_ports.iter().any(|p| p == "all");
                let udp_ports = udp_ports
                    .iter()
                    .filter(|p| *p != "all")
                    .map(|p| {
                        p.parse::<u32>()
                            .map_err(|_| anyhow::anyhow!("invalid UDP port {p:?}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                client
                    .share_sandbox(api::ShareRequest {
                        sandbox_id: id,
                        ports,
                        allowed_clients,
                        is_rotating,
                        udp_ports,
                        is_all_udp: all_udp,
                        is_transparent_ip: is_transparent_ip_disabled.then_some(false),
                    })
                    .await?
                    .into_inner()
            };
            print_share(&share);
        }
        Command::Unshare { id } => {
            client
                .unshare_sandbox(api::SandboxRef { sandbox_id: id })
                .await?;
            println!("share revoked");
        }
        Command::Templates(TemplatesCommand::Ls { warm: false }) => {
            list_templates(&mut client).await?
        }
        Command::Templates(TemplatesCommand::Ls { warm: true }) => {
            list_warm_shapes(&mut client).await?
        }
        Command::Templates(TemplatesCommand::Import {
            images,
            name,
            systemd,
            hypervisor,
        }) => import_template(&mut client, images, name, systemd, hypervisor).await?,
        Command::Templates(TemplatesCommand::Build {
            name,
            from,
            from_ipsw,
            steps,
            hypervisor,
            vcpus,
            mem_mib,
            disk_mib,
            allow_domains,
        }) => {
            let request = api::BuildTemplateRequest {
                name,
                from: from.unwrap_or_default(),
                from_ipsw: from_ipsw.unwrap_or_default(),
                steps: steps
                    .into_iter()
                    .map(|run| api::BuildStep { run })
                    .collect(),
                hypervisor: hypervisor.unwrap_or_default(),
                vcpus,
                mem_mib,
                disk_mib,
                allow_domains,
                ..Default::default()
            };
            build_template(&mut client, request).await?
        }
        Command::Templates(TemplatesCommand::Rm { name }) => {
            client
                .delete_template(api::DeleteTemplateRequest { name: name.clone() })
                .await?;
            println!("removed {name}");
        }
        Command::Volume(VolumeCommand::Create {
            name,
            size_mib,
            node_labels,
        }) => {
            let volume = client
                .create_volume(api::CreateVolumeRequest {
                    name,
                    size_mib,
                    node_labels: parse_pairs("--node-label", &node_labels)?,
                    labels: Default::default(),
                })
                .await?
                .into_inner();
            println!(
                "{} ({}MiB) on {}",
                volume.name, volume.size_mib, volume.node_id
            );
        }
        Command::Volume(VolumeCommand::Ls {
            node,
            is_json_requested: json,
        }) => {
            let resp = client
                .list_volumes(api::ListVolumesRequest {
                    node_id: node.unwrap_or_default(),
                })
                .await?
                .into_inner();
            if json {
                println!("{}", volumes_json(&resp.volumes));
            } else if resp.volumes.is_empty() {
                println!("no volumes");
            } else {
                println!(
                    "{:<24} {:<16} {:>8}  {:<21} ATTACHED TO",
                    "VOLUME", "NODE", "SIZE", "CREATED"
                );
                for volume in resp.volumes {
                    println!(
                        "{:<24} {:<16} {:>7}M  {:<21} {}",
                        truncate(&volume.name, 24),
                        truncate(&volume.node_id, 16),
                        volume.size_mib,
                        rfc3339_from_unix_ms(volume.created_at_unix_ms),
                        if volume.attached_to.is_empty() {
                            "-"
                        } else {
                            &volume.attached_to
                        },
                    );
                }
            }
        }
        Command::Ip(command) => run_ip(&mut client, command).await?,
        Command::Volume(VolumeCommand::Inspect { name }) => {
            let volume = client
                .get_volume(api::VolumeRef { name })
                .await?
                .into_inner();
            println!("name        {}", volume.name);
            println!("node        {}", volume.node_id);
            println!("size        {}MiB", volume.size_mib);
            println!(
                "created     {}",
                rfc3339_from_unix_ms(volume.created_at_unix_ms)
            );
            println!(
                "attached to {}",
                if volume.attached_to.is_empty() {
                    "nothing"
                } else {
                    &volume.attached_to
                }
            );
        }
        Command::Volume(VolumeCommand::Rm { names }) => {
            let mut failed = false;
            for name in names {
                match client
                    .delete_volume(api::VolumeRef { name: name.clone() })
                    .await
                {
                    Ok(_) => println!("deleted {name}"),
                    Err(err) => {
                        eprintln!("{name}: {}", err.message());
                        failed = true;
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
        Command::Snapshot(SnapshotCommand::Create {
            sandbox,
            expiration_secs,
        }) => create_snapshot(&mut client, sandbox, expiration_secs).await?,
        Command::Snapshot(SnapshotCommand::Ls { sandbox }) => {
            let resp = client
                .list_snapshots(api::ListSnapshotsRequest {
                    sandbox_id: sandbox.unwrap_or_default(),
                })
                .await?
                .into_inner();
            if resp.snapshots.is_empty() {
                println!("no snapshots");
            } else {
                println!(
                    "{:<38} {:<24} {:<16} {:>8}  {:<21} {:<21} EXPIRES",
                    "SNAPSHOT", "SANDBOX", "TEMPLATE", "SIZE", "CREATED", "WHERE"
                );
                for snapshot in resp.snapshots {
                    let location = match (snapshot.node_id.is_empty(), snapshot.is_durable) {
                        (false, true) => format!("{} +store", snapshot.node_id),
                        (false, false) => snapshot.node_id.clone(),
                        (true, _) => "object store".to_string(),
                    };
                    println!(
                        "{:<38} {:<24} {:<16} {:>7}M  {:<21} {:<21} {}",
                        snapshot.id,
                        truncate(&snapshot.sandbox_id, 24),
                        truncate(&snapshot.template, 16),
                        snapshot.size_bytes / (1024 * 1024),
                        rfc3339_from_unix_ms(snapshot.created_at_unix_ms),
                        truncate(&location, 21),
                        match snapshot.expires_at_unix_ms {
                            0 => "never".to_string(),
                            at => rfc3339_from_unix_ms(at),
                        },
                    );
                }
            }
        }
        Command::Snapshot(SnapshotCommand::Rm { ids }) => {
            let mut failed = false;
            for id in ids {
                match client
                    .delete_snapshot(api::SnapshotRef { id: id.clone() })
                    .await
                {
                    Ok(_) => println!("deleted {id}"),
                    Err(err) => {
                        eprintln!("{id}: {}", err.message());
                        failed = true;
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
        Command::Events {
            sandbox,
            after,
            follow,
            limit,
        } => {
            println!(
                "{:>6} {:<24} {:<24} {:<17} {:<10} DETAIL",
                "SEQ", "AT", "SANDBOX", "EVENT", "STATE"
            );
            // The log is resumable by position, so a follow whose connection
            // drops, as it does when the replica serving it goes away,
            // reconnects and carries on from the last event it printed.
            let mut last = after;
            loop {
                let opened = client
                    .tail_events(api::TailEventsRequest {
                        after_seq: last,
                        sandbox_id: sandbox.clone().unwrap_or_default(),
                        is_follow: follow,
                        limit,
                    })
                    .await;
                let mut stream = match opened {
                    Ok(stream) => stream.into_inner(),
                    Err(status) if follow && is_transient(&status) => {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    Err(status) => return Err(status.into()),
                };
                let ended = loop {
                    match stream.next().await {
                        Some(Ok(event)) => {
                            last = event.seq;
                            let state = common::SandboxState::try_from(event.state)
                                .map(|s| {
                                    s.as_str_name()
                                        .trim_start_matches("SANDBOX_STATE_")
                                        .to_lowercase()
                                })
                                .unwrap_or_default();
                            println!(
                                "{:>6} {:<24} {:<24} {:<17} {:<10} {}",
                                event.seq,
                                rfc3339_from_unix_ms(event.at_unix_ms),
                                truncate(&sanitize(&event.sandbox_id), 24),
                                common::EventKind::try_from(event.kind)
                                    .unwrap_or_default()
                                    .label(),
                                state,
                                sanitize(&event.detail),
                            );
                        }
                        Some(Err(status)) => break Some(status),
                        None => break None,
                    }
                };
                match ended {
                    Some(status) if follow && is_transient(&status) => {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    Some(status) => return Err(status.into()),
                    None => break,
                }
            }
        }
        Command::Usage {
            from,
            to,
            sandbox,
            tags,
            group_by,
            format,
            is_closed_only,
            after,
            limit,
        } => {
            let bound = |value: Option<String>, flag: &str| -> anyhow::Result<i64> {
                match value {
                    None => Ok(0),
                    Some(text) => unix_ms_from_utc(&text).ok_or_else(|| {
                        anyhow::anyhow!(
                            "--{flag} {text:?} is not a UTC date like 2026-10-01 or 2026-10-01T12:00:00Z"
                        )
                    }),
                }
            };
            let tags = tags
                .iter()
                .map(|tag| {
                    tag.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or_else(|| anyhow::anyhow!("--tag {tag:?} is not KEY=VALUE"))
                })
                .collect::<anyhow::Result<_>>()?;
            let (group, group_by_tag) = match group_by.as_deref() {
                None => (api::UsageGroup::Unspecified, String::new()),
                Some("sandbox") => (api::UsageGroup::Sandbox, String::new()),
                Some("template") => (api::UsageGroup::Template, String::new()),
                Some("node") => (api::UsageGroup::Node, String::new()),
                Some("state") => (api::UsageGroup::State, String::new()),
                Some(other) => match other.strip_prefix("tag:") {
                    Some(key) => (api::UsageGroup::Tag, key.to_string()),
                    None => anyhow::bail!(
                        "--group-by {other:?} is not sandbox, template, node, state or tag:<key>"
                    ),
                },
            };
            let resp = client
                .query_usage(api::QueryUsageRequest {
                    from_unix_ms: bound(from, "from")?,
                    to_unix_ms: bound(to, "to")?,
                    sandbox_id: sandbox.unwrap_or_default(),
                    tags,
                    group_by: group as i32,
                    group_by_tag,
                    after_id: after,
                    limit,
                    is_open_included: !is_closed_only,
                })
                .await?
                .into_inner();
            match (format, group_by.is_some()) {
                (UsageFormat::Json, true) => {
                    let sums: Vec<_> = resp.sums.iter().map(usage_sum_json).collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({ "sums": sums }))
                            .expect("a value renders")
                    );
                }
                (UsageFormat::Json, false) => {
                    let intervals: Vec<_> =
                        resp.intervals.iter().map(usage_interval_json).collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "intervals": intervals,
                            "next_after": resp.next_after_id,
                        }))
                        .expect("a value renders")
                    );
                }
                (UsageFormat::Table, true) => {
                    println!(
                        "{:<24} {:<10} {:>5} {:>12} {:>9} {:>9} {:>10} {:>10} {:>10}",
                        "GROUP", "STATE", "ROWS", "DURATION", "VCPU-H", "GIB-H", "CPU", "RX", "TX"
                    );
                    for sum in &resp.sums {
                        println!(
                            "{:<24} {:<10} {:>5} {:>12} {:>9.3} {:>9.3} {:>10} {:>10} {:>10}",
                            truncate(&sanitize(&sum.group), 24),
                            usage_state(sum.state),
                            sum.intervals,
                            duration_ms(sum.duration_ms),
                            sum.vcpu_ms as f64 / 3_600_000.0,
                            sum.mem_mib_ms as f64 / 1024.0 / 3_600_000.0,
                            cpu_secs(sum.cpu_usage_usec),
                            bytes(sum.rx_bytes),
                            bytes(sum.tx_bytes),
                        );
                    }
                }
                (UsageFormat::Table, false) => {
                    println!(
                        "{:>6} {:<24} {:<10} {:>4} {:>6} {:<20} {:>12} {:>10} {:>10} {:>10} CLOSED",
                        "ID",
                        "SANDBOX",
                        "STATE",
                        "VCPU",
                        "MEM",
                        "STARTED",
                        "DURATION",
                        "CPU",
                        "RX",
                        "TX"
                    );
                    for interval in &resp.intervals {
                        println!(
                            "{:>6} {:<24} {:<10} {:>4} {:>6} {:<20} {:>12} {:>10} {:>10} {:>10} {}",
                            if interval.is_open {
                                "open".to_string()
                            } else {
                                interval.id.to_string()
                            },
                            truncate(&sanitize(&interval.sandbox_id), 24),
                            usage_state(interval.state),
                            interval.vcpus,
                            interval.mem_mib,
                            rfc3339_from_unix_ms(interval.started_at_unix_ms),
                            duration_ms(
                                (interval.ended_at_unix_ms - interval.started_at_unix_ms).max(0)
                                    as u64
                            ),
                            cpu_secs(interval.cpu_usage_usec),
                            bytes(interval.rx_bytes),
                            bytes(interval.tx_bytes),
                            sanitize(&interval.closed_by),
                        );
                    }
                    if resp.next_after_id != 0 {
                        eprintln!("more intervals follow: --after {}", resp.next_after_id);
                    }
                }
            }
        }
        Command::Audit {
            sandbox,
            is_denied_only: denied,
            since,
            limit,
        } => {
            let mut stream = client
                .query_audit(api::AuditQuery {
                    sandbox_id: sandbox.unwrap_or_default(),
                    is_denied_only: denied,
                    since_unix_ms: match since {
                        None => 0,
                        Some(text) => unix_ms_from_utc(&text).ok_or_else(|| {
                            anyhow::anyhow!(
                                "--since {text:?} is not a UTC date like 2026-10-01 or 2026-10-01T12:00:00Z"
                            )
                        })?,
                    },
                    limit,
                })
                .await?
                .into_inner();
            println!(
                "{:<21} {:<24} {:<7} {:<28} REASON",
                "AT", "SANDBOX", "ALLOWED", "HOST",
            );
            while let Some(event) = stream.next().await {
                let event = event?;
                println!(
                    "{:<21} {:<24} {:<7} {:<28} {}",
                    rfc3339_from_unix_ms(event.at_unix_ms),
                    truncate(&sanitize(&event.sandbox_id), 24),
                    if event.is_allowed { "yes" } else { "no" },
                    truncate(
                        &sanitize(if event.host.is_empty() {
                            &event.destination
                        } else {
                            &event.host
                        }),
                        28
                    ),
                    sanitize(&event.reason),
                );
            }
        }
        Command::Dir { id, path } => {
            let mut node = route(&client, &id).await?;
            let id = node.sandbox_id;
            let FsResult::Entries(listed) = fs_call(
                &mut node.client,
                &id,
                FsOp::ReadDir(api::FsReadDir { path: path.clone() }),
            )
            .await?
            else {
                anyhow::bail!("the node answered a listing with something else");
            };
            for entry in listed.entries {
                let FsResult::Stat(stat) = fs_call(
                    &mut node.client,
                    &id,
                    FsOp::Stat(api::FsStat {
                        path: format!("{}/{}", path.trim_end_matches('/'), entry.name),
                        is_nofollow: true,
                    }),
                )
                .await?
                else {
                    anyhow::bail!("the node answered a stat with something else");
                };
                println!(
                    "{:>10}  {:o}  {}{}",
                    stat.size,
                    stat.mode & 0o7777,
                    sanitize(&entry.name),
                    if entry.r#type == api::FileType::Dir as i32 {
                        "/"
                    } else {
                        ""
                    }
                );
            }
        }
    }
    Ok(())
}

async fn run_ip(client: &mut Client, command: IpCommand) -> anyhow::Result<()> {
    const HEADER: &str = "ADDRESS                                  POOL           STATE        SANDBOX              NODE";
    match command {
        IpCommand::Allocate {
            pool,
            is_v6,
            sandbox,
        } => {
            let ip = client
                .allocate_ip(api::AllocateIpRequest {
                    pool: pool.unwrap_or_default(),
                    family: if is_v6 { 6 } else { 4 },
                    sandbox_id: sandbox.unwrap_or_default(),
                })
                .await?
                .into_inner();
            match ip.sandbox_id.is_empty() {
                true => println!("{}", ip.address),
                false => println!("{} attached to {}", ip.address, ip.sandbox_id),
            }
        }
        IpCommand::Release { address } => {
            client
                .release_ip(api::IpRef {
                    address: address.clone(),
                })
                .await?;
            println!("released {address}; quarantined before it is handed out again");
        }
        IpCommand::Attach { address, sandbox } => {
            let ip = client
                .attach_ip(api::AttachIpRequest {
                    address,
                    sandbox_id: sandbox,
                })
                .await?
                .into_inner();
            println!(
                "{} attached to {} on {}",
                ip.address, ip.sandbox_id, ip.node_id
            );
        }
        IpCommand::Detach { address } => {
            let ip = client.detach_ip(api::IpRef { address }).await?.into_inner();
            println!("{} detached", ip.address);
        }
        IpCommand::Ls {
            pool,
            sandbox,
            is_quarantine_included,
            is_json_requested,
        } => {
            let ips = client
                .list_ips(api::ListIpsRequest {
                    pool: pool.unwrap_or_default(),
                    sandbox_id: sandbox.unwrap_or_default(),
                    is_quarantine_included,
                })
                .await?
                .into_inner()
                .ips;
            if is_json_requested {
                let items: Vec<_> = ips.iter().map(ip_json).collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&items).expect("a value renders")
                );
            } else if ips.is_empty() {
                println!("no public ips");
            } else {
                println!("{HEADER}");
                for ip in &ips {
                    println!("{}", ip_line(ip));
                }
            }
        }
        IpCommand::Pool(IpPoolCommand::Create(flags)) => {
            let pool = client.create_ip_pool(flags.pool()?).await?.into_inner();
            println!("{} ({} addresses)", pool.name, pool.total);
        }
        IpCommand::Pool(IpPoolCommand::Update(flags)) => {
            let pool = client.update_ip_pool(flags.pool()?).await?.into_inner();
            println!("{} ({} addresses)", pool.name, pool.total);
        }
        IpCommand::Pool(IpPoolCommand::Rm { name }) => {
            client
                .delete_ip_pool(api::IpPoolRef { name: name.clone() })
                .await?;
            println!("removed {name}");
        }
        IpCommand::Pool(IpPoolCommand::Ls { is_json_requested }) => {
            let pools = client
                .list_ip_pools(api::ListIpPoolsRequest {})
                .await?
                .into_inner()
                .pools;
            if is_json_requested {
                let items: Vec<_> = pools
                    .iter()
                    .map(|pool| {
                        serde_json::json!({
                            "name": pool.name,
                            "node": pool.node_id,
                            "node_labels": pairs_json(&pool.node_labels),
                            "total": pool.total,
                            "allocated": pool.allocated,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&items).expect("a value renders")
                );
            } else if pools.is_empty() {
                println!("no ip pools");
            } else {
                println!(
                    "{:<16} {:<24} {:>9}  ADDRESSES",
                    "POOL", "SCOPE", "ALLOCATED"
                );
                for pool in &pools {
                    let scope = match pool.node_id.is_empty() {
                        false => pool.node_id.clone(),
                        true => {
                            let mut labels: Vec<String> = pool
                                .node_labels
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect();
                            labels.sort();
                            labels.join(",")
                        }
                    };
                    let addresses = match pool.prefix6.is_empty() {
                        false => format!("{} per /{}", pool.prefix6, pool.per_sandbox),
                        true => pool
                            .ranges
                            .iter()
                            .chain(&pool.addresses)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(","),
                    };
                    println!(
                        "{:<16} {:<24} {:>4}/{:<4}  {}",
                        truncate(&pool.name, 16),
                        truncate(&scope, 24),
                        pool.allocated,
                        pool.total,
                        addresses
                    );
                }
            }
        }
    }
    Ok(())
}

/// Builds the create call from the shared flag group.
fn create_request(flags: CreateFlags) -> anyhow::Result<api::CreateSandboxRequest> {
    let CreateFlags {
        ips,
        name,
        template,
        kit_args,
        kit_env,
        reject_capabilities,
        snapshot,
        vcpus,
        mem_mib,
        disk_mib,
        max_lifetime_secs,
        idle_suspend_secs,
        suspended_ttl_secs,
        snapshot_expiration_secs,
        keep_last_snapshots,
        is_evicted_snapshots_kept: keep_evicted_snapshots,
        mounts,
        tags,
        // Published after the sandbox exists, by its caller: the create RPC
        // has no port field, and a node picks the host port.
        publish: _,
        node_labels,
        network,
        access,
        networks,
        alias,
    } = flags;
    let tags = parse_pairs("--tag", &tags)?;
    // A snapshot carries its own template, so nothing is sent unless the
    // caller named one, in which case disagreeing with the snapshot is an
    // error the server raises rather than a default silently overriding it.
    let template = template.unwrap_or_default();
    Ok(api::CreateSandboxRequest {
        public_ips: ips,
        name: name.unwrap_or_default(),
        template,
        snapshot: snapshot.unwrap_or_default(),
        policy: Some(common::Policy {
            resources: Some(common::ResourcePolicy {
                // 0 means "the server's default", which is what lets a create
                // from a snapshot inherit the shape it was taken with.
                vcpus: vcpus.unwrap_or(0),
                mem_mib: mem_mib.unwrap_or(0),
                disk_mib: disk_mib.unwrap_or(0),
            }),
            lifetime: Some(common::LifetimePolicy {
                max_lifetime_secs,
                idle_suspend_secs,
                suspended_ttl_secs,
            }),
            snapshots: Some(common::SnapshotPolicy {
                expiration_secs: snapshot_expiration_secs,
                keep_last: keep_last_snapshots,
                is_evicted_kept: keep_evicted_snapshots,
            }),
            network: Some(network_policy(network)?),
            exec: access.exec_policy(),
            fs: access.fs_policy(),
            volumes: parse_mounts(&mounts)?,
            networks: networks
                .into_iter()
                .map(|network| common::NetworkMembership {
                    network,
                    ingress_ports: vec![],
                    is_egress_allowed: true,
                    is_ingress_allowed: true,
                    alias: alias.clone().unwrap_or_default(),
                })
                .collect(),
        }),
        tags,
        node_labels: parse_pairs("--node-label", &node_labels)?,
        kit: if kit_args.is_empty() && kit_env.is_empty() && reject_capabilities.is_empty() {
            None
        } else {
            Some(kit_spec(&kit_args, &kit_env, reject_capabilities)?)
        },
    })
}

fn kit_spec(
    args: &[String],
    env: &[String],
    reject_types: Vec<String>,
) -> anyhow::Result<common::KitSpec> {
    Ok(common::KitSpec {
        args: parse_pairs("--arg", args)?,
        env: parse_pairs("--kit-env", env)?,
        reject_types,
    })
}

/// The lifecycle moves `stop`, `start`, `shutdown` and `boot` make.
#[derive(Clone, Copy)]
enum Transition {
    Pause,
    Resume,
    Stop,
    Start,
}

impl Transition {
    async fn call(self, client: &mut Client, id: String) -> Result<common::Sandbox, tonic::Status> {
        let id = api::SandboxRef { sandbox_id: id };
        let resp = match self {
            Transition::Pause => client.pause_sandbox(id).await,
            Transition::Resume => client.resume_sandbox(id).await,
            Transition::Stop => client.stop_sandbox(id).await,
            Transition::Start => client.start_sandbox(id).await,
        }?;
        Ok(resp.into_inner())
    }
}

/// Moves every sandbox in `ids`, reporting each failure and exiting 1 if any.
async fn transition_each(client: &mut Client, ids: Vec<String>, to: Transition) {
    let mut failed = false;
    for id in ids {
        match to.call(client, id.clone()).await {
            Ok(sandbox) => println!("{} {}", sandbox.id, state_name(sandbox.state)),
            Err(err) => {
                eprintln!("{id}: {}", err.message());
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}

async fn transition_timed(client: &mut Client, id: String, to: Transition) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let sandbox = to.call(client, id).await?;
    println!(
        "{} {} in {}ms",
        sandbox.id,
        state_name(sandbox.state),
        started.elapsed().as_millis()
    );
    Ok(())
}

/// `run`: one command, in a sandbox that may or may not exist yet.
///
/// The sandbox outlives the command unless the caller says otherwise, so a
/// crashed command leaves something to look at. Cleanup runs whatever the
/// command exited with, and the command's own status is what the CLI returns.
async fn run_in_sandbox(
    client: &mut Client,
    create: CreateFlags,
    exec: ExecFlags,
    stop: bool,
    rm: bool,
    detach: bool,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let publish = create.publish.clone();
    let id = match create.name.clone() {
        // A name makes this get-or-create: the same command is both the first
        // run and every run after it. Ids cannot serve here, because nothing
        // outside the server ever chooses one.
        Some(name) => {
            match client
                .get_sandbox(api::SandboxRef {
                    sandbox_id: name.clone(),
                })
                .await
            {
                Ok(existing) => {
                    let sandbox = existing.into_inner();
                    if create.is_stated() {
                        eprintln!(
                            "warning: sandbox {name} already exists, so the create flags are ignored"
                        );
                    }
                    // A suspended sandbox is still the sandbox the caller
                    // named; bring it back rather than failing the exec
                    // against a stopped VM.
                    if matches!(
                        common::SandboxState::try_from(sandbox.state),
                        Ok(common::SandboxState::Suspended) | Ok(common::SandboxState::Paused)
                    ) {
                        client
                            .resume_sandbox(api::SandboxRef {
                                sandbox_id: sandbox.id.clone(),
                            })
                            .await?;
                    }
                    sandbox.id
                }
                Err(status) if status.code() == tonic::Code::NotFound => {
                    let sandbox = client
                        .create_sandbox(create_request(create)?)
                        .await?
                        .into_inner();
                    // stderr, so piping the command's output stays clean.
                    eprintln!("sandbox {}", sandbox.id);
                    sandbox.id
                }
                Err(status) => return Err(status.into()),
            }
        }
        None => {
            let sandbox = client
                .create_sandbox(create_request(create)?)
                .await?
                .into_inner();
            // stderr, so piping the command's output stays clean.
            eprintln!("sandbox {}", sandbox.id);
            sandbox.id
        }
    };

    if !publish_ports(client, &id, &publish).await? {
        return Ok(1);
    }

    // Detached: the command is started and left running, so there is no exit
    // status to wait for and nothing to clean up afterwards.
    let mut node = route(client, &id).await?;
    if detach {
        let command_id = start_detached(&mut node.client, &node.sandbox_id, &exec, cmd).await?;
        eprintln!("command {command_id}");
        println!("{id}");
        return Ok(0);
    }

    // The sandbox `run` created is this function's to clean up, so --stop and
    // --rm happen whatever the exec did. An exec that failed is exactly the
    // case where a sandbox left behind holds capacity the caller cannot get
    // back without digging its id out of the error.
    let result = run_exec(&mut node.client, &node.sandbox_id, &exec, cmd).await;

    if stop {
        match client
            .pause_sandbox(api::SandboxRef {
                sandbox_id: id.clone(),
            })
            .await
        {
            Ok(_) => eprintln!("stopped {id}"),
            // Reported, not returned: losing the exec's own outcome to a
            // cleanup error would hide a command that did run.
            Err(err) => eprintln!("could not stop {id}: {}", err.message()),
        }
    } else if rm {
        match client
            .delete_sandbox(api::SandboxRef {
                sandbox_id: id.clone(),
            })
            .await
        {
            Ok(_) => eprintln!("deleted {id}"),
            Err(err) => eprintln!("could not delete {id}: {}", err.message()),
        }
    }
    result
}

/// `connect`: an interactive shell, which is `exec --pty` with a default
/// command.
async fn connect_shell(
    client: &Client,
    id: &str,
    user: Option<String>,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    // An interactive shell reading a pipe waits for input its own line editor
    // will never see the end of. Say so instead of hanging.
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("connect needs a terminal on stdin; use `burrow exec` to pipe a command in");
    }
    let cmd = if cmd.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        cmd
    };
    let flags = ExecFlags {
        is_pty_allocated: true,
        envs: Vec::new(),
        workdir: None,
        user,
        log_max_size: None,
        log_max_files: 1,
    };
    let mut node = route(client, id).await?;
    run_exec(&mut node.client, &node.sandbox_id, &flags, cmd).await
}

/// Turns the network flags into the policy the server enforces.
///
/// Shared by `create` and `config network-policy`, so a flag cannot come to
/// mean one thing on a create and another on a replace.
fn network_policy(flags: NetworkFlags) -> anyhow::Result<common::NetworkPolicy> {
    let mode = match flags.net.as_str() {
        "open" => common::NetworkMode::Open,
        "allowlist" => common::NetworkMode::Allowlist,
        _ => common::NetworkMode::None,
    };
    // Inspection happens in the egress proxy: everything in allowlist mode,
    // the hosts rules name in open mode. Asking for it with no egress gets a
    // sandbox that believes it is inspected and is not.
    if flags.is_tls_inspected && mode == common::NetworkMode::None {
        anyhow::bail!("--inspect-tls requires --net allowlist or --net open");
    }
    if !flags.inject_headers.is_empty() && !flags.is_tls_inspected {
        anyhow::bail!("--inject-header requires --inspect-tls");
    }
    if !flags.rules.is_empty() && !flags.is_tls_inspected {
        anyhow::bail!("--rule requires --inspect-tls");
    }
    // --allow-cidr is an L3 allowance: those destinations are reached
    // directly, never through the proxy, so nothing inspects them.
    if flags.is_tls_inspected && !flags.allow_cidrs.is_empty() {
        eprintln!(
            "warning: --allow-cidr destinations bypass the egress proxy, so \
             --inspect-tls does not apply to them"
        );
    }
    Ok(common::NetworkPolicy {
        mode: mode as i32,
        allow_domains: flags.allow_domains,
        allow_cidrs: flags.allow_cidrs,
        allow_ports: flags.allow_ports.into_iter().map(|p| p as u32).collect(),
        deny_cidrs: flags.deny_cidrs,
        deny_domains: flags.deny_domains,
        deny_ports: flags
            .deny_ports
            .iter()
            .map(|spec| parse_port_rule(spec))
            .collect::<anyhow::Result<Vec<_>>>()?,
        is_ipv6_denied: flags.is_ipv6_denied,
        ingress: flags
            .ingress
            .iter()
            .map(|spec| parse_ingress_rule(spec))
            .collect::<anyhow::Result<Vec<_>>>()?,
        is_tls_inspected: flags.is_tls_inspected,
        // `--rule` first: an `--inject-header` rule carries no matcher, so it
        // claims every request to its domain and would shadow any narrower
        // rule written after it.
        rules: flags
            .rules
            .iter()
            .map(|spec| parse_rule(spec))
            .chain(
                flags
                    .inject_headers
                    .iter()
                    .map(|spec| parse_injection(spec)),
            )
            .collect::<anyhow::Result<Vec<_>>>()?,
        ..Default::default()
    })
}

/// Parses `domain:Name=Value` into a rule with no matcher.
///
/// Split on the first `:` and then the first `=`, so a value may contain both.
/// Nothing is trimmed or repaired: a rule the caller did not quite write is a
/// credential going somewhere they did not quite mean.
fn parse_injection(spec: &str) -> anyhow::Result<common::RequestRule> {
    let (domain, rest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--inject-header {spec:?} is not domain:Name=Value"))?;
    let (name, value) = rest
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("--inject-header {spec:?} is not domain:Name=Value"))?;
    if domain.is_empty() || name.is_empty() {
        anyhow::bail!("--inject-header {spec:?} needs both a domain and a header name");
    }
    Ok(common::RequestRule {
        domain: domain.to_string(),
        r#match: None,
        action: Some(common::request_rule::Action::SetHeaders(
            common::SetHeaders {
                headers: vec![common::HeaderValue {
                    name: name.to_string(),
                    value: value.to_string(),
                }],
            },
        )),
        ..Default::default()
    })
}

/// Parses one `--rule`.
///
/// JSON rather than a flag grammar of its own: a rule has four optional match
/// dimensions and two possible actions, and it is the same object the SDK
/// sends, so a rule can be moved between the two by copying it.
fn parse_rule(spec: &str) -> anyhow::Result<common::RequestRule> {
    let value: serde_json::Value = serde_json::from_str(spec)
        .map_err(|err| anyhow::anyhow!("--rule {spec:?} is not a JSON object: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("--rule {spec:?} is not a JSON object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "domain" | "match" | "setHeaders" | "forward" | "expiresIn" | "expiresAtUnixMs"
        ) {
            anyhow::bail!("--rule: unknown key {key:?}");
        }
    }
    let expires_at_unix_ms = match (object.get("expiresIn"), object.get("expiresAtUnixMs")) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--rule: give expiresIn or expiresAtUnixMs, not both")
        }
        (Some(within), None) => {
            let secs = match within {
                serde_json::Value::Number(n) => n.as_u64(),
                serde_json::Value::String(text) => parse_duration_secs(text),
                _ => None,
            }
            .filter(|secs| *secs > 0)
            .ok_or_else(|| {
                anyhow::anyhow!("--rule: expiresIn is seconds, or a number with s, m, h or d")
            })?;
            unix_ms_now().saturating_add(secs.saturating_mul(1000))
        }
        (None, Some(at)) => at
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("--rule: expiresAtUnixMs is unix milliseconds"))?,
        (None, None) => 0,
    };

    let domain = object
        .get("domain")
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow::anyhow!("--rule needs a \"domain\""))?;
    let matcher = object.get("match").map(parse_match).transpose()?;

    let action = match (object.get("setHeaders"), object.get("forward")) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--rule: a rule does one thing, so not both setHeaders and forward")
        }
        (Some(headers), None) => {
            let headers = headers
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("--rule: setHeaders is a name-to-value object"))?;
            common::request_rule::Action::SetHeaders(common::SetHeaders {
                headers: headers
                    .iter()
                    .map(|(name, value)| {
                        Ok(common::HeaderValue {
                            name: name.clone(),
                            value: value
                                .as_str()
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "--rule: the value for {name:?} is not a string"
                                    )
                                })?
                                .to_string(),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
            })
        }
        (None, Some(forward)) => {
            let forward = forward
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("--rule: forward is an object with a url"))?;
            common::request_rule::Action::Forward(common::ForwardRequest {
                url: forward
                    .get("url")
                    .and_then(|u| u.as_str())
                    .ok_or_else(|| anyhow::anyhow!("--rule: forward needs a \"url\""))?
                    .to_string(),
                secret: forward
                    .get("secret")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
        }
        (None, None) => anyhow::bail!("--rule needs either setHeaders or forward"),
    };

    Ok(common::RequestRule {
        domain: domain.to_string(),
        r#match: matcher,
        action: Some(action),
        expires_at_unix_ms,
        ..Default::default()
    })
}

/// Seconds in `120`, `90s`, `15m`, `1h` or `2d`.
fn parse_duration_secs(text: &str) -> Option<u64> {
    let (number, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => text.split_at(at),
        None => (text, "s"),
    };
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    number.parse::<u64>().ok()?.checked_mul(scale)
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_match(value: &serde_json::Value) -> anyhow::Result<common::RequestMatch> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("--rule: match is an object"))?;
    for key in object.keys() {
        if !matches!(key.as_str(), "path" | "method" | "query" | "headers") {
            anyhow::bail!("--rule: unknown match key {key:?}");
        }
    }
    let methods = match object.get("method") {
        None => Vec::new(),
        Some(serde_json::Value::String(one)) => vec![one.clone()],
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("--rule: a method is a string"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        Some(_) => anyhow::bail!("--rule: method is a string or a list of them"),
    };
    Ok(common::RequestMatch {
        path: object.get("path").map(parse_string_match).transpose()?,
        methods,
        query: parse_fields(object.get("query"))?,
        headers: parse_fields(object.get("headers"))?,
    })
}

fn parse_fields(value: Option<&serde_json::Value>) -> anyhow::Result<Vec<common::FieldMatch>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("--rule: query and headers are key-to-match objects"))?;
    object
        .iter()
        .map(|(key, value)| {
            Ok(common::FieldMatch {
                key: key.clone(),
                value: Some(parse_string_match(value)?),
            })
        })
        .collect()
}

/// Reads one comparison: `{"exact"|"startsWith"|"regex": "..."}`, or a bare
/// string, which is the exact match people mean when they write one.
fn parse_string_match(value: &serde_json::Value) -> anyhow::Result<common::StringMatch> {
    if let Some(text) = value.as_str() {
        return Ok(common::StringMatch {
            op: common::StringMatchOp::Exact as i32,
            value: text.to_string(),
        });
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("--rule: a match is a string or one comparator object"))?;
    if object.len() != 1 {
        anyhow::bail!("--rule: a match names exactly one of exact, startsWith or regex");
    }
    let (name, text) = object.iter().next().expect("one entry");
    let op = match name.as_str() {
        "exact" => common::StringMatchOp::Exact,
        "startsWith" => common::StringMatchOp::StartsWith,
        "regex" => common::StringMatchOp::Regex,
        other => anyhow::bail!("--rule: {other:?} is not exact, startsWith or regex"),
    };
    Ok(common::StringMatch {
        op: op as i32,
        value: text
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("--rule: a match pattern is a string"))?
            .to_string(),
    })
}

/// Renders one rule for `show`.
///
/// The plain case (one domain, one header, no matcher) keeps the spelling it
/// was written with, so a policy set with `--inject-header` reads back the way
/// it was typed. Anything a flag could not have expressed is rendered as the
/// rule it is.
fn describe_rule(rule: &common::RequestRule) -> (&'static str, String) {
    use common::request_rule::Action;

    if rule.r#match.is_none()
        && let Some(Action::SetHeaders(set)) = &rule.action
        && let [header] = set.headers.as_slice()
    {
        let mut text = format!("{}:{}={}", rule.domain, header.name, header.value);
        describe_rule_lifetime(rule, &mut text);
        return ("inject-header", text);
    }

    let mut text = rule.domain.clone();
    if let Some(matcher) = &rule.r#match {
        if let Some(path) = &matcher.path {
            text.push_str(&format!(" path{}", describe_match(path)));
        }
        if !matcher.methods.is_empty() {
            text.push_str(&format!(" method={}", matcher.methods.join(",")));
        }
        for entry in &matcher.query {
            text.push_str(&format!(" query[{}]{}", entry.key, describe_field(entry)));
        }
        for entry in &matcher.headers {
            text.push_str(&format!(" header[{}]{}", entry.key, describe_field(entry)));
        }
    }
    match &rule.action {
        Some(Action::SetHeaders(set)) => {
            let headers: Vec<String> = set
                .headers
                .iter()
                .map(|header| format!("{}={}", header.name, header.value))
                .collect();
            text.push_str(&format!(" -> set {}", headers.join(", ")));
        }
        Some(Action::Forward(forward)) => {
            text.push_str(&format!(" -> forward {}", forward.url));
            if !forward.secret.is_empty() {
                text.push_str(&format!(" (secret {})", forward.secret));
            }
        }
        None => text.push_str(" -> nothing"),
    }
    describe_rule_lifetime(rule, &mut text);
    ("rule", text)
}

/// The expiry and binding a rule carries, appended to its description.
fn describe_rule_lifetime(rule: &common::RequestRule, text: &mut String) {
    if rule.expires_at_unix_ms != 0 {
        text.push_str(&format!(
            " (expires at {})",
            rfc3339_from_unix_ms(rule.expires_at_unix_ms as i64)
        ));
    }
    if !rule.bound_sandbox_id.is_empty() {
        text.push_str(&format!(" (bound to {})", rule.bound_sandbox_id));
    }
}

fn describe_field(entry: &common::FieldMatch) -> String {
    match &entry.value {
        Some(value) => describe_match(value),
        None => "=?".to_string(),
    }
}

fn describe_match(value: &common::StringMatch) -> String {
    let op = match common::StringMatchOp::try_from(value.op) {
        Ok(common::StringMatchOp::Exact) => "=",
        Ok(common::StringMatchOp::StartsWith) => "^=",
        Ok(common::StringMatchOp::Regex) => "~=",
        _ => "?=",
    };
    format!("{op}{:?}", value.value)
}

/// One published port.
///
/// The node address is where the port actually is, and the edge URL is the name
/// its node's edge answers for, so both are shown. A node running no edge has no
/// hostname routing, and the address is then printed alone.
fn print_port(mapping: &api::PortMapping) {
    let proto = if mapping.is_udp { "/udp" } else { "" };
    match mapping.edge_url.as_str() {
        // A UDP mapping never has an edge URL: the edge carries HTTP.
        "" => println!(
            "{} -> guest :{}{proto}",
            mapping.host_address, mapping.guest_port
        ),
        url => println!(
            "{} -> guest :{}{proto} ({})",
            url, mapping.guest_port, mapping.host_address
        ),
    }
}

/// The address goes on stdout by itself, so `burrow share <id>` composes with
/// a pipe; what it admits goes to stderr.
fn print_share(share: &api::Share) {
    println!("{}", share.address);
    let ports = if share.ports.is_empty() {
        "all".to_string()
    } else {
        share
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    eprintln!("# ports: {ports}");
    if share.is_all_udp {
        eprintln!("# udp ports: all");
    } else if !share.udp_ports.is_empty() {
        let udp = share
            .udp_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        eprintln!("# udp ports: {udp}");
    }
    if !share.allowed_clients.is_empty() {
        eprintln!("# allowed clients: {}", share.allowed_clients.join(", "));
    }
    if share.is_transparent_ip {
        eprintln!("# source: the client's last verified public IPv4");
    } else {
        eprintln!("# source: the gateway");
    }
    eprintln!("# connect with: tailcat {} <port>", share.address);
}

async fn list_nodes(client: &mut Client) -> anyhow::Result<()> {
    let resp = client
        .list_nodes(api::ListNodesRequest {})
        .await?
        .into_inner();
    if resp.nodes.is_empty() {
        println!("no nodes registered");
        return Ok(());
    }
    print!("{}", node_table(&resp.nodes));
    Ok(())
}

/// `node ls`'s table, one row per node.
///
/// DISK is free over total on the node's data directory. A node whose free
/// disk has fallen below its reserve while it runs sandboxes says `LOW` there
/// and `disk-low` in STATE: it refuses creates, resumes and adopts until disk
/// is freed, and its guests' writes may start failing.
fn node_table(nodes: &[api::Node]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<38} {:<22} {:>5} {:>9} {:>9} {:>16} {:>5} {:<9} {:<24} HOSTNAME",
        "NODE", "ADDRESS", "CPUS", "MEM_MIB", "FREE_MIB", "DISK", "SBX", "STATE", "LABELS"
    );
    for node in nodes {
        let info = node.info.clone().unwrap_or_default();
        let status = node.status.clone().unwrap_or_default();
        let state = if !node.is_healthy {
            "stale"
        } else if status.is_draining {
            "draining"
        } else if status.is_disk_low {
            "disk-low"
        } else {
            "ready"
        };
        let _ = writeln!(
            out,
            "{:<38} {:<22} {:>5} {:>9} {:>9} {:>16} {:>5} {:<9} {:<24} {}",
            info.id,
            info.address,
            info.total_vcpus,
            info.total_mem_mib,
            status.free_mem_mib,
            disk_column(&status),
            status.running_sandboxes,
            state,
            truncate(&format_tags(&info.labels), 24),
            info.hostname,
        );
    }
    out
}

/// Free over total disk in GiB, `LOW` when under the reserve, `-` for a node
/// that does not report disk.
fn disk_column(status: &common::NodeStatus) -> String {
    let Some(disk) = status.disk.filter(|disk| disk.total_bytes != 0) else {
        return "-".into();
    };
    let gib = |bytes: u64| bytes as f64 / (1u64 << 30) as f64;
    let column = format!("{:.1}/{:.0}G", gib(disk.free_bytes), gib(disk.total_bytes));
    if status.is_disk_low {
        format!("{column} LOW")
    } else {
        column
    }
}

/// `ps`: the sandboxes there are, running ones unless --all.
///
/// The API returns every record, so the filtering is done here. Nothing is
/// hidden silently: an empty running listing says how to see the rest.
async fn list_sandboxes(client: &mut Client, tag: String, all: bool) -> anyhow::Result<()> {
    let filtered = !tag.is_empty();
    let resp = client
        .list_sandboxes(api::ListSandboxesRequest { tag })
        .await?
        .into_inner();
    let total = resp.sandboxes.len();
    let sandboxes: Vec<_> = resp
        .sandboxes
        .into_iter()
        .filter(|sandbox| all || is_running(sandbox))
        .collect();
    if sandboxes.is_empty() {
        println!(
            "{}",
            match (filtered, all, total) {
                (true, _, _) => "no sandboxes with that tag".to_string(),
                (false, true, _) => "no sandboxes".to_string(),
                (false, false, 0) => "no sandboxes".to_string(),
                (false, false, n) => format!(
                    "no running sandboxes; `burrow ps -a` shows the {n} that are not running"
                ),
            }
        );
        return Ok(());
    }
    println!(
        "{:<40} {:<20} {:<12} {:<38} {:<20} {:<24} CREATED",
        "SANDBOX", "NAME", "STATE", "NODE", "TEMPLATE", "TAGS"
    );
    for sandbox in sandboxes {
        println!(
            "{:<40} {:<20} {:<12} {:<38} {:<20} {:<24} {}",
            sandbox.id,
            // A dash rather than a blank: an unnamed sandbox is a fact worth
            // seeing in a column of names.
            if sandbox.name.is_empty() {
                "-"
            } else {
                &sandbox.name
            },
            display_state(&sandbox),
            display_node(&sandbox),
            sandbox.template,
            truncate(&format_tags(&sandbox.tags), 24),
            rfc3339_from_unix_ms(sandbox.created_at_unix_ms),
        );
    }
    Ok(())
}

/// Whether a sandbox is one a bare `ps` shows.
///
/// A sandbox still being built, or on its way down, is a live machine and
/// belongs in the same listing. Suspended, finished and lost records are what
/// --all is for.
fn is_running(sandbox: &common::Sandbox) -> bool {
    !sandbox.is_unreachable
        && matches!(
            common::SandboxState::try_from(sandbox.state),
            Ok(common::SandboxState::Creating)
                | Ok(common::SandboxState::Running)
                | Ok(common::SandboxState::Stopping)
        )
}

/// `stats`: what sandboxes have actually consumed.
///
/// Every figure here already rides on the sandbox record, so one id is a get
/// and no id is the same list `ps` reads.
async fn show_stats(client: &mut Client, id: Option<String>, all: bool) -> anyhow::Result<()> {
    let sandboxes = match id {
        Some(id) => vec![
            client
                .get_sandbox(api::SandboxRef { sandbox_id: id })
                .await?
                .into_inner(),
        ],
        None => client
            .list_sandboxes(api::ListSandboxesRequest::default())
            .await?
            .into_inner()
            .sandboxes
            .into_iter()
            .filter(|sandbox| all || is_running(sandbox))
            .collect(),
    };
    if sandboxes.is_empty() {
        println!("no sandboxes");
        return Ok(());
    }
    println!(
        "{:<40} {:<20} {:<12} {:>10} {:>12} NET O",
        "SANDBOX", "NAME", "STATE", "CPU", "NET I"
    );
    for sandbox in sandboxes {
        println!(
            "{:<40} {:<20} {:<12} {:>10} {:>12} {}",
            sandbox.id,
            if sandbox.name.is_empty() {
                "-"
            } else {
                &sandbox.name
            },
            display_state(&sandbox),
            format!("{}ms", sandbox.cpu_usage_usec / 1000),
            bytes(sandbox.rx_bytes),
            bytes(sandbox.tx_bytes),
        );
    }
    Ok(())
}

/// Publishes each guest port `-p` named against a sandbox that already exists.
///
/// Returns false when any of them failed. The sandbox is left alone either
/// way: it was created, and tearing it down over a port would lose work the
/// caller never asked to lose.
async fn publish_ports(client: &mut Client, id: &str, ports: &[u32]) -> anyhow::Result<bool> {
    let mut published = true;
    for port in ports {
        match client
            .expose_port(api::ExposePortRequest {
                sandbox_id: id.to_string(),
                guest_port: *port,
                host_port: 0,
                is_udp: false,
            })
            .await
        {
            Ok(resp) => print_port(&resp.into_inner()),
            Err(err) => {
                eprintln!(
                    "sandbox {id} exists, but publishing guest :{port} failed: {}",
                    err.message()
                );
                published = false;
            }
        }
    }
    Ok(published)
}

async fn list_templates(client: &mut Client) -> anyhow::Result<()> {
    let resp = client
        .list_templates(api::ListTemplatesRequest {})
        .await?
        .into_inner();
    if resp.templates.is_empty() {
        println!("no templates");
        return Ok(());
    }
    println!(
        "{:<24} {:>10}  {:<7}  {:<16}  WARM",
        "TEMPLATE", "SIZE", "INIT", "HYPERVISOR"
    );
    for template in resp.templates {
        let mut shapes: Vec<(u32, u32)> = template
            .warm_shapes
            .iter()
            .filter_map(|shape| shape.resources)
            .map(|resources| (resources.vcpus, resources.mem_mib))
            .collect();
        shapes.sort_unstable();
        shapes.dedup();
        let warm = match shapes.is_empty() {
            true => "-".to_string(),
            false => shapes
                .iter()
                .map(|(vcpus, mem_mib)| format!("{vcpus}x{mem_mib}"))
                .collect::<Vec<_>>()
                .join(","),
        };
        println!(
            "{:<24} {:>9}M  {:<7}  {:<16}  {}",
            template.name,
            template.size_bytes / (1024 * 1024),
            if template.is_systemd {
                "systemd"
            } else {
                "agent"
            },
            template.hypervisor,
            warm,
        );
    }
    Ok(())
}

async fn list_warm_shapes(client: &mut Client) -> anyhow::Result<()> {
    let resp = client
        .list_templates(api::ListTemplatesRequest {})
        .await?
        .into_inner();
    let mut shapes: Vec<_> = resp
        .templates
        .into_iter()
        .flat_map(|template| template.warm_shapes)
        .collect();
    if shapes.is_empty() {
        println!("no warm snapshots");
        return Ok(());
    }
    shapes.sort_by_key(|shape| {
        let resources = shape.resources.unwrap_or_default();
        (
            shape.template.clone(),
            shape.node_id.clone(),
            resources.vcpus,
            resources.mem_mib,
        )
    });
    println!(
        "{:<24} {:<16} {:<10} {:>8} {:>8}  {:<24}  PINNED",
        "TEMPLATE", "NODE", "SHAPE", "DISK", "SIZE", "LAST USED"
    );
    for shape in shapes {
        let resources = shape.resources.unwrap_or_default();
        println!(
            "{:<24} {:<16} {:<10} {:>7}M {:>7}M  {:<24}  {}",
            shape.template,
            shape.node_id,
            format!("{}x{}", resources.vcpus, resources.mem_mib),
            resources.disk_mib,
            shape.size_bytes / (1024 * 1024),
            rfc3339_from_unix_ms(shape.last_used_at_unix_ms),
            if shape.is_pinned { "yes" } else { "no" },
        );
    }
    Ok(())
}

/// Template name for an image reference that did not come with `--name`.
///
/// The last path segment plus the tag, so `python:3.12-slim` and `python:3.13`
/// are different templates rather than the second silently replacing the
/// first. `latest` is left off, because a name ending in `-latest` says
/// nothing and is what most people type first.
///
/// A digest reference keeps the bare segment: a name carrying 64 hex
/// characters is not one anybody would type, and `--name` is the answer when
/// two digests of one repository have to coexist.
fn template_name_for(image: &str) -> String {
    let last = image.rsplit('/').next().unwrap_or(image);
    // A digest has its own delimiter, and everything after it is not a tag.
    let (before_digest, has_digest) = match last.split_once('@') {
        Some((before, _)) => (before, true),
        None => (last, false),
    };
    let (repo, tag) = match before_digest.rsplit_once(':') {
        Some((repo, tag)) => (repo, Some(tag)),
        None => (before_digest, None),
    };
    let repo = if repo.is_empty() { "imported" } else { repo };
    match tag {
        Some(tag) if !has_digest && !tag.is_empty() && tag != "latest" => {
            format!("{repo}-{tag}")
        }
        _ => repo.to_string(),
    }
}

async fn import_template(
    client: &mut Client,
    images: Vec<String>,
    name: Option<String>,
    is_systemd: bool,
    hypervisor: Option<String>,
) -> anyhow::Result<()> {
    let hypervisor = hypervisor.unwrap_or_default();
    // One image converts as it is; several are a kit set, which the node
    // names after its digests unless told otherwise.
    let image = images.join(" + ");
    let request = match <[String; 1]>::try_from(images) {
        Ok([from_image]) => api::BuildTemplateRequest {
            name: name.unwrap_or_else(|| template_name_for(&from_image)),
            from_image,
            is_systemd,
            hypervisor,
            ..Default::default()
        },
        Err(kits) => api::BuildTemplateRequest {
            name: name.unwrap_or_default(),
            kits,
            is_systemd,
            hypervisor,
            ..Default::default()
        },
    };
    let mut stream = client.build_template(request).await?.into_inner();
    while let Some(log) = stream.message().await? {
        match log.event {
            Some(api::build_log::Event::Step(step)) => println!("  {step}"),
            Some(api::build_log::Event::Stdout(bytes))
            | Some(api::build_log::Event::Stderr(bytes)) => {
                print!("{}", String::from_utf8_lossy(&bytes));
            }
            Some(api::build_log::Event::Done(done)) => println!(
                "imported {image} as template {} ({}MiB)",
                done.template,
                done.size_bytes / (1024 * 1024)
            ),
            None => {}
        }
    }
    Ok(())
}

async fn build_template(
    client: &mut Client,
    request: api::BuildTemplateRequest,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let mut stream = client.build_template(request).await?.into_inner();
    while let Some(log) = stream.message().await? {
        match log.event {
            Some(api::build_log::Event::Step(step)) => println!("==> {step}"),
            Some(api::build_log::Event::Stdout(bytes))
            | Some(api::build_log::Event::Stderr(bytes)) => {
                print!("{}", String::from_utf8_lossy(&bytes));
            }
            Some(api::build_log::Event::Done(done)) => println!(
                "built template {} ({}MiB) in {}s",
                done.template,
                done.size_bytes / (1024 * 1024),
                started.elapsed().as_secs()
            ),
            None => {}
        }
    }
    Ok(())
}

async fn create_snapshot(
    client: &mut Client,
    sandbox: String,
    expiration_secs: u64,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let snapshot = client
        .create_snapshot(api::CreateSnapshotRequest {
            sandbox_id: sandbox,
            expiration_secs,
        })
        .await?
        .into_inner();
    println!(
        "{} ({}M) in {}ms",
        snapshot.id,
        snapshot.size_bytes / (1024 * 1024),
        started.elapsed().as_millis()
    );
    Ok(())
}

/// Every VM a sandbox has run, newest first.
async fn list_sessions(client: &mut Client, id: String) -> anyhow::Result<()> {
    let resp = client
        .list_sessions(api::SandboxRef { sandbox_id: id })
        .await?
        .into_inner();
    if resp.sessions.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    println!(
        "{:<40} {:<9} {:<11} {:<22} ENDED AT",
        "SESSION", "START", "END", "STARTED AT"
    );
    for session in resp.sessions {
        println!(
            "{:<40} {:<9} {:<11} {:<22} {}",
            session.id,
            common::SessionStart::try_from(session.started_by)
                .unwrap_or_default()
                .label(),
            // An open session is the running VM, which is a state worth its
            // own word rather than a blank column.
            match common::SessionEnd::try_from(session.ended_by).unwrap_or_default() {
                common::SessionEnd::Unspecified => "open",
                ended => ended.label(),
            },
            rfc3339_from_unix_ms(session.started_at_unix_ms),
            // 0 for a session the node died during: nothing recorded when
            // that VM actually stopped, and a guess would read as a fact.
            match session.ended_at_unix_ms {
                0 => "-".to_string(),
                at => rfc3339_from_unix_ms(at),
            },
        );
    }
    Ok(())
}

/// One sandbox's whole record, as the orchestrator holds it.
///
/// Injected header values arrive redacted from the node and are printed as
/// they arrive: this is a read API, and the guest's credentials stay on the
/// host.
fn print_config(sandbox: &common::Sandbox) {
    let field = |name: &str, value: &str| println!("{name:<16}{value}");
    field("sandbox", &sandbox.id);
    field("state", display_state(sandbox));
    if !sandbox.state_reason.is_empty() {
        field("reason", &sandbox.state_reason);
    }
    field("node", &display_node(sandbox));
    if sandbox.is_unreachable {
        field(
            "unreachable",
            &format!(
                "yes; node {} has missed its heartbeats. The state above is the \
                 last one it reported",
                sandbox.node_id
            ),
        );
    }
    field("template", &sandbox.template);
    field("created", &rfc3339_from_unix_ms(sandbox.created_at_unix_ms));
    if !sandbox.guest_ip.is_empty() {
        field("address", &sandbox.guest_ip);
    }
    for ip in &sandbox.public_ips {
        let address = match ip.family {
            6 => format!("{}/{}", ip.address, ip.prefix_len),
            _ => ip.address.clone(),
        };
        field("public ip", &format!("{address} ({})", ip.pool));
    }
    // Always shown, zeroes included: a sandbox that has spent nothing is a
    // fact, and a missing line reads as "not measured".
    field("cpu", &format!("{}ms", sandbox.cpu_usage_usec / 1000));
    field(
        "network",
        &format!(
            "{} in / {} out",
            bytes(sandbox.rx_bytes),
            bytes(sandbox.tx_bytes)
        ),
    );
    let policy = sandbox.policy.clone().unwrap_or_default();
    if let Some(resources) = &policy.resources {
        // 0 is stored to mean "whatever the node gives out", so printing it
        // raw tells a reader nothing about the machine they actually have.
        field("vcpus", &shape_value(resources.vcpus as u64, 1));
        field("mem-mib", &shape_value(resources.mem_mib as u64, 512));
        if resources.disk_mib > 0 {
            let layout = match common::DiskLayout::try_from(sandbox.disk_layout) {
                Ok(common::DiskLayout::Root) => "root disk",
                _ => "overlay scratch disk",
            };
            field("disk", &format!("{} MiB {layout}", resources.disk_mib));
        }
    }
    if let Some(lifetime) = &policy.lifetime {
        if lifetime.max_lifetime_secs > 0 {
            field("max-lifetime", &format!("{}s", lifetime.max_lifetime_secs));
        }
        if lifetime.idle_suspend_secs > 0 {
            field("idle-suspend", &format!("{}s", lifetime.idle_suspend_secs));
        }
        if lifetime.suspended_ttl_secs > 0 {
            field(
                "suspended-ttl",
                &format!("{}s", lifetime.suspended_ttl_secs),
            );
        }
    }
    // Only shown when set. An absent section is no restriction, and a line
    // saying "exec allowed" on every unrestricted sandbox would bury the one
    // sandbox where it is not.
    if let Some(exec) = &policy.exec {
        field(
            "exec",
            if exec.is_exec_allowed {
                "allowed"
            } else {
                "denied"
            },
        );
    }
    if let Some(fs) = &policy.fs {
        field(
            "upload",
            if fs.is_upload_allowed {
                "allowed"
            } else {
                "denied"
            },
        );
        field(
            "download",
            if fs.is_download_allowed {
                "allowed"
            } else {
                "denied"
            },
        );
        for scope in &fs.path_scopes {
            field("fs-scope", scope);
        }
        if fs.max_upload_bytes > 0 {
            field("max-upload", &bytes(fs.max_upload_bytes));
        }
    }
    let network = policy.network.unwrap_or_default();
    field(
        "net",
        match common::NetworkMode::try_from(network.mode) {
            Ok(common::NetworkMode::Open) => "open",
            Ok(common::NetworkMode::Allowlist) => "allowlist",
            Ok(common::NetworkMode::None) => "none",
            _ => "unspecified",
        },
    );
    for domain in &network.allow_domains {
        field("allow-domain", domain);
    }
    for cidr in &network.allow_cidrs {
        field("allow-cidr", cidr);
    }
    for port in &network.allow_ports {
        field("allow-port", &port.to_string());
    }
    for cidr in &network.deny_cidrs {
        field("deny-cidr", cidr);
    }
    for domain in &network.deny_domains {
        field("deny-domain", domain);
    }
    for rule in &network.deny_ports {
        field("deny-port", &describe_port_rule(rule));
    }
    if network.is_ipv6_denied {
        field("deny-ipv6", "yes");
    }
    for rule in &network.ingress {
        field("ingress", &describe_ingress_rule(rule));
    }
    if network.is_tls_inspected {
        field("inspect-tls", "yes");
    }
    for rule in &network.rules {
        let (label, text) = describe_rule(rule);
        field(label, &text);
    }
    for membership in &policy.networks {
        let alias = if membership.alias.is_empty() {
            sandbox.id.clone()
        } else {
            membership.alias.clone()
        };
        field(
            "network",
            &format!(
                "{} as {alias}.{}.internal",
                membership.network, membership.network
            ),
        );
    }
    let tags = format_tags(&sandbox.tags);
    if !tags.is_empty() {
        field("tags", &tags);
    }
}

/// Replaces a sandbox's published ports with exactly the guest ports named.
///
/// Composed from expose and close rather than a single RPC, so it closes what
/// is no longer wanted before publishing what is: a node that runs out of host
/// ports mid-way leaves the sandbox with a subset of the request, never with
/// ports the caller asked to withdraw.
async fn set_ports(client: &mut Client, id: &str, ports: &[u32]) -> anyhow::Result<()> {
    let current = client
        .list_ports(api::SandboxRef {
            sandbox_id: id.to_string(),
        })
        .await?
        .into_inner()
        .ports;

    for mapping in &current {
        if !ports.contains(&mapping.guest_port) {
            client
                .close_port(api::ClosePortRequest {
                    sandbox_id: id.to_string(),
                    host_port: mapping.host_port,
                })
                .await?;
            println!("closed guest :{}", mapping.guest_port);
        }
    }
    for port in ports {
        if current.iter().any(|m| m.guest_port == *port) {
            continue;
        }
        let mapping = client
            .expose_port(api::ExposePortRequest {
                sandbox_id: id.to_string(),
                guest_port: *port,
                host_port: 0,
                is_udp: false,
            })
            .await?
            .into_inner();
        print_port(&mapping);
    }
    if ports.is_empty() {
        println!("no published ports");
    }
    Ok(())
}

/// Tags as `k=v,k=v`, ordered so two listings of the same sandbox agree.
fn format_tags(tags: &std::collections::HashMap<String, String>) -> String {
    let mut pairs: Vec<_> = tags.iter().collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A byte count at a scale someone can read at a glance.
fn bytes(count: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = count as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{count} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A machine-shape figure, naming the node's default where 0 stands for it.
///
/// The policy stores 0 for "whatever the node gives out", which is the right
/// thing to send and the wrong thing to show: it reads as a sandbox with no
/// cpu rather than one that took the default.
fn shape_value(value: u64, default: u64) -> String {
    match value {
        0 => format!("{default} (default)"),
        set => set.to_string(),
    }
}

/// Keeps table columns aligned when a value is longer than its column.
///
/// Counted in `char`s, not bytes: the names, paths and commands shown here are
/// written by tenants and by whoever is inside the sandbox, and a byte slice
/// that lands inside a multi-byte character panics. Still not display width, a
/// CJK character counts as one and takes two columns, but a column that is a
/// little wide beats a CLI that aborts on a filename.
fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Makes a guest-controlled string safe to print to a terminal.
///
/// Command lines, file names, audit hosts and deny reasons are all chosen by
/// whoever is inside the sandbox. Printed raw, an escape sequence in one of
/// them repaints the screen, hides the lines around it, or on terminals that
/// answer a status query gets the terminal to type text back on this process's
/// stdin. Only the human-readable path needs it; `serde_json` escapes control
/// characters on the `--json` path already.
///
/// Tab survives because it is what a column of output is made of. Every other
/// control character becomes `?`; ordinary non-ASCII text is left alone.
fn sanitize(value: &str) -> String {
    value
        .chars()
        // `char::is_control` is exactly C0, DEL and C1.
        .map(|c| if c == '\t' || !c.is_control() { c } else { '?' })
        .collect()
}

/// Maps an exit status the guest reported onto one this process can exit with.
///
/// `exit(2)` keeps only the low 8 bits, so a command reporting 256 would leave
/// this process exiting 0 and a script would read a failure as a success.
/// Anything nonzero therefore lands in 1..=255, and only a real 0 stays 0.
fn exit_status(code: i32) -> i32 {
    if code == 0 { 0 } else { code.clamp(1, 255) }
}

/// The state to show a reader, which is not always the state on record.
///
/// A sandbox whose node has missed its heartbeats still carries whatever state
/// that node last reported, so it reads as `lost` rather than `running`.
///
/// `starting` is the same correction: a warm create returns as soon as the VM
/// is up, so a sandbox can be `running` with a guest that has not answered yet.
/// Anything sent to it waits.
fn display_state(sandbox: &common::Sandbox) -> &'static str {
    if sandbox.is_unreachable {
        "lost"
    } else if sandbox.is_agent_unconfirmed && sandbox.state == common::SandboxState::Running as i32
    {
        "starting"
    } else {
        state_name(sandbox.state)
    }
}

/// Where a sandbox is, in the same terms `snapshot ls` uses: `+store` once
/// its latest suspend is in the object store, and the store alone for one no
/// node holds, which the next start places.
fn display_node(sandbox: &common::Sandbox) -> String {
    match (sandbox.node_id.is_empty(), sandbox.is_durable) {
        (false, true) => format!("{} +store", sandbox.node_id),
        (false, false) => sandbox.node_id.clone(),
        (true, _) => "object store".to_string(),
    }
}

fn state_name(state: i32) -> &'static str {
    match common::SandboxState::try_from(state) {
        Ok(common::SandboxState::Creating) => "creating",
        Ok(common::SandboxState::Running) => "running",
        Ok(common::SandboxState::Paused) => "paused",
        Ok(common::SandboxState::Suspended) => "suspended",
        Ok(common::SandboxState::Stopping) => "stopping",
        Ok(common::SandboxState::Destroyed) => "destroyed",
        Ok(common::SandboxState::Failed) => "failed",
        Ok(common::SandboxState::Stopped) => "stopped",
        _ => "unknown",
    }
}

/// Streams one command's life: start, stdin, output, exit status.
///
/// With a pty and a terminal on stdin the local terminal goes raw, so keys
/// reach the guest program rather than the local line discipline, and the
/// window size is sent along and resent when it changes.
async fn run_exec(
    client: &mut Passage,
    sandbox_id: &str,
    flags: &ExecFlags,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let env = parse_pairs("--env", &flags.envs)?;
    let interactive = flags.is_pty_allocated && std::io::stdin().is_terminal();
    let (rows, cols) = if interactive {
        term::size().unwrap_or((24, 80))
    } else {
        (24, 80)
    };

    let start = api::ExecInput {
        input: Some(api::exec_input::Input::Start(api::ExecStart {
            sandbox_id: sandbox_id.to_string(),
            cmd,
            env,
            cwd: flags.workdir.clone().unwrap_or_default(),
            is_pty: flags.is_pty_allocated,
            rows,
            cols,
            user: flags.user.clone().unwrap_or_default(),
            log_max_bytes: flags.log_max_size.unwrap_or(0),
            log_max_files: flags.log_max_files,
        })),
    };

    // Capacity enough to keep a typing user ahead of the network without
    // buffering a whole piped file in memory.
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tx.send(start).await.ok();

    // A terminal that is not driving a pty has nothing to send: closing stdin
    // straight away lets the command see EOF rather than hang on a user who is
    // not typing at it. Anything else (a pipe, a file, an interactive pty) is
    // forwarded, and the pump's handle is kept so it can be stopped once the
    // command is over: it sits in a read of stdin, and a pipe nobody is writing
    // to keeps it there long after there is anywhere to send the bytes.
    let stdin_pump = if interactive || !std::io::stdin().is_terminal() {
        Some(tokio::spawn(forward_stdin(
            tx.clone(),
            flags.is_pty_allocated,
        )))
    } else {
        tx.send(api::ExecInput {
            input: Some(api::exec_input::Input::IsStdinEof(true)),
        })
        .await
        .ok();
        None
    };
    if interactive {
        tokio::spawn(forward_resizes(tx.clone()));
    }
    drop(tx);

    // Raw mode for as long as the command runs, restored by the guard however
    // this function leaves.
    let _raw = if interactive {
        Some(term::RawMode::enable()?)
    } else {
        None
    };

    let mut stream = client.exec(ReceiverStream::new(rx)).await?.into_inner();
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    // `None` until the guest says how the command ended: defaulting to 0 would
    // report a command whose stream was cut as a success.
    let mut code = None;
    let mut outcome = Ok(());
    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            // Kept rather than returned so the pump below is stopped on this
            // path too.
            Err(err) => {
                outcome = Err(err);
                break;
            }
        };
        match msg.output {
            Some(api::exec_output::Output::Stdout(b)) => {
                stdout.write_all(&b)?;
                stdout.flush()?;
            }
            Some(api::exec_output::Output::Stderr(b)) => {
                stderr.write_all(&b)?;
                stderr.flush()?;
            }
            Some(api::exec_output::Output::ExitCode(c)) => code = Some(c),
            // Not printed: it would land in the middle of the command's own
            // output. `burrow ps` is where a command's id is read.
            Some(api::exec_output::Output::CommandId(_))
            | Some(api::exec_output::Output::ExitSignal(_))
            | Some(api::exec_output::Output::LostBytes(_))
            | None => {}
        }
    }
    if let Some(pump) = stdin_pump {
        pump.abort();
    }
    outcome?;
    code.ok_or_else(|| {
        anyhow::anyhow!(
            "the exec stream ended without an exit status; `burrow top` lists \
             what the sandbox is still running"
        )
    })
}

/// `run --detach`: start a command and leave it running.
///
/// The stream is held only until the guest reports the command id, which is
/// what `logs` and `kill` need afterwards. A command outlives the exec that
/// started it, so nothing here has to stay attached; it gets no stdin.
async fn start_detached(
    client: &mut Passage,
    sandbox_id: &str,
    flags: &ExecFlags,
    cmd: Vec<String>,
) -> anyhow::Result<String> {
    let start = api::ExecInput {
        input: Some(api::exec_input::Input::Start(api::ExecStart {
            sandbox_id: sandbox_id.to_string(),
            cmd,
            env: parse_pairs("--env", &flags.envs)?,
            cwd: flags.workdir.clone().unwrap_or_default(),
            is_pty: flags.is_pty_allocated,
            rows: 24,
            cols: 80,
            user: flags.user.clone().unwrap_or_default(),
            log_max_bytes: flags.log_max_size.unwrap_or(0),
            log_max_files: flags.log_max_files,
        })),
    };
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(start).await.ok();
    let mut stream = client.exec(ReceiverStream::new(rx)).await?.into_inner();
    while let Some(msg) = stream.next().await {
        if let Some(api::exec_output::Output::CommandId(id)) = msg?.output {
            return Ok(id);
        }
    }
    anyhow::bail!("the command was started but the sandbox never reported its id")
}

/// `top`: the commands a sandbox has run, newest last.
async fn list_commands(client: &mut Client, id: &str) -> anyhow::Result<()> {
    let resp = client
        .list_commands(api::ListCommandsRequest {
            sandbox_id: id.to_string(),
        })
        .await?
        .into_inner();
    if resp.commands.is_empty() {
        println!("no commands");
        return Ok(());
    }

    println!(
        "{:<10} {:<10} {:<8} {:<6} CMD",
        "COMMAND", "USER", "STATE", "CODE"
    );
    for command in resp.commands {
        let code = if command.state == api::CommandState::Exited as i32 {
            command.exit_code.to_string()
        } else {
            "-".to_string()
        };
        println!(
            "{:<10} {:<10} {:<8} {:<6} {}",
            sanitize(&command.command_id),
            sanitize(if command.user.is_empty() {
                "root"
            } else {
                &command.user
            }),
            api::CommandState::try_from(command.state)
                .unwrap_or_default()
                .label(),
            code,
            truncate(&sanitize(&command.cmd.join(" ")), 60)
        );
    }
    Ok(())
}

/// `logs`: what the guest still holds of a command, then the rest of it live.
async fn attach_command(client: &Client, id: &str, command_id: &str) -> anyhow::Result<i32> {
    let mut node = route(client, id).await?;
    let start = api::AttachInput {
        input: Some(api::attach_input::Input::Start(api::AttachStart {
            sandbox_id: node.sandbox_id.clone(),
            command_id: command_id.to_string(),
            from_offset: 0,
        })),
    };
    let mut stream = node
        .client
        .attach(tokio_stream::iter(vec![start]))
        .await?
        .into_inner();

    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    // As in `run_exec`: no status on the stream is not the same as an exit 0.
    let mut code = None;
    while let Some(msg) = stream.next().await {
        match msg?.output {
            Some(api::exec_output::Output::Stdout(b)) => {
                stdout.write_all(&b)?;
                stdout.flush()?;
            }
            Some(api::exec_output::Output::Stderr(b)) => {
                stderr.write_all(&b)?;
                stderr.flush()?;
            }
            Some(api::exec_output::Output::ExitCode(c)) => code = Some(c),
            // Said on stderr, where it does not land in the output itself.
            Some(api::exec_output::Output::LostBytes(lost)) => {
                eprintln!("burrow: {lost} bytes of earlier output are no longer held");
            }
            Some(api::exec_output::Output::CommandId(_))
            | Some(api::exec_output::Output::ExitSignal(_))
            | None => {}
        }
    }
    code.ok_or_else(|| {
        anyhow::anyhow!(
            "the log stream ended without an exit status; `burrow top` shows \
             the command's state"
        )
    })
}

/// Pumps local stdin into the command until it ends, then tells the command's
/// stdin it is over.
///
/// How that is said depends on the terminal: closing a pty's master would tear
/// the terminal down, so a pty session sends the EOF character and lets the
/// guest's line discipline turn it into an end of file. Only a piped command
/// gets a real close.
async fn forward_stdin(tx: tokio::sync::mpsc::Sender<api::ExecInput>, pty: bool) {
    use tokio::io::AsyncReadExt;

    /// ^D, the default VEOF.
    const EOT: u8 = 0x04;

    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let msg = api::ExecInput {
                    input: Some(api::exec_input::Input::Stdin(buf[..n].to_vec())),
                };
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        }
    }
    let end = if pty {
        api::exec_input::Input::Stdin(vec![EOT])
    } else {
        api::exec_input::Input::IsStdinEof(true)
    };
    tx.send(api::ExecInput { input: Some(end) }).await.ok();
}

/// Keeps the guest's pty the same size as the local terminal.
async fn forward_resizes(tx: tokio::sync::mpsc::Sender<api::ExecInput>) {
    let Ok(mut winch) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
    else {
        return;
    };
    while winch.recv().await.is_some() {
        let Some((rows, cols)) = term::size() else {
            continue;
        };
        let msg = api::ExecInput {
            input: Some(api::exec_input::Input::Resize(api::ExecResize {
                rows,
                cols,
            })),
        };
        if tx.send(msg).await.is_err() {
            return;
        }
    }
}

/// One side of a `copy`: a path in a sandbox, or a path on this machine.
#[derive(Debug, PartialEq)]
enum Endpoint {
    Local(String),
    Sandbox { id: String, path: String },
}

/// Reads `<id>:<path>` as a sandbox path and anything else as a local one.
///
/// A colon only marks a sandbox when what precedes it could be an id: no
/// slash, and not empty. That keeps `./a:b` and `/tmp/a:b` local, which is
/// what a caller writing a filename containing a colon meant.
fn parse_endpoint(spec: &str) -> Endpoint {
    match spec.split_once(':') {
        Some((id, path)) if !id.is_empty() && !id.contains('/') && !path.is_empty() => {
            Endpoint::Sandbox {
                id: id.to_string(),
                path: path.to_string(),
            }
        }
        _ => Endpoint::Local(spec.to_string()),
    }
}

/// `copy`: exactly one side names a sandbox.
///
/// Two sandbox paths would be a sandbox-to-sandbox transfer the API does not
/// offer, and two local paths are a job for `cp`; both are refused rather than
/// half-performed.
async fn copy(client: &Client, src: &str, dst: &str) -> anyhow::Result<()> {
    match (parse_endpoint(src), parse_endpoint(dst)) {
        (Endpoint::Local(local), Endpoint::Sandbox { id, path }) => {
            let mut node = route(client, &id).await?;
            let bytes = push(
                &mut node.client,
                &node.sandbox_id,
                std::path::Path::new(&local),
                &path,
            )
            .await?;
            println!("uploaded {bytes} bytes to {id}:{path}");
            Ok(())
        }
        (Endpoint::Sandbox { id, path }, Endpoint::Local(local)) => {
            // `-` is the usual spelling of "stdout" and cannot be a filename
            // anyone meant.
            let local = (local != "-").then(|| std::path::PathBuf::from(local));
            let mut node = route(client, &id).await?;
            pull(&mut node.client, &node.sandbox_id, &path, local).await
        }
        (Endpoint::Sandbox { .. }, Endpoint::Sandbox { .. }) => {
            anyhow::bail!("copy moves a file between this machine and a sandbox, not between two")
        }
        (Endpoint::Local(_), Endpoint::Local(_)) => {
            anyhow::bail!("one side has to be a sandbox path, written as <id>:<path>")
        }
    }
}

use api::fs_request::Op as FsOp;
use api::fs_response::Result as FsResult;

/// Pieces a transfer moves per call: HTTP/2's default flow-control window,
/// as the SDKs and the guest use.
const FS_CHUNK: usize = 64 * 1024;

/// One Fs call as root, with the guest's error turned into this command's.
async fn fs_call(client: &mut Passage, sandbox_id: &str, op: FsOp) -> anyhow::Result<FsResult> {
    let resp = client
        .fs(api::FsRequest {
            sandbox_id: sandbox_id.to_string(),
            user: String::new(),
            op: Some(op),
        })
        .await?
        .into_inner();
    match resp.result {
        Some(FsResult::Error(err)) => anyhow::bail!("{} {}: {}", err.syscall, err.path, err.code),
        Some(result) => Ok(result),
        None => anyhow::bail!("the node answered an fs call with nothing"),
    }
}

async fn fs_open(
    client: &mut Passage,
    sandbox_id: &str,
    path: &str,
    flags: u32,
    mode: u32,
) -> anyhow::Result<u64> {
    match fs_call(
        client,
        sandbox_id,
        FsOp::Open(api::FsOpen {
            path: path.to_string(),
            flags,
            mode,
        }),
    )
    .await?
    {
        FsResult::Handle(handle) => Ok(handle),
        _ => anyhow::bail!("the node answered an open with something else"),
    }
}

async fn push(
    client: &mut Passage,
    sandbox_id: &str,
    local: &std::path::Path,
    remote: &str,
) -> anyhow::Result<u64> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncReadExt;

    const O_WRONLY: u32 = 1;
    const O_CREAT: u32 = 0o100;
    const O_TRUNC: u32 = 0o1000;

    let mut file = tokio::fs::File::open(local).await?;
    let mode = file
        .metadata()
        .await
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    let handle = fs_open(
        client,
        sandbox_id,
        remote,
        O_WRONLY | O_CREAT | O_TRUNC,
        mode,
    )
    .await?;
    let mut buf = vec![0u8; FS_CHUNK];
    let mut total = 0u64;
    let written = async {
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            match fs_call(
                client,
                sandbox_id,
                FsOp::Write(api::FsWrite {
                    handle,
                    position: -1,
                    data: buf[..n].to_vec(),
                }),
            )
            .await?
            {
                FsResult::Written(n) => total += n,
                _ => anyhow::bail!("the node answered a write with something else"),
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fs_call(client, sandbox_id, FsOp::Close(api::FsHandle { handle })).await?;
    written?;
    Ok(total)
}

async fn pull(
    client: &mut Passage,
    sandbox_id: &str,
    remote: &str,
    local: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let handle = fs_open(client, sandbox_id, remote, 0, 0).await?;

    // 0600: a file copied out of a sandbox can hold anything that sandbox
    // held, and the guest's own mode is not a permission grant to every other
    // user of this machine. Only on create; an existing file keeps its mode.
    let mut out: Box<dyn Write> = match &local {
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt as _;
            Box::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?,
            )
        }
        None => Box::new(std::io::stdout()),
    };
    let mut total = 0u64;
    let read = async {
        loop {
            match fs_call(
                client,
                sandbox_id,
                FsOp::Read(api::FsRead {
                    handle,
                    position: -1,
                    length: FS_CHUNK as u32,
                }),
            )
            .await?
            {
                FsResult::Data(data) if data.is_empty() => break,
                FsResult::Data(data) => {
                    out.write_all(&data)?;
                    total += data.len() as u64;
                }
                _ => anyhow::bail!("the node answered a read with something else"),
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    fs_call(client, sandbox_id, FsOp::Close(api::FsHandle { handle })).await?;
    read?;
    out.flush()?;
    if let Some(path) = local {
        println!("wrote {total} bytes to {}", path.display());
    }
    Ok(())
}

/// `k=v` strings, ordered so two renderings of the same map agree.
fn pairs_json(pairs: &std::collections::HashMap<String, String>) -> serde_json::Value {
    let mut pairs: Vec<_> = pairs.iter().collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn volumes_json(volumes: &[common::Volume]) -> String {
    let items: Vec<_> = volumes
        .iter()
        .map(|volume| {
            serde_json::json!({
                "name": volume.name,
                "node": volume.node_id,
                "size_mib": volume.size_mib,
                "created_at": rfc3339_from_unix_ms(volume.created_at_unix_ms),
                "attached_to": volume.attached_to,
                "labels": pairs_json(&volume.labels),
            })
        })
        .collect();
    serde_json::to_string_pretty(&items).expect("a value renders")
}

/// One sandbox's record as JSON, for `inspect --json`.
///
/// The same fields the readable form prints, including the zeroes it shows and
/// the redacted header values the node sent.
fn sandbox_json(sandbox: &common::Sandbox) -> String {
    let policy = sandbox.policy.clone().unwrap_or_default();
    let resources = policy.resources.unwrap_or_default();
    let lifetime = policy.lifetime.unwrap_or_default();
    let snapshots = policy.snapshots.unwrap_or_default();
    let network = policy.network.unwrap_or_default();

    let mut tags: Vec<_> = sandbox.tags.iter().collect();
    tags.sort();

    let mut doc = serde_json::json!({
        "id": sandbox.id,
        "name": sandbox.name,
        "state": display_state(sandbox),
        "state_reason": sandbox.state_reason,
        "unreachable": sandbox.is_unreachable,
        "durable": sandbox.is_durable,
        "agent_unconfirmed": sandbox.is_agent_unconfirmed,
        "node": sandbox.node_id,
        "template": sandbox.template,
        "disk_layout": match common::DiskLayout::try_from(sandbox.disk_layout) {
            Ok(common::DiskLayout::Root) => "root",
            _ => "overlay",
        },
        "created_at": rfc3339_from_unix_ms(sandbox.created_at_unix_ms),
        "address": sandbox.guest_ip,
        "usage": {
            "cpu_usage_usec": sandbox.cpu_usage_usec,
            "rx_bytes": sandbox.rx_bytes,
            "tx_bytes": sandbox.tx_bytes,
        },
        "resources": {
            "vcpus": resources.vcpus,
            "mem_mib": resources.mem_mib,
            "disk_mib": resources.disk_mib,
        },
        "lifetime": {
            "max_lifetime_secs": lifetime.max_lifetime_secs,
            "idle_suspend_secs": lifetime.idle_suspend_secs,
            "suspended_ttl_secs": lifetime.suspended_ttl_secs,
        },
        "snapshots": {
            "expiration_secs": snapshots.expiration_secs,
            "keep_last": snapshots.keep_last,
            "is_evicted_kept": snapshots.is_evicted_kept,
        },
        "network": {
            "mode": match common::NetworkMode::try_from(network.mode) {
                Ok(common::NetworkMode::Open) => "open",
                Ok(common::NetworkMode::Allowlist) => "allowlist",
                Ok(common::NetworkMode::None) => "none",
                _ => "unspecified",
            },
            "allow_domains": network.allow_domains,
            "allow_cidrs": network.allow_cidrs,
            "allow_ports": network.allow_ports,
            "deny_cidrs": network.deny_cidrs,
            "deny_domains": network.deny_domains,
            "deny_ports": network.deny_ports.iter().map(describe_port_rule).collect::<Vec<_>>(),
            "deny_ipv6": network.is_ipv6_denied,
            "ingress": network.ingress.iter().map(describe_ingress_rule).collect::<Vec<_>>(),
            "inspect_tls": network.is_tls_inspected,
            "rules": network
                .rules
                .iter()
                .map(|rule| {
                    let (kind, text) = describe_rule(rule);
                    serde_json::json!({
                        "domain": rule.domain,
                        "kind": kind,
                        "rule": text,
                        "expires_at_unix_ms": rule.expires_at_unix_ms,
                        "bound_sandbox_id": rule.bound_sandbox_id,
                    })
                })
                .collect::<Vec<_>>(),
        },
        "networks": policy
            .networks
            .iter()
            .map(|membership| {
                serde_json::json!({
                    "network": membership.network,
                    "alias": if membership.alias.is_empty() {
                        &sandbox.id
                    } else {
                        &membership.alias
                    },
                })
            })
            .collect::<Vec<_>>(),
        "tags": tags
            .into_iter()
            .map(|(key, value)| serde_json::json!({ "key": key, "value": value }))
            .collect::<Vec<_>>(),
    });
    let fields = doc.as_object_mut().expect("an object");
    // Present only when the sandbox restricts something, exactly as the
    // readable form shows them: an absent section is no restriction, and
    // rendering a permissive one would make the two indistinguishable.
    if let Some(exec) = &policy.exec {
        fields.insert(
            "exec".into(),
            serde_json::json!({ "allow_exec": exec.is_exec_allowed }),
        );
    }
    if let Some(fs) = &policy.fs {
        fields.insert(
            "fs".into(),
            serde_json::json!({
                "allow_upload": fs.is_upload_allowed,
                "allow_download": fs.is_download_allowed,
                "path_scopes": fs.path_scopes,
                "max_upload_bytes": fs.max_upload_bytes,
            }),
        );
    }
    if !sandbox.env.is_empty() {
        fields.insert("env".into(), pairs_json(&sandbox.env));
    }
    if let Some(kit) = &sandbox.kit {
        fields.insert(
            "kit".into(),
            serde_json::json!({
                "args": pairs_json(&kit.args),
                "reject_types": kit.reject_types,
            }),
        );
    }
    if let Ok(selection) = serde_json::from_str::<serde_json::Value>(&sandbox.kit_selection) {
        fields.insert("selection".into(), selection);
    }
    serde_json::to_string_pretty(&doc).expect("a value renders")
}

/// Whether a failed call is worth repeating: the server went away or the
/// connection did, rather than the request being refused.
fn is_transient(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::Internal
    ) && (status.code() == tonic::Code::Unavailable
        || status.message().contains("transport")
        || status.message().contains("broken pipe")
        || status.message().contains("h2 protocol"))
}

fn usage_interval_json(interval: &api::UsageInterval) -> serde_json::Value {
    serde_json::json!({
        "id": interval.id,
        "sandbox_id": interval.sandbox_id,
        "node_id": interval.node_id,
        "template": interval.template,
        "tags": interval.tags,
        "state": usage_state(interval.state),
        "vcpus": interval.vcpus,
        "mem_mib": interval.mem_mib,
        "started_at_unix_ms": interval.started_at_unix_ms.max(0),
        "ended_at_unix_ms": interval.ended_at_unix_ms.max(0),
        "cpu_usage_usec": interval.cpu_usage_usec,
        "rx_bytes": interval.rx_bytes,
        "tx_bytes": interval.tx_bytes,
        "closed_by": interval.closed_by,
        "is_open": interval.is_open,
    })
}

fn usage_sum_json(sum: &api::UsageSum) -> serde_json::Value {
    serde_json::json!({
        "group": sum.group,
        "state": usage_state(sum.state),
        "intervals": sum.intervals,
        "duration_ms": sum.duration_ms,
        "vcpu_ms": sum.vcpu_ms,
        "mem_mib_ms": sum.mem_mib_ms,
        "cpu_usage_usec": sum.cpu_usage_usec,
        "rx_bytes": sum.rx_bytes,
        "tx_bytes": sum.tx_bytes,
    })
}

fn cpu_secs(usec: u64) -> String {
    format!("{:.1}s", usec as f64 / 1e6)
}

fn duration_ms(ms: u64) -> String {
    let secs = ms / 1000;
    match secs {
        0..60 => format!("{:.1}s", ms as f64 / 1000.0),
        60..3600 => format!("{}m {}s", secs / 60, secs % 60),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

/// `2026-10-01` or `2026-10-01T12:00:00Z` as unix milliseconds.
fn unix_ms_from_utc(text: &str) -> Option<i64> {
    let (date, time) = match text.split_once('T') {
        Some((date, time)) => (date, Some(time.strip_suffix('Z')?)),
        None => (text, None),
    };
    let mut date = date.split('-').map(|part| part.parse::<i64>().ok());
    let (y, m, d) = (date.next()??, date.next()??, date.next()??);
    if date.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (h, min, s) = match time {
        None => (0, 0, 0),
        Some(time) => {
            let mut time = time.split(':').map(|part| part.parse::<i64>().ok());
            let parts = (time.next()??, time.next()??, time.next()??);
            if time.next().is_some() || parts.0 > 23 || parts.1 > 59 || parts.2 > 60 {
                return None;
            }
            parts
        }
    };
    // Days from the civil date, the inverse of `rfc3339_from_unix_ms`.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400) + h * 3600 + min * 60 + s) * 1000)
}

/// Unix milliseconds as RFC 3339 to the second, without pulling in a date
/// crate for one column.
fn usage_state(state: i32) -> &'static str {
    api::UsageState::try_from(state).unwrap_or_default().label()
}

fn rfc3339_from_unix_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    fn node(id: &str, status: burrow_proto::common::v1::NodeStatus) -> api::Node {
        api::Node {
            info: Some(burrow_proto::common::v1::NodeInfo {
                id: id.into(),
                address: format!("{id}:7071"),
                hostname: id.into(),
                ..Default::default()
            }),
            status: Some(status),
            is_healthy: true,
            last_heartbeat_at_unix_ms: 0,
        }
    }

    #[test]
    fn config_resources_reads_sizes_and_says_what_it_did() {
        assert_eq!(super::parse_size_mib("20g").unwrap(), 20 * 1024);
        assert_eq!(super::parse_size_mib("20G").unwrap(), 20 * 1024);
        assert_eq!(super::parse_size_mib("512m").unwrap(), 512);
        assert_eq!(super::parse_size_mib("4096").unwrap(), 4096);
        assert!(super::parse_size_mib("0").is_err());
        assert!(super::parse_size_mib("5000000g").is_err());
        let field = |change: api::ResourceChange, previous, value, reason: &str| {
            Some(api::ResourceOutcome {
                change: change as i32,
                previous,
                value,
                reason: reason.into(),
            })
        };
        let lines = super::describe_update(&api::UpdateResourcesResponse {
            vcpus: field(api::ResourceChange::Live, 1, 2, ""),
            mem_mib: field(api::ResourceChange::Refused, 512, 512, "cannot"),
            disk_mib: field(api::ResourceChange::Live, 1024, 2048, ""),
            filesystem_bytes: 2040 << 20,
            ..Default::default()
        });
        assert_eq!(
            lines,
            [
                "vcpus 1 -> 2 live",
                "memory refused: cannot",
                "disk 1024 -> 2048 MiB live, filesystem 2040 MiB",
            ]
        );
        let lines = super::describe_update(&api::UpdateResourcesResponse {
            mem_mib: field(api::ResourceChange::NextBoot, 512, 1024, ""),
            disk_mib: field(api::ResourceChange::Offline, 2048, 1024, ""),
            filesystem_bytes: 1024 << 20,
            ..Default::default()
        });
        assert_eq!(
            lines,
            [
                "memory 512 -> 1024 MiB on its next boot",
                "disk 2048 -> 1024 MiB offline, filesystem 1024 MiB",
            ]
        );
        let grown = super::describe_update(&api::UpdateResourcesResponse {
            disk_mib: field(api::ResourceChange::Offline, 1024, 2048, ""),
            ..Default::default()
        });
        assert!(grown[0].contains("next boot"), "{grown:?}");
        let shrunk = super::describe_update(&api::UpdateResourcesResponse {
            disk_mib: field(api::ResourceChange::NextBoot, 65536, 40960, "cut on boot"),
            filesystem_bytes: 39000 << 20,
            ..Default::default()
        });
        assert_eq!(
            shrunk,
            ["disk 65536 -> 40960 MiB on its next boot, filesystem 39000 MiB; cut on boot"]
        );
    }

    /// `node ls` shows each node's free and total disk, and a node under its
    /// reserve says so twice: LOW beside the figure and disk-low as its state.
    #[test]
    fn node_ls_shows_disk_and_a_node_short_of_it() {
        use burrow_proto::common::v1::NodeStatus;
        let table = node_table(&[
            node(
                "node-a",
                NodeStatus {
                    disk: Some(burrow_proto::common::v1::DiskCapacity {
                        free_bytes: 40 << 30,
                        total_bytes: 100 << 30,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            node(
                "node-b",
                NodeStatus {
                    disk: Some(burrow_proto::common::v1::DiskCapacity {
                        free_bytes: 3 << 29,
                        total_bytes: 100 << 30,
                        ..Default::default()
                    }),
                    is_disk_low: true,
                    running_sandboxes: 2,
                    ..Default::default()
                },
            ),
            node("node-c", NodeStatus::default()),
        ]);
        let lines: Vec<&str> = table.lines().collect();
        assert!(lines[0].contains(" DISK "), "{table}");
        assert!(lines[1].contains("40.0/100G"), "{table}");
        assert!(lines[1].contains(" ready "), "{table}");
        assert!(lines[2].contains("1.5/100G LOW"), "{table}");
        assert!(lines[2].contains(" disk-low "), "{table}");
        // A node that does not report disk shows a dash, not a full disk.
        let unreported: Vec<&str> = lines[3].split_whitespace().collect();
        assert_eq!(unreported[5], "-", "{table}");
    }

    #[test]
    fn usage_bounds_parse_as_utc() {
        assert_eq!(super::unix_ms_from_utc("1970-01-01"), Some(0));
        assert_eq!(
            super::unix_ms_from_utc("2026-10-01"),
            Some(1_790_812_800_000)
        );
        let at = super::unix_ms_from_utc("2026-10-27T03:35:27Z").unwrap();
        assert_eq!(super::rfc3339_from_unix_ms(at), "2026-10-27T03:35:27Z");
        assert_eq!(super::unix_ms_from_utc("2026-13-01"), None);
        assert_eq!(super::unix_ms_from_utc("2026-10-01T12:00:00"), None);
        assert_eq!(super::unix_ms_from_utc("yesterday"), None);
    }

    /// The names, paths and command lines shown here are written by tenants
    /// and by whoever is inside the sandbox; a byte slice through a multi-byte
    /// character aborts the whole command over a filename.
    #[test]
    fn truncation_counts_characters_not_bytes() {
        let truncate = super::truncate;
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly-10", 10), "exactly-10");
        assert_eq!(truncate("abcdefghijk", 10), "abcdefghi…");
        assert_eq!(truncate("ααααααααααα", 10), "ααααααααα…");
        assert_eq!(truncate("日本語のファイル名です", 5), "日本語の…");
    }

    /// A guest that writes an escape sequence into a filename or a deny reason
    /// must not get to drive the operator's terminal with it.
    #[test]
    fn control_characters_are_stripped_from_guest_strings() {
        let sanitize = super::sanitize;
        // A cursor-up plus erase-line would overwrite the line above it.
        assert_eq!(sanitize("safe\u{1b}[1A\u{1b}[2Kfake"), "safe?[1A?[2Kfake");
        assert_eq!(sanitize("del\u{7f}"), "del?");
        // C1 in its 8-bit form, which some terminals still honour.
        assert_eq!(sanitize("csi\u{9b}31m"), "csi?31m");
        // Tab is what a column of output is made of, and ordinary text is
        // left alone.
        assert_eq!(sanitize("a\tb"), "a\tb");
        assert_eq!(sanitize("naïve 日本語 ✓"), "naïve 日本語 ✓");
    }

    /// `exit(2)` keeps only the low 8 bits, so an unclamped 256 exits 0 and a
    /// script reads a failed command as a successful one.
    #[test]
    fn a_nonzero_status_never_clamps_to_success() {
        let status = super::exit_status;
        assert_eq!(status(0), 0);
        assert_eq!(status(137), 137);
        assert_eq!(status(256), 255);
        assert_eq!(status(-1), 1);
    }

    /// The api key travels in a header on every call, so plaintext to anywhere
    /// but this machine has to be asked for explicitly.
    #[test]
    fn only_this_machine_is_plaintext_by_default() {
        let loopback = super::is_loopback;
        assert!(loopback("127.9.9.9"));
        assert!(loopback("LocalHost"));
        // A URL keeps a v6 literal's brackets.
        assert!(loopback("[::1]"));

        assert!(!loopback("10.0.0.5"));
        assert!(!loopback("burrow.example.com"));
        assert!(!loopback(""));
    }

    /// Mirrors the daemons' token files, comments and all.
    #[test]
    fn a_token_file_yields_its_first_real_line() {
        let dir = std::env::temp_dir().join(format!("burrow-cli-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        std::fs::write(&path, "# rotated 2026-01-01\n\n  secret-token  \nolder\n").unwrap();

        assert_eq!(
            super::load_api_key(None, Some(&path)).unwrap(),
            Some("secret-token".to_string())
        );
        // --api-key wins, so a flag can override an environment-set file.
        assert_eq!(
            super::load_api_key(Some("inline"), Some(&path)).unwrap(),
            Some("inline".to_string())
        );
        assert_eq!(super::load_api_key(None, None).unwrap(), None);

        // A file that is there but holds nothing usable is an error, not a
        // silent fall back to calling unauthenticated.
        std::fs::write(&path, "# nothing but a comment\n").unwrap();
        assert!(super::load_api_key(None, Some(&path)).is_err());
        assert!(super::load_api_key(None, Some(&dir.join("absent"))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two tags of one repository are two templates. Before this, both
    /// `python:3.12-slim` and `python:3.13` imported as `python`, and the
    /// second silently replaced the first.
    #[test]
    fn an_imported_template_is_named_after_its_repository_and_tag() {
        let name = super::template_name_for;
        assert_eq!(name("python:3.12-slim"), "python-3.12-slim");
        assert_eq!(name("python:3.13"), "python-3.13");
        assert_eq!(name("ghcr.io/org/tool:v1"), "tool-v1");

        // `latest` says nothing, and is what most people type first.
        assert_eq!(name("alpine:latest"), "alpine");
        assert_eq!(name("alpine"), "alpine");
        assert_eq!(name("ghcr.io/org/tool"), "tool");

        // A digest is not a tag, and is not readable as a name.
        assert_eq!(name("ghcr.io/org/tool@sha256:abc123"), "tool");
        assert_eq!(name("tool:v1@sha256:abc123"), "tool");

        // A registry with a port is a host, not a tag on the last segment.
        assert_eq!(name("localhost:5000/tool:v2"), "tool-v2");
        assert_eq!(name("localhost:5000/tool"), "tool");
    }

    #[test]
    fn a_mount_is_read_write_unless_it_says_otherwise() {
        let parsed = super::parse_mounts(&[
            "cache:/data".into(),
            "shared:/ro:ro".into(),
            "other:/rw:read-write".into(),
        ])
        .unwrap();
        assert_eq!(parsed[0].volume, "cache");
        assert_eq!(parsed[0].path, "/data");
        assert!(!parsed[0].is_read_only, "read-write is the default");
        assert!(parsed[1].is_read_only);
        assert_eq!(parsed[1].path, "/ro");
        assert!(!parsed[2].is_read_only);

        // A colon that is part of the path is not a mode.
        let odd = super::parse_mounts(&["v:/data/a:b".into()]).unwrap();
        assert_eq!(odd[0].path, "/data/a:b");
        assert!(!odd[0].is_read_only);

        for bad in ["cache", "", ":/data", "cache:"] {
            assert!(
                super::parse_mounts(&[bad.into()]).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn a_tmpfs_mount_takes_a_size_and_a_mode() {
        let parsed = super::parse_mounts(&[
            "tmpfs:/scratch".into(),
            "tmpfs:/big:size=2g".into(),
            "tmpfs:/shared:mode=1777:size=512m".into(),
            "tmpfs:/odd:x:size=64".into(),
        ])
        .unwrap();
        assert!(parsed.iter().all(|m| m.is_tmpfs && m.volume.is_empty()));
        assert_eq!(parsed[0].path, "/scratch");
        assert_eq!(parsed[0].size_mib, 0);
        assert_eq!(parsed[1].size_mib, 2048);
        assert_eq!(parsed[2].path, "/shared");
        assert_eq!(parsed[2].size_mib, 512);
        assert_eq!(parsed[2].mode, "1777");
        assert_eq!(parsed[3].path, "/odd:x");
        assert_eq!(parsed[3].size_mib, 64);

        for bad in [
            "tmpfs:",
            "tmpfs:/x:size=",
            "tmpfs:/x:size=0",
            "tmpfs:/x:size=lots",
        ] {
            assert!(
                super::parse_mounts(&[bad.into()]).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(args).unwrap()
    }

    /// `ps` is the sandbox list, and the names it replaced still reach it.
    #[test]
    fn ps_lists_sandboxes_under_every_spelling() {
        for spelling in ["ps", "list", "ls"] {
            assert!(matches!(
                parse(&["burrow", spelling]).command,
                Command::Ps {
                    is_all_shown: false,
                    tag: None
                }
            ));
        }
        assert!(matches!(
            parse(&["burrow", "ps", "-a"]).command,
            Command::Ps {
                is_all_shown: true,
                ..
            }
        ));
        assert!(matches!(
            parse(&["burrow", "ps", "--all", "--tag", "env=ci"]).command,
            Command::Ps {
                is_all_shown: true,
                tag: Some(_)
            }
        ));
        // The command listing moved out of the way rather than staying as a
        // second meaning of `ps`.
        assert!(Args::try_parse_from(["burrow", "ps", "sbx_1"]).is_err());
        assert!(matches!(
            parse(&["burrow", "top", "sbx_1"]).command,
            Command::Top { .. }
        ));
    }

    #[test]
    fn start_is_resume_under_a_docker_name() {
        for spelling in ["start", "resume"] {
            assert!(matches!(
                parse(&["burrow", spelling, "sbx_1"]).command,
                Command::Start { .. }
            ));
        }
    }

    /// The two places burrow takes a command id where docker takes a
    /// container: the id is optional to parse and refused in the handler, so
    /// the error can say what to run instead.
    #[test]
    fn logs_and_kill_accept_a_sandbox_alone_only_to_refuse_it() {
        assert!(matches!(
            parse(&["burrow", "logs", "sbx_1"]).command,
            Command::Logs {
                command_id: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&["burrow", "logs", "sbx_1", "cmd_2"]).command,
            Command::Logs {
                command_id: Some(_),
                ..
            }
        ));
        assert!(matches!(
            parse(&["burrow", "kill", "sbx_1"]).command,
            Command::Kill {
                command_id: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&["burrow", "kill", "sbx_1", "cmd_2", "--signal", "15"]).command,
            Command::Kill {
                command_id: Some(_),
                signal: 15,
                ..
            }
        ));
    }

    #[test]
    fn publish_is_repeatable_on_create_and_run() {
        let Command::Create { create, .. } =
            parse(&["burrow", "create", "-p", "80", "-p", "8080"]).command
        else {
            panic!("expected create");
        };
        assert_eq!(create.publish, vec![80, 8080]);

        let Command::Run { create, .. } =
            parse(&["burrow", "run", "--publish", "8000", "--", "sh"]).command
        else {
            panic!("expected run");
        };
        assert_eq!(create.publish, vec![8000]);
    }

    /// Detaching means there is no exit status to wait for, so the two
    /// cleanups that key off one cannot be asked for alongside it.
    #[test]
    fn detach_rules_out_the_cleanup_flags() {
        assert!(matches!(
            parse(&["burrow", "run", "-d", "--", "sh"]).command,
            Command::Run {
                is_detached: true,
                ..
            }
        ));
        assert!(Args::try_parse_from(["burrow", "run", "-d", "--rm", "--", "sh"]).is_err());
        assert!(Args::try_parse_from(["burrow", "run", "-d", "--stop", "--", "sh"]).is_err());
        assert!(Args::try_parse_from(["burrow", "run", "--rm", "--stop", "--", "sh"]).is_err());
    }

    /// A rename nobody can find is a rename that breaks scripts silently.
    #[test]
    fn every_alias_is_listed_in_help() {
        let help = Args::command().render_long_help().to_string();
        for alias in ["list", "ls", "resume", "ports", "pause", "rm", "cp"] {
            assert!(help.contains(alias), "{alias} is missing from --help");
        }
    }

    /// A bare `ps` shows live machines only, which is what -a exists to widen.
    #[test]
    fn a_bare_listing_holds_only_live_sandboxes() {
        let sandbox = |state: common::SandboxState, unreachable: bool| common::Sandbox {
            state: state as i32,
            is_unreachable: unreachable,
            ..Default::default()
        };
        for live in [
            common::SandboxState::Creating,
            common::SandboxState::Running,
            common::SandboxState::Stopping,
        ] {
            assert!(is_running(&sandbox(live, false)), "{live:?}");
        }
        for gone in [
            common::SandboxState::Paused,
            common::SandboxState::Suspended,
            common::SandboxState::Destroyed,
            common::SandboxState::Failed,
        ] {
            assert!(!is_running(&sandbox(gone, false)), "{gone:?}");
        }
        // A running record on a node nothing can reach is not a sandbox
        // anyone can use, so it waits for -a with the rest.
        assert!(!is_running(&sandbox(common::SandboxState::Running, true)));
    }

    #[test]
    fn a_record_renders_as_json() {
        let sandbox = common::Sandbox {
            id: "sbx_1".into(),
            name: "api".into(),
            state: common::SandboxState::Running as i32,
            cpu_usage_usec: 1500,
            tags: [("env".to_string(), "ci\"1".to_string())]
                .into_iter()
                .collect(),
            policy: Some(common::Policy {
                network: Some(common::NetworkPolicy {
                    mode: common::NetworkMode::Allowlist as i32,
                    allow_domains: vec!["pypi.org".into()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = sandbox_json(&sandbox);
        assert!(json.starts_with("{\n"), "{json}");
        assert!(json.contains(r#""id": "sbx_1""#), "{json}");
        assert!(json.contains(r#""state": "running""#), "{json}");
        assert!(json.contains(r#""mode": "allowlist""#), "{json}");
        assert!(json.contains(r#""cpu_usage_usec": 1500"#), "{json}");
        // An empty list stays a list rather than becoming null or vanishing.
        assert!(json.contains(r#""deny_cidrs": []"#), "{json}");
        assert!(json.contains(r#""value": "ci\"1""#), "{json}");
    }

    #[test]
    fn ingress_flags_become_rules_and_read_back() {
        for spec in [
            "tcp/22",
            "tcp/25,587",
            "udp/27000-27015",
            "tcp/22@203.0.113.0/24",
            "icmp",
            "any/53",
        ] {
            let rule = parse_ingress_rule(spec).unwrap();
            assert_eq!(describe_ingress_rule(&rule), spec);
        }
        let rule = parse_ingress_rule("tcp/22,8000-8010@10.0.0.0/8,2001:db8::/32").unwrap();
        assert_eq!(rule.protocol, common::IngressProtocol::Tcp as i32);
        assert_eq!(rule.ports.len(), 2);
        assert_eq!(rule.ports[1].port_end, 8010);
        assert_eq!(rule.sources, vec!["10.0.0.0/8", "2001:db8::/32"]);
        for bad in ["", "sctp/1", "tcp/", "tcp/x", "icmp/1", "tcp/22@", "tcp/+1"] {
            assert!(
                parse_ingress_rule(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn an_injection_splits_on_the_first_colon_and_equals() {
        let rule = parse_injection("api.example.com:Authorization=Bearer a=b:c").unwrap();
        assert_eq!(rule.domain, "api.example.com");
        // A flag that predates rules becomes the rule it always meant: this
        // domain, every request to it, this header.
        assert!(rule.r#match.is_none());
        let [header] = set_headers(&rule) else {
            panic!("expected one header");
        };
        assert_eq!(header.name, "Authorization");
        // The value keeps every separator after the first of each.
        assert_eq!(header.value, "Bearer a=b:c");
    }

    #[test]
    fn a_malformed_injection_is_refused_rather_than_guessed_at() {
        for bad in [
            "api.example.com",
            "api.example.com:Authorization",
            "Authorization=Bearer t",
            ":Name=v",
            "api.example.com:=v",
        ] {
            assert!(parse_injection(bad).is_err(), "{bad:?} should be refused");
        }
        // An empty value is a real instruction: send the header empty.
        assert_eq!(
            set_headers(&parse_injection("a.example:X-K=").unwrap())[0].value,
            ""
        );
    }

    fn flags(net: &str, inspect_tls: bool, inject: &[&str]) -> NetworkFlags {
        NetworkFlags {
            net: net.into(),
            allow_domains: vec![],
            allow_cidrs: vec![],
            allow_ports: vec![],
            deny_cidrs: vec!["10.0.0.0/8".into()],
            deny_domains: vec![],
            deny_ports: vec![],
            is_ipv6_denied: false,
            ingress: vec![],
            is_tls_inspected: inspect_tls,
            inject_headers: inject.iter().map(|s| (*s).to_string()).collect(),
            rules: vec![],
        }
    }

    #[test]
    fn deny_port_flags_become_port_rules() {
        let mut open = flags("open", false, &[]);
        open.deny_ports = vec![
            "tcp/25".into(),
            "tcp/465-587".into(),
            "5432@10.0.0.0/8,2001:db8::/32".into(),
            "udp/53@10.0.0.0/8".into(),
        ];
        open.is_ipv6_denied = true;
        let policy = network_policy(open).unwrap();
        assert!(policy.is_ipv6_denied);
        let rule =
            |protocol: common::PortProtocol, port, port_end, cidrs: &[&str]| common::PortRule {
                protocol: protocol as i32,
                port,
                port_end,
                cidrs: cidrs.iter().map(|c| (*c).to_string()).collect(),
            };
        assert_eq!(
            policy.deny_ports,
            vec![
                rule(common::PortProtocol::Tcp, 25, 0, &[]),
                rule(common::PortProtocol::Tcp, 465, 587, &[]),
                rule(
                    common::PortProtocol::Unspecified,
                    5432,
                    0,
                    &["10.0.0.0/8", "2001:db8::/32"]
                ),
                rule(common::PortProtocol::Udp, 53, 0, &["10.0.0.0/8"]),
            ]
        );
        // Read back in the spelling it was written in.
        let spelled: Vec<String> = policy.deny_ports.iter().map(describe_port_rule).collect();
        assert_eq!(
            spelled,
            [
                "tcp/25",
                "tcp/465-587",
                "5432@10.0.0.0/8,2001:db8::/32",
                "udp/53@10.0.0.0/8"
            ]
        );

        for bad in [
            "",
            "tcp/",
            "sctp/25",
            "tcp/25-",
            "-25",
            "+25",
            "25@",
            "25@10.0.0.0/8,",
            "tcp/a",
        ] {
            assert!(parse_port_rule(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn a_rule_carries_a_matcher_and_an_action() {
        let rule = parse_rule(
            r#"{"domain":"api.example.com",
                "match":{"path":{"startsWith":"/v1/"},"method":["GET","HEAD"],
                         "query":{"tenant":"acme"},
                         "headers":{"x-client":{"regex":"^cli/"}}},
                "setHeaders":{"Authorization":"Bearer t"}}"#,
        )
        .unwrap();
        assert_eq!(rule.domain, "api.example.com");
        let matcher = rule.r#match.as_ref().unwrap();
        assert_eq!(
            matcher.path.as_ref().unwrap().op,
            common::StringMatchOp::StartsWith as i32
        );
        assert_eq!(matcher.methods, vec!["GET", "HEAD"]);
        // A bare string is the exact match people mean when they write one.
        assert_eq!(matcher.query[0].key, "tenant");
        assert_eq!(
            matcher.query[0].value.as_ref().unwrap().op,
            common::StringMatchOp::Exact as i32
        );
        assert_eq!(
            matcher.headers[0].value.as_ref().unwrap().op,
            common::StringMatchOp::Regex as i32
        );
        assert_eq!(set_headers(&rule)[0].value, "Bearer t");

        let forwarding = parse_rule(
            r#"{"domain":"api.example.com","forward":{"url":"http://gate.internal:8080/","secret":"s"}}"#,
        )
        .unwrap();
        let Some(common::request_rule::Action::Forward(forward)) = &forwarding.action else {
            panic!("expected a forward rule");
        };
        assert_eq!(forward.url, "http://gate.internal:8080/");
        assert_eq!(forward.secret, "s");
    }

    /// A rule the caller did not quite write is a credential going somewhere
    /// they did not quite mean, so nothing here is guessed at.
    #[test]
    fn a_malformed_rule_is_refused_by_name() {
        for bad in [
            "not json",
            r#"["api.example.com"]"#,
            r#"{"setHeaders":{"A":"b"}}"#,
            r#"{"domain":"a.example"}"#,
            r#"{"domain":"a.example","setHeaders":{"A":"b"},"forward":{"url":"http://x/"}}"#,
            r#"{"domain":"a.example","forward":{"secret":"s"}}"#,
            r#"{"domain":"a.example","tranfsorm":{"A":"b"}}"#,
            r#"{"domain":"a.example","match":{"paht":"/v1"},"setHeaders":{"A":"b"}}"#,
            r#"{"domain":"a.example","match":{"path":{"beginsWith":"/v1"}},"setHeaders":{"A":"b"}}"#,
            r#"{"domain":"a.example","match":{"path":{"exact":"/a","regex":"b"}},"setHeaders":{"A":"b"}}"#,
            r#"{"domain":"a.example","setHeaders":{"A":1}}"#,
        ] {
            assert!(parse_rule(bad).is_err(), "{bad:?} should be refused");
        }
    }

    /// `--rule` is evaluated before `--inject-header`, because an injection
    /// carries no matcher and would otherwise shadow every rule after it.
    #[test]
    fn rules_come_before_injections() {
        let mut flags = flags("allowlist", true, &["api.example.com:X-Wide=w"]);
        flags.rules = vec![
            r#"{"domain":"api.example.com","match":{"path":"/v1"},"setHeaders":{"X-Narrow":"n"}}"#
                .to_string(),
        ];
        let policy = network_policy(flags).unwrap();
        assert_eq!(set_headers(&policy.rules[0])[0].name, "X-Narrow");
        assert_eq!(set_headers(&policy.rules[1])[0].name, "X-Wide");
    }

    #[test]
    fn a_rule_needs_inspection_like_an_injection_does() {
        let mut flags = flags("allowlist", false, &[]);
        flags.rules = vec![r#"{"domain":"a.example","forward":{"url":"http://g/"}}"#.to_string()];
        assert!(network_policy(flags).is_err());
    }

    /// The headers a set-headers rule sets, or a panic if it is not one.
    fn set_headers(rule: &common::RequestRule) -> &[common::HeaderValue] {
        match &rule.action {
            Some(common::request_rule::Action::SetHeaders(set)) => &set.headers,
            other => panic!("expected a set-headers rule, got {other:?}"),
        }
    }

    #[test]
    fn brokering_needs_inspection_and_some_egress() {
        let policy = network_policy(flags(
            "allowlist",
            true,
            &["api.example.com:Authorization=Bearer t"],
        ))
        .unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.deny_cidrs, vec!["10.0.0.0/8".to_string()]);

        assert!(network_policy(flags("allowlist", false, &["a.example:X=1"])).is_err());
        assert!(network_policy(flags("none", true, &[])).is_err());
        // Open mode inspects the hosts its rules name.
        let open = network_policy(flags(
            "open",
            true,
            &["api.example.com:Authorization=Bearer t"],
        ))
        .unwrap();
        assert!(open.is_tls_inspected);
        assert_eq!(open.rules.len(), 1);
    }

    #[test]
    fn a_rule_can_expire() {
        let before = unix_ms_now();
        let rule = parse_rule(
            r#"{"domain":"api.example.com","setHeaders":{"Authorization":"Bearer t"},"expiresIn":"1h"}"#,
        )
        .unwrap();
        assert!(rule.expires_at_unix_ms >= before + 3_600_000);
        assert!(rule.expires_at_unix_ms <= unix_ms_now() + 3_600_000);

        let at = parse_rule(
            r#"{"domain":"api.example.com","setHeaders":{"A":"b"},"expiresAtUnixMs":1800000000000}"#,
        )
        .unwrap();
        assert_eq!(at.expires_at_unix_ms, 1_800_000_000_000);
        assert_eq!(
            parse_rule(r#"{"domain":"a.example","setHeaders":{"A":"b"}}"#)
                .unwrap()
                .expires_at_unix_ms,
            0
        );

        for bad in [
            r#"{"domain":"a.example","setHeaders":{"A":"b"},"expiresIn":"1w"}"#,
            r#"{"domain":"a.example","setHeaders":{"A":"b"},"expiresIn":0}"#,
            r#"{"domain":"a.example","setHeaders":{"A":"b"},"expiresIn":"1h","expiresAtUnixMs":1}"#,
        ] {
            assert!(parse_rule(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_duration_secs("90"), Some(90));
        assert_eq!(parse_duration_secs("15m"), Some(900));
        assert_eq!(parse_duration_secs("2d"), Some(172_800));
        assert_eq!(parse_duration_secs("h"), None);
    }

    /// `--net` defaults to `none`, so "no flags" and "deny everything" look
    /// identical unless something distinguishes them. On `fork` the difference
    /// is between inheriting the source's egress and silently removing it.
    #[test]
    fn an_untouched_flag_group_is_not_an_override() {
        let mut untouched = flags("none", false, &[]);
        untouched.deny_cidrs.clear();
        assert!(!untouched.is_stated());

        assert!(flags("open", false, &[]).is_stated());
        assert!(
            flags("none", false, &[]).is_stated(),
            "a deny_cidr was named"
        );

        let mut domains = flags("none", false, &[]);
        domains.deny_cidrs.clear();
        domains.allow_domains.push("pypi.org".into());
        assert!(domains.is_stated());

        let mut ports = flags("none", false, &[]);
        ports.deny_cidrs.clear();
        ports.deny_ports.push("tcp/25".into());
        assert!(ports.is_stated());

        let mut ipv6 = flags("none", false, &[]);
        ipv6.deny_cidrs.clear();
        ipv6.is_ipv6_denied = true;
        assert!(ipv6.is_stated());
    }

    #[test]
    fn a_pair_splits_on_the_first_equals() {
        let tags = parse_pairs("--tag", &["env=staging".into(), "note=a=b".into()]).unwrap();
        assert_eq!(tags["env"], "staging");
        assert_eq!(tags["note"], "a=b");
        // Presence with no value is a real tag.
        assert_eq!(parse_pairs("--tag", &["gpu=".into()]).unwrap()["gpu"], "");
        assert!(parse_pairs("--tag", &[]).unwrap().is_empty());

        for bad in ["env", "=staging", ""] {
            assert!(parse_pairs("--env", &[bad.to_string()]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tags_are_rendered_in_a_stable_order() {
        let tags = parse_pairs("--tag", &["z=1".into(), "a=2".into(), "m=3".into()]).unwrap();
        assert_eq!(format_tags(&tags), "a=2,m=3,z=1");
        assert_eq!(format_tags(&Default::default()), "");
    }

    #[test]
    fn a_copy_endpoint_needs_an_id_before_the_colon() {
        assert_eq!(
            parse_endpoint("sbx-1:/work/out.txt"),
            Endpoint::Sandbox {
                id: "sbx-1".into(),
                path: "/work/out.txt".into()
            }
        );
        // A path with a colon in it is still a local path.
        for local in ["./a:b", "/tmp/a:b", "out.txt", "-", ":/work", "sbx-1:"] {
            assert_eq!(
                parse_endpoint(local),
                Endpoint::Local(local.into()),
                "{local:?} should be local"
            );
        }
    }

    /// `run --name` may land on a sandbox that already exists, where create
    /// flags cannot be applied, so it has to tell that the caller passed some.
    #[test]
    fn an_untouched_create_group_is_not_a_configuration() {
        fn base() -> CreateFlags {
            CreateFlags {
                name: None,
                template: None,
                kit_args: Vec::new(),
                kit_env: Vec::new(),
                reject_capabilities: Vec::new(),
                snapshot: None,
                vcpus: None,
                mem_mib: None,
                disk_mib: None,
                snapshot_expiration_secs: 0,
                keep_last_snapshots: 0,
                is_evicted_snapshots_kept: false,
                mounts: vec![],
                ips: vec![],
                max_lifetime_secs: 0,
                idle_suspend_secs: 0,
                suspended_ttl_secs: 0,
                tags: vec![],
                publish: vec![],
                network: NetworkFlags {
                    net: "none".into(),
                    allow_domains: vec![],
                    allow_cidrs: vec![],
                    allow_ports: vec![],
                    deny_cidrs: vec![],
                    deny_domains: vec![],
                    deny_ports: vec![],
                    is_ipv6_denied: false,
                    ingress: vec![],
                    is_tls_inspected: false,
                    inject_headers: vec![],
                    rules: vec![],
                },
                access: AccessFlags {
                    is_exec_denied: false,
                    is_upload_denied: false,
                    is_download_denied: false,
                    fs_scopes: vec![],
                    max_upload_bytes: 0,
                },
                networks: vec![],
                alias: None,
                node_labels: vec![],
            }
        }
        assert!(!base().is_stated());

        // The name is what `run` matched on, not a configuration that went
        // unapplied, so naming a sandbox is not on its own a create.
        let mut named = base();
        named.name = Some("builder".into());
        assert!(!named.is_stated());

        // A publish is applied after the fact, so it is not a create flag that
        // went unapplied either.
        let mut published = base();
        published.publish.push(8080);
        assert!(!published.is_stated());

        let mut template = base();
        template.template = Some("python".into());
        assert!(template.is_stated());

        let mut tagged = base();
        tagged.tags.push("env=ci".into());
        assert!(tagged.is_stated());

        let mut networked = base();
        networked.network.net = "open".into();
        assert!(networked.is_stated());

        let mut confined = base();
        confined.access.fs_scopes.push("/work".into());
        assert!(confined.is_stated());

        // A placement constraint is a configuration: `run --name` landing on an
        // existing sandbox somewhere else cannot honour it.
        let mut placed = base();
        placed.node_labels.push("rack=b7".into());
        assert!(placed.is_stated());
    }

    /// Absent means allowed on the wire, so a create that restricted nothing
    /// must leave both sections unset rather than sending a permissive one.
    #[test]
    fn access_sections_are_sent_only_when_something_was_restricted() {
        let open = AccessFlags {
            is_exec_denied: false,
            is_upload_denied: false,
            is_download_denied: false,
            fs_scopes: vec![],
            max_upload_bytes: 0,
        };
        assert!(open.exec_policy().is_none());
        assert!(open.fs_policy().is_none());

        let scoped = AccessFlags {
            is_exec_denied: true,
            is_download_denied: true,
            fs_scopes: vec!["/work".into()],
            max_upload_bytes: 4096,
            ..open
        };
        assert!(!scoped.exec_policy().unwrap().is_exec_allowed);
        let fs = scoped.fs_policy().unwrap();
        assert!(fs.is_upload_allowed);
        assert!(!fs.is_download_allowed);
        assert_eq!(fs.path_scopes, vec!["/work".to_string()]);
        assert_eq!(fs.max_upload_bytes, 4096);

        // An exec restriction on its own leaves the fs section absent.
        let no_exec = AccessFlags {
            is_exec_denied: true,
            is_upload_denied: false,
            is_download_denied: false,
            fs_scopes: vec![],
            max_upload_bytes: 0,
        };
        assert!(no_exec.fs_policy().is_none());
    }

    /// On an update, silence about a section means "leave it", so a section is
    /// sent only when the caller spelled one of its flags either way.
    #[test]
    fn an_update_sends_only_the_sections_the_caller_named() {
        fn quiet() -> AccessUpdateFlags {
            AccessUpdateFlags {
                is_exec_denied: false,
                is_exec_allowed: false,
                is_upload_denied: false,
                is_upload_allowed: false,
                is_download_denied: false,
                is_download_allowed: false,
                fs_scopes: vec![],
                max_upload_bytes: None,
            }
        }
        assert!(quiet().exec_policy().is_none());
        assert!(quiet().fs_policy().is_none());

        // Tightening files says nothing about exec, which is the case the
        // node must not read as "allow everything".
        let files = AccessUpdateFlags {
            is_upload_denied: true,
            fs_scopes: vec!["/work".into()],
            ..quiet()
        };
        assert!(files.exec_policy().is_none());
        let fs = files.fs_policy().unwrap();
        assert!(!fs.is_upload_allowed);
        assert!(fs.is_download_allowed);
        assert_eq!(fs.path_scopes, vec!["/work".to_string()]);

        // Both spellings of an exec allowance produce a section; they differ
        // only in what it says.
        let denied = AccessUpdateFlags {
            is_exec_denied: true,
            ..quiet()
        };
        assert!(!denied.exec_policy().unwrap().is_exec_allowed);
        let allowed = AccessUpdateFlags {
            is_exec_allowed: true,
            ..quiet()
        };
        assert!(allowed.exec_policy().unwrap().is_exec_allowed);
        assert!(allowed.fs_policy().is_none());

        // A cap of 0 is "unlimited", and is distinguishable from not saying so.
        let uncapped = AccessUpdateFlags {
            max_upload_bytes: Some(0),
            ..quiet()
        };
        assert_eq!(uncapped.fs_policy().unwrap().max_upload_bytes, 0);
    }

    /// Contradicting yourself is refused by the parser rather than resolved by
    /// argument order.
    #[test]
    fn an_exec_allowance_cannot_be_stated_both_ways() {
        use clap::Parser as _;

        assert!(
            Args::try_parse_from(["burrow", "config", "access", "sbx_1", "--no-exec"]).is_ok(),
            "one spelling alone must parse"
        );
        for contradiction in [
            ["--no-exec", "--allow-exec"],
            ["--no-upload", "--allow-upload"],
            ["--no-download", "--allow-download"],
        ] {
            assert!(
                Args::try_parse_from([
                    "burrow",
                    "config",
                    "access",
                    "sbx_1",
                    contradiction[0],
                    contradiction[1],
                ])
                .is_err(),
                "{contradiction:?} should be refused"
            );
        }
    }
}
