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
    #[arg(long, global = true, env = "BURROW_INSECURE")]
    insecure: bool,
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
        .map_err(|err| anyhow::anyhow!("--orchestrator {endpoint} is not a URL: {err}"))?;
    let mut builder = tonic::transport::Endpoint::from(uri.clone());

    if uri.scheme_str() == Some("https") {
        builder = builder.tls_config(
            tonic::transport::ClientTlsConfig::new()
                .with_native_roots()
                .with_enabled_roots(),
        )?;
    } else if !insecure && !is_loopback(uri.host().unwrap_or_default()) {
        anyhow::bail!(
            "refusing to send the api key in plaintext to {}: use https://, or pass \
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
        #[arg(long)]
        connect: bool,
    },
    /// List sandboxes.
    ///
    /// Running sandboxes only, as `docker ps` does. Everything the fleet holds,
    /// suspended and lost records included, needs --all.
    #[command(visible_aliases = ["list", "ls"])]
    Ps {
        /// Include sandboxes that are not running: stopped, suspended, failed
        /// and lost ones.
        #[arg(long, short = 'a')]
        all: bool,
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
        #[arg(long)]
        json: bool,
    },
    /// Show what sandboxes have consumed.
    Stats {
        /// Sandbox to report on. Omitted covers every sandbox.
        id: Option<String>,
        /// Include sandboxes that are not running.
        #[arg(long, short = 'a')]
        all: bool,
    },
    /// List templates.
    Images,
    /// Import an OCI image as a template, e.g. `python:3.12-slim`.
    Pull {
        /// Image reference: [registry/]repository[:tag|@digest].
        image: String,
        /// Template name. Defaults to the image's repository name.
        #[arg(long)]
        name: Option<String>,
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
        /// Id for the child; omitted has one generated.
        #[arg(long = "id")]
        child_id: Option<String>,
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
    /// The guest keeps the last 256 KiB of each command's output, so a chatty
    /// command replays its tail rather than everything it has said.
    Logs {
        id: String,
        /// Command to follow, from `burrow top`. Required: burrow's logs belong
        /// to a command, not to the sandbox as a whole.
        command_id: Option<String>,
    },
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
        #[arg(long, conflicts_with = "rm")]
        stop: bool,
        /// Delete the sandbox once the command exits.
        #[arg(long)]
        rm: bool,
        /// Start the command and return, printing the sandbox id. The command
        /// keeps running; follow it with `burrow logs`.
        #[arg(long, short = 'd', conflicts_with_all = ["stop", "rm"])]
        detach: bool,
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
    /// List the VMs a sandbox has run, newest first.
    Sessions { id: String },
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
        #[arg(long)]
        rotate: bool,
        /// Source connections from the gateway instead of from the client's
        /// own address, which is what the guest sees by default.
        #[arg(long)]
        no_transparent_ip: bool,
        /// Guest UDP port reachable through the share, or `all`. Repeatable;
        /// omitted shares no UDP.
        #[arg(long = "udp-port", value_delimiter = ',')]
        udp_ports: Vec<String>,
        /// Print the existing share without changing it.
        #[arg(long, conflicts_with_all = ["ports", "allowed_clients", "rotate", "udp_ports", "no_transparent_ip"])]
        show: bool,
    },
    /// Revoke a sandbox's share.
    Unshare { id: String },
    /// List a directory inside a sandbox.
    Dir { id: String, path: String },
    /// Template operations.
    #[command(subcommand)]
    Templates(TemplatesCommand),
    /// Snapshot operations.
    #[command(subcommand, visible_alias = "snapshots")]
    Snapshot(SnapshotCommand),
    /// Volume operations.
    #[command(subcommand, visible_alias = "volumes")]
    Volume(VolumeCommand),
    /// Show recorded egress attempts and DNS lookups.
    Audit {
        /// Restrict to one sandbox.
        #[arg(long)]
        sandbox: Option<String>,
        /// Only attempts the proxy refused.
        #[arg(long)]
        denied: bool,
        /// RFC 3339 lower bound, e.g. 2026-08-27T00:00:00Z.
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user with a private home directory.
    Create { id: String, name: String },
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
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print a sandbox's current configuration. Same output as `burrow
    /// inspect`.
    List {
        id: String,
        /// Emit the record as JSON instead of the readable field list.
        #[arg(long)]
        json: bool,
    },
    /// Replace a running sandbox's egress policy.
    NetworkPolicy {
        id: String,
        #[command(flatten)]
        network: NetworkFlags,
    },
    /// Move a running sandbox's lifetime clocks.
    ///
    /// The machine shape is not movable: a running VM's configuration is
    /// fixed, and a restore takes it from the snapshot.
    Lifetime {
        id: String,
        /// Destroy the sandbox this many seconds after it was created.
        /// 0 lets it live until something deletes it.
        secs: u64,
        /// Also replace the idle-suspend timeout.
        #[arg(long)]
        idle_suspend_secs: Option<u64>,
        /// Also replace how long a suspended sandbox is kept.
        #[arg(long)]
        suspended_ttl_secs: Option<u64>,
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
    /// Name for the sandbox, usable anywhere its id is. 1-63 characters of
    /// lowercase letters, digits and '-'. Unique across the fleet, and fixed
    /// once the sandbox exists.
    #[arg(long)]
    name: Option<String>,
    /// Template to boot, as imported by `burrow pull`. Required unless
    /// `--snapshot` is given, which carries its own.
    #[arg(long)]
    template: Option<String>,
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
    #[arg(long)]
    keep_evicted_snapshots: bool,
    /// Mount a volume, as `name:/path` or `name:/path:ro`. Repeatable.
    /// A sandbox that mounts a volume is placed on the node holding it, and
    /// boots cold rather than restoring a warm snapshot.
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
    fn stated(&self) -> bool {
        self.template.is_some()
            || self.snapshot.is_some()
            || self.vcpus.is_some()
            || self.mem_mib.is_some()
            || self.max_lifetime_secs != 0
            || self.idle_suspend_secs != 0
            || self.suspended_ttl_secs != 0
            || self.snapshot_expiration_secs != 0
            || self.keep_last_snapshots != 0
            || self.keep_evicted_snapshots
            || !self.mounts.is_empty()
            || !self.tags.is_empty()
            || !self.node_labels.is_empty()
            || !self.networks.is_empty()
            || self.alias.is_some()
            || self.network.stated()
            || self.access.stated()
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
    #[arg(long)]
    no_exec: bool,
    /// Refuse uploads into this sandbox.
    #[arg(long)]
    no_upload: bool,
    /// Refuse downloads out of this sandbox.
    #[arg(long)]
    no_download: bool,
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
    fn stated(&self) -> bool {
        self.no_exec
            || self.no_upload
            || self.no_download
            || !self.fs_scopes.is_empty()
            || self.max_upload_bytes != 0
    }

    /// The exec section, set only when the caller restricted exec.
    ///
    /// An absent section means "allowed" to the node, so sending one that says
    /// exactly that would be noise in every record.
    fn exec_policy(&self) -> Option<common::ExecPolicy> {
        self.no_exec
            .then_some(common::ExecPolicy { allow_exec: false })
    }

    /// The fs section, set only when the caller restricted file access. One
    /// fs flag settles all four fields, since the message is enforced whole.
    fn fs_policy(&self) -> Option<common::FsPolicy> {
        let stated = self.no_upload
            || self.no_download
            || !self.fs_scopes.is_empty()
            || self.max_upload_bytes != 0;
        stated.then(|| common::FsPolicy {
            allow_upload: !self.no_upload,
            allow_download: !self.no_download,
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
    #[arg(long, conflicts_with = "allow_exec")]
    no_exec: bool,
    /// Allow them again.
    #[arg(long)]
    allow_exec: bool,
    /// Refuse uploads into this sandbox.
    #[arg(long, conflicts_with = "allow_upload")]
    no_upload: bool,
    /// Allow uploads again.
    #[arg(long)]
    allow_upload: bool,
    /// Refuse downloads out of this sandbox.
    #[arg(long, conflicts_with = "allow_download")]
    no_download: bool,
    /// Allow downloads again.
    #[arg(long)]
    allow_download: bool,
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
        (self.no_exec || self.allow_exec).then_some(common::ExecPolicy {
            allow_exec: !self.no_exec,
        })
    }

    /// The fs section, sent only when the caller said something about files.
    /// One fs flag settles all four fields, because the node replaces the
    /// section whole.
    fn fs_policy(&self) -> Option<common::FsPolicy> {
        let stated = self.no_upload
            || self.allow_upload
            || self.no_download
            || self.allow_download
            || !self.fs_scopes.is_empty()
            || self.max_upload_bytes.is_some();
        stated.then(|| common::FsPolicy {
            allow_upload: !self.no_upload,
            allow_download: !self.no_download,
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
    pty: bool,
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
    /// Terminate this sandbox's TLS so the host named inside the session
    /// is checked, not just the SNI. Closes domain fronting, at the cost
    /// of the proxy being able to read the payload.
    #[arg(long)]
    inspect_tls: bool,
    /// Credential the host adds to requests for a domain, as
    /// 'domain:Name=Value'. Requires --inspect-tls; the value never enters the
    /// guest. Repeatable.
    #[arg(long = "inject-header")]
    inject_headers: Vec<String>,
    /// Rule for inspected requests, as a JSON object: a domain, an optional
    /// match, and either setHeaders or forward. Evaluated in order, and
    /// before every --inject-header. Requires --inspect-tls. Repeatable.
    ///
    /// {"domain":"api.example.com","match":{"path":{"startsWith":"/v1/"},
    /// "method":["GET"]},"setHeaders":{"Authorization":"Bearer t"}}
    #[arg(long = "rule")]
    rules: Vec<String>,
}

impl NetworkFlags {
    /// Whether the caller named any egress flag at all.
    ///
    /// `--net` defaults to `none`, which is a real instruction on `create` and
    /// would be a silent lockdown on `fork`: a child given nothing should
    /// inherit its source's policy, not lose it.
    fn stated(&self) -> bool {
        self.net != "none"
            || self.inspect_tls
            || !self.allow_domains.is_empty()
            || !self.allow_cidrs.is_empty()
            || !self.allow_ports.is_empty()
            || !self.deny_cidrs.is_empty()
            || !self.inject_headers.is_empty()
            || !self.rules.is_empty()
    }
}

/// Parses repeated `--mount name:/path[:ro|rw]` flags.
///
/// The mode is last so the common case reads as `name:/path`, and a path may
/// itself contain colons: the volume name is taken up to the first colon, and
/// a trailing `:ro` or `:rw` off the end.
fn parse_mounts(mounts: &[String]) -> anyhow::Result<Vec<common::VolumeMount>> {
    let mut out = Vec::new();
    for raw in mounts {
        let (volume, rest) = raw.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("--mount {raw:?} must be name:/path, optionally with :ro or :rw")
        })?;
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
            read_only,
        });
    }
    Ok(out)
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
    /// List templates.
    Ls,
    /// Import an OCI image as a template, e.g. `python:3.12-slim`.
    Import {
        /// Image reference: [registry/]repository[:tag|@digest].
        image: String,
        /// Template name. Defaults to the image's repository name.
        #[arg(long)]
        name: Option<String>,
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
enum NodesCommand {
    /// List registered nodes.
    Ls,
    /// Stop placing new sandboxes on a node.
    Drain {
        node_id: String,
        /// Also snapshot the sandboxes it is running.
        #[arg(long)]
        suspend: bool,
    },
    /// Resume placing sandboxes on a node.
    Undrain { node_id: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let api_key = load_api_key(args.api_key.as_deref(), args.api_key_file.as_deref())?;
    let channel = connect(&args.orchestrator, args.insecure).await?;
    let mut client = BurrowClient::with_interceptor(channel, BearerAuth(api_key));

    match args.command {
        Command::Health => {
            let resp = client.health(api::HealthRequest {}).await?.into_inner();
            println!("ok (orchestrator v{})", resp.version);
        }
        Command::Nodes(NodesCommand::Ls) => list_nodes(&mut client).await?,
        Command::Nodes(NodesCommand::Drain { node_id, suspend }) => {
            let resp = client
                .drain_node(api::DrainNodeRequest {
                    node_id: node_id.clone(),
                    drain: true,
                    suspend_sandboxes: suspend,
                })
                .await?
                .into_inner();
            println!("draining {node_id} ({} suspended)", resp.suspended);
        }
        Command::Nodes(NodesCommand::Undrain { node_id }) => {
            client
                .drain_node(api::DrainNodeRequest {
                    node_id: node_id.clone(),
                    drain: false,
                    suspend_sandboxes: false,
                })
                .await?;
            println!("{node_id} accepting sandboxes again");
        }
        Command::Create { create, connect } => {
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
                let code = connect_shell(&mut client, &sandbox.id, None, Vec::new()).await?;
                if code != 0 {
                    std::process::exit(exit_status(code));
                }
            }
        }
        Command::Ps { all, tag } => {
            list_sandboxes(&mut client, tag.unwrap_or_default(), all).await?
        }
        Command::Top { id } => list_commands(&mut client, &id).await?,
        Command::Inspect { id, json } => {
            let sandbox = client
                .get_sandbox(api::SandboxRef { id })
                .await?
                .into_inner();
            if json {
                println!("{}", sandbox_json(&sandbox));
            } else {
                print_config(&sandbox);
            }
        }
        Command::Stats { id, all } => show_stats(&mut client, id, all).await?,
        Command::Images => list_templates(&mut client).await?,
        Command::Pull { image, name } => import_template(&mut client, image, name).await?,
        Command::Commit {
            sandbox,
            expiration_secs,
        } => create_snapshot(&mut client, sandbox, expiration_secs).await?,
        Command::Fork {
            id,
            child_id,
            name,
            network,
            access,
            node_labels,
        } => {
            // Only an override the caller actually asked for: an unset flag
            // group means "inherit", not "no egress" and not "no access".
            let egress = network
                .stated()
                .then(|| network_policy(network))
                .transpose()?;
            let policy = (egress.is_some() || access.stated()).then(|| common::Policy {
                network: egress,
                exec: access.exec_policy(),
                fs: access.fs_policy(),
                ..Default::default()
            });
            let started = std::time::Instant::now();
            let sandbox = client
                .fork_sandbox(api::ForkSandboxRequest {
                    r#ref: Some(api::SandboxRef { id }),
                    sandbox_id: child_id.unwrap_or_default(),
                    name: name.unwrap_or_default(),
                    policy,
                    node_labels: parse_pairs("--node-label", &node_labels)?,
                })
                .await?
                .into_inner();
            println!("{} in {}ms", sandbox.id, started.elapsed().as_millis());
        }
        Command::Exec { id, exec, cmd } => {
            let code = run_exec(&mut client, &id, &exec, cmd).await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
        }
        Command::Connect { id, user, cmd } => {
            let code = connect_shell(&mut client, &id, user, cmd).await?;
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
            let code = attach_command(&mut client, &id, &command_id).await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
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
        Command::Run {
            create,
            exec,
            stop,
            rm,
            detach,
            cmd,
        } => {
            let code = run_in_sandbox(&mut client, create, exec, stop, rm, detach, cmd).await?;
            if code != 0 {
                std::process::exit(exit_status(code));
            }
        }
        Command::Copy { src, dst } => copy(&mut client, &src, &dst).await?,
        Command::Stop { ids } => {
            let mut failed = false;
            for id in ids {
                match client
                    .pause_sandbox(api::SandboxRef { id: id.clone() })
                    .await
                {
                    Ok(resp) => {
                        let sandbox = resp.into_inner();
                        println!("{} {}", sandbox.id, state_name(sandbox.state));
                    }
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
        Command::Start { id } => {
            let started = std::time::Instant::now();
            let sandbox = client
                .resume_sandbox(api::SandboxRef { id })
                .await?
                .into_inner();
            println!(
                "{} {} in {}ms",
                sandbox.id,
                state_name(sandbox.state),
                started.elapsed().as_millis()
            );
        }
        Command::Sessions { id } => list_sessions(&mut client, id).await?,
        Command::Remove { ids } => {
            let mut failed = false;
            for id in ids {
                match client
                    .delete_sandbox(api::SandboxRef { id: id.clone() })
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
        Command::Config(ConfigCommand::List { id, json }) => {
            let sandbox = client
                .get_sandbox(api::SandboxRef { id })
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
                    r#ref: Some(api::SandboxRef { id }),
                    network: Some(network_policy(network)?),
                })
                .await?
                .into_inner();
            println!("{} network policy updated", sandbox.id);
        }
        Command::Config(ConfigCommand::Lifetime {
            id,
            secs,
            idle_suspend_secs,
            suspended_ttl_secs,
        }) => {
            let sandbox = client
                .update_resources(api::UpdateResourcesRequest {
                    r#ref: Some(api::SandboxRef { id }),
                    max_lifetime_secs: Some(secs),
                    idle_suspend_secs,
                    suspended_ttl_secs,
                    // Named here only so the server can refuse them; the CLI
                    // offers no way to ask.
                    vcpus: 0,
                    mem_mib: 0,
                    scratch_disk_mib: 0,
                })
                .await?
                .into_inner();
            let resources = sandbox
                .policy
                .unwrap_or_default()
                .resources
                .unwrap_or_default();
            println!(
                "{} max-lifetime {}",
                sandbox.id,
                match resources.max_lifetime_secs {
                    0 => "unlimited".to_string(),
                    secs => format!("{secs}s"),
                }
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
                    r#ref: Some(api::SandboxRef { id }),
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
                    Some(exec) if !exec.allow_exec => "denied",
                    _ => "allowed",
                },
                match &policy.fs {
                    Some(fs) if !fs.allow_upload => "denied",
                    _ => "allowed",
                },
                match &policy.fs {
                    Some(fs) if !fs.allow_download => "denied",
                    _ => "allowed",
                },
            );
        }
        Command::Config(ConfigCommand::Tags { id, tags }) => {
            let sandbox = client
                .update_tags(api::UpdateTagsRequest {
                    r#ref: Some(api::SandboxRef { id }),
                    tags: parse_pairs("--tag", &tags)?,
                })
                .await?
                .into_inner();
            println!("{} now has {} tags", sandbox.id, sandbox.metadata.len());
        }
        Command::Config(ConfigCommand::Ports { id, ports }) => {
            set_ports(&mut client, &id, &ports).await?
        }
        Command::Expose {
            id,
            guest_port,
            host_port,
        } => {
            let mapping = client
                .expose_port(api::ExposePortRequest {
                    sandbox_id: id,
                    guest_port,
                    host_port,
                })
                .await?
                .into_inner();
            print_port(&mapping);
        }
        Command::Port { id } => {
            let resp = client
                .list_ports(api::SandboxRef { id })
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
            rotate,
            udp_ports,
            no_transparent_ip,
            show,
        } => {
            let share = if show {
                client.get_share(api::SandboxRef { id }).await?.into_inner()
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
                        rotate,
                        udp_ports,
                        all_udp,
                        no_transparent_ip,
                    })
                    .await?
                    .into_inner()
            };
            print_share(&share);
        }
        Command::Unshare { id } => {
            client.unshare_sandbox(api::SandboxRef { id }).await?;
            println!("share revoked");
        }
        Command::Templates(TemplatesCommand::Ls) => list_templates(&mut client).await?,
        Command::Templates(TemplatesCommand::Import { image, name }) => {
            import_template(&mut client, image, name).await?
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
                })
                .await?
                .into_inner();
            println!(
                "{} ({}MiB) on {}",
                volume.name, volume.size_mib, volume.node_id
            );
        }
        Command::Volume(VolumeCommand::Ls { node }) => {
            let resp = client
                .list_volumes(api::ListVolumesRequest {
                    node_id: node.unwrap_or_default(),
                })
                .await?
                .into_inner();
            if resp.volumes.is_empty() {
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
                        volume.created_at,
                        if volume.attached_to.is_empty() {
                            "-"
                        } else {
                            &volume.attached_to
                        },
                    );
                }
            }
        }
        Command::Volume(VolumeCommand::Inspect { name }) => {
            let volume = client
                .get_volume(api::VolumeRef { name })
                .await?
                .into_inner();
            println!("name        {}", volume.name);
            println!("node        {}", volume.node_id);
            println!("size        {}MiB", volume.size_mib);
            println!("created     {}", volume.created_at);
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
                    sandbox: sandbox.unwrap_or_default(),
                })
                .await?
                .into_inner();
            if resp.snapshots.is_empty() {
                println!("no snapshots");
            } else {
                println!(
                    "{:<38} {:<24} {:<16} {:>8}  {:<21} EXPIRES",
                    "SNAPSHOT", "SANDBOX", "TEMPLATE", "SIZE", "CREATED"
                );
                for snapshot in resp.snapshots {
                    println!(
                        "{:<38} {:<24} {:<16} {:>7}M  {:<21} {}",
                        snapshot.id,
                        truncate(&snapshot.sandbox_id, 24),
                        truncate(&snapshot.template, 16),
                        snapshot.size_bytes / (1024 * 1024),
                        snapshot.created_at,
                        if snapshot.expires_at.is_empty() {
                            "never"
                        } else {
                            &snapshot.expires_at
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
        Command::Audit {
            sandbox,
            denied,
            since,
            limit,
        } => {
            let mut stream = client
                .query_audit(api::AuditQuery {
                    sandbox_id: sandbox.unwrap_or_default(),
                    denied_only: denied,
                    since: since.unwrap_or_default(),
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
                    sanitize(&event.at),
                    truncate(&sanitize(&event.sandbox_id), 24),
                    if event.allowed { "yes" } else { "no" },
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
            let resp = client
                .list_dir(api::ListDirRequest {
                    sandbox_id: id,
                    path,
                })
                .await?
                .into_inner();
            for entry in resp.entries {
                println!(
                    "{:>10}  {:o}  {}{}",
                    entry.size,
                    entry.mode & 0o7777,
                    sanitize(&entry.name),
                    if entry.is_dir { "/" } else { "" }
                );
            }
        }
    }
    Ok(())
}

/// Builds the create call from the shared flag group.
fn create_request(flags: CreateFlags) -> anyhow::Result<api::CreateSandboxRequest> {
    let CreateFlags {
        name,
        template,
        snapshot,
        vcpus,
        mem_mib,
        max_lifetime_secs,
        idle_suspend_secs,
        suspended_ttl_secs,
        snapshot_expiration_secs,
        keep_last_snapshots,
        keep_evicted_snapshots,
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
    let metadata = parse_pairs("--tag", &tags)?;
    // A snapshot carries its own template, so nothing is sent unless the
    // caller named one, in which case disagreeing with the snapshot is an
    // error the server raises rather than a default silently overriding it.
    let template = template.unwrap_or_default();
    Ok(api::CreateSandboxRequest {
        name: name.unwrap_or_default(),
        template,
        snapshot: snapshot.unwrap_or_default(),
        policy: Some(common::Policy {
            resources: Some(common::ResourcePolicy {
                // 0 means "the server's default", which is what lets a create
                // from a snapshot inherit the shape it was taken with.
                vcpus: vcpus.unwrap_or(0),
                mem_mib: mem_mib.unwrap_or(0),
                max_lifetime_secs,
                idle_suspend_secs,
                suspended_ttl_secs,
                snapshot_expiration_secs,
                keep_last_snapshots,
                keep_evicted_snapshots,
                ..Default::default()
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
                    allow_egress: true,
                    allow_ingress: true,
                    alias: alias.clone().unwrap_or_default(),
                })
                .collect(),
        }),
        metadata,
        node_labels: parse_pairs("--node-label", &node_labels)?,
    })
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
                .get_sandbox(api::SandboxRef { id: name.clone() })
                .await
            {
                Ok(existing) => {
                    let sandbox = existing.into_inner();
                    if create.stated() {
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
                                id: sandbox.id.clone(),
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
    if detach {
        let command_id = start_detached(client, &id, &exec, cmd).await?;
        eprintln!("command {command_id}");
        println!("{id}");
        return Ok(0);
    }

    // The sandbox `run` created is this function's to clean up, so --stop and
    // --rm happen whatever the exec did. An exec that failed is exactly the
    // case where a sandbox left behind holds capacity the caller cannot get
    // back without digging its id out of the error.
    let result = run_exec(client, &id, &exec, cmd).await;

    if stop {
        match client
            .pause_sandbox(api::SandboxRef { id: id.clone() })
            .await
        {
            Ok(_) => eprintln!("stopped {id}"),
            // Reported, not returned: losing the exec's own outcome to a
            // cleanup error would hide a command that did run.
            Err(err) => eprintln!("could not stop {id}: {}", err.message()),
        }
    } else if rm {
        match client
            .delete_sandbox(api::SandboxRef { id: id.clone() })
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
    client: &mut Client,
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
        pty: true,
        envs: Vec::new(),
        workdir: None,
        user,
    };
    run_exec(client, id, &flags, cmd).await
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
    // Inspection happens in the egress proxy, and only allowlist mode
    // redirects traffic there. Asking for it in any other mode gets a
    // sandbox that believes it is inspected and is not.
    if flags.inspect_tls && mode != common::NetworkMode::Allowlist {
        anyhow::bail!("--inspect-tls requires --net allowlist");
    }
    if !flags.inject_headers.is_empty() && !flags.inspect_tls {
        anyhow::bail!("--inject-header requires --inspect-tls");
    }
    if !flags.rules.is_empty() && !flags.inspect_tls {
        anyhow::bail!("--rule requires --inspect-tls");
    }
    // --allow-cidr is an L3 allowance: those destinations are reached
    // directly, never through the proxy, so nothing inspects them.
    if flags.inspect_tls && !flags.allow_cidrs.is_empty() {
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
        inspect_tls: flags.inspect_tls,
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
        if !matches!(key.as_str(), "domain" | "match" | "setHeaders" | "forward") {
            anyhow::bail!("--rule: unknown key {key:?}");
        }
    }

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
    })
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
        return (
            "inject-header",
            format!("{}:{}={}", rule.domain, header.name, header.value),
        );
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
    ("rule", text)
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
    match mapping.edge_url.as_str() {
        "" => println!("{} -> guest :{}", mapping.host_address, mapping.guest_port),
        url => println!(
            "{} -> guest :{} ({})",
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
    if share.all_udp {
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
    if share.transparent_ip {
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
    println!(
        "{:<38} {:<22} {:>5} {:>9} {:>9} {:>5} {:<9} {:<24} HOSTNAME",
        "NODE", "ADDRESS", "CPUS", "MEM_MIB", "FREE_MIB", "SBX", "STATE", "LABELS"
    );
    for node in resp.nodes {
        let info = node.info.unwrap_or_default();
        let status = node.status.unwrap_or_default();
        let state = if !node.healthy {
            "stale"
        } else if status.draining {
            "draining"
        } else {
            "ready"
        };
        println!(
            "{:<38} {:<22} {:>5} {:>9} {:>9} {:>5} {:<9} {:<24} {}",
            info.id,
            info.address,
            info.total_vcpus,
            info.total_mem_mib,
            status.free_mem_mib,
            status.running_sandboxes,
            state,
            truncate(&format_tags(&info.labels), 24),
            info.hostname,
        );
    }
    Ok(())
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
            sandbox.node_id,
            sandbox.template,
            truncate(&format_tags(&sandbox.metadata), 24),
            sandbox.created_at,
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
    !sandbox.unreachable
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
                .get_sandbox(api::SandboxRef { id })
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
    println!("{:<24} {:>10}  WARM", "TEMPLATE", "SIZE");
    for template in resp.templates {
        println!(
            "{:<24} {:>9}M  {}",
            template.name,
            template.size_bytes / (1024 * 1024),
            if template.warm { "yes" } else { "no" },
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
    image: String,
    name: Option<String>,
) -> anyhow::Result<()> {
    let name = name.unwrap_or_else(|| template_name_for(&image));
    let mut stream = client
        .build_template(api::BuildTemplateRequest {
            name: name.clone(),
            from_image: image.clone(),
            ..Default::default()
        })
        .await?
        .into_inner();
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

async fn create_snapshot(
    client: &mut Client,
    sandbox: String,
    expiration_secs: u64,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let snapshot = client
        .create_snapshot(api::CreateSnapshotRequest {
            r#ref: Some(api::SandboxRef { id: sandbox }),
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
        .list_sessions(api::SandboxRef { id })
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
            session.started_by,
            // An open session is the running VM, which is a state worth its
            // own word rather than a blank column.
            if session.ended_by.is_empty() {
                "open"
            } else {
                &session.ended_by
            },
            session.started_at,
            // Empty for a session the node died during: nothing recorded when
            // that VM actually stopped, and a guess would read as a fact.
            if session.ended_at.is_empty() {
                "-"
            } else {
                &session.ended_at
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
    field("node", &sandbox.node_id);
    if sandbox.unreachable {
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
    field("created", &sandbox.created_at);
    if !sandbox.guest_ip.is_empty() {
        field("address", &sandbox.guest_ip);
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
        if resources.max_lifetime_secs > 0 {
            field("max-lifetime", &format!("{}s", resources.max_lifetime_secs));
        }
        if resources.idle_suspend_secs > 0 {
            field("idle-suspend", &format!("{}s", resources.idle_suspend_secs));
        }
        if resources.suspended_ttl_secs > 0 {
            field(
                "suspended-ttl",
                &format!("{}s", resources.suspended_ttl_secs),
            );
        }
    }
    // Only shown when set. An absent section is no restriction, and a line
    // saying "exec allowed" on every unrestricted sandbox would bury the one
    // sandbox where it is not.
    if let Some(exec) = &policy.exec {
        field("exec", if exec.allow_exec { "allowed" } else { "denied" });
    }
    if let Some(fs) = &policy.fs {
        field("upload", if fs.allow_upload { "allowed" } else { "denied" });
        field(
            "download",
            if fs.allow_download {
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
    if network.inspect_tls {
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
    let tags = format_tags(&sandbox.metadata);
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
        .list_ports(api::SandboxRef { id: id.to_string() })
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
    if sandbox.unreachable {
        "lost"
    } else if sandbox.agent_unconfirmed && sandbox.state == common::SandboxState::Running as i32 {
        "starting"
    } else {
        state_name(sandbox.state)
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
        _ => "unknown",
    }
}

/// Streams one command's life: start, stdin, output, exit status.
///
/// With a pty and a terminal on stdin the local terminal goes raw, so keys
/// reach the guest program rather than the local line discipline, and the
/// window size is sent along and resent when it changes.
async fn run_exec(
    client: &mut Client,
    sandbox_id: &str,
    flags: &ExecFlags,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let env = parse_pairs("--env", &flags.envs)?;
    let interactive = flags.pty && std::io::stdin().is_terminal();
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
            pty: flags.pty,
            rows,
            cols,
            user: flags.user.clone().unwrap_or_default(),
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
        Some(tokio::spawn(forward_stdin(tx.clone(), flags.pty)))
    } else {
        tx.send(api::ExecInput {
            input: Some(api::exec_input::Input::StdinEof(true)),
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
            Some(api::exec_output::Output::CommandId(_)) | None => {}
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
    client: &mut Client,
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
            pty: flags.pty,
            rows: 24,
            cols: 80,
            user: flags.user.clone().unwrap_or_default(),
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
        let code = if command.state == "exited" {
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
            sanitize(&command.state),
            code,
            truncate(&sanitize(&command.cmd.join(" ")), 60)
        );
    }
    Ok(())
}

/// `logs`: what the guest still holds of a command, then the rest of it live.
async fn attach_command(client: &mut Client, id: &str, command_id: &str) -> anyhow::Result<i32> {
    let mut stream = client
        .attach_command(api::AttachCommandRequest {
            sandbox_id: id.to_string(),
            command_id: command_id.to_string(),
        })
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
            Some(api::exec_output::Output::CommandId(_)) | None => {}
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
        api::exec_input::Input::StdinEof(true)
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
async fn copy(client: &mut Client, src: &str, dst: &str) -> anyhow::Result<()> {
    match (parse_endpoint(src), parse_endpoint(dst)) {
        (Endpoint::Local(local), Endpoint::Sandbox { id, path }) => {
            let bytes = push(client, &id, std::path::Path::new(&local), &path).await?;
            println!("uploaded {bytes} bytes to {id}:{path}");
            Ok(())
        }
        (Endpoint::Sandbox { id, path }, Endpoint::Local(local)) => {
            // `-` is the usual spelling of "stdout" and cannot be a filename
            // anyone meant.
            let local = (local != "-").then(|| std::path::PathBuf::from(local));
            pull(client, &id, &path, local).await
        }
        (Endpoint::Sandbox { .. }, Endpoint::Sandbox { .. }) => {
            anyhow::bail!("copy moves a file between this machine and a sandbox, not between two")
        }
        (Endpoint::Local(_), Endpoint::Local(_)) => {
            anyhow::bail!("one side has to be a sandbox path, written as <id>:<path>")
        }
    }
}

async fn push(
    client: &mut Client,
    sandbox_id: &str,
    local: &std::path::Path,
    remote: &str,
) -> anyhow::Result<u64> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(local).await?;
    let mode = file
        .metadata()
        .await
        .map(|m| m.permissions().mode())
        .unwrap_or(0o644);

    // Chunked so a large file has to fit neither in one gRPC message nor in
    // memory. Matches the SDK and the guest: HTTP/2's default flow-control
    // window.
    const CHUNK: usize = 64 * 1024;

    // Shallow, so the reader stays roughly a chunk ahead of the wire rather
    // than racing to buffer the whole file behind a slow link.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let sandbox_id = sandbox_id.to_string();
    let remote = remote.to_string();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        let mut first = true;
        loop {
            let n = file.read(&mut buf).await?;
            // An empty file still sends one chunk: the first chunk is what
            // carries the path and the mode, so skipping it would upload
            // nothing at all.
            if n == 0 && !first {
                break;
            }
            let chunk = api::FileChunk {
                sandbox_id: if first {
                    sandbox_id.clone()
                } else {
                    String::new()
                },
                path: if first { remote.clone() } else { String::new() },
                mode: if first { mode } else { 0 },
                data: buf[..n].to_vec(),
            };
            first = false;
            // The receiver is gone when the RPC has already failed; its error
            // is the one worth reporting, so this one is dropped.
            if tx.send(chunk).await.is_err() || n == 0 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    });

    let result = client
        .upload_file(ReceiverStream::new(rx))
        .await?
        .into_inner();
    // A read that failed part way leaves a truncated file in the sandbox, and
    // the RPC would report that as a successful upload of fewer bytes.
    reader.await??;
    Ok(result.bytes_written)
}

async fn pull(
    client: &mut Client,
    sandbox_id: &str,
    remote: &str,
    local: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let mut stream = client
        .download_file(api::DownloadRequest {
            sandbox_id: sandbox_id.to_string(),
            path: remote.to_string(),
        })
        .await?
        .into_inner();

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
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        out.write_all(&chunk.data)?;
        total += chunk.data.len() as u64;
    }
    out.flush()?;
    if let Some(path) = local {
        println!("wrote {total} bytes to {}", path.display());
    }
    Ok(())
}

/// The smallest JSON document model that covers a sandbox record.
///
/// Hand-rolled because the CLI has no serializer and one record does not earn
/// a dependency. Nothing here is parsed back, so it only has to be correct on
/// the way out.
enum Json {
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    fn str(value: impl Into<String>) -> Json {
        Json::Str(value.into())
    }

    fn write(&self, out: &mut String, indent: usize) {
        let pad = |out: &mut String, depth: usize| out.push_str(&"  ".repeat(depth));
        match self {
            Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Json::Num(value) => out.push_str(&value.to_string()),
            Json::Str(value) => escape(value, out),
            Json::Arr(items) if items.is_empty() => out.push_str("[]"),
            Json::Arr(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, indent + 1);
                    item.write(out, indent + 1);
                    out.push_str(if i + 1 == items.len() { "\n" } else { ",\n" });
                }
                pad(out, indent);
                out.push(']');
            }
            Json::Obj(fields) if fields.is_empty() => out.push_str("{}"),
            Json::Obj(fields) => {
                out.push_str("{\n");
                for (i, (key, value)) in fields.iter().enumerate() {
                    pad(out, indent + 1);
                    escape(key, out);
                    out.push_str(": ");
                    value.write(out, indent + 1);
                    out.push_str(if i + 1 == fields.len() { "\n" } else { ",\n" });
                }
                pad(out, indent);
                out.push('}');
            }
        }
    }
}

/// A JSON string literal, quotes included.
///
/// Control characters are escaped by code point rather than dropped: a tag
/// value the guest chose must not be able to end the string early.
fn escape(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

/// One sandbox's record as JSON, for `inspect --json`.
///
/// The same fields the readable form prints, including the zeroes it shows and
/// the redacted header values the node sent.
fn sandbox_json(sandbox: &common::Sandbox) -> String {
    let policy = sandbox.policy.clone().unwrap_or_default();
    let resources = policy.resources.unwrap_or_default();
    let network = policy.network.unwrap_or_default();
    let strings = |values: &[String]| Json::Arr(values.iter().map(Json::str).collect());

    let mut tags: Vec<_> = sandbox.metadata.iter().collect();
    tags.sort();

    // Present only when the sandbox restricts something, exactly as the
    // readable form shows them: an absent section is no restriction, and
    // rendering a permissive one would make the two indistinguishable.
    let access: Vec<(&'static str, Json)> = policy
        .exec
        .iter()
        .map(|exec| {
            (
                "exec",
                Json::Obj(vec![("allow_exec", Json::Bool(exec.allow_exec))]),
            )
        })
        .chain(policy.fs.iter().map(|fs| {
            (
                "fs",
                Json::Obj(vec![
                    ("allow_upload", Json::Bool(fs.allow_upload)),
                    ("allow_download", Json::Bool(fs.allow_download)),
                    ("path_scopes", strings(&fs.path_scopes)),
                    ("max_upload_bytes", Json::Num(fs.max_upload_bytes)),
                ]),
            )
        }))
        .collect();

    let mut fields = vec![
        ("id", Json::str(&sandbox.id)),
        ("name", Json::str(&sandbox.name)),
        ("state", Json::str(display_state(sandbox))),
        ("unreachable", Json::Bool(sandbox.unreachable)),
        ("agent_unconfirmed", Json::Bool(sandbox.agent_unconfirmed)),
        ("node", Json::str(&sandbox.node_id)),
        ("template", Json::str(&sandbox.template)),
        ("created_at", Json::str(&sandbox.created_at)),
        ("address", Json::str(&sandbox.guest_ip)),
        (
            "usage",
            Json::Obj(vec![
                ("cpu_usage_usec", Json::Num(sandbox.cpu_usage_usec)),
                ("rx_bytes", Json::Num(sandbox.rx_bytes)),
                ("tx_bytes", Json::Num(sandbox.tx_bytes)),
            ]),
        ),
        (
            "resources",
            Json::Obj(vec![
                ("vcpus", Json::Num(resources.vcpus as u64)),
                ("mem_mib", Json::Num(resources.mem_mib as u64)),
                ("max_lifetime_secs", Json::Num(resources.max_lifetime_secs)),
                ("idle_suspend_secs", Json::Num(resources.idle_suspend_secs)),
                (
                    "suspended_ttl_secs",
                    Json::Num(resources.suspended_ttl_secs),
                ),
                (
                    "snapshot_expiration_secs",
                    Json::Num(resources.snapshot_expiration_secs),
                ),
                (
                    "keep_last_snapshots",
                    Json::Num(resources.keep_last_snapshots as u64),
                ),
                (
                    "keep_evicted_snapshots",
                    Json::Bool(resources.keep_evicted_snapshots),
                ),
            ]),
        ),
        (
            "network",
            Json::Obj(vec![
                (
                    "mode",
                    Json::str(match common::NetworkMode::try_from(network.mode) {
                        Ok(common::NetworkMode::Open) => "open",
                        Ok(common::NetworkMode::Allowlist) => "allowlist",
                        Ok(common::NetworkMode::None) => "none",
                        _ => "unspecified",
                    }),
                ),
                ("allow_domains", strings(&network.allow_domains)),
                ("allow_cidrs", strings(&network.allow_cidrs)),
                (
                    "allow_ports",
                    Json::Arr(
                        network
                            .allow_ports
                            .iter()
                            .map(|port| Json::Num(*port as u64))
                            .collect(),
                    ),
                ),
                ("deny_cidrs", strings(&network.deny_cidrs)),
                ("inspect_tls", Json::Bool(network.inspect_tls)),
                (
                    "rules",
                    Json::Arr(
                        network
                            .rules
                            .iter()
                            .map(|rule| {
                                let (kind, text) = describe_rule(rule);
                                Json::Obj(vec![
                                    ("domain", Json::str(&rule.domain)),
                                    ("kind", Json::str(kind)),
                                    ("rule", Json::str(&text)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
        ),
        (
            "networks",
            Json::Arr(
                policy
                    .networks
                    .iter()
                    .map(|membership| {
                        Json::Obj(vec![
                            ("network", Json::str(&membership.network)),
                            (
                                "alias",
                                Json::str(if membership.alias.is_empty() {
                                    &sandbox.id
                                } else {
                                    &membership.alias
                                }),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "tags",
            Json::Arr(
                tags.into_iter()
                    .map(|(key, value)| {
                        Json::Obj(vec![("key", Json::str(key)), ("value", Json::str(value))])
                    })
                    .collect(),
            ),
        ),
    ];
    fields.extend(access);
    let doc = Json::Obj(fields);
    let mut out = String::new();
    doc.write(&mut out, 0);
    out
}

#[cfg(test)]
mod tests {
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
        assert!(!parsed[0].read_only, "read-write is the default");
        assert!(parsed[1].read_only);
        assert_eq!(parsed[1].path, "/ro");
        assert!(!parsed[2].read_only);

        // A colon that is part of the path is not a mode.
        let odd = super::parse_mounts(&["v:/data/a:b".into()]).unwrap();
        assert_eq!(odd[0].path, "/data/a:b");
        assert!(!odd[0].read_only);

        for bad in ["cache", "", ":/data", "cache:"] {
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
                    all: false,
                    tag: None
                }
            ));
        }
        assert!(matches!(
            parse(&["burrow", "ps", "-a"]).command,
            Command::Ps { all: true, .. }
        ));
        assert!(matches!(
            parse(&["burrow", "ps", "--all", "--tag", "env=ci"]).command,
            Command::Ps {
                all: true,
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
            Command::Run { detach: true, .. }
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
            unreachable,
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
    fn json_strings_survive_what_a_tag_may_contain() {
        let mut out = String::new();
        escape("a\"b\\c\nd\te\u{1}", &mut out);
        assert_eq!(out, r#""a\"b\\c\nd\te\u0001""#);
    }

    #[test]
    fn a_record_renders_as_json() {
        let sandbox = common::Sandbox {
            id: "sbx_1".into(),
            name: "api".into(),
            state: common::SandboxState::Running as i32,
            cpu_usage_usec: 1500,
            metadata: [("env".to_string(), "ci\"1".to_string())]
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
            inspect_tls,
            inject_headers: inject.iter().map(|s| (*s).to_string()).collect(),
            rules: vec![],
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
    fn brokering_needs_an_inspected_allowlist() {
        let policy = network_policy(flags(
            "allowlist",
            true,
            &["api.example.com:Authorization=Bearer t"],
        ))
        .unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.deny_cidrs, vec!["10.0.0.0/8".to_string()]);

        assert!(network_policy(flags("allowlist", false, &["a.example:X=1"])).is_err());
        assert!(network_policy(flags("open", true, &[])).is_err());
    }

    /// `--net` defaults to `none`, so "no flags" and "deny everything" look
    /// identical unless something distinguishes them. On `fork` the difference
    /// is between inheriting the source's egress and silently removing it.
    #[test]
    fn an_untouched_flag_group_is_not_an_override() {
        let mut untouched = flags("none", false, &[]);
        untouched.deny_cidrs.clear();
        assert!(!untouched.stated());

        assert!(flags("open", false, &[]).stated());
        assert!(flags("none", false, &[]).stated(), "a deny_cidr was named");

        let mut domains = flags("none", false, &[]);
        domains.deny_cidrs.clear();
        domains.allow_domains.push("pypi.org".into());
        assert!(domains.stated());
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
                snapshot: None,
                vcpus: None,
                mem_mib: None,
                snapshot_expiration_secs: 0,
                keep_last_snapshots: 0,
                keep_evicted_snapshots: false,
                mounts: vec![],
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
                    inspect_tls: false,
                    inject_headers: vec![],
                    rules: vec![],
                },
                access: AccessFlags {
                    no_exec: false,
                    no_upload: false,
                    no_download: false,
                    fs_scopes: vec![],
                    max_upload_bytes: 0,
                },
                networks: vec![],
                alias: None,
                node_labels: vec![],
            }
        }
        assert!(!base().stated());

        // The name is what `run` matched on, not a configuration that went
        // unapplied, so naming a sandbox is not on its own a create.
        let mut named = base();
        named.name = Some("builder".into());
        assert!(!named.stated());

        // A publish is applied after the fact, so it is not a create flag that
        // went unapplied either.
        let mut published = base();
        published.publish.push(8080);
        assert!(!published.stated());

        let mut template = base();
        template.template = Some("python".into());
        assert!(template.stated());

        let mut tagged = base();
        tagged.tags.push("env=ci".into());
        assert!(tagged.stated());

        let mut networked = base();
        networked.network.net = "open".into();
        assert!(networked.stated());

        let mut confined = base();
        confined.access.fs_scopes.push("/work".into());
        assert!(confined.stated());

        // A placement constraint is a configuration: `run --name` landing on an
        // existing sandbox somewhere else cannot honour it.
        let mut placed = base();
        placed.node_labels.push("rack=b7".into());
        assert!(placed.stated());
    }

    /// Absent means allowed on the wire, so a create that restricted nothing
    /// must leave both sections unset rather than sending a permissive one.
    #[test]
    fn access_sections_are_sent_only_when_something_was_restricted() {
        let open = AccessFlags {
            no_exec: false,
            no_upload: false,
            no_download: false,
            fs_scopes: vec![],
            max_upload_bytes: 0,
        };
        assert!(open.exec_policy().is_none());
        assert!(open.fs_policy().is_none());

        let scoped = AccessFlags {
            no_exec: true,
            no_download: true,
            fs_scopes: vec!["/work".into()],
            max_upload_bytes: 4096,
            ..open
        };
        assert!(!scoped.exec_policy().unwrap().allow_exec);
        let fs = scoped.fs_policy().unwrap();
        assert!(fs.allow_upload);
        assert!(!fs.allow_download);
        assert_eq!(fs.path_scopes, vec!["/work".to_string()]);
        assert_eq!(fs.max_upload_bytes, 4096);

        // An exec restriction on its own leaves the fs section absent.
        let no_exec = AccessFlags {
            no_exec: true,
            no_upload: false,
            no_download: false,
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
                no_exec: false,
                allow_exec: false,
                no_upload: false,
                allow_upload: false,
                no_download: false,
                allow_download: false,
                fs_scopes: vec![],
                max_upload_bytes: None,
            }
        }
        assert!(quiet().exec_policy().is_none());
        assert!(quiet().fs_policy().is_none());

        // Tightening files says nothing about exec, which is the case the
        // node must not read as "allow everything".
        let files = AccessUpdateFlags {
            no_upload: true,
            fs_scopes: vec!["/work".into()],
            ..quiet()
        };
        assert!(files.exec_policy().is_none());
        let fs = files.fs_policy().unwrap();
        assert!(!fs.allow_upload);
        assert!(fs.allow_download);
        assert_eq!(fs.path_scopes, vec!["/work".to_string()]);

        // Both spellings of an exec allowance produce a section; they differ
        // only in what it says.
        let denied = AccessUpdateFlags {
            no_exec: true,
            ..quiet()
        };
        assert!(!denied.exec_policy().unwrap().allow_exec);
        let allowed = AccessUpdateFlags {
            allow_exec: true,
            ..quiet()
        };
        assert!(allowed.exec_policy().unwrap().allow_exec);
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
