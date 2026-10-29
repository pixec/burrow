use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Args;
use tonic::transport::Server;

use burrow_proto::common::v1::{NodeInfo, NodeStatus};
use burrow_proto::node::v1 as nodepb;
use burrow_proto::node::v1::node_registry_client::NodeRegistryClient;
use burrow_proto::node::v1::node_service_server::NodeServiceServer;

use crate::nodeapi::NodeApi;
use crate::sandbox::{NodeConfig, SandboxManager};

#[derive(Args, Clone)]
pub struct ServeArgs {
    /// Orchestrator gRPC endpoint.
    #[arg(
        long,
        default_value = "http://127.0.0.1:7070",
        env = "BURROW_ORCHESTRATOR"
    )]
    pub orchestrator: String,
    /// Address to serve the node gRPC API on.
    #[arg(long, default_value = "127.0.0.1:7071", env = "BURROWD_LISTEN")]
    pub listen: std::net::SocketAddr,
    /// Address the orchestrator should dial us at; defaults to --listen.
    #[arg(long, env = "BURROWD_ADVERTISE")]
    pub advertise: Option<String>,
    /// Stable node id; keep this fixed per machine so re-registration
    /// preserves identity. Empty = orchestrator assigns one.
    #[arg(long, default_value = "", env = "BURROWD_NODE_ID")]
    pub node_id: String,
    /// Root of node state: images/, sandboxes/.
    #[arg(long, default_value = "/var/lib/burrow", env = "BURROW_DATA_DIR")]
    pub data_dir: PathBuf,
    #[arg(long, default_value = "/usr/local/bin/firecracker")]
    pub firecracker: PathBuf,
    /// Hypervisors this node offers, comma-separated: `firecracker`,
    /// `cloud-hypervisor`. A template records one when it is built, and its
    /// sandboxes are only placed on nodes offering it. One whose binary is
    /// missing is left out of what the node advertises, with a warning.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "firecracker",
        env = "BURROWD_HYPERVISORS"
    )]
    pub hypervisors: Vec<burrow_vmm::Hypervisor>,
    #[arg(long, default_value = "/usr/local/bin/cloud-hypervisor")]
    pub cloud_hypervisor: PathBuf,
    /// Kernel Cloud Hypervisor boots instead of each template's own, for
    /// templates whose kernel lacks virtio-pci. Unset boots the template's.
    #[arg(long)]
    pub cloud_hypervisor_kernel: Option<PathBuf>,
    /// Run Cloud Hypervisor unconfined even with `--jailer`: as root, in the
    /// host's namespaces, with the host's filesystem in view. For a dev box
    /// whose kernel cannot build the jail; nowhere a guest is untrusted.
    #[arg(
        long = "unjailed-cloud-hypervisor",
        env = "BURROWD_UNJAILED_CLOUD_HYPERVISOR"
    )]
    pub is_cloud_hypervisor_unjailed: bool,
    /// Bucket snapshots are copied to so they outlive this node, as
    /// `s3://bucket[/prefix]`. Credentials come from AWS_ACCESS_KEY_ID and
    /// AWS_SECRET_ACCESS_KEY. Unset keeps snapshots node-local.
    #[arg(long, env = "BURROW_OBJECT_STORE")]
    pub object_store: Option<String>,
    /// The store's S3 endpoint, e.g. `https://s3.eu-west-1.amazonaws.com` or
    /// a self-hosted one. Required with --object-store.
    #[arg(long, env = "BURROW_OBJECT_STORE_ENDPOINT")]
    pub object_store_endpoint: Option<String>,
    /// Region the endpoint signs for. Self-hosted stores accept anything.
    #[arg(long, default_value = "us-east-1", env = "BURROW_OBJECT_STORE_REGION")]
    pub object_store_region: String,
    /// A 32-byte key every node shares, sealing the brokered credentials a
    /// suspended sandbox carries into the object store. Without it a sandbox
    /// holding any stays on its node. Never generated: a key each node made
    /// for itself would seal what no other node can open.
    #[arg(long, env = "BURROW_OBJECT_STORE_KEY_FILE")]
    pub object_store_key_file: Option<PathBuf>,
    /// Use an object store that ignores conditional writes (`If-Match`,
    /// `If-None-Match`). A node takes a stored sandbox by a conditional write
    /// on its manifest, so on such a store two nodes adopting one sandbox at
    /// once can both run it. Without this flag a node refuses to start on one.
    #[arg(
        long = "allow-unconditional-object-store",
        env = "BURROW_ALLOW_UNCONDITIONAL_OBJECT_STORE"
    )]
    pub is_unconditional_object_store_allowed: bool,
    /// Appended to every guest kernel command line.
    #[arg(
        long,
        default_value = "quiet loglevel=0",
        env = "BURROW_GUEST_BOOT_ARGS"
    )]
    pub guest_boot_args: String,
    /// Seconds to wait for a new sandbox's agent to become reachable.
    #[arg(long, default_value_t = 30)]
    pub agent_timeout: u64,
    /// Default size a command's output log rotates at, as Docker's
    /// `max-size`; unset keeps every byte. An exec may ask for its own.
    #[arg(long, value_parser = burrow_common::cmdlog::parse_size, env = "BURROW_COMMAND_LOG_MAX_SIZE")]
    pub command_log_max_size: Option<u64>,
    /// Log files kept once rotating, as Docker's `max-file`.
    #[arg(
        long,
        default_value_t = 1,
        requires = "command_log_max_size",
        env = "BURROW_COMMAND_LOG_MAX_FILES"
    )]
    pub command_log_max_files: u32,
    /// Where the node's resolver listens. Must cover every sandbox's gateway
    /// address, which is why it binds all interfaces.
    #[arg(long, default_value = "0.0.0.0:53")]
    pub dns_listen: std::net::SocketAddr,
    /// Where guest lookups are forwarded.
    #[arg(long, default_value = "1.1.1.1:53")]
    pub dns_upstream: std::net::SocketAddr,
    /// Address the transparent egress proxy listens on. Must match the port
    /// the firewall redirects allowlist-mode traffic to.
    #[arg(long, default_value = "0.0.0.0:3128")]
    pub proxy_listen: std::net::SocketAddr,
    /// cgroup2 mount point used to cap sandbox CPU and memory.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup_root: PathBuf,
    /// Address other nodes dial for the WireGuard mesh, e.g. `node-b:51820`.
    /// Without it this node still runs, but its sandboxes are only reachable
    /// by sandboxes on the same node.
    #[arg(long, env = "BURROW_MESH_ENDPOINT")]
    pub mesh_endpoint: Option<String>,
    /// Port the mesh listens on.
    #[arg(long, default_value_t = burrow_net::mesh::DEFAULT_PORT)]
    pub mesh_port: u16,
    /// Days of egress audit to keep. 0 disables pruning, which lets audit
    /// rows grow without bound.
    #[arg(long, default_value_t = 7)]
    pub audit_retention_days: u32,
    /// Days a cached build layer and an unreferenced content-addressed blob
    /// are kept. 0 disables collection, which lets `blobs/` and `layers/` grow
    /// for the life of the node.
    #[arg(long, default_value_t = 7)]
    pub artifact_retention_days: u32,
    /// Fallback for --node-token, kept so a single-binary dev setup can hand
    /// one token to everything. A node has no client-facing surface of its
    /// own, so using the tenant api key here lets a leaked tenant key drive
    /// this node directly; the node warns at startup when it falls back.
    #[arg(long, env = "BURROW_API_KEY")]
    pub api_key: Option<String>,
    #[arg(long, env = "BURROW_API_KEY_FILE")]
    pub api_key_file: Option<PathBuf>,
    /// The node-facing secret, matching the orchestrator's --node-token.
    ///
    /// Used in both directions: this node requires it on incoming calls (from
    /// the orchestrator and from peer nodes) and presents it when registering
    /// and when dialling a peer. Keeping it distinct from --api-key is what
    /// stops a tenant key registering a node or calling one.
    #[arg(long, env = "BURROW_NODE_TOKEN")]
    pub node_token: Option<String>,
    #[arg(long, env = "BURROW_NODE_TOKEN_FILE")]
    pub node_token_file: Option<PathBuf>,
    /// Refuse to start a sandbox whose resource limits cannot be applied.
    /// Off by default so the stack runs where cgroups are unavailable; worth
    /// turning on wherever sandboxes share a host with anything that matters.
    #[arg(long = "require-resource-limits")]
    pub is_resource_limits_required: bool,
    /// Serve restored guest memory from burrow's own page-fault handler.
    ///
    /// Off by default: firecracker's `File` backend already maps the snapshot
    /// demand-paged and shares one page cache across sandboxes restored from
    /// the same warm template, so this wins no density and costs a little, each
    /// served page becoming a private copy even when only read. Six sandboxes
    /// touching 768 MiB cost 857-876 MiB with it and 792-860 MiB without.
    ///
    /// Kept wired up because it is the only way to serve pages from something
    /// that is not a local file: a lazily fetched remote chunk, or a prefetch
    /// plan.
    #[arg(long = "lazy-memory", default_value_t = false, action = clap::ArgAction::Set)]
    pub is_memory_lazy: bool,
    /// OTLP collector to export traces and sandbox metrics to, e.g.
    /// `http://collector:4317`. Unset leaves tracing local to this node's logs.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,
    /// What lifecycle calls do while the orchestrator cannot acknowledge this
    /// node's events. Either way the events queue in the node's store and are
    /// delivered in order once it answers; `proceed` lets calls return
    /// meanwhile, `fail` refuses them.
    #[arg(long, value_enum, default_value_t = crate::delivery::Policy::Proceed, env = "BURROW_EVENT_DELIVERY")]
    pub event_delivery: crate::delivery::Policy,
    /// Run each firecracker under the jailer, chrooted into its own sandbox
    /// directory and dropped to `--jail-uid`. Turns on Cloud Hypervisor's
    /// confinement too, which burrowd builds itself, to the same uid.
    ///
    /// Off by default only because it needs a uid to drop to and a writable
    /// chroot base; it is what should be on wherever sandboxes share a host
    /// with anything that matters.
    #[arg(long)]
    pub jailer: Option<PathBuf>,
    /// Unprivileged uid both VMMs run as under `--jailer`.
    #[arg(long, default_value_t = 65534)]
    pub jail_uid: u32,
    #[arg(long, default_value_t = 65534)]
    pub jail_gid: u32,
    /// Base directory the jailer builds chroots under.
    #[arg(long, default_value = "/var/lib/burrow/jail")]
    pub chroot_base: PathBuf,
    /// Docker-format credentials file for registries that need authentication.
    ///
    /// The same shape as `~/.docker/config.json`, so an existing one can be
    /// used as is rather than maintaining a second copy of the same secrets.
    #[arg(long, default_value = "/etc/burrow/registry-auth.json")]
    pub registry_auth: PathBuf,
    /// Registry host that may be reached over plain HTTP, e.g.
    /// `registry.internal:5000`. Repeatable.
    ///
    /// Opt-in per host rather than a global switch: downgrading a pull means
    /// image bytes and registry credentials crossing the network in the clear,
    /// which should be a decision about one registry, not all of them.
    #[arg(long = "insecure-registry")]
    pub insecure_registry: Vec<String>,
    /// Guest agent binary to install into images imported from OCI.
    ///
    /// An OCI image has no init of its own, and a microVM booted without one
    /// panics, so the agent is copied in as part of the conversion.
    #[arg(long, default_value = "/usr/local/bin/burrow-guest")]
    pub guest_binary: PathBuf,
    /// Kernel every guest boots.
    ///
    /// An OCI image carries a userland and no kernel, so the node supplies
    /// one and links it into each template it builds. Defaults to `vmlinux`
    /// under the data directory, which is where the quickstart puts it.
    #[arg(long)]
    pub guest_kernel: Option<PathBuf>,
    /// File of `<node-id> <wireguard-public-key>` lines that this node treats
    /// as authoritative, overriding anything the orchestrator reports.
    ///
    /// Keys are otherwise pinned on first sight, which closes silent
    /// substitution after first contact but takes that first key on faith.
    #[arg(long, default_value = "/etc/burrow/mesh-pins")]
    pub mesh_pins: PathBuf,
    /// Where this node accepts sandbox traffic forwarded with the cluster
    /// token's prelude. This node's own edge splices into a guest directly and
    /// does not go through it.
    ///
    /// Separate from the API port because it carries tenant traffic rather
    /// than control calls, and guests are firewalled off it either way.
    #[arg(long, default_value = "0.0.0.0:7072")]
    pub sandbox_proxy_listen: std::net::SocketAddr,
    /// Address a forwarder should use to reach the above. Defaults to the
    /// advertised API host with the sandbox-proxy port substituted.
    #[arg(long)]
    pub advertise_sandbox_proxy: Option<String>,
    /// Serve an edge router on this node, so published ports on sandboxes
    /// *here* are reachable at `<port>-<sandbox-id>.<edge-domain>`. Unset
    /// disables it, which is the default, and a node without one has no
    /// hostname routing at all: a published port on it is reachable only at
    /// the node address the caller is handed.
    ///
    /// Sandboxes never move between nodes, so a hostname served here stays
    /// correct for a sandbox's whole life.
    #[arg(long, env = "BURROWD_EDGE_LISTEN")]
    pub edge_listen: Option<std::net::SocketAddr>,
    /// Domain this node's edge serves under, e.g. `node-a.sandbox.example.com`.
    ///
    /// Must be a name only this node answers for: the router serves the
    /// sandboxes this node holds and 404s everything else, so the wildcard
    /// record has to point at this node.
    #[arg(long, default_value = "", env = "BURROWD_EDGE_DOMAIN")]
    pub edge_domain: String,
    /// Address or CIDR of a reverse proxy in front of this node's edge,
    /// repeatable.
    ///
    /// A connection from one of these keeps its `X-Forwarded-For` and has the
    /// edge's own hop appended, because the peer is the proxy rather than the
    /// client. Anything else has its forwarding headers replaced outright.
    ///
    /// Only set it when the edge is reachable through that proxy and nothing
    /// else: a client that can also reach the edge directly from a trusted
    /// address can put whatever it likes in the header a guest then believes.
    #[arg(long = "edge-trusted-proxy", value_name = "CIDR")]
    pub edge_trusted_proxy: Vec<String>,
    /// Where the Access service listens: exec, attach and files for this
    /// node's sandboxes, called by clients directly with a token from the
    /// orchestrator's IssueAccess. It is the only way that traffic reaches a
    /// sandbox, so clients have to be able to reach it.
    #[arg(long, default_value = "0.0.0.0:7073", env = "BURROWD_ACCESS_LISTEN")]
    pub access_listen: std::net::SocketAddr,
    /// URL clients reach --access-listen at, scheme included, e.g.
    /// `https://node-a.example.com:7073`. Handed out with every token for
    /// this node. Defaults to --advertise's host on --access-listen's port,
    /// over https when a certificate is given and plain http otherwise.
    #[arg(long, env = "BURROWD_ACCESS_ADVERTISE")]
    pub access_advertise: Option<String>,
    /// Certificate chain, PEM, the Access service presents. With
    /// --access-tls-key. Without both it is plaintext, which is for a test
    /// harness only: the tokens it carries are bearer credentials.
    #[arg(long, env = "BURROWD_ACCESS_TLS_CERT")]
    pub access_tls_cert: Option<PathBuf>,
    #[arg(long, env = "BURROWD_ACCESS_TLS_KEY")]
    pub access_tls_key: Option<PathBuf>,
    /// Fact about this node, as key=value, e.g. `--label rack=b7`. Repeatable,
    /// and comma-separated in BURROW_NODE_LABELS.
    ///
    /// Callers constrain placement by naming labels a node must carry, which is
    /// what burrow has instead of regions. At most 16, keys 1-64 bytes and
    /// values up to 256, neither carrying control characters.
    #[arg(long = "label", value_delimiter = ',', env = "BURROW_NODE_LABELS")]
    pub labels: Vec<String>,
    /// Refuse to share sandboxes through tailcat addresses.
    ///
    /// A share is a WireGuard tunnel bootstrapped over a DERP relay, so a
    /// node that can reach a relay can serve them without any port of its own
    /// being reachable. Off means `burrow share` fails on this node.
    #[arg(long = "no-tailcat", env = "BURROWD_NO_TAILCAT")]
    pub is_tailcat_disabled: bool,
    /// DERP region shares listen through. Unset picks the nearest region of
    /// the DERP map by latency, once, and remembers it: the region is part of
    /// every share's address.
    #[arg(long, env = "BURROWD_TAILCAT_REGION")]
    pub tailcat_region: Option<i64>,
    /// Where to fetch the DERP map from. The default is tailcat's public map,
    /// whose relays are free and rate limited; a fleet with real traffic runs
    /// its own `derper` and points this at a map naming it.
    #[arg(long, env = "BURROWD_TAILCAT_DERP_MAP_URL")]
    pub tailcat_derp_map_url: Option<String>,
    /// Make every share on this node source guest connections from the
    /// gateway instead of the client's own address.
    ///
    /// Sourcing from the client needs a policy route and an nftables chain,
    /// which this node installs the first time a share wants them. Set this
    /// on a node where that state is unwelcome.
    #[arg(long = "no-transparent-ip", env = "BURROWD_NO_TRANSPARENT_IP")]
    pub is_transparent_ip_disabled: bool,
}

impl ServeArgs {
    /// How firecracker should be confined, if at all.
    fn jail(&self) -> Option<burrow_vmm::Jail> {
        self.jailer.as_ref().map(|jailer| burrow_vmm::Jail {
            jailer: jailer.clone(),
            uid: self.jail_uid,
            gid: self.jail_gid,
            chroot_base: self.chroot_base.clone(),
        })
    }

    /// How Cloud Hypervisor should be confined: whenever Firecracker is, so
    /// `--jailer` never leaves one VMM running unconfined beside the other
    /// unless `--unjailed-cloud-hypervisor` says so.
    fn cloud_hypervisor_jail(&self) -> Option<burrow_vmm::ChJail> {
        self.jailer.as_ref()?;
        if self.is_cloud_hypervisor_unjailed {
            tracing::warn!(
                "--unjailed-cloud-hypervisor: Cloud Hypervisor runs as root with the host's \
                 filesystem in view"
            );
            return None;
        }
        Some(burrow_vmm::ChJail {
            helper: "/proc/self/exe".into(),
            uid: self.jail_uid,
            gid: self.jail_gid,
        })
    }

    /// What this node tells the orchestrator to send sandbox traffic to.
    fn access_advertisement(&self) -> String {
        if let Some(explicit) = &self.access_advertise {
            return explicit.clone();
        }
        let scheme = if self.access_tls_cert.is_some() {
            "https"
        } else {
            "http"
        };
        let port = self.access_listen.port();
        let host = match &self.advertise {
            Some(advertised) => advertised
                .rsplit_once(':')
                .map_or(advertised.as_str(), |(host, _)| host)
                .to_string(),
            None if !self.access_listen.ip().is_unspecified() => {
                self.access_listen.ip().to_string()
            }
            None => sysinfo::System::host_name().unwrap_or_else(|| "localhost".into()),
        };
        format!("{scheme}://{host}:{port}")
    }

    fn sandbox_proxy_advertisement(&self) -> String {
        if let Some(explicit) = &self.advertise_sandbox_proxy {
            return explicit.clone();
        }
        let port = self.sandbox_proxy_listen.port();
        match &self.advertise {
            // The advertised API address names the host; only the port differs.
            Some(advertised) => match advertised.rsplit_once(':') {
                Some((host, _)) => format!("{host}:{port}"),
                None => format!("{advertised}:{port}"),
            },
            None => self.sandbox_proxy_listen.to_string(),
        }
    }
}

/// The last word of what `<vmm> --version` prints on its first line, e.g.
/// `v1.16.1` from Firecracker and `v54.0` from Cloud Hypervisor.
///
/// Recorded on snapshots and reported to the orchestrator, because a snapshot
/// only restores under the VMM that wrote it, and placement of one fetched
/// from the object store has to know that before it sends the create.
async fn vmm_version(bin: &std::path::Path) -> String {
    let output = tokio::process::Command::new(bin)
        .arg("--version")
        .output()
        .await;
    let Ok(output) = output else {
        return String::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or_default()
        .to_string()
}

/// The hypervisors asked for whose binaries are here. One that is missing is
/// left out rather than advertised: placement would send this node sandboxes
/// it could only fail to start. A node offering none is refused, since an
/// empty list is how a node from before the choice says it runs Firecracker.
fn offered_hypervisors(args: &ServeArgs) -> anyhow::Result<Vec<burrow_vmm::Hypervisor>> {
    let mut offered = Vec::new();
    for hypervisor in &args.hypervisors {
        let bin = match hypervisor {
            burrow_vmm::Hypervisor::Firecracker => &args.firecracker,
            burrow_vmm::Hypervisor::CloudHypervisor => &args.cloud_hypervisor,
            // Part of the OS rather than a binary; offered where the host
            // supports it and this process carries the entitlement, which
            // the first configuration checks.
            #[cfg(target_os = "macos")]
            burrow_vmm::Hypervisor::Vz => {
                if !burrow_vmm::vz::is_supported() {
                    tracing::warn!(%hypervisor, "Virtualization.framework unsupported here; not offering it");
                } else if !offered.contains(hypervisor) {
                    offered.push(*hypervisor);
                }
                continue;
            }
        };
        if !bin.exists() {
            tracing::warn!(%hypervisor, bin = %bin.display(), "hypervisor binary missing; not offering it");
        } else if !offered.contains(hypervisor) {
            offered.push(*hypervisor);
        }
    }
    if offered.is_empty() {
        anyhow::bail!(
            "no hypervisor to offer: none of --hypervisors {} has its binary here",
            args.hypervisors
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(offered)
}

fn local_node_info(args: &ServeArgs) -> anyhow::Result<NodeInfo> {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    // Refused at startup rather than at registration: a node that came up and
    // then quietly registered without the labels it was given would be placed
    // on by nobody, and the operator would have no line saying why.
    let labels = burrow_common::tags::parse_labels(&args.labels)
        .map_err(|err| anyhow::anyhow!("--label: {}", err.message()))?;
    Ok(NodeInfo {
        id: args.node_id.clone(),
        address: args
            .advertise
            .clone()
            .unwrap_or_else(|| args.listen.to_string()),
        total_vcpus: std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1),
        total_mem_mib: sys.total_memory() / (1024 * 1024),
        hostname: sysinfo::System::host_name().unwrap_or_default(),
        sandbox_proxy_address: args.sandbox_proxy_advertisement(),
        labels,
        // Filled in once the edge listener is actually serving: a URL naming a
        // router that never bound resolves nowhere.
        edge_domain: String::new(),
        edge_port: 0,
        arch: std::env::consts::ARCH.to_string(),
        // Filled in once the binary has been asked.
        firecracker_version: String::new(),
        // Filled in once the Access listener is serving, like the edge.
        access_endpoint: String::new(),
        // Filled in once the binaries have been looked for.
        hypervisors: Vec::new(),
        hypervisor_versions: Default::default(),
    })
}

/// How often idle and lifetime policies are checked.
///
/// Both are expressed in seconds but neither is a deadline anyone measures
/// precisely, so a coarse sweep costs nothing and keeps the node quiet.
pub(crate) const REAP_INTERVAL_SECS: u64 = 10;

async fn current_status(sandboxes: &SandboxManager, data_dir: &std::path::Path) -> NodeStatus {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();

    let mut templates = Vec::new();
    let mut kit_templates = Vec::new();
    let mut warm_templates = std::collections::HashMap::new();
    for template in crate::template::bootable(data_dir).await {
        if template.is_warm {
            warm_templates.insert(template.name.clone(), 1);
        }
        if template.is_kit {
            kit_templates.push(template.name.clone());
        }
        templates.push(template.name);
    }
    // sysinfo undercounts on macOS; see `macnode::available_memory`.
    #[cfg(target_os = "macos")]
    let avail = crate::macnode::available_memory().unwrap_or_else(|| sys.available_memory());
    #[cfg(not(target_os = "macos"))]
    let avail = match sys.available_memory() {
        0 => sys.free_memory(),
        n => n,
    };
    NodeStatus {
        running_sandboxes: sandboxes.count().await as u32,
        free_mem_mib: avail / (1024 * 1024),
        warm_templates,
        templates,
        kit_templates,
        is_draining: sandboxes.is_draining(),
        // Suspended sandboxes count: they hold their address, disks and
        // snapshot, and resuming must not find the node oversubscribed.
        committed_vcpus: sandboxes.committed_vcpus().await,
        volumes: sandboxes.volumes().list().await,
    }
}

/// Sets up the Access service, refusing a configuration that would advertise
/// an endpoint clients cannot use, and saying so when bearer tokens would
/// cross the wire in plaintext.
fn serve_access(
    args: &ServeArgs,
    listen: std::net::SocketAddr,
    access: crate::access::AccessApi,
) -> anyhow::Result<impl std::future::Future<Output = Result<(), tonic::transport::Error>> + use<>>
{
    use anyhow::Context as _;
    use burrow_proto::api::v1::access_server::AccessServer;

    let advertised = args.access_advertisement();
    let advertised = advertised.as_str();
    let is_https = advertised.starts_with("https://");
    if !is_https && !advertised.starts_with("http://") {
        anyhow::bail!("--access-advertise must start with https:// or http://");
    }
    let mut builder = Server::builder();
    match (&args.access_tls_cert, &args.access_tls_key) {
        (Some(cert), Some(key)) => {
            if !is_https {
                anyhow::bail!(
                    "the Access service serves TLS, so --access-advertise must be https://"
                );
            }
            let identity = tonic::transport::Identity::from_pem(
                std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?,
                std::fs::read(key).with_context(|| format!("reading {}", key.display()))?,
            );
            builder = builder
                .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
                .context("--access-tls-cert/--access-tls-key")?;
        }
        (None, None) if is_https => anyhow::bail!(
            "--access-advertise is https:// but no --access-tls-cert/--access-tls-key is set"
        ),
        (None, None) => tracing::warn!(
            "the Access service is PLAINTEXT: anyone on the path can read the access tokens \
             and the exec and file traffic they carry. Set --access-tls-cert and \
             --access-tls-key outside a test harness."
        ),
        _ => anyhow::bail!("--access-tls-cert and --access-tls-key go together"),
    }
    tracing::info!(listen = %listen, advertised, "Access service listening");
    Ok(builder.add_service(AccessServer::new(access)).serve(listen))
}

/// Registers with the orchestrator and heartbeats forever, reconnecting and
/// re-registering as needed (e.g. across orchestrator restarts).
async fn registration_loop(
    args: &ServeArgs,
    mut info: NodeInfo,
    sandboxes: SandboxManager,
    node_id: Arc<Mutex<String>>,
    token: Option<String>,
    identity: Option<Arc<burrow_net::mesh::Identity>>,
    access_keys: crate::access::SharedKeys,
) {
    // Claimed rather than requested: sandboxes here already hold addresses
    // from this slice.
    crate::template::set_guest_kernel(
        args.guest_kernel
            .clone()
            .unwrap_or_else(|| args.data_dir.join("vmlinux")),
    );
    let claimed_index = load_node_index(&args.data_dir).await;
    let mut applied_peers: Vec<burrow_net::Peer> = Vec::new();
    let mut denied_edges: Vec<std::net::IpAddr> = Vec::new();
    let mut pins =
        burrow_net::pinning::PinnedKeys::load(&args.data_dir.join("mesh-pins"), &args.mesh_pins)
            .await;
    loop {
        let mut client = match connect_orchestrator(&args.orchestrator, token.clone()).await {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(%err, orchestrator = args.orchestrator, "orchestrator unreachable; retrying");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };

        let resp = match client
            .register(nodepb::RegisterRequest {
                info: Some(info.clone()),
                wireguard_public_key: identity
                    .as_ref()
                    .map(|id| id.public_key.clone())
                    .unwrap_or_default(),
                wireguard_endpoint: args.mesh_endpoint.clone().unwrap_or_default(),
                claimed_node_index: claimed_index,
            })
            .await
        {
            Ok(resp) => resp.into_inner(),
            Err(err) => {
                tracing::warn!(%err, "registration failed; retrying");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        info.id = resp.node_id.clone();
        *node_id.lock().unwrap() = resp.node_id.clone();
        crate::access::apply_keys(&access_keys, &resp.access_keys);
        // Confines address allocation to this node's slice before any sandbox
        // is created, so no address can collide with another node's.
        sandboxes.set_node_index(resp.node_index).await;
        store_node_index(&args.data_dir, sandboxes.node_index().await).await;
        let interval = Duration::from_secs(resp.heartbeat_interval_secs.max(1) as u64);
        tracing::info!(
            node_id = info.id,
            node_index = resp.node_index,
            ?interval,
            "registered with orchestrator"
        );

        loop {
            sandboxes.wait_to_report(interval).await;
            match client
                .heartbeat(nodepb::HeartbeatRequest {
                    node_id: info.id.clone(),
                    status: Some(current_status(&sandboxes, &args.data_dir).await),
                    sandboxes: sandboxes.state_reports().await,
                    // The node's reaper sweeps expired snapshots and retention
                    // evicts old ones, neither of which the orchestrator asked
                    // for; this is how it learns they are gone.
                    snapshots: sandboxes.snapshots().ids().await,
                    durable_snapshots: sandboxes.snapshots().durable_ids().await,
                    // Restated so a relabelled node converges on its next beat
                    // rather than on its next registration.
                    info: Some(info.clone()),
                })
                .await
            {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    if resp.is_reregistration_required {
                        tracing::warn!("orchestrator asked us to re-register");
                        break;
                    }
                    sandboxes.renew_lease(resp.sandbox_lease_secs);
                    crate::access::apply_keys(&access_keys, &resp.access_keys);
                    sandboxes.confirm(&resp.confirmed_sandboxes);
                    sandboxes.relinquish(&resp.relinquished_sandboxes).await;
                    apply_edge_denial(
                        &sandboxes,
                        &[
                            resp.edge_hosts.as_slice(),
                            resp.control_plane_hosts.as_slice(),
                            resp.node_hosts.as_slice(),
                        ]
                        .concat(),
                        &mut denied_edges,
                    )
                    .await;
                    apply_mesh(
                        &sandboxes,
                        identity.as_deref(),
                        args,
                        resp,
                        &mut applied_peers,
                        &mut pins,
                    )
                    .await;
                }
                Err(err) => {
                    tracing::warn!(%err, "heartbeat failed; re-registering");
                    break;
                }
            }
        }
    }
}

/// The address slice this node used last time it ran, if any.
async fn load_node_index(data_dir: &std::path::Path) -> Option<u32> {
    tokio::fs::read_to_string(data_dir.join("node-index"))
        .await
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

async fn store_node_index(data_dir: &std::path::Path, index: u32) {
    let path = data_dir.join("node-index");
    if let Err(err) = tokio::fs::write(&path, index.to_string()).await {
        tracing::warn!(path = %path.display(), %err, "could not record the address slice");
    }
}

/// Denies every edge router in the fleet to this node's sandboxes.
///
/// An edge proxies into a published port addressed by sandbox id alone, so a
/// sandbox that can reach one has reached every sandbox that edge serves. Edges
/// are opt-in per node, so this node's own flags cannot say which peers run
/// one. Every orchestrator replica's own address rides in the same list: the
/// address this node was configured with is denied at startup, but with
/// several replicas that is only the balancer in front of them.
///
/// Applied only when it changes, because a render rewrites the whole ruleset.
/// An empty result for a non-empty list is a resolver failure rather than a
/// fleet without edges, and keeps the denial already in place.
async fn apply_edge_denial(
    sandboxes: &SandboxManager,
    hosts: &[String],
    applied: &mut Vec<std::net::IpAddr>,
) {
    let mut addresses = Vec::new();
    for host in hosts {
        // Tolerant of a host:port, since an operator's advertisement may carry
        // one; every port on the address is denied either way.
        addresses.extend(resolve_denied(endpoint_host(host)).await);
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() && !hosts.is_empty() {
        tracing::warn!(
            ?hosts,
            "no edge router resolved to an address; keeping the denial already applied"
        );
        return;
    }
    if addresses == *applied {
        return;
    }
    match sandboxes.set_edge_addresses(addresses.clone()).await {
        Ok(()) => {
            tracing::info!(
                ?addresses,
                "denying the fleet's nodes, edge routers and control plane to sandboxes"
            );
            *applied = addresses;
        }
        // Left unrecorded so the next beat tries again: a sandbox that can
        // reach an edge is a sandbox that can reach its neighbours.
        Err(err) => tracing::error!(%err, "could not deny the fleet's edge routers"),
    }
}

/// Brings the mesh in line with what the orchestrator last reported.
///
/// Peers and cross-node membership arrive on every heartbeat, so a node
/// converges on the fleet without any separate coordination; both are applied
/// only when they change.
async fn apply_mesh(
    sandboxes: &SandboxManager,
    identity: Option<&burrow_net::mesh::Identity>,
    args: &ServeArgs,
    resp: nodepb::HeartbeatResponse,
    applied_peers: &mut Vec<burrow_net::Peer>,
    pins: &mut burrow_net::pinning::PinnedKeys,
) {
    use burrow_net::Peer;
    use burrow_net::pinning::Verdict;

    let members = resp
        .network_members
        .into_iter()
        .map(|entry| (entry.network, entry.members))
        .collect();
    sandboxes.set_remote_members(members).await;

    let Some(identity) = identity else {
        return;
    };
    // A peer's key is what makes its tunnel unforgeable, and the orchestrator
    // is the one telling us what it is. Pinning means it can introduce new
    // nodes but cannot change the identity of an existing one.
    let mut refused = 0;
    let peers: Vec<Peer> = resp
        .peers
        .into_iter()
        .filter(|p| match pins.check(&p.node_id, &p.public_key) {
            Verdict::Known => true,
            Verdict::Learned => {
                tracing::info!(
                    node_id = p.node_id,
                    public_key = p.public_key,
                    "pinned a mesh peer's key"
                );
                true
            }
            // Loud, and dropped: a peer whose key changed is either a
            // reprovisioned node or an orchestrator trying to put itself in
            // the middle, and this node cannot tell which.
            Verdict::Conflict { pinned } => {
                tracing::error!(
                    node_id = p.node_id,
                    pinned,
                    offered = p.public_key,
                    "REFUSING a mesh peer: its key does not match the pinned one. \
                     If this node was legitimately reprovisioned, remove it from \
                     the pin file; otherwise the orchestrator is lying about it."
                );
                refused += 1;
                false
            }
            // Nothing can be pinned against an id the pin file cannot hold, so
            // there is no key here to trust or to contradict.
            Verdict::InvalidNodeId => {
                tracing::error!(
                    node_id = p.node_id,
                    "REFUSING a mesh peer: the orchestrator gave it a node id that \
                     cannot be pinned"
                );
                refused += 1;
                false
            }
        })
        .map(|p| Peer {
            node_id: p.node_id,
            public_key: p.public_key,
            endpoint: p.endpoint,
            subnet: p.subnet,
        })
        .collect();

    if refused == 0
        && let Err(err) = pins.save().await
    {
        tracing::warn!(%err, "could not persist mesh key pins");
    }

    // Heartbeats arrive every few seconds; reapplying an unchanged peer set
    // would churn the interface and flood the log for no benefit.
    if peers == *applied_peers {
        return;
    }
    match burrow_net::mesh::configure(identity, args.mesh_port, &sandboxes.subnet().await, &peers)
        .await
    {
        Ok(()) => *applied_peers = peers,
        Err(err) => {
            tracing::error!(%err, "could not configure the mesh; cross-node traffic will not flow")
        }
    }
}

/// Drops audit records past their retention window, hourly.
///
/// A busy sandbox can produce thousands of egress records a minute and nothing
/// else ever removes them, so without this the node's database grows until the
/// disk does.
fn spawn_audit_pruner(store: Arc<burrow_store::Store>, retention_days: u32) {
    if retention_days == 0 {
        tracing::warn!("audit retention disabled; records will accumulate without bound");
        return;
    }
    tokio::spawn(async move {
        // Hourly rather than on a timer tied to the window: pruning is cheap
        // and a node that runs for weeks should not accumulate a huge backlog
        // to delete in one go.
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            let cutoff = burrow_common::rfc3339_days_ago(retention_days as u64);
            match store.prune_egress(&cutoff).await {
                Ok(0) => {}
                Ok(removed) => tracing::info!(removed, %cutoff, "pruned audit records"),
                Err(err) => tracing::error!(%err, "audit pruning failed"),
            }
        }
    });
}

/// Addresses the orchestrator answers on, to be denied to every sandbox.
///
/// Its API creates and destroys sandboxes and routes exec and logs, and an
/// open-mode sandbox has NAT'd egress to anywhere this node can route.
///
/// Resolved once at startup, since the endpoint is operator configuration that
/// does not change under a running node. Best effort: a name that does not
/// resolve yet leaves the node no worse off than before there was a rule, and
/// is why the orchestrator should not share an address with anything a sandbox
/// is meant to reach.
async fn control_plane_addresses(endpoint: &str) -> Vec<std::net::IpAddr> {
    let addresses = resolve_denied(endpoint_host(endpoint)).await;
    if addresses.is_empty() {
        tracing::warn!(
            orchestrator = endpoint,
            "the orchestrator resolves to no address; sandboxes will not be denied it by address"
        );
    } else {
        tracing::info!(
            orchestrator = endpoint,
            ?addresses,
            "denying the control plane to sandboxes"
        );
    }
    addresses
}

/// The IPv4 addresses a host resolves to, for denying it to sandboxes.
///
/// Port 0 because every port on the address is denied, not just the one burrow
/// dials. A v6 address is dropped: the ruleset matches on `ip daddr` and cannot
/// render one.
/// Binds a listener that serves both families where the host allows it.
///
/// An IPv6 wildcard socket accepts IPv4 too, as v4-mapped addresses, which is
/// why the proxy unmaps every source it sees. A host with IPv6 unavailable
/// falls back to the address as configured rather than leaving allowlist
/// sandboxes with nowhere to be redirected.
async fn bind_dual_stack(
    configured: std::net::SocketAddr,
) -> std::io::Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    if configured.ip().is_unspecified() {
        let dual = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, configured.port()));
        match tokio::net::TcpListener::bind(dual).await {
            Ok(listener) => return Ok((listener, dual)),
            Err(err) => tracing::warn!(%dual, %err, "no dual-stack listener; IPv4 only"),
        }
    }
    let listener = tokio::net::TcpListener::bind(configured).await?;
    Ok((listener, configured))
}

async fn resolve_denied(host: &str) -> Vec<std::net::IpAddr> {
    match tokio::net::lookup_host((host, 0u16)).await {
        // Both families. The ruleset renders a matcher per family, so a host
        // reachable only over IPv6 is denied like any other; dropping those
        // here is what used to leave one undenied.
        Ok(addresses) => addresses.map(|address| address.ip()).collect(),
        Err(err) => {
            tracing::warn!(host, %err, "could not resolve a host that must be denied to sandboxes");
            Vec::new()
        }
    }
}

/// The host part of a `scheme://host:port/path` endpoint.
fn endpoint_host(endpoint: &str) -> &str {
    let rest = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // A bracketed v6 literal keeps its colons; a `host:port` loses the port.
    if let Some(end) = rest.starts_with('[').then(|| rest.find(']')).flatten() {
        return &rest[..=end];
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            host
        }
        _ => rest,
    }
}

/// Dials the orchestrator with the cluster token attached.
pub(crate) async fn connect_orchestrator(
    endpoint: &str,
    token: Option<String>,
) -> Result<
    NodeRegistryClient<
        tonic::service::interceptor::InterceptedService<
            tonic::transport::Channel,
            OrchestratorAuth,
        >,
    >,
    tonic::transport::Error,
> {
    let channel = tonic::transport::Endpoint::try_from(endpoint.to_string())?
        .connect()
        .await?;
    Ok(NodeRegistryClient::with_interceptor(
        channel,
        OrchestratorAuth(token),
    ))
}

#[derive(Clone)]
pub struct OrchestratorAuth(Option<String>);

impl tonic::service::Interceptor for OrchestratorAuth {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(token) = &self.0 {
            let value = format!("Bearer {token}")
                .parse()
                .map_err(|_| tonic::Status::internal("malformed cluster token"))?;
            req.metadata_mut().insert("authorization", value);
        }
        Ok(req)
    }
}

/// Resolves when the process is asked to stop.
async fn shutdown_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(sig) => sig,
        Err(err) => {
            tracing::error!(%err, "cannot watch SIGTERM; sandboxes will not be suspended on stop");
            std::future::pending::<()>().await;
            unreachable!()
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(sig) => sig,
        Err(_) => {
            term.recv().await;
            return "SIGTERM";
        }
    };
    tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = interrupt.recv() => "SIGINT",
    }
}

/// Denies every other local user access to a directory holding guest state:
/// snapshot memory images, scratch and rootfs disks, and (jailed) a chroot a
/// dropped-privilege VMM runs in. Best effort, like [`burrow_store`]'s own
/// version of this: a node that cannot be made private is still a working
/// node, and refusing to start over it would take the whole daemon down for
/// what is defence in depth against another account on the same host, not the
/// primary guest/host boundary.
#[cfg(unix)]
fn restrict_to_owner(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &std::path::Path) {}

pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
    // Before anything is opened: a malformed label is a startup error, not a
    // node that comes up unplaceable.
    let mut node_info = local_node_info(&args)?;
    // Same, and for a sharper reason: a mistyped CIDR would otherwise mean an
    // edge that silently trusts nobody, or trusts the wrong network.
    let trusted_proxies = args
        .edge_trusted_proxy
        .iter()
        .map(|entry| {
            burrow_common::edge::parse_trusted_proxy(entry).ok_or_else(|| {
                anyhow::anyhow!("--edge-trusted-proxy {entry:?} is not an address or a CIDR")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    tracing::info!(
        listen = %args.listen,
        orchestrator = args.orchestrator,
        labels = ?node_info.labels,
        "burrowd starting"
    );

    // Guest memory, disk images and the jail chroot base all live here; every
    // one of them is created lazily by whatever first needs it, so this is
    // the one place that runs before any of them exist. Restricting the
    // parent is what actually matters: a subdirectory's own mode is moot if
    // another local user cannot traverse into it to begin with.
    for dir in [
        args.data_dir.join("sandboxes"),
        args.data_dir.join("snapshots"),
    ]
    .into_iter()
    .chain(args.jailer.as_ref().map(|_| args.chroot_base.clone()))
    {
        let _ = tokio::fs::create_dir_all(&dir).await;
        restrict_to_owner(&dir);
    }

    let store = Arc::new(
        burrow_store::Store::open(&args.data_dir.join("node.db"))
            .await
            .map_err(|err| anyhow::anyhow!("cannot open node store: {err}"))?,
    );

    let firecracker_version = vmm_version(&args.firecracker).await;
    let cloud_hypervisor_version = vmm_version(&args.cloud_hypervisor).await;
    let hypervisors = offered_hypervisors(&args)?;
    #[cfg(target_os = "macos")]
    let vz_version = burrow_vmm::vz::host_version();
    // Hashed once: every handshake compares the guest's agent against it, and
    // a guest running another build is upgraded in place.
    let guest_upgrade = Some(Arc::new(crate::guestconn::GuestUpgrade {
        digest: crate::blobs::hash_file(&args.guest_binary)
            .await
            .map_err(|err| {
                anyhow::anyhow!("--guest-binary {}: {err}", args.guest_binary.display())
            })?
            .to_string(),
        path: args.guest_binary.clone(),
    }));
    node_info.firecracker_version = firecracker_version.clone();
    node_info.hypervisors = hypervisors.iter().map(|h| h.to_string()).collect();
    node_info.hypervisor_versions = hypervisors
        .iter()
        .map(|h| {
            let version = match h {
                burrow_vmm::Hypervisor::Firecracker => &firecracker_version,
                burrow_vmm::Hypervisor::CloudHypervisor => &cloud_hypervisor_version,
                #[cfg(target_os = "macos")]
                burrow_vmm::Hypervisor::Vz => &vz_version,
            };
            (h.to_string(), version.clone())
        })
        .collect();
    let object_store = match (&args.object_store, &args.object_store_endpoint) {
        (Some(url), Some(endpoint)) => {
            let store = crate::objstore::ObjectStore::open(&crate::objstore::Options {
                url: url.clone(),
                endpoint: endpoint.clone(),
                region: args.object_store_region.clone(),
            })?;
            store
                .ensure_bucket()
                .await
                .map_err(|err| anyhow::anyhow!("--object-store: {}", err.message()))?;
            let is_conditional = store
                .probe_conditional_writes()
                .await
                .map_err(|err| anyhow::anyhow!("--object-store: {}", err.message()))?;
            match (is_conditional, args.is_unconditional_object_store_allowed) {
                (true, _) => {}
                (false, false) => anyhow::bail!(
                    "--object-store {} ignores conditional writes, which the lease on a stored \
                     sandbox depends on: two nodes could run one sandbox. Use a store that \
                     honours If-Match and If-None-Match (AWS S3 does, as does versitygw 1.10; \
                     1.0.14 does not), or pass --allow-unconditional-object-store to accept the race",
                    store.describe()
                ),
                (false, true) => tracing::error!(
                    store = store.describe(),
                    "the object store ignores conditional writes; two nodes adopting one sandbox \
                     at once can both run it"
                ),
            }
            tracing::info!(
                store = store.describe(),
                "snapshots are copied to the object store"
            );
            Some(store)
        }
        (Some(_), None) => anyhow::bail!("--object-store needs --object-store-endpoint"),
        (None, _) => None,
    };
    let store_vault = match &args.object_store_key_file {
        Some(path) => {
            if !path.exists() {
                anyhow::bail!(
                    "--object-store-key-file {} does not exist; create one key for the whole \
                     fleet, e.g. `head -c 32 /dev/urandom > {}`, and give every node the same file",
                    path.display(),
                    path.display()
                );
            }
            Some(Arc::new(burrow_common::vault::Vault::open(path).map_err(
                |err| anyhow::anyhow!("--object-store-key-file: {err}"),
            )?))
        }
        None => None,
    };

    // The proxy and the sandbox manager share one policy table: the manager
    // writes it whenever sandboxes change, the proxy reads it per connection.
    let proxy_policies = Arc::new(burrow_proxy::PolicyTable::default());
    let resolutions = Arc::new(burrow_proxy::Resolutions::default());
    // Shared the same way: the manager renders the denied set on every firewall
    // sync, the proxy consults it per connection.
    let denied = Arc::new(burrow_proxy::DeniedAddresses::default());
    let directory = Arc::new(burrow_proxy::directory::Directory::default());
    let sandboxes = SandboxManager::new(
        NodeConfig {
            data_dir: args.data_dir.clone(),
            firecracker_bin: args.firecracker.clone(),
            extra_boot_args: args.guest_boot_args.clone(),
            agent_timeout: Duration::from_secs(args.agent_timeout),
            command_log_rotation: burrow_common::cmdlog::Rotation {
                max_bytes: args.command_log_max_size.unwrap_or(0),
                max_files: args.command_log_max_files,
            },
            cgroup_root: Some(args.cgroup_root.clone()),
            is_resource_limits_required: args.is_resource_limits_required,
            is_memory_lazy: args.is_memory_lazy,
            jail: args.jail(),
            cloud_hypervisor: burrow_vmm::CloudHypervisorConfig {
                bin: args.cloud_hypervisor.clone(),
                kernel: args.cloud_hypervisor_kernel.clone(),
                jail: args.cloud_hypervisor_jail(),
            },
            hypervisors,
            artifact_retention: Duration::from_secs(
                u64::from(args.artifact_retention_days) * 24 * 60 * 60,
            ),
            control_plane: control_plane_addresses(&args.orchestrator).await,
            share: crate::share::ShareOptions {
                is_enabled: !args.is_tailcat_disabled,
                is_transparent: !args.is_transparent_ip_disabled,
                region: args.tailcat_region,
                derp_map_url: args.tailcat_derp_map_url.clone(),
            },
            object_store,
            store_vault,
            firecracker_version,
            cloud_hypervisor_version,
            guest_upgrade,
            event_delivery: args.event_delivery,
        },
        Arc::clone(&proxy_policies),
        Arc::clone(&resolutions),
        Arc::clone(&denied),
        Arc::clone(&directory),
        Arc::clone(&store),
        burrow_common::vault::Vault::open(&args.data_dir.join("secrets.key"))
            .map_err(|err| anyhow::anyhow!("secrets key: {err}"))?,
    );

    // Policy fields are only real if something acts on them; this is what
    // makes idle_suspend_secs and max_lifetime_secs mean anything.
    {
        let sandboxes = sandboxes.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(REAP_INTERVAL_SECS));
            // A missed tick must not cause a burst of catch-up passes.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                sandboxes.reap().await;
            }
        });
    }
    {
        let sandboxes = sandboxes.clone();
        tokio::spawn(async move { sandboxes.collect_stored_garbage().await });
    }

    let audit = burrow_proxy::AuditLog::new(
        args.data_dir.join("logs/egress.jsonl"),
        Some(Arc::clone(&store)),
    );
    // Generated once and kept, because guests are told to trust it: a new
    // authority each boot would break every sandbox that survived a restart.
    //
    // Fatal when it cannot be loaded. A node that carried on without one would
    // accept sandboxes asking for inspection and hand them an unchecked,
    // SNI-only session instead, silently downgrading the control they asked
    // for; refusing to start is the only answer that fails closed.
    let authority = Arc::new(
        burrow_proxy::inspect::Authority::load_or_create(&args.data_dir).map_err(|err| {
            anyhow::anyhow!(
                "cannot load the TLS inspection authority from {}: {err}. \
                 Inspection must not fail open, so burrowd will not start; fix the \
                 directory's permissions, or remove the broken CA files to have a \
                 new authority generated",
                args.data_dir.display()
            )
        })?,
    );
    // Handed to guests that opt in, so they trust the certificates the proxy
    // presents for the hosts they asked for.
    sandboxes.set_inspection_ca(authority.certificate_pem().to_string());

    let proxy = Arc::new(burrow_proxy::Proxy {
        policies: Arc::clone(&proxy_policies),
        audit: audit.clone(),
        resolutions: Arc::clone(&resolutions),
        authority: Some(Arc::clone(&authority)),
        denied: Arc::clone(&denied),
    });
    match bind_dual_stack(args.proxy_listen).await {
        Ok((listener, listen)) => {
            tracing::info!(%listen, "egress proxy listening");
            tokio::spawn(proxy.serve(listener));
        }
        // Without the proxy, allowlist-mode sandboxes have their traffic
        // redirected nowhere, which fails closed. Worth shouting about.
        Err(err) => tracing::error!(
            listen = %args.proxy_listen, %err,
            "egress proxy failed to bind; allowlist sandboxes will have no egress"
        ),
    }
    spawn_audit_pruner(Arc::clone(&store), args.audit_retention_days);
    // A macOS guest's flows never reach the proxy or the resolver over a
    // tap; its stack hands them over in process, with the same pieces.
    #[cfg(target_os = "macos")]
    sandboxes.set_usernet_node(burrow_net::usernet::Node {
        audit: audit.clone(),
        resolutions: Arc::clone(&resolutions),
        denied: Arc::clone(&denied),
        authority: Some(Arc::clone(&authority)),
        directory: Arc::clone(&directory),
        dns_upstream: args.dns_upstream,
    });

    // Guests resolve through burrow so lookups are recorded; the firewall
    // permits this one host service, and the resolver forwards upstream.
    let resolver = Arc::new(burrow_proxy::Resolver {
        policies: proxy_policies,
        audit,
        upstream: args.dns_upstream,
        resolutions,
        directory: Arc::clone(&directory),
    });
    match tokio::net::UdpSocket::bind(args.dns_listen).await {
        Ok(socket) => {
            tracing::info!(listen = %args.dns_listen, upstream = %args.dns_upstream, "dns resolver listening");
            tokio::spawn(resolver.serve(socket));
        }
        Err(err) => tracing::error!(
            listen = %args.dns_listen, %err,
            "dns resolver failed to bind; sandboxes will not resolve names"
        ),
    }

    // Filled in by registration; sandbox records carry it so the orchestrator can
    // tell which node owns what even when reading a node's own listing.
    let node_id = Arc::new(Mutex::new(args.node_id.clone()));

    // A node without WireGuard still works; its sandboxes are simply not
    // reachable from other nodes.
    let identity = match burrow_net::mesh::Identity::load_or_create(&args.data_dir).await {
        Ok(identity) => Some(Arc::new(identity)),
        Err(err) => {
            tracing::warn!(%err, "no mesh identity; cross-node private networks unavailable");
            None
        }
    };
    if let Some(identity) = &identity {
        tracing::info!(public_key = identity.public_key, "mesh identity ready");
    }

    // Before recovery, so recovered sandboxes reload into the range they were
    // created in rather than whatever index 0 happens to be.
    if let Some(index) = load_node_index(&args.data_dir).await {
        sandboxes.set_node_index(index).await;
    }

    // Pick up anything the previous run left behind before serving, so a
    // client never sees a window where recovered sandboxes appear missing.
    sandboxes.recover().await;

    // A node has no client-facing surface: everything on it is reached over the
    // node-facing hop, from the orchestrator or from a peer node. So one secret
    // guards all of it, in both directions -- the NodeService interceptor, the
    // sandbox proxy prelude, peer template pulls, and registration.
    //
    // `--api-key` is the fallback only so the single-binary dev setup, where
    // one token is handed to everything, keeps working. Sharing the client key
    // here means a leaked tenant key drives nodes directly.
    let api_tokens =
        burrow_common::auth::load_tokens(args.api_key.as_deref(), args.api_key_file.as_deref());
    let node_tokens = burrow_common::auth::load_tokens(
        args.node_token.as_deref(),
        args.node_token_file.as_deref(),
    );
    let tokens = if node_tokens.is_empty() {
        if !api_tokens.is_empty() {
            tracing::warn!(
                "no --node-token configured: this node's API accepts the client \
                 api key, so any API client can call it directly. Set --node-token \
                 (or BURROW_NODE_TOKEN) to the same value the orchestrator uses."
            );
        }
        api_tokens
    } else {
        node_tokens
    };
    let api = NodeApi {
        sandboxes: sandboxes.clone(),
        node_id: node_id.clone(),
        data_dir: args.data_dir.clone(),
        store: Arc::clone(&store),
        // Pulling a template means dialling a peer node, which is guarded by
        // the same cluster secret this node presents to the orchestrator.
        cluster_token: tokens.first().cloned(),
        guest_binary: args.guest_binary.clone(),
        registry_credentials: crate::oci::auth::Store::load(&args.registry_auth).await,
        insecure_registries: args.insecure_registry.clone(),
        access_sessions: Arc::default(),
    };
    let auth = burrow_common::auth::TokenAuth::new(tokens.clone());
    if !auth.is_enabled() {
        tracing::warn!(
            "no --node-token or --api-key configured: this node's API is UNAUTHENTICATED"
        );
    }
    let cluster_token = tokens.first().cloned();
    // One token for the whole node-facing hop, so what this node accepts is
    // also what it presents when registering and when dialling a peer.
    let registration_token = cluster_token.clone();
    sandboxes.metrics().register(Arc::clone(&node_id));
    tokio::spawn(crate::delivery::run(
        sandboxes.delivery(),
        Arc::clone(&store),
        args.orchestrator.clone(),
        registration_token.clone(),
        Arc::clone(&node_id),
    ));

    // Accepts traffic forwarded for sandboxes on this node, behind the cluster
    // token's prelude. Guests cannot reach it: the `tohost` chain admits only
    // the resolver and the egress proxy, and drops everything else aimed at the
    // host.
    let sandbox_proxy = Arc::new(crate::sandboxproxy::SandboxProxy {
        sandboxes: sandboxes.clone(),
        cluster_token: cluster_token.clone(),
    });
    match tokio::net::TcpListener::bind(args.sandbox_proxy_listen).await {
        Ok(listener) => {
            tracing::info!(
                listen = %args.sandbox_proxy_listen,
                advertised = args.sandbox_proxy_advertisement(),
                "sandbox proxy listening"
            );
            tokio::spawn(sandbox_proxy.serve(listener));
        }
        Err(err) => tracing::error!(
            listen = %args.sandbox_proxy_listen, %err,
            "sandbox proxy could not bind; forwarded sandbox traffic will be refused"
        ),
    }

    // The node's own edge, when the operator asked for one. Advertised to the
    // orchestrator only once it is serving, so a published port's URL never
    // names a router that is not there.
    if let Some(edge_listen) = args.edge_listen {
        if args.edge_domain.is_empty() {
            tracing::warn!(
                "--edge-listen without --edge-domain: this node's edge will answer for any \
                 hostname, and no edge URL can be advertised for its sandboxes"
            );
        }
        if !trusted_proxies.is_empty() {
            tracing::warn!(
                "--edge-trusted-proxy is set: the client address a guest sees comes from a \
                 header when the peer matches, so this node's edge must not be reachable \
                 except through that proxy"
            );
        }
        match tokio::net::TcpListener::bind(edge_listen).await {
            Ok(listener) => {
                tracing::info!(
                    listen = %edge_listen,
                    domain = args.edge_domain,
                    "node edge listening; this node's sandbox ports are reachable at \
                     <port>-<sandbox-id>.<domain>"
                );
                node_info.edge_domain = args.edge_domain.clone();
                node_info.edge_port = u32::from(edge_listen.port());
                tokio::spawn(
                    Arc::new(crate::edge::NodeEdge {
                        sandboxes: sandboxes.clone(),
                        domain: args.edge_domain.clone(),
                        trusted_proxies,
                    })
                    .serve(listener),
                );
            }
            // The node is still useful without an edge: its published ports
            // stay reachable at the node address, which is what a caller is
            // handed when no edge is serving.
            Err(err) => tracing::error!(
                listen = %edge_listen, %err,
                "node edge could not bind; this node's published ports are reachable only \
                 at the node address"
            ),
        }
    }

    let api = Arc::new(api);
    let access_keys = crate::access::SharedKeys::default();
    let access = crate::access::AccessApi {
        sessions: Arc::clone(&api.access_sessions),
        api: Arc::clone(&api),
        keys: Arc::clone(&access_keys),
    };
    let access_server = serve_access(&args, args.access_listen, access)?;
    node_info.access_endpoint = args.access_advertisement();

    let server = Server::builder()
        .add_service(tonic::service::interceptor::InterceptedService::new(
            NodeServiceServer::from_arc(api),
            auth,
        ))
        .serve(args.listen);

    tokio::select! {
        result = server => result?,
        // Without it no exec or file call reaches this node's sandboxes, so
        // its stopping stops the node rather than leaving it half there.
        result = access_server => anyhow::Context::context(result, "the Access service stopped")?,
        _ = registration_loop(&args, node_info, sandboxes.clone(), node_id, registration_token, identity, access_keys) => {
            unreachable!("registration loop never returns")
        }
        // A stop signal would otherwise destroy every sandbox on the node.
        // Snapshotting them turns a restart into a pause and a resume.
        signal = shutdown_signal() => {
            tracing::info!(signal, "shutting down; suspending sandboxes");
            sandboxes.delivery().close();
            sandboxes.suspend_all().await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The orchestrator's address is what a sandbox is denied, so the host has
    /// to come out of the endpoint whatever shape the operator wrote it in.
    #[test]
    fn an_endpoint_yields_its_host() {
        for (endpoint, host) in [
            ("http://orchestrator:7070", "orchestrator"),
            ("https://orch.example.com:443/", "orch.example.com"),
            ("http://10.0.0.5:7070", "10.0.0.5"),
            ("orchestrator:7070", "orchestrator"),
            ("http://orchestrator", "orchestrator"),
            // A bracketed v6 literal keeps its colons; only a port is stripped.
            ("http://[::1]:7070", "[::1]"),
        ] {
            assert_eq!(endpoint_host(endpoint), host, "{endpoint}");
        }
    }

    /// A node whose every hypervisor binary was missing advertised an empty
    /// list, which placement reads as a node from before the choice, running
    /// Firecracker. It refuses to start instead.
    #[test]
    fn a_node_with_no_hypervisor_binary_refuses_to_start() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            serve: ServeArgs,
        }
        let serve = |bin: &str| {
            <Cli as clap::Parser>::parse_from([
                "burrowd",
                "--hypervisors",
                "firecracker,cloud-hypervisor",
                "--firecracker",
                bin,
                "--cloud-hypervisor",
                "/nonexistent/cloud-hypervisor",
            ])
            .serve
        };
        assert!(offered_hypervisors(&serve("/nonexistent/firecracker")).is_err());
        let here = std::env::current_exe().unwrap();
        assert_eq!(
            offered_hypervisors(&serve(here.to_str().unwrap())).unwrap(),
            vec![burrow_vmm::Hypervisor::Firecracker]
        );
    }

    /// Guest memory and disk images are not for every local user to read,
    /// same as the node's own sqlite store.
    #[test]
    fn a_restricted_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("burrow-restrict-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        restrict_to_owner(&dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "directory is {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
