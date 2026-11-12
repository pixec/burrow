"""The SDK's data shapes: what calls take and return."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Union


@dataclass
class Usage:
    """What a sandbox has consumed, accumulated across every VM it has run."""

    cpu_usage_usec: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass
class ResourcePolicy:
    """The machine a sandbox runs on. Fixed for its life; 0 is the server's
    default, which is what lets a create from a snapshot inherit its shape."""

    vcpus: int = 0
    memory_mib: int = 0
    disk_mib: int = 0


@dataclass
class LifetimePolicy:
    """How long a sandbox stays paid for. Seconds; 0 is unlimited or never."""

    max_lifetime_secs: int = 0
    idle_suspend_secs: int = 0
    suspended_ttl_secs: int = 0


@dataclass
class SnapshotPolicy:
    """How long the snapshots taken of a sandbox stay paid for."""

    # Seconds from last use; 0 never expires.
    expiration_secs: int = 0
    # Keep the N most recent, 1..=10; 0 is unlimited.
    keep_last: int = 0
    # Let an evicted snapshot live out its expiration instead of deleting it.
    evicted_kept: bool = False


@dataclass
class ExecPolicy:
    allow_exec: bool = True


@dataclass
class FsPolicy:
    allow_upload: bool = True
    allow_download: bool = True
    path_scopes: List[str] = field(default_factory=list)
    max_upload_bytes: int = 0


@dataclass
class RequestRule:
    """A rule the proxy applies to inspected requests to one domain.

    In open mode ``domain`` is an exact host name, since it also names the one
    host whose TLS is inspected. ``expires_at_unix_ms`` is when the rule stops
    applying, 0 for never. ``bound_sandbox_id`` is set by the server on a rule
    whose value came from a scoped secret: a copy of the policy anywhere else
    refuses the requests the rule would have claimed.
    """

    domain: str
    match: Optional[dict] = None
    set_headers: Optional[Dict[str, str]] = None
    forward: Optional[dict] = None
    expires_at_unix_ms: int = 0
    bound_sandbox_id: str = ""


@dataclass
class SecretInfo:
    """A stored secret's name and who may use it: sandbox ids or names, and
    tags as ``key=value``. Both empty is every sandbox. Never a value."""

    name: str
    allowed_sandboxes: List[str] = field(default_factory=list)
    allowed_tags: List[str] = field(default_factory=list)


@dataclass
class PortRule:
    """Destination ports a sandbox may never connect to, in any mode.

    ``protocol`` is ``"tcp"``, ``"udp"`` or ``"any"`` (both). ``port_end`` is
    the inclusive end of a range, 0 for ``port`` alone. ``cidrs`` narrows the
    denial to destination ranges of either family; empty is every destination.
    """

    port: int
    protocol: str = "any"
    port_end: int = 0
    cidrs: List[str] = field(default_factory=list)


@dataclass
class IngressRule:
    """One door into a sandbox's public addresses: its dedicated IPs and its
    global IPv6 address. Nothing is admitted without a rule.

    ``protocol`` is ``"tcp"``, ``"udp"``, ``"icmp"`` (echo, no ports) or
    ``"any"`` (TCP and UDP). ``ports`` holds ports and ``"N-M"`` ranges; empty
    is every port. ``sources`` are CIDRs of either family; empty is anyone.
    """

    protocol: str = "any"
    ports: List[Union[int, str]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


@dataclass
class NetworkPolicy:
    mode: str = "none"
    allow_domains: List[str] = field(default_factory=list)
    allow_cidrs: List[str] = field(default_factory=list)
    allow_ports: List[int] = field(default_factory=list)
    deny_cidrs: List[str] = field(default_factory=list)
    deny_ports: List[PortRule] = field(default_factory=list)
    # Refuse every IPv6 destination, in every mode.
    deny_ipv6: bool = False
    ingress: List[IngressRule] = field(default_factory=list)
    inspect_tls: bool = False
    rules: List[RequestRule] = field(default_factory=list)


@dataclass
class NetworkMembership:
    network: str
    ingress_ports: List[int] = field(default_factory=list)
    allow_egress: bool = True
    allow_ingress: bool = True
    alias: str = ""


@dataclass
class VolumeMount:
    volume: str
    path: str
    read_only: bool = False


@dataclass
class SandboxPolicy:
    resources: ResourcePolicy = field(default_factory=ResourcePolicy)
    lifetime: LifetimePolicy = field(default_factory=LifetimePolicy)
    snapshots: SnapshotPolicy = field(default_factory=SnapshotPolicy)
    exec_policy: Optional[ExecPolicy] = None
    fs: Optional[FsPolicy] = None
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    networks: List[NetworkMembership] = field(default_factory=list)
    volumes: List[VolumeMount] = field(default_factory=list)


@dataclass
class SandboxInfo:
    id: str
    name: str
    node_id: str
    template: str
    state: str
    created_at: datetime
    guest_ip: str
    tags: Dict[str, str]
    policy: SandboxPolicy
    unreachable: bool
    usage: Usage
    # Suspended with its latest suspend in the object store, so it can resume
    # on another node. A durable sandbox with an empty `node_id` is held by no
    # node, and its next resume places it.
    durable: bool = False
    hypervisor: str = ""
    hypervisor_version: str = ""
    arch: str = ""
    guest_os: str = ""
    # Dedicated public addresses attached to it.
    public_ips: List["PublicIp"] = field(default_factory=list)
    # Its own global IPv6 address from its node's routed prefix; "" for none.
    ipv6_address: str = ""


@dataclass
class PublicIp:
    """A dedicated public address, as the orchestrator records it."""

    address: str
    # 4 or 6.
    family: int
    # The prefix routed to the sandbox: 32, or 128 or a subnet for IPv6.
    prefix_len: int
    pool: str
    # "allocated", or "quarantined" while a released address sits out.
    state: str
    # "" while detached.
    sandbox_id: str
    # The node it reaches. A sandbox holding it stays there.
    node_id: str
    allocated_at: datetime
    # None while detached.
    attached_at: Optional[datetime]
    # Set while a released address sits out its quarantine.
    quarantined_until: Optional[datetime]


@dataclass
class IpPool:
    """Where public addresses come from. Operator configuration.

    One node (``node_id``) or every node carrying all of ``node_labels``.
    IPv4 ``ranges`` as ``"first-last"`` and single ``addresses`` with their
    ``gateway`` and its network's ``prefix_len``; or an IPv6 ``prefix6`` and
    the share each sandbox gets, ``per_sandbox``. ``total`` and
    ``allocated`` are read only.
    """

    name: str
    node_id: str = ""
    node_labels: Dict[str, str] = field(default_factory=dict)
    ranges: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    gateway: str = ""
    prefix_len: int = 0
    nameservers: List[str] = field(default_factory=list)
    prefix6: str = ""
    per_sandbox: int = 0
    # The upstream looks addresses up on the uplink, so the node answers for
    # them there.
    on_link: bool = False
    allow_smtp: bool = False
    wake_on_traffic: bool = False
    # 0 is the orchestrator's default.
    quarantine_secs: int = 0
    total: int = 0
    allocated: int = 0


@dataclass
class ResourceOutcome:
    """What became of one field of `Sandbox.update_resources`."""

    # "live": applied to the running guest. "next_boot": recorded on a
    # shut-down sandbox for its next boot. "offline": a shut-down sandbox's
    # disk resized now. "refused": not applied, and `reason` says why.
    # "unchanged": it already had that value.
    change: str
    previous: int
    # What the sandbox has now: the value asked for, or `previous` when
    # refused.
    value: int
    reason: str = ""


@dataclass
class ResourcesUpdate:
    """What `Sandbox.update_resources` did, a field per one asked for."""

    vcpus: Optional[ResourceOutcome] = None
    memory_mib: Optional[ResourceOutcome] = None
    disk_mib: Optional[ResourceOutcome] = None
    # The root filesystem's size after a disk change, in bytes. 0 when no
    # guest has seen the disk yet: a shut-down sandbox grown, whose guest fills
    # it on its next boot.
    filesystem_bytes: int = 0


@dataclass
class Session:
    """One VM boot inside a sandbox's life."""

    id: str
    sandbox_id: str
    started_at: datetime
    # None while the session is open, and for one the node died during.
    ended_at: Optional[datetime]
    # "boot", "restore" or "resume".
    started_by: str
    # "suspended", "deleted", "stopped", "failed", "unknown", or "" while open.
    ended_by: str


@dataclass
class CommandInfo:
    """One command the sandbox has run."""

    cmd_id: str
    cmd: List[str]
    user: str
    # "running", "exited", or "unknown".
    state: str
    exit_code: int
    started_at: datetime
    ended_at: Optional[datetime]
    # Output held in the sandbox for a later attach.
    buffered_bytes: int
    # The signal that ended the command; 0 if none did.
    exit_signal: int = 0
    # Output produced in all, which is the offset an up-to-date reader
    # resumes from.
    output_bytes: int = 0


@dataclass
class WatchEvent:
    # "created", "modified" or "deleted".
    kind: str
    path: str
    is_dir: bool


@dataclass
class PortMapping:
    guest_port: int
    host_port: int
    url: str
    # Empty unless the holding node's edge is serving, and always empty for a
    # UDP mapping, which the edge cannot route.
    edge_url: str = ""
    udp: bool = False


@dataclass
class Share:
    """A sandbox reachable through a tailcat address.

    The address is the credential: any `tailcat` client holding it can
    connect, unless `allowed_clients` narrows that. Treat it as a secret.
    """

    address: str
    # Guest TCP ports reachable through the share; empty means every port.
    ports: List[int]
    # `nodekey:<hex>` of each admitted client; empty admits anyone.
    allowed_clients: List[str]
    # When the current keys were issued.
    created_at: datetime
    # Guest UDP ports reachable through the share; none unless listed or all_udp.
    udp_ports: List[int] = field(default_factory=list)
    all_udp: bool = False
    # What the share is doing: connections sourced from each client's own
    # public IPv4, or from the gateway when the node cannot carry the reply
    # path whatever was asked for.
    transparent_ip: bool = True


@dataclass
class GuestUser:
    username: str
    uid: int
    gid: int
    home: str


@dataclass
class GuestGroup:
    groupname: str
    gid: int
    shared_dir: str


@dataclass
class DeletedUser:
    home: str
    home_removed: bool


@dataclass
class DeletedGroup:
    shared_dir: str
    shared_dir_removed: bool


@dataclass
class PrunedCommands:
    removed: int
    freed_bytes: int


@dataclass
class DiskCapacity:
    """A node's data filesystem, as its last heartbeat reported it. A total of
    0 is a node that does not report disk."""

    free_bytes: int = 0
    total_bytes: int = 0
    reserve_bytes: int = 0
    unwritten_bytes: int = 0
    overcommit: float = 0.0


@dataclass
class NodeInfo:
    id: str
    address: str
    hostname: str
    total_vcpus: int
    total_memory_mib: int
    free_memory_mib: int
    running_sandboxes: int
    healthy: bool
    draining: bool
    labels: Dict[str, str]
    # Cpu architecture and each offered hypervisor's version. A durable
    # snapshot only restores on a node where both match what took it.
    arch: str = ""
    hypervisor_versions: Dict[str, str] = field(default_factory=dict)
    disk: DiskCapacity = field(default_factory=DiskCapacity)
    disk_low: bool = False
    last_heartbeat_at: Optional[datetime] = None


@dataclass
class DrainResult:
    suspended: int
    # Sandboxes kept on the node by their public IPs.
    pinned_sandbox_ids: List[str] = field(default_factory=list)


@dataclass
class Health:
    version: str


@dataclass
class AuditEvent:
    at: datetime
    sandbox_id: str
    source_ip: str
    destination: str
    host: str
    port: int
    allowed: bool
    reason: str
    bytes_sent: int
    bytes_received: int
    node_id: str


@dataclass
class LifecycleEvent:
    """One thing that happened to a sandbox, from the fleet's lifecycle log.

    Each event carries the sandbox's cpu and network totals at that instant, so
    the interval between two events is time spent in one state at one shape.
    """

    # Position in the fleet-wide log. Pass it as `after` to resume.
    seq: int
    node_id: str
    # Position in the recording node's own log.
    node_seq: int
    at: datetime
    sandbox_id: str
    # "created", "started", "agent_ready", "stopped", "destroyed",
    # "snapshot_created", "recovered" for each sandbox a node found on
    # restart, or "ip_attached" and "ip_detached" with the address as detail.
    kind: str
    state: str
    # How a VM started ("boot", "restore", "resume") or stopped ("suspended",
    # "deleted", "stopped", "failed", or "lost" for a VM a node found gone on
    # restart), what a sandbox was created from ("fork:<id>",
    # "snapshot:<id>"), or the snapshot a commit produced.
    detail: str
    template: str
    tags: Dict[str, str]
    cpu_usage_usec: int
    rx_bytes: int
    tx_bytes: int
    vcpus: int
    memory_mib: int


@dataclass
class TemplateInfo:
    name: str
    size_bytes: int
    # True when it has a warm snapshot at some shape: creates asking for that
    # vCPU and memory size restore it instead of booting.
    warm: bool
    # Imported from Sandbox Kits: creates run their lifecycle.
    kit: bool = False
    # Sandboxes from it run systemd under the agent.
    systemd: bool = False
    # "linux", "windows" or "macos".
    guest_os: str = ""
    hypervisor: str = ""


@dataclass
class BuiltTemplate:
    """What a build reports when it finishes."""

    name: str
    size_bytes: int


@dataclass
class UsageInterval:
    """One stretch a sandbox spent in one state at one shape, from the usage
    ledger. The usage is the difference of the sandbox's totals at the two
    bounds, so it survives the sandbox and its node."""

    # Ledger row id, ascending in write order. 0 for an open interval.
    id: int
    sandbox_id: str
    node_id: str
    template: str
    tags: Dict[str, str]
    # "running", "suspended" or "stopped".
    state: str
    vcpus: int
    memory_mib: int
    started_at: datetime
    ended_at: datetime
    cpu_usage_usec: int
    rx_bytes: int
    tx_bytes: int
    # The event kind that ended the state, "checkpoint" for the hourly split,
    # or "write_off" for a node that went silent. Empty while open.
    closed_by: str
    open: bool


@dataclass
class UsageSum:
    """Intervals summed for one group in one state."""

    group: str
    state: str
    intervals: int
    duration_ms: int
    # Duration weighted by vCPUs, for vCPU-hours.
    vcpu_ms: int
    # Duration weighted by memory, for GiB-hours.
    memory_mib_ms: int
    cpu_usage_usec: int
    rx_bytes: int
    tx_bytes: int


@dataclass
class UsageReport:
    intervals: List[UsageInterval] = field(default_factory=list)
    sums: List[UsageSum] = field(default_factory=list)
    # Pass as `after_id` for the next page; 0 when there is none.
    next_after_id: int = 0
