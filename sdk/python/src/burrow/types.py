"""The SDK's data shapes: what calls return, read back from the wire."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Usage:
    """What a sandbox has consumed, accumulated across every VM it has run."""

    cpu_usage_usec: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass
class ResourcePolicy:
    vcpus: int = 0
    memory_mib: int = 0
    disk_mib: int = 0
    max_lifetime_secs: int = 0
    idle_suspend_secs: int = 0
    suspended_ttl_secs: int = 0
    snapshot_expiration_secs: int = 0
    keep_last_snapshots: int = 0
    keep_evicted_snapshots: bool = False


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
    """A rule the proxy applies to inspected requests to one domain."""

    domain: str
    match: Optional[dict] = None
    set_headers: Optional[Dict[str, str]] = None
    forward: Optional[dict] = None


@dataclass
class HeaderInjection:
    domain: str
    name: str
    value: str


@dataclass
class NetworkPolicy:
    mode: str = "none"
    allow_domains: List[str] = field(default_factory=list)
    allow_cidrs: List[str] = field(default_factory=list)
    allow_ports: List[int] = field(default_factory=list)
    deny_cidrs: List[str] = field(default_factory=list)
    inspect_tls: bool = False
    rules: List[RequestRule] = field(default_factory=list)
    # The rules that are exactly what `inject_headers` used to describe, so
    # code written before rules existed still reads what it wrote.
    inject_headers: List[HeaderInjection] = field(default_factory=list)


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
    exec: Optional[ExecPolicy] = None
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
    created_at: str
    guest_ip: str
    tags: Dict[str, str]
    policy: SandboxPolicy
    unreachable: bool
    usage: Usage
    # Suspended with its latest suspend in the object store, so it can resume
    # on another node. A durable sandbox with an empty `node_id` is held by no
    # node, and its next resume places it.
    durable: bool = False


@dataclass
class Session:
    """One VM boot inside a sandbox's life."""

    id: str
    sandbox_id: str
    started_at: str
    ended_at: str
    # "boot", "restore", "resume", or "unknown".
    started_by: str
    # "suspended", "deleted", "failed", "unknown", or "" while open.
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
    type: str
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
    # RFC 3339; when the current keys were issued.
    created_at: str
    # Guest UDP ports reachable through the share; none unless listed or all_udp.
    udp_ports: List[int] = field(default_factory=list)
    all_udp: bool = False
    # Packet source is the last disco-pong-verified public IPv4.
    # What the share is doing: a node that cannot carry the reply path
    # serves from the gateway whatever was asked for.
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
    # Cpu architecture and Firecracker version. A durable snapshot only
    # restores on a node where both match.
    arch: str = ""
    firecracker_version: str = ""


@dataclass
class AuditEvent:
    at: str
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
    at_unix_ms: int
    sandbox_id: str
    # "created", "started", "agent_ready", "stopped", "destroyed",
    # "snapshot_created", or "recovered" for each sandbox a node found on
    # restart.
    type: str
    state: str
    # How a VM started ("boot", "restore", "resume") or stopped ("suspended",
    # "deleted", "stopped", "failed", or "lost" for a VM a node found gone on
    # restart), what a sandbox was created from ("fork:<id>",
    # "snapshot:<id>"), or the snapshot a commit produced.
    detail: str
    template: str
    metadata: Dict[str, str]
    cpu_usage_usec: int
    rx_bytes: int
    tx_bytes: int
    vcpus: int
    memory_mib: int


@dataclass
class TemplateInfo:
    name: str
    size_bytes: int
    # True when creates from this template restore a snapshot instead of
    # booting.
    warm: bool
    # Imported from Sandbox Kits: creates run their lifecycle.
    kit: bool = False
    # Sandboxes from it run systemd under the agent.
    systemd: bool = False


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
    metadata: Dict[str, str]
    # "running", "suspended" or "stopped".
    state: str
    vcpus: int
    memory_mib: int
    started_at_unix_ms: int
    ended_at_unix_ms: int
    cpu_usage_usec: int
    rx_bytes: int
    tx_bytes: int
    # The event type that ended the state, "checkpoint" for the hourly split,
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
