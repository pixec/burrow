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

    @property
    def metadata(self) -> Dict[str, str]:
        return self.tags


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
class OutputChunk:
    """One piece of a running command's output."""

    # "stdout", "stderr" or "exit".
    type: str
    data: str = ""
    exit_code: int = 0


@dataclass
class CommandResult:
    """A finished command's output and exit."""

    stdout: str
    stderr: str
    exit_code: int
    success: bool


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
    buffered_bytes: int


@dataclass
class DirEntry:
    name: str
    is_dir: bool
    size: int
    mode: int


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
    # Empty unless the holding node's edge is serving.
    edge_url: str = ""


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
class TemplateInfo:
    name: str
    size_bytes: int
    # True when creates from this template restore a snapshot instead of
    # booting.
    warm: bool
