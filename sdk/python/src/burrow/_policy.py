"""Policy conversion between the SDK's dataclasses and the wire shape
`burrow.common.v1.Policy`, so nothing else assembles proto objects inline.

Every section is read and written through the same dataclass, so a policy
read back from a sandbox can be passed straight into an update. A dict is
accepted wherever a dataclass is, and converted through it, which is what
refuses a key burrow does not implement rather than dropping it: a misspelt
``match`` would widen a credential from one path and method to every request
to the domain.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Dict, List, Optional, Sequence, Type, TypeVar, Union

from ._pb import common_pb2
from ._wire import label, value
from .errors import BurrowError
from .types import (
    ExecPolicy,
    FsPolicy,
    IngressRule,
    LifetimePolicy,
    NetworkMembership,
    NetworkPolicy,
    PortRule,
    RequestRule,
    ResourcePolicy,
    SandboxPolicy,
    SnapshotPolicy,
    VolumeMount,
)

T = TypeVar("T")

_MODES = ("none", "allowlist", "open")
_PROTOCOLS = {"any": "UNSPECIFIED", "tcp": "TCP", "udp": "UDP"}
_INGRESS_PROTOCOLS = {"any": "UNSPECIFIED", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
_MATCH_KEYS = {"path", "method", "query_string", "headers"}
_FORWARD_KEYS = {"url", "secret"}


def _check_keys(where: str, given: Dict[str, Any], known: Sequence[str]) -> None:
    for key in given:
        if key not in known:
            raise BurrowError(
                f"{where}: unknown key {key!r}; one of {', '.join(sorted(known))}",
                "invalid_argument",
            )


def as_section(cls: Type[T], where: str, given: Any) -> T:
    """`given` as an instance of `cls`: itself, a dict converted through it, or
    the default for `None`."""
    if given is None:
        return cls()
    if isinstance(given, cls):
        return given
    if not isinstance(given, dict):
        raise BurrowError(f"{where}: a {cls.__name__} or a dict", "invalid_argument")
    _check_keys(where, given, [f.name for f in dataclasses.fields(cls)])
    try:
        return cls(**given)
    except TypeError as err:
        raise BurrowError(f"{where}: {err}", "invalid_argument") from None


def network_policy(network: Any) -> NetworkPolicy:
    """A mode, a dict or a `NetworkPolicy` as a `NetworkPolicy`."""
    if isinstance(network, str):
        network = {"mode": network}
    policy = as_section(NetworkPolicy, "network_policy", network)
    if policy.mode not in _MODES:
        raise BurrowError(
            f"network_policy: unknown mode {policy.mode!r}; one of {', '.join(_MODES)}",
            "invalid_argument",
        )
    policy.deny_ports = [
        _port_rule(index, rule) for index, rule in enumerate(policy.deny_ports)
    ]
    policy.ingress = [
        _ingress_rule(index, rule) for index, rule in enumerate(policy.ingress)
    ]
    policy.rules = [_request_rule(rule) for rule in policy.rules]
    return policy


def _port_rule(index: int, rule: Any) -> PortRule:
    where = f"network_policy.deny_ports[{index}]"
    rule = as_section(PortRule, where, rule)
    if rule.protocol not in _PROTOCOLS:
        raise BurrowError(
            f"{where}: unknown protocol {rule.protocol!r}; one of tcp, udp, any",
            "invalid_argument",
        )
    if not isinstance(rule.port, int) or isinstance(rule.port, bool):
        raise BurrowError(f"{where}: port is an integer", "invalid_argument")
    return rule


def _ingress_rule(index: int, rule: Any) -> IngressRule:
    where = f"network_policy.ingress[{index}]"
    rule = as_section(IngressRule, where, rule)
    if rule.protocol not in _INGRESS_PROTOCOLS:
        raise BurrowError(
            f"{where}: unknown protocol {rule.protocol!r}; one of tcp, udp, icmp, any",
            "invalid_argument",
        )
    for entry in rule.ports:
        if isinstance(entry, bool) or not re.fullmatch(r"(\d+)(?:-(\d+))?", str(entry)):
            raise BurrowError(f"{where}: port {entry!r} is not N or N-M", "invalid_argument")
    return rule


def _to_port_range(entry: Union[int, str]) -> common_pb2.PortRange:
    first, _, last = str(entry).partition("-")
    return common_pb2.PortRange(port=int(first), port_end=int(last) if last else 0)


def _from_ingress_rule(raw: common_pb2.IngressRule) -> IngressRule:
    return IngressRule(
        protocol=label(common_pb2.IngressProtocol, raw.protocol, "INGRESS_PROTOCOL_") or "any",
        ports=[
            f"{entry.port}-{entry.port_end}" if entry.port_end else entry.port
            for entry in raw.ports
        ],
        sources=list(raw.sources),
    )


def _request_rule(rule: Any) -> RequestRule:
    domain = rule.get("domain", "") if isinstance(rule, dict) else rule.domain
    where = f"network_policy.rules[{domain!r}]"
    rule = as_section(RequestRule, where, rule)
    _check_keys(f"{where}.match", rule.match or {}, _MATCH_KEYS)
    _check_keys(f"{where}.forward", rule.forward or {}, _FORWARD_KEYS)
    if rule.set_headers and rule.forward:
        raise BurrowError(
            f"{where}: a rule either sets headers or forwards, not both",
            "invalid_argument",
        )
    if not rule.set_headers and not rule.forward:
        raise BurrowError(
            f"{where}: a rule needs either set_headers or forward",
            "invalid_argument",
        )
    expires_at = rule.expires_at_unix_ms
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at < 0:
        raise BurrowError(
            f"{where}: expires_at_unix_ms is unix milliseconds, or 0 for never",
            "invalid_argument",
        )
    if rule.forward:
        _check_forward_url(where, rule.forward.get("url", ""))
    for name in rule.set_headers or {}:
        _check_header_name(where, name)
    return rule


_OPS = ("exact", "starts_with", "regex")


def _to_string_match(where: str, given: Any) -> common_pb2.StringMatch:
    """Builds one wire `StringMatch`. A bare string is the exact match it reads as."""
    if isinstance(given, str):
        return common_pb2.StringMatch(op=common_pb2.STRING_MATCH_OP_EXACT, value=given)
    if not isinstance(given, dict):
        raise BurrowError(
            f"{where}: a match is a string or one of {{exact, starts_with, regex}}",
            "invalid_argument",
        )
    named = [key for key in given if key in _OPS]
    if len(named) != 1 or len(given) != 1:
        raise BurrowError(
            f"{where}: a match names exactly one of exact, starts_with or regex",
            "invalid_argument",
        )
    pattern = given[named[0]]
    if not isinstance(pattern, str):
        raise BurrowError(f"{where}: a match pattern is a string", "invalid_argument")
    return common_pb2.StringMatch(
        op=value(common_pb2.StringMatchOp, named[0], "STRING_MATCH_OP_", where),
        value=pattern,
    )


def _to_field_matches(where: str, fields: Any) -> List[common_pb2.FieldMatch]:
    return [
        common_pb2.FieldMatch(key=key, value=_to_string_match(f"{where}[{key!r}]", given))
        for key, given in (fields or {}).items()
    ]


def _to_request_match(where: str, match: Any) -> Optional[common_pb2.RequestMatch]:
    if not match:
        return None
    method = match.get("method")
    methods = [] if method is None else method if isinstance(method, list) else [method]
    wire = common_pb2.RequestMatch(
        methods=methods,
        query=_to_field_matches(f"{where}.query_string", match.get("query_string")),
        headers=_to_field_matches(f"{where}.headers", match.get("headers")),
    )
    if match.get("path") is not None:
        wire.path.CopyFrom(_to_string_match(f"{where}.path", match["path"]))
    return wire


def _to_request_rule(rule: RequestRule) -> common_pb2.RequestRule:
    where = f"network_policy.rules[{rule.domain!r}]"
    wire = common_pb2.RequestRule(
        domain=rule.domain,
        expires_at_unix_ms=rule.expires_at_unix_ms,
        bound_sandbox_id=rule.bound_sandbox_id,
    )
    match = _to_request_match(where, rule.match)
    if match is not None:
        wire.match.CopyFrom(match)
    if rule.forward:
        wire.forward.url = rule.forward["url"]
        wire.forward.secret = rule.forward.get("secret") or ""
    else:
        for name, header in (rule.set_headers or {}).items():
            wire.set_headers.headers.append(common_pb2.HeaderValue(name=name, value=header))
    return wire


def _check_forward_url(where: str, url: str) -> None:
    """Refuses a forward URL burrow would refuse anyway, where it is easier to
    read. Exactly the node's own rules and no others, so the client never
    rejects a policy the node would accept."""
    if not re.match(r"^https?://", url):
        raise BurrowError(
            f"{where}: a forward url must begin with http:// or https://",
            "invalid_argument",
        )
    if "?" in url or "#" in url:
        raise BurrowError(
            f"{where}: a forward url may not carry a query string or a fragment",
            "invalid_argument",
        )


def _check_header_name(where: str, name: str) -> None:
    if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name):
        raise BurrowError(f"{where}: {name!r} is not a valid header name", "invalid_argument")


def _from_request_rule(raw: common_pb2.RequestRule) -> RequestRule:
    """Reads one wire `RequestRule` back. Secrets arrive redacted."""
    rule = RequestRule(
        domain=raw.domain,
        expires_at_unix_ms=raw.expires_at_unix_ms,
        bound_sandbox_id=raw.bound_sandbox_id,
    )
    if raw.HasField("match"):
        rule.match = _from_request_match(raw.match)
    if raw.HasField("forward"):
        rule.forward = {"url": raw.forward.url, "secret": raw.forward.secret}
    elif raw.HasField("set_headers"):
        rule.set_headers = {header.name: header.value for header in raw.set_headers.headers}
    return rule


def _from_request_match(raw: common_pb2.RequestMatch) -> Dict[str, Any]:
    match: Dict[str, Any] = {}
    if raw.HasField("path"):
        match["path"] = _from_string_match(raw.path)
    if raw.methods:
        match["method"] = list(raw.methods)
    if raw.query:
        match["query_string"] = {f.key: _from_string_match(f.value) for f in raw.query}
    if raw.headers:
        match["headers"] = {f.key: _from_string_match(f.value) for f in raw.headers}
    return match


def _from_string_match(raw: common_pb2.StringMatch) -> Dict[str, str]:
    return {label(common_pb2.StringMatchOp, raw.op, "STRING_MATCH_OP_") or "exact": raw.value}


def to_network_policy(policy: NetworkPolicy) -> common_pb2.NetworkPolicy:
    return common_pb2.NetworkPolicy(
        mode=value(common_pb2.NetworkMode, policy.mode, "NETWORK_MODE_", "network_policy"),
        allow_domains=policy.allow_domains,
        allow_cidrs=policy.allow_cidrs,
        allow_ports=policy.allow_ports,
        deny_cidrs=policy.deny_cidrs,
        deny_domains=policy.deny_domains,
        deny_ports=[
            common_pb2.PortRule(
                protocol=getattr(common_pb2, f"PORT_PROTOCOL_{_PROTOCOLS[rule.protocol]}"),
                port=rule.port,
                port_end=rule.port_end,
                cidrs=rule.cidrs,
            )
            for rule in policy.deny_ports
        ],
        is_ipv6_denied=policy.deny_ipv6,
        ingress=[
            common_pb2.IngressRule(
                protocol=getattr(
                    common_pb2, f"INGRESS_PROTOCOL_{_INGRESS_PROTOCOLS[rule.protocol]}"
                ),
                ports=[_to_port_range(entry) for entry in rule.ports],
                sources=rule.sources,
            )
            for rule in policy.ingress
        ],
        is_tls_inspected=policy.inspect_tls,
        rules=[_to_request_rule(rule) for rule in policy.rules],
    )


def from_network_policy(raw: common_pb2.NetworkPolicy) -> NetworkPolicy:
    """Reads a `NetworkPolicy` back. Secrets arrive redacted."""
    return NetworkPolicy(
        mode=label(common_pb2.NetworkMode, raw.mode, "NETWORK_MODE_") or "none",
        allow_domains=list(raw.allow_domains),
        allow_cidrs=list(raw.allow_cidrs),
        allow_ports=list(raw.allow_ports),
        deny_cidrs=list(raw.deny_cidrs),
        deny_domains=list(raw.deny_domains),
        deny_ports=[
            PortRule(
                protocol=label(common_pb2.PortProtocol, rule.protocol, "PORT_PROTOCOL_") or "any",
                port=rule.port,
                port_end=rule.port_end,
                cidrs=list(rule.cidrs),
            )
            for rule in raw.deny_ports
        ],
        deny_ipv6=raw.is_ipv6_denied,
        ingress=[_from_ingress_rule(rule) for rule in raw.ingress],
        inspect_tls=raw.is_tls_inspected,
        rules=[_from_request_rule(rule) for rule in raw.rules],
    )


def to_resources(resources: ResourcePolicy) -> common_pb2.ResourcePolicy:
    return common_pb2.ResourcePolicy(
        vcpus=resources.vcpus,
        mem_mib=resources.memory_mib,
        disk_mib=resources.disk_mib,
    )


def from_resources(raw: common_pb2.ResourcePolicy) -> ResourcePolicy:
    return ResourcePolicy(vcpus=raw.vcpus, memory_mib=raw.mem_mib, disk_mib=raw.disk_mib)


def to_lifetime(lifetime: LifetimePolicy) -> common_pb2.LifetimePolicy:
    return common_pb2.LifetimePolicy(
        max_lifetime_secs=lifetime.max_lifetime_secs,
        idle_suspend_secs=lifetime.idle_suspend_secs,
        suspended_ttl_secs=lifetime.suspended_ttl_secs,
        checkpoint_secs=lifetime.checkpoint_secs,
        is_memory_checkpointed=lifetime.checkpoint_memory,
    )


def from_lifetime(raw: common_pb2.LifetimePolicy) -> LifetimePolicy:
    return LifetimePolicy(
        max_lifetime_secs=raw.max_lifetime_secs,
        idle_suspend_secs=raw.idle_suspend_secs,
        suspended_ttl_secs=raw.suspended_ttl_secs,
        checkpoint_secs=raw.checkpoint_secs,
        checkpoint_memory=raw.is_memory_checkpointed,
    )


def to_snapshots(snapshots: SnapshotPolicy) -> common_pb2.SnapshotPolicy:
    return common_pb2.SnapshotPolicy(
        expiration_secs=snapshots.expiration_secs,
        keep_last=snapshots.keep_last,
        is_evicted_kept=snapshots.evicted_kept,
    )


def from_snapshots(raw: common_pb2.SnapshotPolicy) -> SnapshotPolicy:
    return SnapshotPolicy(
        expiration_secs=raw.expiration_secs,
        keep_last=raw.keep_last,
        evicted_kept=raw.is_evicted_kept,
    )


def to_networks(
    networks: Optional[Sequence[Union[str, Dict[str, Any], NetworkMembership]]],
    alias: str = "",
) -> List[common_pb2.NetworkMembership]:
    """Normalises private-network memberships.

    A bare string is the common case: join the network, talk both ways, answer
    to the sandbox id. The dict and dataclass forms are there for the rest.
    """
    out = []
    for index, entry in enumerate(networks or []):
        if isinstance(entry, str):
            entry = {"network": entry}
        membership = as_section(NetworkMembership, f"networks[{index}]", entry)
        out.append(
            common_pb2.NetworkMembership(
                network=membership.network,
                ingress_ports=membership.ingress_ports,
                is_egress_allowed=membership.allow_egress,
                is_ingress_allowed=membership.allow_ingress,
                alias=membership.alias or alias,
            )
        )
    return out


def from_networks(raw: Any) -> List[NetworkMembership]:
    return [
        NetworkMembership(
            network=entry.network,
            ingress_ports=list(entry.ingress_ports),
            allow_egress=entry.is_egress_allowed,
            allow_ingress=entry.is_ingress_allowed,
            alias=entry.alias,
        )
        for entry in raw
    ]


def to_exec_policy(given: Any) -> Optional[common_pb2.ExecPolicy]:
    """Builds the wire `ExecPolicy`, or nothing at all.

    An absent section means "allowed" to the node, so options that restrict
    nothing send no section rather than a permissive one.
    """
    if given is None:
        return None
    policy = as_section(ExecPolicy, "exec_policy", given)
    return common_pb2.ExecPolicy(is_exec_allowed=policy.allow_exec)


def to_fs_policy(given: Any) -> Optional[common_pb2.FsPolicy]:
    """Builds the wire `FsPolicy`, or nothing at all."""
    if given is None:
        return None
    policy = as_section(FsPolicy, "fs", given)
    return common_pb2.FsPolicy(
        is_upload_allowed=policy.allow_upload,
        is_download_allowed=policy.allow_download,
        path_scopes=policy.path_scopes,
        max_upload_bytes=policy.max_upload_bytes,
    )


def from_exec_policy(raw: Any, present: bool) -> Optional[ExecPolicy]:
    if not present:
        return None
    return ExecPolicy(allow_exec=raw.is_exec_allowed)


def from_fs_policy(raw: Any, present: bool) -> Optional[FsPolicy]:
    if not present:
        return None
    return FsPolicy(
        allow_upload=raw.is_upload_allowed,
        allow_download=raw.is_download_allowed,
        path_scopes=list(raw.path_scopes),
        max_upload_bytes=raw.max_upload_bytes,
    )


def to_volume_mounts(
    mounts: Optional[Sequence[Union[Dict[str, Any], VolumeMount]]],
) -> List[common_pb2.VolumeMount]:
    out = []
    for index, entry in enumerate(mounts or []):
        mount = as_section(VolumeMount, f"volumes[{index}]", entry)
        out.append(
            common_pb2.VolumeMount(
                volume=mount.volume, path=mount.path, is_read_only=mount.read_only
            )
        )
    return out


def from_volume_mounts(raw: Any) -> List[VolumeMount]:
    return [
        VolumeMount(
            volume=mount.volume,
            path=mount.path,
            read_only=mount.is_read_only,
            generation=mount.generation,
        )
        for mount in raw
    ]


def to_policy(
    *,
    resources: Any = None,
    lifetime: Any = None,
    snapshots: Any = None,
    network_policy: Any = None,
    networks: Any = None,
    alias: str = "",
    exec_policy: Any = None,
    fs: Any = None,
    volumes: Any = None,
) -> common_pb2.Policy:
    """Builds a whole `Policy`. Sections that are `None` are sent empty, which
    the node reads as its default; exec and fs are left off entirely, since
    absent is what the node reads as "allowed"."""
    policy = common_pb2.Policy(
        resources=to_resources(as_section(ResourcePolicy, "resources", resources)),
        lifetime=to_lifetime(as_section(LifetimePolicy, "lifetime", lifetime)),
        snapshots=to_snapshots(as_section(SnapshotPolicy, "snapshots", snapshots)),
        network=to_network_policy(network_policy_or_default(network_policy)),
        networks=to_networks(networks, alias),
        volumes=to_volume_mounts(volumes),
    )
    exec_wire = to_exec_policy(exec_policy)
    if exec_wire is not None:
        policy.exec.CopyFrom(exec_wire)
    fs_wire = to_fs_policy(fs)
    if fs_wire is not None:
        policy.fs.CopyFrom(fs_wire)
    return policy


def network_policy_or_default(network: Any) -> NetworkPolicy:
    """No egress at all unless asked for."""
    return network_policy(network) if network is not None else NetworkPolicy()


def from_policy(raw: common_pb2.Policy) -> SandboxPolicy:
    return SandboxPolicy(
        resources=from_resources(raw.resources),
        lifetime=from_lifetime(raw.lifetime),
        snapshots=from_snapshots(raw.snapshots),
        exec_policy=from_exec_policy(raw.exec, raw.HasField("exec")),
        fs=from_fs_policy(raw.fs, raw.HasField("fs")),
        network=from_network_policy(raw.network),
        networks=from_networks(raw.networks),
        volumes=from_volume_mounts(raw.volumes),
    )
