"""Policy conversion between the SDK's flat options and the wire shape
`burrow.common.v1.Policy`, so nothing else assembles proto objects inline."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Union

from ._pb import common_pb2
from .errors import BurrowError
from .types import (
    ExecPolicy,
    FsPolicy,
    HeaderInjection,
    NetworkMembership,
    NetworkPolicy,
    RequestRule,
    ResourcePolicy,
    SandboxPolicy,
    VolumeMount,
)

_MODE_TO_WIRE = {
    "none": common_pb2.NETWORK_MODE_NONE,
    "allowlist": common_pb2.NETWORK_MODE_ALLOWLIST,
    "open": common_pb2.NETWORK_MODE_OPEN,
}

_MODE_FROM_WIRE = {
    common_pb2.NETWORK_MODE_NONE: "none",
    common_pb2.NETWORK_MODE_ALLOWLIST: "allowlist",
    common_pb2.NETWORK_MODE_OPEN: "open",
}


def resolve_network(
    network: Any,
    allow_domains: Optional[List[str]] = None,
    allow_cidrs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Normalises the two ways a network can be described.

    ``network="allowlist"`` with sibling ``allow_domains`` is the original
    shape and still works; a dict carries the fields the shorthand has no room
    for, and ``{"allow": ..., "subnets": ...}`` is the shorthand mapped onto a
    full policy.
    """
    legacy = {"allow_domains": allow_domains, "allow_cidrs": allow_cidrs}
    if isinstance(network, str):
        mode = {"allow-all": "open", "deny-all": "none"}.get(network, network)
        return {"mode": mode, **legacy}
    if network and _is_shorthand(network):
        return _with_legacy(_from_shorthand(network), legacy)
    if network:
        out = dict(network)
        if out.get("allow_domains") is None:
            out["allow_domains"] = allow_domains
        if out.get("allow_cidrs") is None:
            out["allow_cidrs"] = allow_cidrs
        return out
    return legacy


def _with_legacy(base: Dict[str, Any], legacy: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    if legacy.get("allow_domains"):
        out["allow_domains"] = (out.get("allow_domains") or []) + legacy["allow_domains"]
    if legacy.get("allow_cidrs"):
        out["allow_cidrs"] = (out.get("allow_cidrs") or []) + legacy["allow_cidrs"]
    return out


def _is_shorthand(network: Dict[str, Any]) -> bool:
    # The shorthand and the full policy share no key names, so one key decides;
    # carrying neither is the full form, all defaulted.
    return "allow" in network or "subnets" in network


# Everything burrow understands on a per-domain rule.
_RULE_KEYS = {"match", "transform", "forward_url", "forward_secret"}

# Every dimension a matcher may name.
_MATCH_KEYS = {"path", "method", "query_string", "headers"}


def _check_rule_keys(domain: str, rule: Any) -> None:
    """Refuses a rule key burrow does not implement, rather than dropping it.

    It earns its place because dropping a ``match`` would widen a credential
    from one path and method to every request to the domain.
    """
    if not isinstance(rule, dict):
        return
    where = f"network_policy.allow[{domain!r}]"
    for key in rule:
        if key not in _RULE_KEYS:
            raise BurrowError(
                f"{where}: unknown key {key!r} in a rule for {domain}",
                "invalid_argument",
            )
    if rule.get("transform") and rule.get("forward_url"):
        raise BurrowError(
            f"{where}: a rule either rewrites a request or forwards it, not both",
            "invalid_argument",
        )
    for key in rule.get("match") or {}:
        if key not in _MATCH_KEYS:
            raise BurrowError(
                f"{where}: unknown key {key!r} in a match. Burrow matches on "
                f"path, method, query_string and headers.",
                "invalid_argument",
            )


_OP_TO_WIRE = {
    "exact": common_pb2.STRING_MATCH_OP_EXACT,
    "starts_with": common_pb2.STRING_MATCH_OP_STARTS_WITH,
    "regex": common_pb2.STRING_MATCH_OP_REGEX,
}

_OP_FROM_WIRE = {
    common_pb2.STRING_MATCH_OP_EXACT: "exact",
    common_pb2.STRING_MATCH_OP_STARTS_WITH: "starts_with",
    common_pb2.STRING_MATCH_OP_REGEX: "regex",
}


def _to_string_match(where: str, value: Any) -> common_pb2.StringMatch:
    """Builds one wire `StringMatch`. A bare string is the exact match it reads as."""
    if isinstance(value, str):
        return common_pb2.StringMatch(op=_OP_TO_WIRE["exact"], value=value)
    if not isinstance(value, dict):
        raise BurrowError(
            f"{where}: a match is a string or one of {{exact, starts_with, regex}}",
            "invalid_argument",
        )
    named = [key for key in value if key in _OP_TO_WIRE]
    if len(named) != 1 or len(value) != 1:
        raise BurrowError(
            f"{where}: a match names exactly one of exact, starts_with or regex",
            "invalid_argument",
        )
    pattern = value[named[0]]
    if not isinstance(pattern, str):
        raise BurrowError(f"{where}: a match pattern is a string", "invalid_argument")
    return common_pb2.StringMatch(op=_OP_TO_WIRE[named[0]], value=pattern)


def _to_field_matches(where: str, fields: Any) -> List[common_pb2.FieldMatch]:
    return [
        common_pb2.FieldMatch(
            key=key, value=_to_string_match(f"{where}[{key!r}]", value)
        )
        for key, value in (fields or {}).items()
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


def _to_request_rule(rule: Dict[str, Any]) -> common_pb2.RequestRule:
    """Builds one wire `RequestRule`."""
    domain = rule.get("domain", "")
    where = f"network_policy.rules[{domain!r}]"
    if rule.get("set_headers") and rule.get("forward"):
        raise BurrowError(
            f"{where}: a rule either sets headers or forwards, not both",
            "invalid_argument",
        )
    wire = common_pb2.RequestRule(domain=domain)
    match = _to_request_match(where, rule.get("match"))
    if match is not None:
        wire.match.CopyFrom(match)
    forward = rule.get("forward")
    set_headers = rule.get("set_headers")
    if forward:
        _check_forward_url(where, forward.get("url", ""))
        wire.forward.url = forward["url"]
        wire.forward.secret = forward.get("secret") or ""
    elif set_headers:
        for name, value in set_headers.items():
            _check_header_name(where, name)
            wire.set_headers.headers.append(
                common_pb2.HeaderValue(name=name, value=value)
            )
    else:
        raise BurrowError(
            f"{where}: a rule needs either set_headers or forward",
            "invalid_argument",
        )
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
        raise BurrowError(
            f"{where}: {name!r} is not a valid header name", "invalid_argument"
        )


def _from_request_rule(raw: common_pb2.RequestRule) -> RequestRule:
    """Reads one wire `RequestRule` back. Secrets arrive redacted."""
    rule = RequestRule(domain=raw.domain)
    if raw.HasField("match"):
        rule.match = _from_request_match(raw.match)
    if raw.HasField("forward"):
        rule.forward = {"url": raw.forward.url, "secret": raw.forward.secret}
    elif raw.HasField("set_headers"):
        rule.set_headers = {
            header.name: header.value for header in raw.set_headers.headers
        }
    return rule


def _from_request_match(raw: common_pb2.RequestMatch) -> Dict[str, Any]:
    match: Dict[str, Any] = {}
    if raw.HasField("path"):
        match["path"] = _from_string_match(raw.path)
    if raw.methods:
        match["method"] = list(raw.methods)
    if raw.query:
        match["query_string"] = {
            f.key: _from_string_match(f.value) for f in raw.query
        }
    if raw.headers:
        match["headers"] = {f.key: _from_string_match(f.value) for f in raw.headers}
    return match


def _from_string_match(raw: common_pb2.StringMatch) -> Dict[str, str]:
    return {_OP_FROM_WIRE.get(raw.op, "exact"): raw.value}


def _from_shorthand(shorthand: Dict[str, Any]) -> Dict[str, Any]:
    """Maps ``{allow, subnets}`` onto a burrow policy. Naming any domain is an
    allowlist, the only mode where the proxy sits in the path and can tell one
    domain from another."""
    allow = shorthand.get("allow")
    domains = allow if isinstance(allow, list) else list(allow) if allow else []
    per_domain = allow if isinstance(allow, dict) else {}

    rules: List[Dict[str, Any]] = []
    for domain, written in per_domain.items():
        where = f"network_policy.allow[{domain!r}]"
        for rule in written if isinstance(written, list) else [written]:
            _check_rule_keys(domain, rule)
            if not isinstance(rule, dict):
                continue
            if rule.get("forward_url"):
                rules.append(
                    {
                        "domain": domain,
                        "match": rule.get("match"),
                        "forward": {
                            "url": rule["forward_url"],
                            "secret": rule.get("forward_secret"),
                        },
                    }
                )
                continue
            for transform in rule.get("transform") or []:
                headers = (transform or {}).get("headers")
                if not headers:
                    raise BurrowError(
                        f"{where}: a transform needs headers", "invalid_argument"
                    )
                for name in headers:
                    _check_header_name(where, name)
                rules.append(
                    {"domain": domain, "match": rule.get("match"), "set_headers": headers}
                )
            if not rule.get("transform") and rule.get("match"):
                raise BurrowError(
                    f"{where}: a match selects which requests a rule acts on, "
                    f"so the rule needs a transform or a forward_url",
                    "invalid_argument",
                )

    # A rule on a domain that is not inspected would be silently dropped.
    if rules and not domains:
        raise BurrowError(
            "network_policy: a rule needs its domain in `allow`, since rules "
            "only apply to inspected requests",
            "invalid_argument",
        )

    subnets = shorthand.get("subnets") or {}
    return {
        "mode": "allowlist" if domains or shorthand.get("subnets") else "none",
        "allow_domains": domains,
        "allow_cidrs": subnets.get("allow") or [],
        "deny_cidrs": subnets.get("deny") or [],
        "inspect_tls": bool(rules),
        "rules": rules,
    }


def to_network_policy(options: Optional[Dict[str, Any]] = None) -> common_pb2.NetworkPolicy:
    """Builds the wire `NetworkPolicy`. Defaults to no egress at all."""
    options = options or {}
    mode = options.get("mode") or "none"
    if mode not in _MODE_TO_WIRE:
        raise BurrowError(
            f"network_policy: unknown mode {mode!r}; one of none, allowlist, open",
            "invalid_argument",
        )
    # Rules first, then the injections: an injection carries no matcher, so it
    # claims every request to its domain and would shadow anything after it.
    rules = list(options.get("rules") or [])
    for header in options.get("inject_headers") or []:
        rules.append(
            {
                "domain": header["domain"],
                "set_headers": {header["name"]: header["value"]},
            }
        )
    return common_pb2.NetworkPolicy(
        mode=_MODE_TO_WIRE[mode],
        allow_domains=options.get("allow_domains") or [],
        allow_cidrs=options.get("allow_cidrs") or [],
        allow_ports=options.get("allow_ports") or [],
        deny_cidrs=options.get("deny_cidrs") or [],
        inspect_tls=options.get("inspect_tls") or False,
        rules=[_to_request_rule(rule) for rule in rules],
    )


def from_network_policy(raw: common_pb2.NetworkPolicy) -> NetworkPolicy:
    """Reads a `NetworkPolicy` back. Secrets arrive redacted."""
    rules = [_from_request_rule(rule) for rule in raw.rules]
    return NetworkPolicy(
        mode=_MODE_FROM_WIRE.get(raw.mode, "none"),
        allow_domains=list(raw.allow_domains),
        allow_cidrs=list(raw.allow_cidrs),
        allow_ports=list(raw.allow_ports),
        deny_cidrs=list(raw.deny_cidrs),
        inspect_tls=raw.inspect_tls,
        rules=rules,
        inject_headers=[
            HeaderInjection(domain=rule.domain, name=name, value=value)
            for rule in rules
            if rule.set_headers and not rule.match
            for name, value in rule.set_headers.items()
        ],
    )


def to_resource_policy(options: Optional[Dict[str, Any]] = None) -> common_pb2.ResourcePolicy:
    """Builds the wire `ResourcePolicy`. Zero means "server default" throughout."""
    options = options or {}
    return common_pb2.ResourcePolicy(
        # Zero rather than 1 and 512: sending the defaults as if the caller had
        # asked makes a create from a snapshot look like a shape change.
        vcpus=options.get("vcpus") or 0,
        mem_mib=options.get("memory_mib") or 0,
        scratch_disk_mib=options.get("disk_mib") or 0,
        max_lifetime_secs=options.get("max_lifetime_secs") or 0,
        idle_suspend_secs=options.get("idle_suspend_secs") or 0,
        suspended_ttl_secs=options.get("suspended_ttl_secs") or 0,
        snapshot_expiration_secs=options.get("snapshot_expiration_secs") or 0,
        keep_last_snapshots=options.get("keep_last_snapshots") or 0,
        keep_evicted_snapshots=options.get("keep_evicted_snapshots") or False,
    )


def from_resource_policy(raw: common_pb2.ResourcePolicy) -> ResourcePolicy:
    return ResourcePolicy(
        vcpus=raw.vcpus,
        memory_mib=raw.mem_mib,
        disk_mib=raw.scratch_disk_mib,
        max_lifetime_secs=raw.max_lifetime_secs,
        idle_suspend_secs=raw.idle_suspend_secs,
        suspended_ttl_secs=raw.suspended_ttl_secs,
        snapshot_expiration_secs=raw.snapshot_expiration_secs,
        keep_last_snapshots=raw.keep_last_snapshots,
        keep_evicted_snapshots=raw.keep_evicted_snapshots,
    )


def to_networks(
    networks: Optional[Sequence[Union[str, Dict[str, Any]]]],
    alias: Optional[str] = None,
) -> List[common_pb2.NetworkMembership]:
    """Normalises private-network memberships.

    A bare string is the common case: join the network, talk both ways, answer
    to the sandbox id. The dict form is there for the rest.
    """
    out = []
    for entry in networks or []:
        membership = {"network": entry} if isinstance(entry, str) else entry
        out.append(
            common_pb2.NetworkMembership(
                network=membership["network"],
                ingress_ports=membership.get("ingress_ports") or [],
                allow_egress=membership.get("allow_egress", True),
                allow_ingress=membership.get("allow_ingress", True),
                alias=membership.get("alias") or alias or "",
            )
        )
    return out


def from_networks(raw: Any) -> List[NetworkMembership]:
    return [
        NetworkMembership(
            network=entry.network,
            ingress_ports=list(entry.ingress_ports),
            allow_egress=entry.allow_egress,
            allow_ingress=entry.allow_ingress,
            alias=entry.alias,
        )
        for entry in raw
    ]


def to_exec_policy(options: Optional[Dict[str, Any]]) -> Optional[common_pb2.ExecPolicy]:
    """Builds the wire `ExecPolicy`, or nothing at all.

    An absent section means "allowed" to the node, so options that restrict
    nothing send no section rather than a permissive one.
    """
    if options is None:
        return None
    return common_pb2.ExecPolicy(allow_exec=options.get("allow_exec", True))


def to_fs_policy(options: Optional[Dict[str, Any]]) -> Optional[common_pb2.FsPolicy]:
    """Builds the wire `FsPolicy`, or nothing at all."""
    if options is None:
        return None
    return common_pb2.FsPolicy(
        allow_upload=options.get("allow_upload", True),
        allow_download=options.get("allow_download", True),
        path_scopes=options.get("path_scopes") or [],
        max_upload_bytes=options.get("max_upload_bytes") or 0,
    )


def from_exec_policy(raw: Any, present: bool) -> Optional[ExecPolicy]:
    if not present:
        return None
    return ExecPolicy(allow_exec=raw.allow_exec)


def from_fs_policy(raw: Any, present: bool) -> Optional[FsPolicy]:
    if not present:
        return None
    return FsPolicy(
        allow_upload=raw.allow_upload,
        allow_download=raw.allow_download,
        path_scopes=list(raw.path_scopes),
        max_upload_bytes=raw.max_upload_bytes,
    )


def to_volume_mounts(
    mounts: Optional[Sequence[Dict[str, Any]]],
) -> List[common_pb2.VolumeMount]:
    return [
        common_pb2.VolumeMount(
            volume=mount["volume"],
            path=mount["path"],
            read_only=mount.get("read_only", False),
        )
        for mount in mounts or []
    ]


def from_volume_mounts(raw: Any) -> List[VolumeMount]:
    return [
        VolumeMount(volume=mount.volume, path=mount.path, read_only=mount.read_only)
        for mount in raw
    ]


def from_policy(raw: common_pb2.Policy) -> SandboxPolicy:
    return SandboxPolicy(
        resources=from_resource_policy(raw.resources),
        exec=from_exec_policy(raw.exec, raw.HasField("exec")),
        fs=from_fs_policy(raw.fs, raw.HasField("fs")),
        network=from_network_policy(raw.network),
        networks=from_networks(raw.networks),
        volumes=from_volume_mounts(raw.volumes),
    )
