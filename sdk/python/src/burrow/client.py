"""`Burrow`: one connection to a control plane, and everything reached over it."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Callable, Dict, Iterator, List, Optional

from ._pb import api_pb2, common_pb2
from ._policy import to_policy
from ._transport import _DEFAULT, Transport
from ._wire import at, at_or_none, kernel, label, unix_ms, value
from .errors import BurrowError
from .ip import Ips
from .sandbox import Sandbox, _state_of, _to_kit_spec, _to_sandbox_info
from .snapshot import Snapshot
from .template import BuildLogEvent, TemplateBuilder, build_template, to_template_info
from .types import (
    AuditEvent,
    BuiltTemplate,
    DiskCapacity,
    DrainResult,
    Health,
    LifecycleEvent,
    NodeInfo,
    SecretInfo,
    TemplateInfo,
    UsageInterval,
    UsageReport,
    UsageSum,
)
from .volume import Volume

# How many times `get_or_create` looks before giving up. Only a lost race gets
# this far, waiting on another caller's create to finish.
_GET_OR_CREATE_ATTEMPTS = 10


class Sandboxes:
    """`burrow.sandboxes`: creating and finding sandboxes on one connection."""

    def __init__(self, transport: Transport):
        self._transport = transport

    def create(
        self,
        *,
        template: str = "",
        snapshot: str = "",
        name: str = "",
        request_id: str = "",
        verbose_console: bool = False,
        tags: Optional[Dict[str, str]] = None,
        node_labels: Optional[Dict[str, str]] = None,
        public_ips: Optional[List[str]] = None,
        resources: Any = None,
        lifetime: Any = None,
        snapshots: Any = None,
        network_policy: Any = None,
        networks: Any = None,
        alias: str = "",
        exec_policy: Any = None,
        fs: Any = None,
        volumes: Any = None,
        kit: Optional[Dict[str, Any]] = None,
        env: Optional[Dict[str, str]] = None,
        auto_resume: bool = True,
        on_resume: Optional[Callable[[Sandbox], Any]] = None,
        timeout: float = 120.0,
    ) -> Sandbox:
        """Creates a sandbox and waits for it to be ready to accept commands.

        ```python
        sandbox = burrow.sandboxes.create(template="python")
        ```

        Policy sections take their dataclass (`ResourcePolicy`,
        `LifetimePolicy`, `SnapshotPolicy`, `NetworkPolicy`, `ExecPolicy`,
        `FsPolicy`) or a dict of the same fields; `network_policy` also takes
        a bare mode. `public_ips` are allocated addresses attached once it is
        up; a static one places the sandbox on the node it reaches. `env` is
        merged under every command this handle runs and lives on the handle
        alone. `verbose_console` boots with a verbose kernel console, read
        with `Sandbox.console`, for debugging a template; it boots cold.
        `request_id` makes the create safe to retry: a create naming
        the request id of one that already made a sandbox returns that
        sandbox, and one naming a create still running waits for it.
        """
        # A snapshot carries its own template, and one that disagrees is an
        # error, so nothing is sent as if the caller had asked for it. Without
        # a snapshot there is nothing to boot from, and a made-up "default"
        # would turn a missing argument into a not_found for a template nobody
        # named.
        if not template and not snapshot:
            raise BurrowError(
                "a template is required: pass template=... (or snapshot=... to "
                "restore one)",
                "invalid_argument",
            )
        request = api_pb2.CreateSandboxRequest(
            name=name,
            request_id=request_id,
            snapshot=snapshot,
            template=template,
            tags=tags or {},
            node_labels=node_labels or {},
            policy=to_policy(
                resources=resources,
                lifetime=lifetime,
                snapshots=snapshots,
                network_policy=network_policy,
                networks=networks,
                alias=alias,
                exec_policy=exec_policy,
                fs=fs,
                volumes=volumes,
            ),
            kit=_to_kit_spec(kit),
            public_ips=public_ips or [],
        )
        request.policy.is_console_verbose = verbose_console
        raw = self._transport.unary("CreateSandbox", request, timeout)
        sandbox = Sandbox(self._transport.retain(), _to_sandbox_info(raw), True, auto_resume, env)
        sandbox._on_resume = on_resume
        return sandbox

    def get_or_create(
        self,
        *,
        name: str,
        on_create: Optional[Callable[[Sandbox], Any]] = None,
        resume: bool = False,
        env: Optional[Dict[str, str]] = None,
        auto_resume: bool = True,
        on_resume: Optional[Callable[[Sandbox], Any]] = None,
        **create: Any,
    ) -> Sandbox:
        """Returns the sandbox with this name, creating it if it is not there.

        ```python
        sandbox = burrow.sandboxes.get_or_create(
            name="build-482",
            template="python-tools",
            on_create=lambda s: s.Path("/work/app.py").write_text(src),
        )
        ```

        A `name` is the only key: ids are generated by the server, so there is
        no id to ask for before the sandbox exists. The create options apply
        only when it turns out not to exist, so the same call is safe from
        every worker; an existing sandbox is handed back as it is. A suspended
        one stays suspended unless `resume` is set, though the first call that
        needs a running VM resumes it anyway.
        """
        if not name:
            raise BurrowError(
                "get_or_create needs a name: without one there is nothing to get",
                "invalid_argument",
            )

        # Two processes racing on the same name both find nothing and both
        # create. The loser is told ALREADY_EXISTS while the winner's sandbox
        # is still booting, so the get is retried rather than made once.
        for attempt in range(_GET_OR_CREATE_ATTEMPTS):
            try:
                sandbox = self.get(name, auto_resume=auto_resume, env=env)
                sandbox._on_resume = on_resume
                if resume and sandbox.state == "suspended":
                    sandbox.resume()
                return sandbox
            except BurrowError as err:
                if err.code != "not_found":
                    raise

            try:
                sandbox = self.create(
                    name=name, env=env, auto_resume=auto_resume, on_resume=on_resume, **create
                )
                if on_create:
                    on_create(sandbox)
                return sandbox
            except BurrowError as err:
                if err.code != "already_exists":
                    raise
                # The winner's record appears once the node has built the
                # sandbox.
                time.sleep(min(0.2 * 2**attempt, 1.0))
        raise BurrowError(
            f"sandbox {name} is being created elsewhere and did not become available",
            "unavailable",
        )

    def get(
        self,
        sandbox: str,
        *,
        auto_resume: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> Sandbox:
        """Returns a handle for a sandbox that already exists, by id or name.

        The server resolves a reference as an id first and as a name second,
        and the two cannot collide.
        """
        raw = self._transport.unary("GetSandbox", api_pb2.SandboxRef(sandbox_id=sandbox))
        return Sandbox(self._transport.retain(), _to_sandbox_info(raw), True, auto_resume, env)

    def list(self, *, tag: str = "") -> List[Sandbox]:
        """Lists sandboxes, newest state first, optionally only those carrying
        a `key=value` tag."""
        res = self._transport.unary("ListSandboxes", api_pb2.ListSandboxesRequest(tag=tag))
        return [Sandbox(self._transport.retain(), _to_sandbox_info(raw)) for raw in res.sandboxes]


class Snapshots:
    """`burrow.snapshots`."""

    def __init__(self, transport: Transport):
        self._transport = transport

    def get(self, snapshot_id: str) -> Snapshot:
        raw = self._transport.unary("GetSnapshot", api_pb2.SnapshotRef(id=snapshot_id))
        return Snapshot(self._transport.retain(), raw)

    def list(self, *, sandbox_id: str = "") -> List[Snapshot]:
        """Lists snapshots, newest first, optionally only those taken of one
        sandbox (by id or name)."""
        res = self._transport.unary(
            "ListSnapshots", api_pb2.ListSnapshotsRequest(sandbox_id=sandbox_id)
        )
        return [Snapshot(self._transport.retain(), raw) for raw in res.snapshots]


class Volumes:
    """`burrow.volumes`."""

    def __init__(self, transport: Transport):
        self._transport = transport

    def create(
        self,
        name: str,
        *,
        size_mib: int = 1024,
        node_labels: Optional[Dict[str, str]] = None,
        labels: Optional[Dict[str, str]] = None,
    ) -> Volume:
        """Creates a volume, placing it on a node that satisfies `node_labels`.

        A volume stays where this places it, and so does every sandbox that
        mounts it, unless it is durable (its node has an object store): a
        durable volume moves with a sandbox that mounts it, or to another node
        once its own is written off.
        """
        raw = self._transport.unary(
            "CreateVolume",
            api_pb2.CreateVolumeRequest(
                name=name,
                size_mib=size_mib,
                node_labels=node_labels or {},
                labels=labels or {},
            ),
        )
        return Volume(self._transport.retain(), raw)

    def get(self, name: str) -> Volume:
        """Read from the node holding it, so `attached_to` is current rather
        than whatever the orchestrator last cached."""
        raw = self._transport.unary("GetVolume", api_pb2.VolumeRef(name=name))
        return Volume(self._transport.retain(), raw)

    def list(self, *, node_id: str = "") -> List[Volume]:
        res = self._transport.unary("ListVolumes", api_pb2.ListVolumesRequest(node_id=node_id))
        return [Volume(self._transport.retain(), raw) for raw in res.volumes]


class Templates:
    """`burrow.templates`."""

    def __init__(self, transport: Transport):
        self._transport = transport

    def build(
        self,
        template: TemplateBuilder,
        name: str,
        *,
        vcpus: int = 0,
        memory_mib: int = 0,
        disk_mib: int = 0,
        hypervisor: str = "",
        kernel: str = "",
        allow_domains: Optional[List[str]] = None,
        systemd: bool = False,
        on_build_logs: Optional[Callable[[BuildLogEvent], Any]] = None,
        timeout: float = 30 * 60.0,
    ) -> BuiltTemplate:
        """Builds a template and publishes it under `name`."""
        return build_template(
            self._transport,
            template,
            name,
            vcpus=vcpus,
            memory_mib=memory_mib,
            disk_mib=disk_mib,
            hypervisor=hypervisor,
            kernel=kernel,
            allow_domains=allow_domains,
            systemd=systemd,
            on_build_logs=on_build_logs,
            timeout=timeout,
        )

    def list(self) -> List[TemplateInfo]:
        res = self._transport.unary("ListTemplates", api_pb2.ListTemplatesRequest())
        return [to_template_info(raw) for raw in res.templates]

    def delete(self, name: str) -> None:
        self._transport.unary("DeleteTemplate", api_pb2.DeleteTemplateRequest(name=name))


class Burrow:
    """A connection to a burrow control plane.

    Sandboxes, snapshots, volumes, templates and public IPs hang off it and
    share its channel; the rest is the fleet's: health, audit, events, usage, nodes and
    secrets.

    ```python
    with Burrow(endpoint="https://burrow.example.com", api_key="...") as burrow:
        sandbox = burrow.sandboxes.create(template="python")
    ```

    Handles obtained from it keep their share of the connection, so closing
    the `Burrow` does not pull it from under them.
    """

    def __init__(
        self,
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ):
        self._transport = Transport(
            endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route
        )
        self.sandboxes = Sandboxes(self._transport)
        self.snapshots = Snapshots(self._transport)
        self.volumes = Volumes(self._transport)
        self.templates = Templates(self._transport)
        self.ips = Ips(self._transport)

    def health(self) -> Health:
        res = self._transport.unary("Health", api_pb2.HealthRequest())
        return Health(version=res.version)

    def audit(
        self,
        *,
        sandbox_id: str = "",
        denied_only: bool = False,
        since: Optional[datetime] = None,
        limit: int = 0,
    ) -> List[AuditEvent]:
        """Reads the egress audit trail, newest first.

        Records cover both connection attempts and DNS lookups, so an attempt
        is visible even when the policy blocked it.
        """
        return [
            AuditEvent(
                at=at(raw.at_unix_ms),
                sandbox_id=raw.sandbox_id,
                source_ip=raw.source_ip,
                destination=raw.destination,
                host=raw.host,
                port=raw.port,
                allowed=raw.is_allowed,
                reason=raw.reason,
                bytes_sent=raw.bytes_sent,
                bytes_received=raw.bytes_received,
                node_id=raw.node_id,
            )
            for raw in self._transport.server_stream(
                "QueryAudit",
                api_pb2.AuditQuery(
                    sandbox_id=sandbox_id,
                    is_denied_only=denied_only,
                    since_unix_ms=unix_ms(since),
                    limit=limit,
                ),
            )
        ]

    def events(
        self,
        *,
        after: int = 0,
        sandbox_id: str = "",
        follow: bool = False,
        limit: int = 0,
    ) -> Iterator[LifecycleEvent]:
        """Reads the fleet's lifecycle log, oldest first.

        Without `follow` the iterator ends after the replay. With it, the
        stream stays open and yields events as they happen until the loop
        breaks. `sandbox_id` takes an id or name. Keep the last `seq` seen and
        pass it as `after` to resume after a disconnect.

        ```python
        for event in burrow.events(sandbox_id="build-482", follow=True):
            print(event.seq, event.kind, event.detail)
        ```
        """
        for raw in self._transport.server_stream(
            "TailEvents",
            api_pb2.TailEventsRequest(
                after_seq=after, sandbox_id=sandbox_id, is_follow=follow, limit=limit
            ),
            # A follow outlives any request deadline.
            None if follow else _DEFAULT,
        ):
            yield LifecycleEvent(
                seq=raw.seq,
                node_id=raw.node_id,
                node_seq=raw.node_seq,
                at=at(raw.at_unix_ms),
                sandbox_id=raw.sandbox_id,
                kind=label(common_pb2.EventKind, raw.kind, "EVENT_KIND_"),
                state=_state_of(raw.state),
                detail=raw.detail,
                template=raw.template,
                tags=dict(raw.tags),
                cpu_usage_usec=raw.cpu_usage_usec,
                rx_bytes=raw.rx_bytes,
                tx_bytes=raw.tx_bytes,
                vcpus=raw.vcpus,
                memory_mib=raw.mem_mib,
            )

    def usage(
        self,
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        sandbox_id: str = "",
        tags: Optional[Dict[str, str]] = None,
        group_by: Optional[str] = None,
        after_id: int = 0,
        limit: int = 0,
        include_open: bool = True,
    ) -> UsageReport:
        """Reads the usage ledger: the intervals sandboxes spent in one state at
        one shape, or with `group_by` their sums per group and state.

        An interval belongs to the window `[start, end)` it started in. The
        ledger outlives the sandboxes and nodes it describes. `group_by` is
        `"sandbox"`, `"template"`, `"node"`, `"state"` or `"tag:<key>"`. Pass
        a report's `next_after_id` as `after_id` to continue an export.

        ```python
        report = burrow.usage(
            start=datetime(2026, 10, 1, tzinfo=timezone.utc),
            end=datetime(2026, 11, 1, tzinfo=timezone.utc),
            group_by="tag:customer",
        )
        ```
        """
        group, group_by_tag = api_pb2.USAGE_GROUP_UNSPECIFIED, ""
        if group_by is not None:
            if group_by.startswith("tag:"):
                group, group_by_tag = api_pb2.USAGE_GROUP_TAG, group_by[len("tag:"):]
            else:
                group = value(api_pb2.UsageGroup, group_by, "USAGE_GROUP_", "group_by")
        res = self._transport.unary(
            "QueryUsage",
            api_pb2.QueryUsageRequest(
                from_unix_ms=unix_ms(start),
                to_unix_ms=unix_ms(end),
                sandbox_id=sandbox_id,
                tags=tags or {},
                group_by=group,
                group_by_tag=group_by_tag,
                after_id=after_id,
                limit=limit,
                is_open_included=include_open,
            ),
        )
        state = lambda raw: label(api_pb2.UsageState, raw, "USAGE_STATE_")
        return UsageReport(
            intervals=[
                UsageInterval(
                    id=raw.id,
                    sandbox_id=raw.sandbox_id,
                    node_id=raw.node_id,
                    template=raw.template,
                    tags=dict(raw.tags),
                    state=state(raw.state),
                    vcpus=raw.vcpus,
                    memory_mib=raw.mem_mib,
                    started_at=at(raw.started_at_unix_ms),
                    ended_at=at(raw.ended_at_unix_ms),
                    cpu_usage_usec=raw.cpu_usage_usec,
                    rx_bytes=raw.rx_bytes,
                    tx_bytes=raw.tx_bytes,
                    closed_by=raw.closed_by,
                    open=raw.is_open,
                )
                for raw in res.intervals
            ],
            sums=[
                UsageSum(
                    group=raw.group,
                    state=state(raw.state),
                    intervals=raw.intervals,
                    duration_ms=raw.duration_ms,
                    vcpu_ms=raw.vcpu_ms,
                    memory_mib_ms=raw.mem_mib_ms,
                    cpu_usage_usec=raw.cpu_usage_usec,
                    rx_bytes=raw.rx_bytes,
                    tx_bytes=raw.tx_bytes,
                )
                for raw in res.sums
            ],
            next_after_id=res.next_after_id,
        )

    def drain_node(
        self,
        node_id: str,
        *,
        drain: bool = True,
        suspend: bool = False,
        keep_pinned: bool = False,
    ) -> DrainResult:
        """Stops (or resumes) placing new sandboxes on a node; `suspend` also
        pauses every sandbox it runs. Refused while sandboxes on it hold public
        IPs, unless `keep_pinned` leaves them there."""
        res = self._transport.unary(
            "DrainNode",
            api_pb2.DrainNodeRequest(
                node_id=node_id,
                is_draining=drain,
                is_suspending=suspend,
                is_pinned_kept=keep_pinned,
            ),
        )
        return DrainResult(
            suspended=res.suspended, pinned_sandbox_ids=list(res.pinned_sandbox_ids)
        )

    def set_secret(
        self,
        name: str,
        value: str,
        *,
        allowed_sandboxes: Optional[List[str]] = None,
        allowed_tags: Optional[List[str]] = None,
    ) -> None:
        """Stores a credential that Sandbox Kits ask for by service name. The
        orchestrator keeps it sealed, and the egress proxy on the sandbox's
        node injects it into matching requests, so a guest never holds it. `name` is lowercase
        kebab-case, the `service` a Kit credential names.

        `allowed_sandboxes` (ids or names) and `allowed_tags` (`key=value`)
        scope the secret: a reference to it from any other sandbox is refused.
        Neither given, every sandbox may use it. Setting a secret replaces its
        scope along with its value."""
        self._transport.unary(
            "SetSecret",
            api_pb2.SetSecretRequest(
                name=name,
                value=value,
                allowed_sandboxes=list(allowed_sandboxes or []),
                allowed_tags=list(allowed_tags or []),
            ),
        )

    def list_secrets(self) -> List[SecretInfo]:
        """The stored secrets with their scopes. Values are never returned."""
        res = self._transport.unary("ListSecrets", api_pb2.ListSecretsRequest())
        return [
            SecretInfo(
                name=secret.name,
                allowed_sandboxes=list(secret.allowed_sandboxes),
                allowed_tags=list(secret.allowed_tags),
            )
            for secret in res.secrets
        ]

    def delete_secret(self, name: str) -> None:
        self._transport.unary("DeleteSecret", api_pb2.DeleteSecretRequest(name=name))

    def nodes(self) -> List[NodeInfo]:
        res = self._transport.unary("ListNodes", api_pb2.ListNodesRequest())
        return [
            NodeInfo(
                id=n.info.id,
                address=n.info.address,
                hostname=n.info.hostname,
                total_vcpus=n.info.total_vcpus,
                total_memory_mib=n.info.total_mem_mib,
                free_memory_mib=n.status.free_mem_mib,
                running_sandboxes=n.status.running_sandboxes,
                healthy=n.is_healthy,
                draining=n.status.is_draining,
                labels=dict(n.info.labels),
                committed_cpus=n.status.committed_cpu_millis / 1000,
                arch=n.info.arch,
                hypervisor_versions=dict(n.info.hypervisor_versions),
                kernels=[kernel(k) for k in n.info.kernels],
                disk=DiskCapacity(
                    free_bytes=n.status.disk.free_bytes,
                    total_bytes=n.status.disk.total_bytes,
                    reserve_bytes=n.status.disk.reserve_bytes,
                    overcommit=n.status.disk.overcommit,
                    provisioned_bytes=n.status.disk.provisioned_bytes,
                ),
                disk_low=n.status.is_disk_low,
                last_heartbeat_at=at_or_none(n.last_heartbeat_at_unix_ms),
            )
            for n in res.nodes
        ]

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "Burrow":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
