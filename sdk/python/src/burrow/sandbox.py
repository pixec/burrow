"""Sandboxes: the SDK's public surface."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

import grpc

from ._fileio import open_file
from ._os import SandboxOs, os_error
from ._pathlib import SandboxPath
from ._pb import api_pb2, common_pb2
from ._policy import (
    from_policy,
    resolve_network,
    to_exec_policy,
    to_fs_policy,
    to_network_policy,
    to_networks,
    to_resource_policy,
    to_volume_mounts,
)
from ._shutil import SandboxShutil
from ._subprocess import SandboxSubprocess
from ._transport import _DEFAULT, Transport, transport_options as _transport_options
from .errors import BurrowError
from .snapshot import Snapshot
from .terminal import Terminal
from .types import (
    AuditEvent,
    CommandInfo,
    GuestGroup,
    GuestUser,
    LifecycleEvent,
    NodeInfo,
    PortMapping,
    Share,
    SandboxInfo,
    Session,
    Usage,
    UsageInterval,
    UsageReport,
    UsageSum,
    WatchEvent,
)


def _state_of(state: int) -> str:
    try:
        name = common_pb2.SandboxState.Name(state)
    except ValueError:
        return "unknown"
    name = name.replace("SANDBOX_STATE_", "").lower()
    known = (
        "creating",
        "running",
        "paused",
        "suspended",
        "stopped",
        "stopping",
        "destroyed",
        "failed",
    )
    return name if name in known else "unknown"


def _to_sandbox_info(raw: common_pb2.Sandbox) -> SandboxInfo:
    return SandboxInfo(
        id=raw.id,
        name=raw.name,
        node_id=raw.node_id,
        template=raw.template,
        state=_state_of(raw.state),
        created_at=raw.created_at,
        guest_ip=raw.guest_ip,
        tags=dict(raw.metadata),
        policy=from_policy(raw.policy),
        unreachable=raw.is_unreachable,
        usage=Usage(
            cpu_usage_usec=raw.cpu_usage_usec,
            rx_bytes=raw.rx_bytes,
            tx_bytes=raw.tx_bytes,
        ),
        durable=raw.is_durable,
    )


def _to_session(raw: common_pb2.Session) -> Session:
    return Session(
        id=raw.id,
        sandbox_id=raw.sandbox_id,
        started_at=raw.started_at,
        ended_at=raw.ended_at,
        # A reason this client has no name for reads as "unknown" rather than
        # passing a string through that callers branch on.
        started_by=raw.started_by
        if raw.started_by in ("boot", "restore", "resume")
        else "unknown",
        ended_by=raw.ended_by
        if raw.ended_by in ("suspended", "deleted", "failed", "unknown", "")
        else "unknown",
    )


def _to_command_info(raw: api_pb2.CommandInfo) -> CommandInfo:
    return CommandInfo(
        cmd_id=raw.command_id,
        cmd=list(raw.cmd),
        user=raw.user,
        state=raw.state if raw.state in ("running", "exited") else "unknown",
        exit_code=raw.exit_code,
        started_at=datetime.fromtimestamp(raw.started_at_unix_ms / 1000),
        ended_at=datetime.fromtimestamp(raw.ended_at_unix_ms / 1000)
        if raw.ended_at_unix_ms > 0
        else None,
        buffered_bytes=raw.buffered_bytes,
        exit_signal=raw.exit_signal,
        output_bytes=raw.output_bytes,
    )


def _to_create_request(options: Dict[str, Any]) -> api_pb2.CreateSandboxRequest:
    """Builds a `CreateSandboxRequest`."""
    network = resolve_network(options.get("network_policy"))
    resources = options.get("resources") or {}
    # A snapshot carries its own template, and one that disagrees is an error,
    # so nothing is sent as if the caller had asked for it.
    template = options.get("template") or ""
    # Without a snapshot there is nothing to boot from, and a made-up
    # "default" would turn a missing argument into a not_found for a template
    # nobody named.
    if not template and not options.get("snapshot"):
        raise BurrowError(
            "a template is required: pass template=... (or snapshot=... to "
            "restore one)",
            "invalid_argument",
        )
    request = api_pb2.CreateSandboxRequest(
        name=options.get("name") or "",
        snapshot=options.get("snapshot") or "",
        template=template,
        metadata=options.get("tags") or {},
        node_labels=options.get("node_labels") or {},
    )
    request.policy.resources.CopyFrom(to_resource_policy(resources))
    request.policy.network.CopyFrom(to_network_policy(network))
    # Left off the request entirely unless the caller asked for a limit:
    # absent is what the node reads as "allowed".
    exec_policy = to_exec_policy(options.get("exec"))
    if exec_policy is not None:
        request.policy.exec.CopyFrom(exec_policy)
    fs_policy = to_fs_policy(options.get("fs"))
    if fs_policy is not None:
        request.policy.fs.CopyFrom(fs_policy)
    request.policy.networks.extend(
        to_networks(options.get("networks"), options.get("alias"))
    )
    request.policy.volumes.extend(to_volume_mounts(options.get("volumes")))
    request.kit.CopyFrom(_to_kit_spec(options.get("kit")))
    return request


def _to_kit_spec(kit: Optional[Dict[str, Any]]) -> common_pb2.KitSpec:
    """Builds a `KitSpec` from `{"args": {...}, "env": {...},
    "reject_capabilities": [...]}`. Absent inputs are sent empty, which the
    node reads as none."""
    kit = kit or {}
    spec = common_pb2.KitSpec()
    spec.args.update(kit.get("args") or {})
    spec.env.update(kit.get("env") or {})
    spec.reject_types.extend(kit.get("reject_capabilities") or [])
    return spec


def _to_fork_request(source: str, options: Dict[str, Any]) -> api_pb2.ForkSandboxRequest:
    """Builds a `ForkSandboxRequest`. An omitted policy inherits the source's."""
    request = api_pb2.ForkSandboxRequest(
        ref=api_pb2.SandboxRef(id=source),
        sandbox_id=options.get("sandbox_id") or options.get("id") or "",
        name=options.get("name") or "",
        node_labels=options.get("node_labels") or {},
    )
    network = options.get("network_policy")
    stated = (
        network is not None
        or options.get("networks") is not None
        or options.get("exec") is not None
        or options.get("fs") is not None
    )
    if stated:
        # Resources are absent deliberately: a restore takes its machine
        # configuration from the snapshot, and the node refuses an override.
        if network is not None:
            request.policy.network.CopyFrom(to_network_policy(resolve_network(network)))
        request.policy.networks.extend(to_networks(options.get("networks")))
        # Each section is inherited on its own, so overriding one does not
        # strip the others off the child.
        exec_policy = to_exec_policy(options.get("exec"))
        if exec_policy is not None:
            request.policy.exec.CopyFrom(exec_policy)
        fs_policy = to_fs_policy(options.get("fs"))
        if fs_policy is not None:
            request.policy.fs.CopyFrom(fs_policy)
    return request


def _to_share(raw: api_pb2.Share) -> Share:
    return Share(
        address=raw.address,
        ports=list(raw.ports),
        allowed_clients=list(raw.allowed_clients),
        created_at=raw.created_at,
        udp_ports=list(raw.udp_ports),
        all_udp=raw.is_all_udp,
        transparent_ip=raw.is_transparent_ip,
    )


def _to_port(raw: api_pb2.PortMapping, fallback_host: str) -> PortMapping:
    # The node advertises where it accepts traffic; when it has not, the
    # control plane's own host is the best guess, and the right one for a
    # single node.
    address = raw.host_address or f"{fallback_host}:{raw.host_port}"
    return PortMapping(
        guest_port=raw.guest_port,
        host_port=raw.host_port,
        url=f"http://{address}",
        # Empty unless the holding node's edge is serving, rather than a name
        # that resolves nowhere.
        edge_url=raw.edge_url,
        udp=raw.is_udp,
    )


# How many times `Sandbox.get_or_create` looks before giving up. Only a lost
# race gets this far, waiting on another caller's create to finish.
_GET_OR_CREATE_ATTEMPTS = 10


class Watcher:
    """A running directory watch. Iterate it for events, `stop()` to end it."""

    def __init__(self, call: Any):
        self._call = call

    def __iter__(self) -> Iterator[WatchEvent]:
        try:
            for raw in self._call:
                yield WatchEvent(type=raw.type, path=raw.path, is_dir=raw.is_dir)
        except grpc.RpcError as err:
            # A cancelled call is a stopped watch, not a failure.
            if not self._call.cancelled():
                raise BurrowError.from_grpc(err) from None

    def stop(self) -> None:
        self._call.cancel()


class Sandbox:
    """A sandbox.

    Obtained from `Sandbox.create`, `Sandbox.get` or `Sandbox.fork`; not
    constructed directly.
    """

    def __init__(
        self,
        transport: Transport,
        info: SandboxInfo,
        owned: bool,
        auto_resume: bool = True,
        env: Optional[Dict[str, str]] = None,
    ):
        self._transport = transport
        self._info = info
        self.id = info.id
        self._owned = owned
        # Resume a suspended sandbox and retry once, rather than failing the
        # call.
        self.auto_resume = auto_resume
        # Environment merged under every command this handle runs.
        # Client-side, because the server has nowhere to keep it: a handle
        # obtained elsewhere does not have these, and the sandbox itself never
        # learns them.
        self._env = env or {}
        # Guest user every command from this handle runs as. Empty is root.
        # Set only on a handle from `as_user`; a per-command `user` still wins.
        self._default_user = ""
        # Called after this handle resumes the sandbox, including auto-resume.
        self._on_resume: Optional[Callable[["Sandbox"], Any]] = None
        # Set by `delete`: a destroyed sandbox has nothing left to call.
        self._destroyed = False
        # The stdlib's file and process APIs, against this sandbox: someone
        # who knows `os`, `shutil`, `pathlib` and `subprocess` already knows
        # these. Each acts as this handle's user.
        self.os = SandboxOs(self)
        self.shutil = SandboxShutil(self)
        self.subprocess = SandboxSubprocess(self)
        self.Path = type("Path", (SandboxPath,), {"__slots__": (), "_sandbox": self})

    def _assert_live(self) -> None:
        """Refuses a call on a deleted sandbox. `delete` released the
        connection, so the alternative is an obscure transport failure some
        calls later."""
        if self._destroyed:
            raise BurrowError(f"sandbox {self.id} was deleted", "failed_precondition")

    @staticmethod
    def create(**options: Any) -> "Sandbox":
        """Creates a sandbox and waits for it to be ready to accept commands.

        ```python
        sandbox = Sandbox.create(template="python")
        ```
        """
        transport = Transport(**_transport_options(options))
        try:
            raw = transport.unary(
                "CreateSandbox",
                _to_create_request(options),
                options.get("timeout", 120.0),
            )
            sandbox = Sandbox(
                transport,
                _to_sandbox_info(raw),
                True,
                options.get("auto_resume", True),
                options.get("env") or {},
            )
            sandbox._on_resume = options.get("on_resume")
            return sandbox
        except BaseException:
            transport.close()
            raise

    @staticmethod
    def get_or_create(**options: Any) -> "Sandbox":
        """Returns the sandbox with this name, creating it if it is not there.

        ```python
        sandbox = Sandbox.get_or_create(
            name="build-482",
            template="python-tools",
            on_create=lambda s: s.Path("/work/app.py").write_text(src),
        )
        ```

        A `name` is the only key: ids are generated by the server, so there is
        no id to ask for before the sandbox exists. The create options apply
        only when it turns out not to exist, so the same call is safe from
        every worker; an existing sandbox is handed back as it is. A stopped
        one stays stopped unless `resume` is set, though the first call that
        needs a running VM resumes it anyway.
        """
        key = options.get("name")
        if not key:
            raise BurrowError(
                "get_or_create needs a name: without one there is nothing to get",
                "invalid_argument",
            )

        # Two processes racing on the same name both find nothing and both
        # create. The loser is told ALREADY_EXISTS while the winner's sandbox
        # is still booting, so the get is retried rather than made once.
        for attempt in range(_GET_OR_CREATE_ATTEMPTS):
            try:
                sandbox = Sandbox.get(key, **options)
                sandbox._env = options.get("env") or {}
                sandbox._on_resume = options.get("on_resume")
                if options.get("resume") and sandbox.state in ("paused", "suspended"):
                    sandbox.resume()
                return sandbox
            except BurrowError as err:
                if err.code != "not_found":
                    raise

            try:
                sandbox = Sandbox.create(**options)
                on_create = options.get("on_create")
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
            f"sandbox {key} is being created elsewhere and did not become available",
            "unavailable",
        )

    @staticmethod
    def get(ref: Optional[str] = None, **options: Any) -> "Sandbox":
        """Returns a handle for a sandbox that already exists.

        ```python
        sandbox = Sandbox.get("sbx_...")
        ```
        """
        # Ids and names share one lookup: the server resolves a reference as an
        # id first and as a name second, and the two cannot collide.
        target = ref or options.get("sandbox_id") or options.get("id") or options.get("name")
        if not target:
            raise BurrowError("an id or a name is required", "invalid_argument")

        transport = Transport(**_transport_options(options))
        try:
            raw = transport.unary("GetSandbox", api_pb2.SandboxRef(id=target))
            return Sandbox(
                transport,
                _to_sandbox_info(raw),
                True,
                options.get("auto_resume", True),
            )
        except BaseException:
            transport.close()
            raise

    @staticmethod
    def list(tag: str = "", **options: Any) -> List["Sandbox"]:
        """Lists sandboxes, newest state first.

        ```python
        for sandbox in Sandbox.list(tag="owner=ci"):
            sandbox.stop()
        ```

        The handles share one connection, released once the last of them is
        closed.
        """
        transport = Transport(**_transport_options(options))
        try:
            res = transport.unary(
                "ListSandboxes", api_pb2.ListSandboxesRequest(tag=tag)
            )
            return [
                Sandbox(transport.retain(), _to_sandbox_info(raw), True)
                for raw in res.sandboxes
            ]
        finally:
            transport.close()

    @property
    def name(self) -> str:
        """The name the sandbox was created with, falling back to its id when
        it was created without one. Both work anywhere the API takes a
        sandbox."""
        return self._info.name or self.id

    @property
    def state(self) -> str:
        return self._info.state

    @property
    def template(self) -> str:
        return self._info.template

    @property
    def node_id(self) -> str:
        """Node hosting the sandbox."""
        return self._info.node_id

    @property
    def unreachable(self) -> bool:
        """Whether the node hosting this sandbox has missed its heartbeats.

        When true, `state` is a stale reading and calls fail with
        `unavailable` until it returns. `delete()` still works: the
        orchestrator drops the sandbox on its own word and destroys it if the
        node comes back.
        """
        return self._info.unreachable

    @property
    def tags(self) -> Dict[str, str]:
        """Tags, as of the last call that returned the sandbox record."""
        return self._info.tags

    @property
    def vcpus(self) -> int:
        return self._info.policy.resources.vcpus

    @property
    def memory_mib(self) -> int:
        """The same number under its unit-bearing name."""
        return self._info.policy.resources.memory_mib

    @property
    def usage(self) -> Usage:
        """What the sandbox has consumed, as of the last call that returned its
        record; `refresh` for a current reading. Accumulated across every VM it
        has run, so a stop and a resume do not reset it."""
        return self._info.usage

    @property
    def created_at(self) -> str:
        """RFC 3339. There is no `updated_at`: the record does not carry one."""
        return self._info.created_at

    @property
    def policy(self):
        """The whole policy in force, with injected header values redacted."""
        return self._info.policy

    def refresh(self) -> SandboxInfo:
        """Re-reads the sandbox's current state from the server."""
        self._assert_live()
        raw = self._transport.unary("GetSandbox", api_pb2.SandboxRef(id=self.id))
        self._info = _to_sandbox_info(raw)
        return self._info

    def _with_resume(self, op: Callable[[], Any], enabled: Optional[bool] = None) -> Any:
        """Runs `op`, resuming the sandbox and retrying once if it is suspended.

        The daemon answers a call that needs a live guest with
        `FAILED_PRECONDITION: sandbox is suspended; resume it first`, and
        nothing else in the API reports that, so it is specific enough to act
        on.
        """
        if enabled is None:
            enabled = self.auto_resume
        try:
            return op()
        except BurrowError as err:
            if not enabled or not err.is_suspended:
                raise
        self.resume()
        return op()

    def _fs(self, **op: Any) -> api_pb2.FsResponse:
        """Makes one `Fs` call as this handle's user.

        A failure in the guest kernel is a reply, not the call's status, and is
        raised here as the `OSError` the stdlib would raise for it. A policy
        refusal comes back the same way, as EACCES.
        """
        self._assert_live()
        request = api_pb2.FsRequest(sandbox_id=self.id, user=self._default_user, **op)
        res = self._with_resume(
            lambda: self._transport.route(self.id).unary("Fs", request)
        )
        if res.WhichOneof("result") == "error":
            raise os_error(res.error)
        return res

    def open(
        self,
        file: Any,
        mode: str = "r",
        buffering: int = -1,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ) -> Any:
        """Builtin `open()`, for a file in the sandbox.

        ```python
        with sandbox.open("/work/app.py", "w") as f:
            f.write("print('hi')\\n")
        ```

        The modes, the objects returned and the errors raised are `open()`'s.
        Text defaults to UTF-8 rather than this machine's locale encoding,
        `buffering=-1` buffers 1 MiB since each refill is a round trip, and
        `fileno()` raises: a sandbox file has no local descriptor.
        """
        return open_file(self, file, mode, buffering, encoding, errors, newline)

    def list_commands(self) -> List[CommandInfo]:
        """Lists the commands this sandbox has run, oldest first.

        ```python
        for command in sandbox.list_commands():
            print(command.cmd_id, command.state, " ".join(command.cmd))
        ```
        """
        self._assert_live()
        res = self._transport.unary(
            "ListCommands", api_pb2.ListCommandsRequest(sandbox_id=self.id)
        )
        return [_to_command_info(raw) for raw in res.commands]

    def get_command(
        self,
        cmd_id: str,
        from_offset: int = 0,
        *,
        text: Optional[bool] = None,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
    ) -> Any:
        """Reattaches to a command by id, from anywhere.

        ```python
        server = sandbox.get_command(cmd_id)
        for line in server.stdout:
            print(line)
        ```

        The command need not have been started by this process: it lives in the
        sandbox, and so does every byte it has printed. What comes back is a
        `sandbox.subprocess.Popen` whose `stdout` and `stderr` replay from
        `from_offset`, counting both streams' bytes together from the
        command's start, and then follow the command live; a reader that saw N
        bytes passes N and gets only what came after. `stdin` feeds it, a
        shell whose original stream is long gone included, and `kill()`,
        `wait()` and `returncode` work as on any other. Leaving a `with` block
        lets go of the command without ending it or its stdin. Several
        handles may follow one command at once. `info` is the `CommandInfo`
        read when it attached. Raises `not_found` when the id names nothing,
        a pruned command included.
        """
        self._assert_live()
        # Read first, so a bad id fails here rather than on the first read.
        raw = self._transport.unary(
            "GetCommand",
            api_pb2.GetCommandRequest(sandbox_id=self.id, command_id=cmd_id),
        )
        return self.subprocess.Popen._attach(
            _to_command_info(raw), from_offset, encoding, errors, text
        )

    def prune_commands(self) -> Dict[str, int]:
        """Removes finished commands and their output, as `docker container
        prune` does. Running commands are left alone. Returns how many were
        removed and the log bytes freed on the node.
        """
        self._assert_live()
        res = self._transport.unary(
            "PruneCommands", api_pb2.PruneCommandsRequest(sandbox_id=self.id)
        )
        return {"removed": res.removed, "freed_bytes": res.freed_bytes}

    def _signal_command(self, cmd_id: str, signal: int) -> None:
        self._transport.unary(
            "SignalCommand",
            api_pb2.SignalCommandRequest(
                sandbox_id=self.id, command_id=cmd_id, signal=signal
            ),
        )

    def create_user(self, name: str) -> GuestUser:
        """Creates a guest user with a private home directory.

        ```python
        alice = sandbox.create_user("alice")
        sandbox.subprocess.run(["whoami"], user=alice.username)
        ```

        The home is 0700, so one agent's files are not readable by another's.
        Names are `[a-z_][a-z0-9_-]*`, at most 32 characters.
        """
        self._assert_live()
        res = self._with_resume(
            lambda: self._transport.unary(
                "CreateUser", api_pb2.CreateUserRequest(sandbox_id=self.id, name=name)
            )
        )
        return GuestUser(
            username=res.username or name, uid=res.uid, gid=res.gid, home=res.home
        )

    def create_group(self, name: str) -> GuestGroup:
        """Creates a guest group and a directory its members share.

        The directory is group-owned and setgid, so a file one member creates
        in it stays readable by the others.
        """
        self._assert_live()
        res = self._with_resume(
            lambda: self._transport.unary(
                "CreateGroup", api_pb2.CreateGroupRequest(sandbox_id=self.id, name=name)
            )
        )
        return GuestGroup(
            groupname=res.groupname or name, gid=res.gid, shared_dir=res.shared_dir
        )

    def add_user_to_group(self, user: str, group: str) -> None:
        """Adds a user to a group, so the group's shared directory opens to
        them."""
        self._membership("AddUserToGroup", user, group)

    def remove_user_from_group(self, user: str, group: str) -> None:
        """Removes a user from a group, closing the shared directory to them."""
        self._membership("RemoveUserFromGroup", user, group)

    def _membership(self, method: str, user: str, group: str) -> None:
        self._assert_live()
        self._with_resume(
            lambda: self._transport.unary(
                method,
                api_pb2.GroupMembershipRequest(
                    sandbox_id=self.id, user=user, group=group
                ),
            )
        )

    def as_user(self, name: str) -> "Sandbox":
        """A handle onto the same sandbox that acts as `name`.

        ```python
        alice = sandbox.as_user("alice")
        alice.subprocess.run("touch ~/notes.txt", shell=True)
        alice.Path("/home/alice/notes.txt").exists()
        ```

        Its `open`, `os`, `shutil`, `Path`, `subprocess` and `terminal` all
        act as the user: the guest kernel decides what the user may read and
        write, and what they create is theirs. A per-command `user` still wins.
        The user has to exist already.
        """
        self._assert_live()
        # Shares the connection but does not own it: closing a user handle must
        # not close the sandbox's.
        handle = Sandbox(self._transport, self._info, False, self.auto_resume, self._env)
        handle._default_user = name
        return handle

    def terminal(self, **options: Any) -> Terminal:
        """Opens an interactive shell with a pty, for when input arrives over
        time (a browser terminal, an agent driving a REPL). For a command that
        runs to completion, use `subprocess.run`."""
        self._assert_live()
        return Terminal(
            self._transport.route(self.id), self.id, {"user": self._default_user, **options}
        )

    def watch(
        self,
        path: str,
        recursive: bool = False,
        interval: float = 0,
        on_event: Optional[Callable[[WatchEvent], Any]] = None,
        on_error: Optional[Callable[[Exception], Any]] = None,
    ) -> Watcher:
        """Watches a directory for changes.

        The guest polls and reports differences, so an edit is seen within
        roughly `interval` seconds and a file created and removed between two
        scans is not seen at all.

        ```python
        watcher = sandbox.watch("/work/src", recursive=True,
                                on_event=lambda e: print(e.type, e.path))
        # ...later
        watcher.stop()
        ```
        """
        self._assert_live()
        call = self._transport.route(self.id).open_server_stream(
            "Watch",
            api_pb2.WatchRequest(
                sandbox_id=self.id,
                path=path,
                is_recursive=recursive,
                interval_ms=int(interval * 1000),
            ),
            # Watches outlive any request deadline.
            None,
        )
        watcher = Watcher(call)

        # Callback style drives the iterator in the background; iterator style
        # hands it to the caller. Both stop the same way.
        if on_event:

            def pump() -> None:
                try:
                    for event in watcher:
                        on_event(event)
                except Exception as err:  # noqa: BLE001 - handed to the caller
                    if on_error:
                        on_error(err)

            threading.Thread(target=pump, daemon=True).start()

        return watcher

    def expose_port(
        self, guest_port: int, host_port: int = 0, udp: bool = False
    ) -> PortMapping:
        """Publishes a port from inside the sandbox on its node's address.

        A host port carries one protocol, so publishing both TCP and UDP for
        a guest port takes two calls.

        ```python
        mapping = sandbox.expose_port(8000)
        print(mapping.url)
        ```
        """
        self._assert_live()
        res = self._transport.unary(
            "ExposePort",
            api_pb2.ExposePortRequest(
                sandbox_id=self.id,
                guest_port=guest_port,
                host_port=host_port,
                is_udp=udp,
            ),
        )
        return _to_port(res, self._transport.host)

    def list_ports(self) -> List[PortMapping]:
        self._assert_live()
        res = self._transport.unary("ListPorts", api_pb2.SandboxRef(id=self.id))
        return [_to_port(port, self._transport.host) for port in res.ports]

    def domain(self, guest_port: int) -> str:
        """Where a published guest port answers.

        When the node holding the sandbox runs an edge, this is a full URL on a
        per-sandbox hostname, `http://<port>-<sandbox-id>.<edge-domain>/`, and
        traffic arriving on it wakes a stopped sandbox. When that node runs no
        edge there is no hostname routing, and this is a bare `host:port` on
        the node's own address. Raises when the port is not published.
        """
        for mapping in self.list_ports():
            if mapping.guest_port == guest_port:
                return mapping.edge_url or mapping.url.replace("http://", "", 1)
        raise BurrowError(
            f"port {guest_port} is not published; call expose_port({guest_port}) first",
            "not_found",
        )

    def close_port(self, host_port: int) -> None:
        self._assert_live()
        self._transport.unary(
            "ClosePort", api_pb2.ClosePortRequest(sandbox_id=self.id, host_port=host_port)
        )

    def share(
        self,
        ports: Optional[Sequence[int]] = None,
        allowed_clients: Optional[Sequence[str]] = None,
        rotate: bool = False,
        udp_ports: Optional[Sequence[int]] = None,
        all_udp: bool = False,
        no_transparent_ip: bool = False,
    ) -> Share:
        """Shares the sandbox through a tailcat address.

        A share is a WireGuard tunnel bootstrapped over a DERP relay, dialed
        with the `tailcat` CLI: no host port, no edge, and a connection wakes
        a suspended sandbox. Calling it again reshapes an existing share and
        keeps its address; `rotate=True` issues new keys and so a new address.
        TCP is shared on every port unless `ports` narrows it; UDP only on
        `udp_ports`, or everywhere with `all_udp=True`. The guest sees each
        client's own public IPv4 as the packet source; `no_transparent_ip`
        sources from the gateway instead.

        ```python
        share = sandbox.share(ports=[22])
        print(f"tailcat ssh {share.address}")
        ```
        """
        self._assert_live()
        res = self._transport.unary(
            "ShareSandbox",
            api_pb2.ShareRequest(
                sandbox_id=self.id,
                ports=list(ports or []),
                allowed_clients=list(allowed_clients or []),
                is_rotating=rotate,
                udp_ports=list(udp_ports or []),
                is_all_udp=all_udp,
                is_transparent_ip_disabled=no_transparent_ip,
            ),
        )
        return _to_share(res)

    def get_share(self) -> Share:
        """The sandbox's share. Raises `not_found` when it has none."""
        self._assert_live()
        return _to_share(self._transport.unary("GetShare", api_pb2.SandboxRef(id=self.id)))

    def unshare(self) -> None:
        """Revokes the share; its address stops working at once."""
        self._assert_live()
        self._transport.unary("UnshareSandbox", api_pb2.SandboxRef(id=self.id))

    def update_resources(
        self,
        max_lifetime_secs: Optional[int] = None,
        idle_suspend_secs: Optional[int] = None,
        suspended_ttl_secs: Optional[int] = None,
    ) -> SandboxInfo:
        """Moves the clocks the sandbox is measured against.

        An omitted field is left where it is, which is what lets `0` keep
        meaning "unlimited" here as it does on create. The machine shape is not
        among them: a running VM's configuration is fixed.
        """
        self._assert_live()
        request = api_pb2.UpdateResourcesRequest(ref=api_pb2.SandboxRef(id=self.id))
        if max_lifetime_secs is not None:
            request.max_lifetime_secs = max_lifetime_secs
        if idle_suspend_secs is not None:
            request.idle_suspend_secs = idle_suspend_secs
        if suspended_ttl_secs is not None:
            request.suspended_ttl_secs = suspended_ttl_secs
        raw = self._transport.unary("UpdateResources", request)
        self._info = _to_sandbox_info(raw)
        return self._info

    def update_tags(self, tags: Dict[str, str]) -> SandboxInfo:
        """Replaces the sandbox's tags. An empty map clears them."""
        self._assert_live()
        raw = self._transport.unary(
            "UpdateTags",
            api_pb2.UpdateTagsRequest(ref=api_pb2.SandboxRef(id=self.id), tags=tags),
        )
        self._info = _to_sandbox_info(raw)
        return self._info

    def update_network_policy(self, policy: Any) -> SandboxInfo:
        """Replaces the sandbox's egress policy.

        Firewall rules, proxy allowlist, DNS filtering and header injection all
        re-render at once, so the sandbox is never briefly half-governed.
        """
        self._assert_live()
        wanted = resolve_network(policy)
        # The guest is handed the inspection CA during its first handshake, so
        # a sandbox that did not start with TLS inspection cannot gain it. That
        # makes this the one policy change refused here rather than sent.
        if wanted.get("inspect_tls") and not self._info.policy.network.inspect_tls:
            raise BurrowError(
                f"sandbox {self.id} was created without TLS inspection, so "
                f"headers cannot be injected into its traffic; create it with "
                f"inspect_tls set",
                "failed_precondition",
            )
        raw = self._transport.unary(
            "UpdateNetworkPolicy",
            api_pb2.UpdateNetworkPolicyRequest(
                ref=api_pb2.SandboxRef(id=self.id), network=to_network_policy(wanted)
            ),
        )
        self._info = _to_sandbox_info(raw)
        return self._info

    def update_access_policy(
        self,
        exec: Optional[Dict[str, Any]] = None,
        fs: Optional[Dict[str, Any]] = None,
    ) -> SandboxInfo:
        """Replaces the sandbox's exec policy, its file policy, or both.

        A section you pass replaces that section wholesale, so a field left out
        of it is an allowance withdrawn. A section you do not pass is left
        exactly as it is, deliberately unlike create, where an omitted section
        means "no restriction": on a live sandbox that reading would make
        tightening files a silent re-opening of exec. Both are enforced on the
        node, before a command or a path reaches the guest.

        ```python
        # Deny exec. The file policy, whatever it is, is untouched.
        sandbox.update_access_policy(exec={"allow_exec": False})
        ```
        """
        self._assert_live()
        if exec is None and fs is None:
            raise BurrowError(
                "update_access_policy needs exec, fs or both: a call with "
                "neither would change nothing",
                "invalid_argument",
            )
        request = api_pb2.UpdateAccessPolicyRequest(ref=api_pb2.SandboxRef(id=self.id))
        # Absent stays absent on the wire: presence is what carries "leave this
        # section alone" to the node.
        exec_policy = to_exec_policy(exec)
        if exec_policy is not None:
            request.exec.CopyFrom(exec_policy)
        fs_policy = to_fs_policy(fs)
        if fs_policy is not None:
            request.fs.CopyFrom(fs_policy)
        raw = self._transport.unary("UpdateAccessPolicy", request)
        self._info = _to_sandbox_info(raw)
        return self._info

    def stop(self) -> SandboxInfo:
        """Snapshots the sandbox to disk and stops its VM. It keeps its
        filesystem, its address and its memory, and rejects commands until it
        is resumed; `delete` destroys one instead."""
        self._assert_live()
        raw = self._transport.unary("PauseSandbox", api_pb2.SandboxRef(id=self.id))
        self._info = _to_sandbox_info(raw)
        return self._info

    def resume(self) -> SandboxInfo:
        """Restores a stopped sandbox, typically in a few hundred milliseconds.

        Every resume this handle performs goes through here, auto-resume
        included, so this is the one place `on_resume` has to fire.
        """
        self._assert_live()
        raw = self._transport.unary("ResumeSandbox", api_pb2.SandboxRef(id=self.id))
        self._info = _to_sandbox_info(raw)
        if self._on_resume:
            self._on_resume(self)
        return self._info

    def shutdown(self) -> SandboxInfo:
        """Shuts the VM down, keeping the writable disk and volumes. Unlike
        `stop`, nothing in memory survives: processes end, and `boot` runs the
        image's init again on the same disk. For a Sandbox Kit template that
        is the stop and start its spec describes, and the Kit's startup hooks
        run again on the way up."""
        self._assert_live()
        raw = self._transport.unary("StopSandbox", api_pb2.SandboxRef(id=self.id))
        self._info = _to_sandbox_info(raw)
        return self._info

    def boot(self) -> SandboxInfo:
        """Cold-boots a shut-down sandbox on its existing disks. It takes as
        long as a create, since there is no memory image to restore, and the
        sandbox keeps its id, name, address and published ports."""
        self._assert_live()
        raw = self._transport.unary("StartSandbox", api_pb2.SandboxRef(id=self.id))
        self._info = _to_sandbox_info(raw)
        if self._on_resume:
            self._on_resume(self)
        return self._info

    def recreate(
        self, template: Optional[str] = None, kit: Optional[Dict[str, Any]] = None
    ) -> SandboxInfo:
        """Replaces the root disk, discarding everything written to it, while
        keeping the sandbox's id, name, address and volumes. With `template`
        the sandbox moves onto another template; a Kit is provisioned again on
        the new disk with the recorded inputs, as changed by `kit`: `args` and
        `env` replace by name, `reject_capabilities` wholesale, so an empty
        list clears it."""
        self._assert_live()
        raw = self._transport.unary(
            "RecreateSandbox",
            api_pb2.RecreateSandboxRequest(
                sandbox_id=self.id, template=template or "", kit=_to_kit_spec(kit)
            ),
        )
        self._info = _to_sandbox_info(raw)
        if self._on_resume:
            self._on_resume(self)
        return self._info

    def list_sessions(self) -> List[Session]:
        """Every VM this sandbox has run, newest first.

        A sandbox outlives its VMs: `stop` ends one and `resume` starts the
        next. The node keeps only the most recent sessions of each sandbox, and
        drops them all when the sandbox is deleted.
        """
        self._assert_live()
        res = self._transport.unary("ListSessions", api_pb2.SandboxRef(id=self.id))
        return [_to_session(raw) for raw in res.sessions]

    def current_session(self) -> Optional[Session]:
        """The VM the sandbox is running now, or `None` when it is stopped.

        The open session is the one `list_sessions` reports with no `ended_at`.
        """
        for session in self.list_sessions():
            if not session.ended_at:
                return session
        return None

    def fork(self, **options: Any) -> "Sandbox":
        """Creates a sandbox from this one's current state.

        This sandbox keeps running; a running source's state is written first,
        so the child starts from its state as of the call. The child lands on
        the same node, because a snapshot and its disks are node-local files.

        ```python
        child = sandbox.fork()
        branch = sandbox.fork(network_policy="none")
        ```
        """
        self._assert_live()
        raw = self._transport.unary(
            "ForkSandbox", _to_fork_request(self.id, options), 120.0
        )
        # A fork shares its parent's connection, released once both are done.
        transport = self._transport.retain() if self._owned else self._transport
        return Sandbox(
            transport,
            _to_sandbox_info(raw),
            self._owned,
            self.auto_resume,
            # A fork is the same sandbox again, so it runs commands with the
            # same environment this handle applies.
            self._env,
        )

    def move(
        self, node_id: str = "", node_labels: Optional[Dict[str, str]] = None
    ) -> SandboxInfo:
        """Moves the sandbox to another node through the object store.

        A running sandbox is suspended, carried over and resumed. It keeps its
        id, name and policy and gets an address on the new node. `node_id`
        names the destination; otherwise it is placed like a create, on a node
        carrying `node_labels`. Volumes do not move.
        """
        self._assert_live()
        raw = self._transport.unary(
            "MoveSandbox",
            api_pb2.MoveSandboxRequest(
                ref=api_pb2.SandboxRef(id=self.id),
                node_id=node_id,
                node_labels=node_labels or {},
            ),
            300.0,
        )
        self._info = _to_sandbox_info(raw)
        return self._info

    def snapshot(self, expiration: int = 0) -> Snapshot:
        """Saves the sandbox's state as a snapshot object and keeps running.

        The guest is paused only long enough to write its state. Unlike the
        sandbox's own stop state, which dies with it, a snapshot outlives its
        source and can start any number of new sandboxes:

        ```python
        snapshot = prepared.snapshot(expiration=86_400)
        worker = Sandbox.create(snapshot=snapshot.id)
        ```
        """
        self._assert_live()
        raw = self._transport.unary(
            "CreateSnapshot",
            api_pb2.CreateSnapshotRequest(
                ref=api_pb2.SandboxRef(id=self.id), expiration_secs=expiration
            ),
            # Writing a memory image and copying a scratch disk; seconds, not
            # milliseconds, on a large guest.
            120.0,
        )
        # The snapshot shares this handle's connection, released once both are
        # done.
        return Snapshot._adopt(
            self._transport.retain() if self._owned else self._transport, raw
        )

    def delete(self) -> None:
        """Destroys the sandbox and everything in it. The handle is inert
        afterwards: every later call raises rather than failing obscurely
        against an id that is no longer anywhere."""
        self._assert_live()
        try:
            self._transport.unary("DeleteSandbox", api_pb2.SandboxRef(id=self.id))
        finally:
            self._destroyed = True
            if self._owned:
                self._transport.close()

    def close(self) -> None:
        """Releases the connection without destroying the sandbox."""
        if self._owned:
            self._transport.close()

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, *exc: Any) -> None:
        """Destroys the sandbox when the `with` block ends.

        ```python
        with Sandbox.create(template="python") as sandbox:
            ...
        ```

        Use `close()` instead when the sandbox should outlive the block.
        """
        self.delete()


class Burrow:
    """A connection to a burrow control plane, for what is not one sandbox's:
    health, audit, events, nodes and secrets. Sandboxes are reached through
    `Sandbox`."""

    def __init__(self, **options: Any):
        self._transport = Transport(**_transport_options(options))

    def health(self) -> Dict[str, str]:
        res = self._transport.unary("Health", api_pb2.HealthRequest())
        return {"version": res.version}

    def audit(
        self,
        sandbox_id: str = "",
        denied_only: bool = False,
        since: str = "",
        limit: int = 0,
    ) -> List[AuditEvent]:
        """Reads the egress audit trail, newest first.

        Records cover both connection attempts and DNS lookups, so an attempt
        is visible even when the policy blocked it.
        """
        return [
            AuditEvent(
                at=raw.at,
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
                    since=since,
                    limit=limit,
                ),
            )
        ]

    def events(
        self,
        after: int = 0,
        sandbox: str = "",
        follow: bool = False,
        limit: int = 0,
    ) -> Iterator[LifecycleEvent]:
        """Reads the fleet's lifecycle log, oldest first.

        Without `follow` the iterator ends after the replay. With it, the
        stream stays open and yields events as they happen until the loop
        breaks. `sandbox` takes an id or name. Keep the last `seq` seen and
        pass it as `after` to resume after a disconnect.

        ```python
        for event in burrow.events(sandbox="build-482", follow=True):
            print(event.seq, event.type, event.detail)
        ```
        """
        for raw in self._transport.server_stream(
            "TailEvents",
            api_pb2.TailEventsRequest(
                after_seq=after, sandbox=sandbox, is_follow=follow, limit=limit
            ),
            # A follow outlives any request deadline.
            None if follow else _DEFAULT,
        ):
            yield LifecycleEvent(
                seq=raw.seq,
                node_id=raw.node_id,
                node_seq=raw.node_seq,
                at_unix_ms=raw.at_unix_ms,
                sandbox_id=raw.sandbox_id,
                type=raw.type,
                state=_state_of(raw.state),
                detail=raw.detail,
                template=raw.template,
                metadata=dict(raw.metadata),
                cpu_usage_usec=raw.cpu_usage_usec,
                rx_bytes=raw.rx_bytes,
                tx_bytes=raw.tx_bytes,
                vcpus=raw.vcpus,
                memory_mib=raw.mem_mib,
            )

    def usage(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        sandbox: str = "",
        tags: Optional[Dict[str, str]] = None,
        group_by: str = "",
        after_id: int = 0,
        limit: int = 0,
        include_open: bool = True,
    ) -> UsageReport:
        """Reads the usage ledger: the intervals sandboxes spent in one state at
        one shape, or with `group_by` their sums per group and state.

        An interval belongs to the window `[start, end)` it started in. The
        ledger outlives the sandboxes and nodes it describes. `group_by` is
        "sandbox", "template", "node", "state" or a tag key. Pass a report's
        `next_after_id` as `after_id` to continue an export.

        ```python
        report = burrow.usage(
            start=datetime(2026, 10, 1, tzinfo=timezone.utc),
            end=datetime(2026, 11, 1, tzinfo=timezone.utc),
            group_by="customer",
        )
        ```
        """
        def ms(at: Optional[datetime]) -> int:
            return int(at.timestamp() * 1000) if at else 0

        res = self._transport.unary(
            "QueryUsage",
            api_pb2.QueryUsageRequest(
                from_unix_ms=ms(start),
                to_unix_ms=ms(end),
                sandbox=sandbox,
                tags=tags or {},
                group_by=group_by,
                after_id=after_id,
                limit=limit,
                is_open_included=include_open,
            ),
        )
        return UsageReport(
            intervals=[
                UsageInterval(
                    id=raw.id,
                    sandbox_id=raw.sandbox_id,
                    node_id=raw.node_id,
                    template=raw.template,
                    metadata=dict(raw.metadata),
                    state=raw.state,
                    vcpus=raw.vcpus,
                    memory_mib=raw.mem_mib,
                    started_at_unix_ms=raw.started_at_unix_ms,
                    ended_at_unix_ms=raw.ended_at_unix_ms,
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
                    state=raw.state,
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
        self, node_id: str, drain: bool = True, suspend_sandboxes: bool = False
    ) -> int:
        """Stops (or resumes) placing new sandboxes on a node. Returns how many
        sandboxes were suspended."""
        res = self._transport.unary(
            "DrainNode",
            api_pb2.DrainNodeRequest(
                node_id=node_id, is_draining=drain, suspend_sandboxes=suspend_sandboxes
            ),
        )
        return res.suspended

    def set_secret(self, name: str, value: str) -> None:
        """Stores a credential that Sandbox Kits ask for by service name. The
        value stays on the node and is injected into matching requests by the
        egress proxy, so a guest never holds it. `name` is lowercase
        kebab-case, the `service` a Kit credential names."""
        self._transport.unary("SetSecret", api_pb2.SetSecretRequest(name=name, value=value))

    def list_secrets(self) -> List[str]:
        """Names of the stored secrets. Values are never returned."""
        res = self._transport.unary("ListSecrets", api_pb2.ListSecretsRequest())
        return list(res.names)

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
                arch=n.info.arch,
                firecracker_version=n.info.firecracker_version,
            )
            for n in res.nodes
        ]

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "Burrow":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
