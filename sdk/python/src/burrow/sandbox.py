"""Sandboxes: the SDK's public surface."""

from __future__ import annotations

import contextlib
import threading
from datetime import datetime
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Union

import grpc

from ._fileio import open_file
from ._os import SandboxOs, os_error
from ._pathlib import SandboxPath
from ._pb import api_pb2, common_pb2
from ._policy import (
    from_policy,
    network_policy,
    to_exec_policy,
    to_fs_policy,
    to_network_policy,
    to_policy,
)
from ._shutil import SandboxShutil
from ._subprocess import SandboxSubprocess
from ._transport import _DEFAULT, Transport
from ._wire import at, at_or_none, label
from .errors import BurrowError
from .snapshot import Snapshot
from .terminal import Terminal
from .types import (
    CommandInfo,
    DeletedGroup,
    DeletedUser,
    GuestGroup,
    GuestUser,
    NetworkPolicy,
    PortMapping,
    PrunedCommands,
    SandboxInfo,
    SandboxPolicy,
    Session,
    Share,
    Usage,
    WatchEvent,
)


def _state_of(state: int) -> str:
    return label(common_pb2.SandboxState, state, "SANDBOX_STATE_") or "unknown"


def _to_sandbox_info(raw: common_pb2.Sandbox) -> SandboxInfo:
    return SandboxInfo(
        id=raw.id,
        name=raw.name,
        node_id=raw.node_id,
        template=raw.template,
        state=_state_of(raw.state),
        created_at=at(raw.created_at_unix_ms),
        guest_ip=raw.guest_ip,
        tags=dict(raw.tags),
        policy=from_policy(raw.policy),
        unreachable=raw.is_unreachable,
        usage=Usage(
            cpu_usage_usec=raw.cpu_usage_usec,
            rx_bytes=raw.rx_bytes,
            tx_bytes=raw.tx_bytes,
        ),
        durable=raw.is_durable,
        hypervisor=raw.hypervisor,
        hypervisor_version=raw.hypervisor_version,
        arch=raw.arch,
        guest_os=raw.guest_os,
    )


def _to_session(raw: common_pb2.Session) -> Session:
    return Session(
        id=raw.id,
        sandbox_id=raw.sandbox_id,
        started_at=at(raw.started_at_unix_ms),
        ended_at=at_or_none(raw.ended_at_unix_ms),
        started_by=label(common_pb2.SessionStart, raw.started_by, "SESSION_START_"),
        ended_by=label(common_pb2.SessionEnd, raw.ended_by, "SESSION_END_"),
    )


def _to_command_info(raw: api_pb2.CommandInfo) -> CommandInfo:
    return CommandInfo(
        cmd_id=raw.command_id,
        cmd=list(raw.cmd),
        user=raw.user,
        state=label(api_pb2.CommandState, raw.state, "COMMAND_STATE_") or "unknown",
        exit_code=raw.exit_code,
        started_at=at(raw.started_at_unix_ms),
        ended_at=at_or_none(raw.ended_at_unix_ms),
        buffered_bytes=raw.buffered_bytes,
        exit_signal=raw.exit_signal,
        output_bytes=raw.output_bytes,
    )


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


def _to_share(raw: api_pb2.Share) -> Share:
    return Share(
        address=raw.address,
        ports=list(raw.ports),
        allowed_clients=list(raw.allowed_clients),
        created_at=at(raw.created_at_unix_ms),
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


class Watcher:
    """A running directory watch. Iterate it for events, `stop()` to end it."""

    def __init__(self, call: Any):
        self._call = call

    def __iter__(self) -> Iterator[WatchEvent]:
        try:
            for raw in self._call:
                yield WatchEvent(
                    kind=label(api_pb2.WatchEventKind, raw.kind, "WATCH_EVENT_KIND_"),
                    path=raw.path,
                    is_dir=raw.is_dir,
                )
        except grpc.RpcError as err:
            # A cancelled call is a stopped watch, not a failure.
            if not self._call.cancelled():
                raise BurrowError.from_grpc(err) from None

    def stop(self) -> None:
        self._call.cancel()

    def __enter__(self) -> "Watcher":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


class Sandbox:
    """A sandbox.

    Obtained from `Burrow.sandboxes`, the `Sandbox.create`/`get`/`list`
    shortcuts or `Sandbox.fork`; not constructed directly.
    """

    def __init__(
        self,
        transport: Transport,
        info: SandboxInfo,
        owned: bool = True,
        auto_resume: bool = True,
        env: Optional[Dict[str, str]] = None,
    ):
        self._transport = transport
        self._info = info
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
        self._closed = False
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
    def create(
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
        **options: Any,
    ) -> "Sandbox":
        """`Burrow(...).sandboxes.create(...)` on a connection of its own.

        ```python
        sandbox = Sandbox.create(template="python")
        ```
        """
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.sandboxes.create(**options)

    @staticmethod
    def get_or_create(
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
        **options: Any,
    ) -> "Sandbox":
        """`Burrow(...).sandboxes.get_or_create(...)` on a connection of its own."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.sandboxes.get_or_create(**options)

    @staticmethod
    def get(
        sandbox: str,
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
        auto_resume: bool = True,
    ) -> "Sandbox":
        """Returns a handle for a sandbox that already exists, by id or name.

        ```python
        sandbox = Sandbox.get("sbx_...")
        ```
        """
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.sandboxes.get(sandbox, auto_resume=auto_resume)

    @staticmethod
    def list(
        *,
        tag: str = "",
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> List["Sandbox"]:
        """Lists sandboxes, newest state first.

        ```python
        for sandbox in Sandbox.list(tag="owner=ci"):
            sandbox.pause()
        ```

        The handles share one connection, released once the last of them is
        closed.
        """
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.sandboxes.list(tag=tag)

    @property
    def id(self) -> str:
        return self._info.id

    @property
    def name(self) -> str:
        """The name the sandbox was created with, falling back to its id when
        it was created without one. Both work anywhere the API takes a
        sandbox."""
        return self._info.name or self._info.id

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
    def guest_ip(self) -> str:
        return self._info.guest_ip

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
    def durable(self) -> bool:
        """Suspended with its latest suspend in the object store, so it can
        resume on another node."""
        return self._info.durable

    @property
    def tags(self) -> Dict[str, str]:
        """Tags, as of the last call that returned the sandbox record."""
        return self._info.tags

    @property
    def vcpus(self) -> int:
        return self._info.policy.resources.vcpus

    @property
    def memory_mib(self) -> int:
        return self._info.policy.resources.memory_mib

    @property
    def usage(self) -> Usage:
        """What the sandbox has consumed, as of the last call that returned its
        record; `refresh` for a current reading. Accumulated across every VM it
        has run, so a pause and a resume do not reset it."""
        return self._info.usage

    @property
    def created_at(self) -> datetime:
        """There is no `updated_at`: the record does not carry one."""
        return self._info.created_at

    @property
    def policy(self) -> SandboxPolicy:
        """The whole policy in force, with injected header values redacted."""
        return self._info.policy

    def refresh(self) -> SandboxInfo:
        """Re-reads the sandbox's current state from the server."""
        return self._apply("GetSandbox", api_pb2.SandboxRef(sandbox_id=self.id))

    def _apply(self, method: str, request: Any, timeout: Any = _DEFAULT) -> SandboxInfo:
        """Makes a call that returns the sandbox record, and keeps it."""
        self._assert_live()
        raw = self._transport.unary(method, request, timeout)
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

    def prune_commands(self) -> PrunedCommands:
        """Removes finished commands and their output, as `docker container
        prune` does. Running commands are left alone. Returns how many were
        removed and the log bytes freed on the node.
        """
        self._assert_live()
        res = self._transport.unary(
            "PruneCommands", api_pb2.PruneCommandsRequest(sandbox_id=self.id)
        )
        return PrunedCommands(removed=res.removed, freed_bytes=res.freed_bytes)

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

    def delete_user(self, name: str, *, remove_home: bool = False) -> DeletedUser:
        """Deletes a guest user that `create_user` could have made.

        Root, system and built-in accounts, administrators and the accounts
        the agent relies on are refused, as is a user with a running process:
        end it first. The user's own group goes with them. Their home is kept,
        handed to root on Linux and macOS, unless `remove_home`.
        """
        self._assert_live()
        res = self._with_resume(
            lambda: self._transport.unary(
                "DeleteUser",
                api_pb2.DeleteUserRequest(
                    sandbox_id=self.id, name=name, is_home_removed=remove_home
                ),
            )
        )
        return DeletedUser(home=res.home, home_removed=res.is_home_removed)

    def delete_group(self, name: str, *, remove_shared_dir: bool = False) -> DeletedGroup:
        """Deletes a guest group that `create_group` could have made.

        A group that is some user's primary group is refused; delete the user.
        Members simply lose it. Its shared directory is kept, handed to root on
        Linux and macOS, unless `remove_shared_dir`.
        """
        self._assert_live()
        res = self._with_resume(
            lambda: self._transport.unary(
                "DeleteGroup",
                api_pb2.DeleteGroupRequest(
                    sandbox_id=self.id,
                    name=name,
                    is_shared_dir_removed=remove_shared_dir,
                ),
            )
        )
        return DeletedGroup(
            shared_dir=res.shared_dir, shared_dir_removed=res.is_shared_dir_removed
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

    def terminal(
        self,
        *,
        command: Union[str, Sequence[str]] = "/bin/sh",
        cols: int = 80,
        rows: int = 24,
        env: Optional[Dict[str, str]] = None,
        cwd: str = "",
        user: Optional[str] = None,
    ) -> Terminal:
        """Opens an interactive shell with a pty, for when input arrives over
        time (a browser terminal, an agent driving a REPL). For a command that
        runs to completion, use `subprocess.run`."""
        self._assert_live()
        return Terminal(
            self._transport.route(self.id),
            self.id,
            command=command,
            cols=cols,
            rows=rows,
            env={**self._env, **(env or {})},
            cwd=cwd,
            user=self._default_user if user is None else user,
        )

    def watch(
        self,
        path: str,
        *,
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
                                on_event=lambda e: print(e.kind, e.path))
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
                    else:
                        raise

            threading.Thread(target=pump, daemon=True).start()

        return watcher

    def expose_port(
        self, guest_port: int, *, host_port: int = 0, udp: bool = False
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
        res = self._transport.unary("ListPorts", api_pb2.SandboxRef(sandbox_id=self.id))
        return [_to_port(port, self._transport.host) for port in res.ports]

    def domain(self, guest_port: int) -> str:
        """Where a published guest port answers.

        When the node holding the sandbox runs an edge, this is a full URL on a
        per-sandbox hostname, `http://<port>-<sandbox-id>.<edge-domain>/`, and
        traffic arriving on it wakes a suspended sandbox. When that node runs
        no edge there is no hostname routing, and this is a bare `host:port` on
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
        *,
        ports: Optional[Sequence[int]] = None,
        allowed_clients: Optional[Sequence[str]] = None,
        rotate: bool = False,
        udp_ports: Optional[Sequence[int]] = None,
        all_udp: bool = False,
        transparent_ip: Optional[bool] = None,
    ) -> Share:
        """Shares the sandbox through a tailcat address.

        A share is a WireGuard tunnel bootstrapped over a DERP relay, dialed
        with the `tailcat` CLI: no host port, no edge, and a connection wakes
        a suspended sandbox. Calling it again reshapes an existing share and
        keeps its address; `rotate=True` issues new keys and so a new address.
        TCP is shared on every port unless `ports` narrows it; UDP only on
        `udp_ports`, or everywhere with `all_udp=True`. The guest sees each
        client's own public IPv4 as the packet source unless
        `transparent_ip=False` sources from the gateway instead.

        ```python
        share = sandbox.share(ports=[22])
        print(f"tailcat ssh {share.address}")
        ```
        """
        self._assert_live()
        request = api_pb2.ShareRequest(
            sandbox_id=self.id,
            ports=list(ports or []),
            allowed_clients=list(allowed_clients or []),
            is_rotating=rotate,
            udp_ports=list(udp_ports or []),
            is_all_udp=all_udp,
        )
        if transparent_ip is not None:
            request.is_transparent_ip = transparent_ip
        return _to_share(self._transport.unary("ShareSandbox", request))

    def get_share(self) -> Share:
        """The sandbox's share. Raises `not_found` when it has none."""
        self._assert_live()
        return _to_share(
            self._transport.unary("GetShare", api_pb2.SandboxRef(sandbox_id=self.id))
        )

    def unshare(self) -> None:
        """Revokes the share; its address stops working at once."""
        self._assert_live()
        self._transport.unary("UnshareSandbox", api_pb2.SandboxRef(sandbox_id=self.id))

    def update_lifetime(
        self,
        *,
        max_lifetime_secs: Optional[int] = None,
        idle_suspend_secs: Optional[int] = None,
        suspended_ttl_secs: Optional[int] = None,
    ) -> SandboxInfo:
        """Moves the clocks the sandbox is measured against.

        An omitted field is left where it is, which is what lets `0` keep
        meaning "unlimited" here as it does on create. The machine shape is not
        among them: a running VM's configuration is fixed.
        """
        request = api_pb2.UpdateLifetimeRequest(sandbox_id=self.id)
        if max_lifetime_secs is not None:
            request.max_lifetime_secs = max_lifetime_secs
        if idle_suspend_secs is not None:
            request.idle_suspend_secs = idle_suspend_secs
        if suspended_ttl_secs is not None:
            request.suspended_ttl_secs = suspended_ttl_secs
        return self._apply("UpdateLifetime", request)

    def update_tags(self, tags: Dict[str, str]) -> SandboxInfo:
        """Replaces the sandbox's tags. An empty map clears them."""
        return self._apply(
            "UpdateTags", api_pb2.UpdateTagsRequest(sandbox_id=self.id, tags=tags)
        )

    def update_network_policy(
        self, policy: Union[str, Dict[str, Any], NetworkPolicy]
    ) -> SandboxInfo:
        """Replaces the sandbox's egress policy.

        Firewall rules, proxy allowlist, DNS filtering and header injection all
        re-render at once, so the sandbox is never briefly half-governed. Takes
        a mode, a dict or the `NetworkPolicy` read back from `policy.network`.
        """
        self._assert_live()
        wanted = network_policy(policy)
        # The guest is handed the inspection CA during its first handshake, so
        # a sandbox that did not start with TLS inspection cannot gain it. That
        # makes this the one policy change refused here rather than sent.
        if wanted.inspect_tls and not self._info.policy.network.inspect_tls:
            raise BurrowError(
                f"sandbox {self.id} was created without TLS inspection, so "
                f"headers cannot be injected into its traffic; create it with "
                f"inspect_tls set",
                "failed_precondition",
            )
        return self._apply(
            "UpdateNetworkPolicy",
            api_pb2.UpdateNetworkPolicyRequest(
                sandbox_id=self.id, network=to_network_policy(wanted)
            ),
        )

    def update_access_policy(
        self, *, exec_policy: Any = None, fs: Any = None
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
        sandbox.update_access_policy(exec_policy={"allow_exec": False})
        ```
        """
        if exec_policy is None and fs is None:
            raise BurrowError(
                "update_access_policy needs exec_policy, fs or both: a call with "
                "neither would change nothing",
                "invalid_argument",
            )
        request = api_pb2.UpdateAccessPolicyRequest(sandbox_id=self.id)
        # Absent stays absent on the wire: presence is what carries "leave this
        # section alone" to the node.
        exec_wire = to_exec_policy(exec_policy)
        if exec_wire is not None:
            request.exec.CopyFrom(exec_wire)
        fs_wire = to_fs_policy(fs)
        if fs_wire is not None:
            request.fs.CopyFrom(fs_wire)
        return self._apply("UpdateAccessPolicy", request)

    def pause(self) -> SandboxInfo:
        """Snapshots the sandbox to disk and stops its VM. It keeps its
        filesystem, its address and its memory, and rejects commands until it
        is resumed; `delete` destroys one instead."""
        return self._apply("PauseSandbox", api_pb2.SandboxRef(sandbox_id=self.id))

    def resume(self) -> SandboxInfo:
        """Restores a paused sandbox, typically in a few hundred milliseconds.
        One that was stopped has no memory to restore and is refused with
        FAILED_PRECONDITION; `start` it instead.

        Every resume this handle performs goes through here, auto-resume
        included, so this is the one place `on_resume` has to fire.
        """
        info = self._apply("ResumeSandbox", api_pb2.SandboxRef(sandbox_id=self.id))
        if self._on_resume:
            self._on_resume(self)
        return info

    def stop(self) -> SandboxInfo:
        """Shuts the VM down, keeping the writable disk and volumes. Unlike
        `pause`, nothing in memory survives: processes end, and `start` runs
        the image's init again on the same disk. For a Sandbox Kit template
        that is the stop and start its spec describes, and the Kit's startup
        hooks run again on the way up."""
        return self._apply("StopSandbox", api_pb2.SandboxRef(sandbox_id=self.id))

    def start(self) -> SandboxInfo:
        """Cold-boots a stopped sandbox on its existing disks. It takes as long
        as a create, since there is no memory image to restore, and the
        sandbox keeps its id, name, address and published ports."""
        info = self._apply("StartSandbox", api_pb2.SandboxRef(sandbox_id=self.id))
        if self._on_resume:
            self._on_resume(self)
        return info

    def recreate(
        self, *, template: Optional[str] = None, kit: Optional[Dict[str, Any]] = None
    ) -> SandboxInfo:
        """Replaces the root disk, discarding everything written to it, while
        keeping the sandbox's id, name, address and volumes. With `template`
        the sandbox moves onto another template; a Kit is provisioned again on
        the new disk with the recorded inputs, as changed by `kit`: `args` and
        `env` replace by name, `reject_capabilities` wholesale, so an empty
        list clears it."""
        info = self._apply(
            "RecreateSandbox",
            api_pb2.RecreateSandboxRequest(
                sandbox_id=self.id, template=template or "", kit=_to_kit_spec(kit)
            ),
        )
        if self._on_resume:
            self._on_resume(self)
        return info

    def list_sessions(self) -> List[Session]:
        """Every VM this sandbox has run, newest first.

        A sandbox outlives its VMs: `pause` ends one and `resume` starts the
        next. The node keeps only the most recent sessions of each sandbox, and
        drops them all when the sandbox is deleted.
        """
        self._assert_live()
        res = self._transport.unary("ListSessions", api_pb2.SandboxRef(sandbox_id=self.id))
        return [_to_session(raw) for raw in res.sessions]

    def current_session(self) -> Optional[Session]:
        """The VM the sandbox is running now, or `None` when it has none.

        The open session is the one `list_sessions` reports with no `ended_by`.
        """
        for session in self.list_sessions():
            if not session.ended_by:
                return session
        return None

    def fork(
        self,
        *,
        name: str = "",
        node_labels: Optional[Dict[str, str]] = None,
        tags: Optional[Dict[str, str]] = None,
        network_policy: Any = None,
        networks: Any = None,
        alias: str = "",
        exec_policy: Any = None,
        fs: Any = None,
        volumes: Any = None,
    ) -> "Sandbox":
        """Creates a sandbox from this one's current state.

        This sandbox keeps running; a running source's state is written first,
        so the child starts from its state as of the call. The child lands on
        the same node, because a snapshot and its disks are node-local files.
        The policy options are `create`'s; a child with none stated inherits
        its source's whole policy. The machine shape cannot change: a restore
        takes it from the state.

        ```python
        child = sandbox.fork()
        branch = sandbox.fork(network_policy="none")
        ```
        """
        self._assert_live()
        request = api_pb2.ForkSandboxRequest(
            sandbox_id=self.id, name=name, node_labels=node_labels or {}
        )
        sections = (network_policy, networks, exec_policy, fs, volumes)
        if any(section is not None for section in sections):
            policy = to_policy(
                network_policy=network_policy,
                networks=networks,
                alias=alias,
                exec_policy=exec_policy,
                fs=fs,
                volumes=volumes,
            )
            # Each inherited section stays off the wire, so overriding one does
            # not strip the others off the child. Resources are never sent:
            # the node refuses a shape other than the state's.
            policy.ClearField("resources")
            policy.ClearField("lifetime")
            policy.ClearField("snapshots")
            if network_policy is None:
                policy.ClearField("network")
            request.policy.CopyFrom(policy)
        raw = self._transport.unary("ForkSandbox", request, 120.0)
        # A fork shares its parent's connection, released once both are done.
        child = Sandbox(
            self._transport.retain(),
            _to_sandbox_info(raw),
            True,
            self.auto_resume,
            # A fork is the same sandbox again, so it runs commands with the
            # same environment this handle applies.
            dict(self._env),
        )
        if tags is not None:
            child.update_tags(tags)
        return child

    def move(
        self, *, node_id: str = "", node_labels: Optional[Dict[str, str]] = None
    ) -> SandboxInfo:
        """Moves the sandbox to another node through the object store.

        A running sandbox is paused, carried over and resumed. It keeps its
        id, name and policy and gets an address on the new node. `node_id`
        names the destination; otherwise it is placed like a create, on a node
        carrying `node_labels`. Volumes do not move.
        """
        return self._apply(
            "MoveSandbox",
            api_pb2.MoveSandboxRequest(
                sandbox_id=self.id, node_id=node_id, node_labels=node_labels or {}
            ),
            300.0,
        )

    def snapshot(self, *, expiration_secs: int = 0) -> Snapshot:
        """Saves the sandbox's state as a snapshot object and keeps running.

        The guest is paused only long enough to write its state. Unlike the
        sandbox's own pause state, which dies with it, a snapshot outlives its
        source and can start any number of new sandboxes:

        ```python
        snapshot = prepared.snapshot(expiration_secs=86_400)
        worker = Sandbox.create(snapshot=snapshot.id)
        ```
        """
        self._assert_live()
        raw = self._transport.unary(
            "CreateSnapshot",
            api_pb2.CreateSnapshotRequest(sandbox_id=self.id, expiration_secs=expiration_secs),
            # Writing a memory image and copying a scratch disk; seconds, not
            # milliseconds, on a large guest.
            120.0,
        )
        # The snapshot shares this handle's connection, released once both are
        # done.
        return Snapshot(self._transport.retain(), raw)

    def delete(self) -> None:
        """Destroys the sandbox and everything in it. The handle is inert
        afterwards: every later call raises rather than failing obscurely
        against an id that is no longer anywhere."""
        self._assert_live()
        try:
            self._transport.unary("DeleteSandbox", api_pb2.SandboxRef(sandbox_id=self.id))
        finally:
            self._destroyed = True
            self.close()

    def close(self) -> None:
        """Releases this handle's share of the connection without destroying
        the sandbox. Closing twice does nothing more."""
        if self._owned and not self._closed:
            self._closed = True
            self._transport.close()

    @contextlib.contextmanager
    def deleting(self) -> Iterator["Sandbox"]:
        """Destroys the sandbox when the block ends.

        ```python
        with Sandbox.create(template="python").deleting() as sandbox:
            ...
        ```
        """
        try:
            yield self
        finally:
            self.delete()

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, *exc: Any) -> None:
        """Releases the connection when the `with` block ends; the sandbox
        goes on. `deleting()` is the block that destroys it."""
        self.close()
