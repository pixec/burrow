"""Sandboxes: the SDK's public surface."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Union

import grpc

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
from ._transport import _DEFAULT, Transport, transport_options as _transport_options
from .errors import BurrowError, CommandFailedError
from .snapshot import Snapshot
from .terminal import Terminal
from .types import (
    AuditEvent,
    CommandInfo,
    CommandResult,
    DirEntry,
    GuestGroup,
    GuestUser,
    NodeInfo,
    OutputChunk,
    PortMapping,
    SandboxInfo,
    Session,
    Usage,
    WatchEvent,
)


def _state_of(state: int) -> str:
    try:
        name = common_pb2.SandboxState.Name(state)
    except ValueError:
        return "unknown"
    name = name.replace("SANDBOX_STATE_", "").lower()
    known = ("creating", "running", "paused", "suspended", "stopping", "destroyed", "failed")
    return name if name in known else "unknown"


def _status_of(state: str) -> str:
    """The five-state view of a sandbox's lifecycle."""
    if state == "creating":
        return "pending"
    if state in ("running", "stopping"):
        return state
    # All three are "not going to run anything until something is done".
    if state in ("paused", "suspended", "destroyed"):
        return "stopped"
    # `failed`, and any state a newer server reports that this client has no
    # name for.
    return "failed"


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
        unreachable=raw.unreachable,
        usage=Usage(
            cpu_usage_usec=raw.cpu_usage_usec,
            rx_bytes=raw.rx_bytes,
            tx_bytes=raw.tx_bytes,
        ),
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
    )


def _to_create_request(options: Dict[str, Any]) -> api_pb2.CreateSandboxRequest:
    """Builds a `CreateSandboxRequest` from the SDK's flatter options."""
    network = options.get("network")
    if network is None:
        network = options.get("network_policy")
    network = resolve_network(
        network,
        allow_domains=options.get("allow_domains"),
        allow_cidrs=options.get("allow_cidrs"),
    )
    resources = options.get("resources") or {
        "vcpus": options.get("vcpus"),
        "memory_mib": options.get("memory_mib"),
    }
    # A snapshot carries its own template, and one that disagrees is an error,
    # so the default is not sent as if the caller had asked for it.
    template = options.get("template") or options.get("image") or ""
    request = api_pb2.CreateSandboxRequest(
        name=options.get("name") or "",
        snapshot=options.get("snapshot") or "",
        template=template or ("" if options.get("snapshot") else "default"),
        metadata=options.get("tags") or options.get("metadata") or {},
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
    return request


def _to_fork_request(source: str, options: Dict[str, Any]) -> api_pb2.ForkSandboxRequest:
    """Builds a `ForkSandboxRequest`. An omitted policy inherits the source's."""
    request = api_pb2.ForkSandboxRequest(
        ref=api_pb2.SandboxRef(id=source),
        sandbox_id=options.get("sandbox_id") or options.get("id") or "",
        name=options.get("name") or "",
        node_labels=options.get("node_labels") or {},
    )
    network = options.get("network")
    if network is None:
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


def _to_chunks(msg: api_pb2.ExecOutput) -> Iterator[OutputChunk]:
    """One `ExecOutput` message as the SDK's chunk, if it carries anything.
    Shared by a running exec and a later attach. The oneof tag is checked
    rather than the fields: proto defaults give every message an exit code of 0
    and empty byte fields."""
    kind = msg.WhichOneof("output")
    if kind == "stdout" and msg.stdout:
        yield OutputChunk(type="stdout", data=msg.stdout.decode("utf-8", "replace"))
    elif kind == "stderr" and msg.stderr:
        yield OutputChunk(type="stderr", data=msg.stderr.decode("utf-8", "replace"))
    elif kind == "exit_code":
        yield OutputChunk(type="exit", exit_code=msg.exit_code)


def _collect(chunks: Iterator[OutputChunk]) -> CommandResult:
    """Drains a command's output into the result a finished command reports."""
    stdout: List[str] = []
    stderr: List[str] = []
    exit_code = 0
    for chunk in chunks:
        if chunk.type == "stdout":
            stdout.append(chunk.data)
        elif chunk.type == "stderr":
            stderr.append(chunk.data)
        else:
            exit_code = chunk.exit_code
    return CommandResult(
        stdout="".join(stdout),
        stderr="".join(stderr),
        exit_code=exit_code,
        success=exit_code == 0,
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
    )


def _shell_quote(value: str) -> str:
    """Quotes a path for `sh -c`."""
    quoted = value.replace("'", "'\\''")
    return f"'{quoted}'"


# Bytes per uploaded chunk, matching HTTP/2's default flow-control window.
# Larger chunks showed no measurable gain: a message bigger than the window
# stalls for WINDOW_UPDATE round trips rather than pipelining.
_UPLOAD_CHUNK = 64 * 1024

# How many times `Sandbox.get_or_create` looks before giving up. Only a lost
# race gets this far, waiting on another caller's create to finish.
_GET_OR_CREATE_ATTEMPTS = 10


class DetachedCommand:
    """A command started without waiting for it, or reattached by id."""

    def __init__(
        self,
        sandbox_id: str,
        cmd_id: str,
        logs: Callable[[], Iterator[OutputChunk]],
        signal: Callable[[str, int], None],
        info: Optional[CommandInfo] = None,
    ):
        self.sandbox_id = sandbox_id
        self.cmd_id = cmd_id
        self._logs = logs
        self._signal = signal
        self.info = info

    def logs(self) -> Iterator[OutputChunk]:
        """The command's output, replayed from what the guest holds and then
        followed live."""
        return self._logs()

    def wait(self) -> CommandResult:
        """Drains the output and returns the result."""
        return _collect(self.logs())

    def kill(self, signal: int = 9) -> None:
        """Signals the command.

        Only one refusal is swallowed: the command had already exited, which is
        what kill wanted anyway. Every other failure raises, because a sandbox
        tightened to deny exec refuses signals too, and silently doing nothing
        there is indistinguishable from having killed it.
        """
        try:
            self._signal(self.cmd_id, signal)
        except BurrowError as err:
            if not err.is_already_exited:
                raise


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
            on_create=lambda s: s.write_files([{"path": "/work/app.py", "content": src}]),
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
                if options.get("resume") and sandbox.status == "stopped":
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
    def connect(ref: str, **options: Any) -> "Sandbox":
        """Reattaches to an existing sandbox by id. Alias of `Sandbox.get`."""
        return Sandbox.get(ref, **options)

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

    @staticmethod
    def fork_from(source: str, **options: Any) -> "Sandbox":
        """Creates a sandbox from another's current state.

        The source keeps running; a running source's state is written first, so
        the child starts from its state as of the call.
        """
        transport = Transport(**_transport_options(options))
        try:
            raw = transport.unary(
                "ForkSandbox",
                _to_fork_request(source, options),
                options.get("timeout", 120.0),
            )
            return Sandbox(transport, _to_sandbox_info(raw), True)
        except BaseException:
            transport.close()
            raise

    @staticmethod
    def _adopt(transport: Transport, raw: common_pb2.Sandbox) -> "Sandbox":
        """Used by `Burrow` so clients share one connection."""
        return Sandbox(transport, _to_sandbox_info(raw), False)

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
    def status(self) -> str:
        """The five-state view of `state`. Suspended reads as `stopped`."""
        return _status_of(self._info.state)

    @property
    def template(self) -> str:
        return self._info.template

    @property
    def image(self) -> str:
        """The template, under the name an image-shaped SDK uses."""
        return self._info.template

    @property
    def node_id(self) -> str:
        """Node hosting the sandbox."""
        return self._info.node_id

    @property
    def unreachable(self) -> bool:
        """Whether the node hosting this sandbox has missed its heartbeats.

        When true, `state` and `status` are stale readings and calls fail with
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
    def metadata(self) -> Dict[str, str]:
        return self._info.tags

    @property
    def vcpus(self) -> int:
        return self._info.policy.resources.vcpus

    @property
    def memory(self) -> int:
        return self._info.policy.resources.memory_mib

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
    def network_policy(self):
        """The egress policy in force, with injected header values redacted."""
        return self._info.policy.network

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

    def run_command(
        self,
        cmd: Union[str, Dict[str, Any]],
        args: Optional[Sequence[str]] = None,
        **options: Any,
    ) -> Union[CommandResult, DetachedCommand]:
        """Runs a command and returns once it exits.

        ```python
        install = sandbox.run_command("pip", ["install", "cowsay"])
        print(install.exit_code, install.stdout)
        ```

        A bare string goes through `/bin/sh -c`, so pipes and redirection work.
        Once `args` are given the command is passed to execve directly, with no
        shell involved. `detached=True` returns a `DetachedCommand` handle
        without waiting.
        """
        if isinstance(cmd, dict):
            options = {**cmd, **options}
            args = options.pop("args", None)
            cmd = options.pop("cmd")

        # `stdout`/`stderr` are writable files, and the callbacks are the same
        # thing one chunk at a time, so one is expressed in terms of the other.
        for sink_key, callback_key in (("stdout", "on_stdout"), ("stderr", "on_stderr")):
            sink = options.pop(sink_key, None)
            if sink is not None:
                previous = options.get(callback_key)

                def chained(chunk, sink=sink, previous=previous):
                    if previous:
                        previous(chunk)
                    sink.write(chunk)

                options[callback_key] = chained

        argv = list(args or [])
        shell = options.pop("shell", not argv)
        command: Union[str, List[str]] = (
            " ".join([cmd, *argv]) if shell and argv else cmd if shell else [cmd, *argv]
        )

        if options.pop("detached", False):
            return self._spawn(command, options)
        return self.exec(command, **options)

    def exec(self, command: Union[str, Sequence[str]], **options: Any) -> CommandResult:
        """Runs a command and returns once it exits.

        A string is run through `/bin/sh -c`, so pipes and redirection work; a
        list is passed to execve directly, with no shell involved.

        ```python
        sandbox.exec("pip install cowsay")
        sandbox.exec(["python3", "-c", "print(1 + 1)"])
        ```
        """
        on_stdout = options.get("on_stdout")
        on_stderr = options.get("on_stderr")

        def run() -> CommandResult:
            stdout: List[str] = []
            stderr: List[str] = []
            exit_code = 0
            # Auto-resume is handled here rather than around the stream: a
            # stream that has already yielded cannot be restarted without
            # replaying output.
            for chunk in self._start_exec(command, options)[0]:
                if chunk.type == "stdout":
                    stdout.append(chunk.data)
                    if on_stdout:
                        on_stdout(chunk.data)
                elif chunk.type == "stderr":
                    stderr.append(chunk.data)
                    if on_stderr:
                        on_stderr(chunk.data)
                else:
                    exit_code = chunk.exit_code
            return CommandResult(
                stdout="".join(stdout),
                stderr="".join(stderr),
                exit_code=exit_code,
                success=exit_code == 0,
            )

        result = self._with_resume(run, options.get("auto_resume"))
        if options.get("check") and not result.success:
            raise CommandFailedError(
                command if isinstance(command, str) else " ".join(command),
                result.exit_code,
                result.stdout,
                result.stderr,
            )
        return result

    def exec_stream(
        self, command: Union[str, Sequence[str]], **options: Any
    ) -> Iterator[OutputChunk]:
        """Runs a command, yielding output as it is produced.

        ```python
        for chunk in sandbox.exec_stream("npm install"):
            if chunk.type == "stdout":
                sys.stdout.write(chunk.data)
        ```
        """
        return self._start_exec(command, options)[0]

    def _start_exec(
        self,
        command: Union[str, Sequence[str]],
        options: Dict[str, Any],
        keep_open: bool = False,
    ):
        """Starts a command, returning its output and the id the guest gave it."""
        self._assert_live()
        cmd = ["/bin/sh", "-c", command] if isinstance(command, str) else list(command)

        start = api_pb2.ExecInput(
            start=api_pb2.ExecStart(
                sandbox_id=self.id,
                cmd=cmd,
                # A per-command variable wins over the handle's defaults, so
                # one call can override what every other call inherits.
                env={**self._env, **(options.get("env") or {})},
                cwd=options.get("cwd") or "",
                pty=options.get("pty") or False,
                rows=options.get("rows") or 24,
                cols=options.get("cols") or 80,
                user=options.get("user", self._default_user),
            )
        )

        done = threading.Event()

        def requests() -> Iterator[api_pb2.ExecInput]:
            yield start
            if keep_open:
                # Closes the child's stdin without closing the request side,
                # which a detached command keeps open until its stream ends.
                yield api_pb2.ExecInput(stdin_eof=True)
                done.wait()

        # A detached command outlives any request deadline.
        timeout = options.get("timeout", None if keep_open else _DEFAULT)
        call = self._transport.duplex("Exec", requests(), timeout)
        output = iter(call)

        # The guest names the command before anything else. Pulled here rather
        # than in the generator below, which nothing iterates until the caller
        # asks for output: a detached command's id has to exist before then.
        try:
            first = next(output, None)
        except grpc.RpcError as err:
            done.set()
            raise BurrowError.from_grpc(err) from None
        command_id = (
            first.command_id
            if first is not None and first.WhichOneof("output") == "command_id"
            else ""
        )

        def chunks() -> Iterator[OutputChunk]:
            try:
                # An older agent starts straight in on output, with no id at
                # all.
                if first is not None and first.WhichOneof("output") != "command_id":
                    for chunk in _to_chunks(first):
                        yield chunk
                for msg in output:
                    # Only ever the first message, but an agent that repeated
                    # it must not put an empty chunk into the caller's stream.
                    if msg.WhichOneof("output") == "command_id":
                        continue
                    for chunk in _to_chunks(msg):
                        yield chunk
            except grpc.RpcError as err:
                raise BurrowError.from_grpc(err) from None
            finally:
                done.set()
                call.cancel()

        return chunks(), command_id

    def _spawn(
        self, command: Union[str, Sequence[str]], options: Dict[str, Any]
    ) -> DetachedCommand:
        """Starts a command and returns a handle without waiting for it."""
        output, cmd_id = self._start_exec(command, options, keep_open=True)

        on_stdout = options.get("on_stdout")
        on_stderr = options.get("on_stderr")

        def stream() -> Iterator[OutputChunk]:
            for chunk in output:
                if chunk.type == "stdout" and on_stdout:
                    on_stdout(chunk.data)
                elif chunk.type == "stderr" and on_stderr:
                    on_stderr(chunk.data)
                yield chunk

        # `logs()` and `wait()` drain the same stream, so only the first of
        # them gets anything; the second is refused rather than left empty.
        taken = [False]
        chunks = stream()

        def take() -> Iterator[OutputChunk]:
            if taken[0]:
                raise BurrowError(
                    "this command's output has already been consumed",
                    "failed_precondition",
                )
            taken[0] = True
            return chunks

        # The same RPC `get_command(...).kill()` uses: the command lives in the
        # sandbox, not on this stream.
        return DetachedCommand(self.id, cmd_id, take, self._signal_command)

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

    def get_command(self, cmd_id: str) -> DetachedCommand:
        """Reattaches to a command by id, from anywhere.

        ```python
        command = sandbox.get_command(cmd_id)
        for chunk in command.logs():
            sys.stdout.write(chunk.data)
        ```

        The command need not have been started by this process: it lives in the
        sandbox. `logs()` replays what the guest still holds and then follows
        the command live, and several readers may do that at once. Raises
        `not_found` when the id names nothing, an evicted command included.
        """
        self._assert_live()
        # Read first, so a bad id fails here rather than on the first `logs()`.
        raw = self._transport.unary(
            "GetCommand",
            api_pb2.GetCommandRequest(sandbox_id=self.id, command_id=cmd_id),
        )

        def attach() -> Iterator[OutputChunk]:
            stream = self._transport.server_stream(
                "AttachCommand",
                api_pb2.AttachCommandRequest(sandbox_id=self.id, command_id=cmd_id),
                # A command outlives any request deadline.
                None,
            )
            for msg in stream:
                for chunk in _to_chunks(msg):
                    yield chunk

        return DetachedCommand(
            self.id, cmd_id, attach, self._signal_command, info=_to_command_info(raw)
        )

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
        sandbox.run_command("whoami", user=alice.username)
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
        """A handle onto the same sandbox whose commands run as `name`.

        ```python
        alice = sandbox.as_user("alice")
        alice.run_command("touch ~/notes.txt")
        ```

        Commands, terminals and `mkdir` run as the user, and `write_file` hands
        what it wrote to them. Reads are not confined: `read_file` and
        `list_dir` are served by the guest agent as root, so a user handle can
        still read a file its user could not. The user has to exist already.
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
        runs to completion, use `run_command`."""
        self._assert_live()
        return Terminal(self._transport, self.id, options)

    def write_files(self, files: Sequence[Dict[str, Any]]) -> None:
        """Writes files, creating parent directories as needed.

        ```python
        sandbox.write_files([
            {"path": "/work/app.py", "content": "print('hi')\\n"},
            {"path": "/work/run.sh", "content": "python3 app.py\\n", "mode": 0o755},
        ])
        ```
        """
        for file in files:
            content = file.get("content", file.get("contents", ""))
            self.write_file(file["path"], content, mode=file.get("mode", 0))

    def write_file(
        self, path: str, contents: Union[str, bytes], mode: int = 0
    ) -> int:
        """Writes a single file, creating parent directories as needed."""
        self._assert_live()
        data = contents.encode("utf-8") if isinstance(contents, str) else contents

        def chunks() -> Iterator[api_pb2.FileChunk]:
            offset = 0
            first = True
            while offset < len(data) or first:
                end = min(offset + _UPLOAD_CHUNK, len(data))
                yield api_pb2.FileChunk(
                    # Only the first chunk names the destination.
                    sandbox_id=self.id if first else "",
                    path=path if first else "",
                    mode=mode if first else 0,
                    data=data[offset:end],
                )
                first = False
                offset = end

        res = self._with_resume(
            lambda: self._transport.client_stream("UploadFile", chunks())
        )
        # The agent writes as root, so a handle from `as_user` has to hand the
        # file over or the user could not touch what it wrote.
        if self._default_user:
            # `user=""` is root: the user being handed the file cannot be the
            # one handing it over.
            self.exec(["/bin/chown", self._default_user, "--", path], user="")
        return res.bytes_written

    def read_file(self, path: str) -> str:
        """Reads a file as a string. Raises when it does not exist."""
        return self.read_file_bytes(path).decode("utf-8")

    def read_file_bytes(self, path: str) -> bytes:
        """Reads a file as raw bytes. Raises when it does not exist."""
        self._assert_live()

        def read() -> bytes:
            parts = []
            for chunk in self._transport.server_stream(
                "DownloadFile", api_pb2.DownloadRequest(sandbox_id=self.id, path=path)
            ):
                if chunk.data:
                    parts.append(chunk.data)
            return b"".join(parts)

        return self._with_resume(read)

    def open_file(self, path: str) -> Optional[Iterator[bytes]]:
        """Starts a download, returning `None` if the file is missing.

        The first chunk is pulled eagerly because that is when the server
        reports a missing file, and a `None` return has to be decided up front.
        """
        self._assert_live()

        def opened():
            source = self._transport.server_stream(
                "DownloadFile", api_pb2.DownloadRequest(sandbox_id=self.id, path=path)
            )
            return source, next(source, None)

        try:
            source, first = self._with_resume(opened)
        except BurrowError as err:
            if err.code == "not_found":
                return None
            raise

        def stream() -> Iterator[bytes]:
            if first is not None and first.data:
                yield first.data
            for chunk in source:
                if chunk.data:
                    yield chunk.data

        return stream()

    def download_file(self, src: str, dst: str, mkdir: bool = True) -> Optional[str]:
        """Copies a file out of the sandbox onto the local filesystem.

        Returns the absolute path it was written to, or `None` when the sandbox
        has no such file. Parent directories are created unless you say
        otherwise.

        ```python
        path = sandbox.download_file("/work/out.txt", "./out.txt")
        ```
        """
        stream = self.open_file(src)
        if stream is None:
            return None
        destination = os.path.abspath(dst)
        if mkdir:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
        # Streamed rather than buffered: a download is exactly the case where
        # the file is too big to want in memory.
        with open(destination, "wb") as out:
            for chunk in stream:
                out.write(chunk)
        return destination

    def list_dir(self, path: str) -> List[DirEntry]:
        """Lists a directory."""
        self._assert_live()
        res = self._with_resume(
            lambda: self._transport.unary(
                "ListDir", api_pb2.ListDirRequest(sandbox_id=self.id, path=path)
            )
        )
        return [
            DirEntry(name=e.name, is_dir=e.is_dir, size=e.size, mode=e.mode)
            for e in res.entries
        ]

    def mkdir(self, path: str, recursive: bool = True) -> None:
        """Creates a directory.

        There is no mkdir RPC, so this runs `mkdir -p` in the sandbox: it costs
        one exec and fails the way a command does rather than the way an RPC
        does.
        """
        flag = "-p " if recursive else ""
        res = self.exec(f"mkdir {flag}{_shell_quote(path)}")
        if not res.success:
            raise BurrowError(f"mkdir {path} failed: {res.stderr.strip()}", "internal")

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
        call = self._transport.open_server_stream(
            "Watch",
            api_pb2.WatchRequest(
                sandbox_id=self.id,
                path=path,
                recursive=recursive,
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

    def expose_port(self, guest_port: int, host_port: int = 0) -> PortMapping:
        """Publishes a port from inside the sandbox on its node's address.

        ```python
        mapping = sandbox.expose_port(8000)
        print(mapping.url)
        ```
        """
        self._assert_live()
        res = self._transport.unary(
            "ExposePort",
            api_pb2.ExposePortRequest(
                sandbox_id=self.id, guest_port=guest_port, host_port=host_port
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

    def update(self, **options: Any) -> SandboxInfo:
        """Updates tags, the network policy, the access policy, or any
        combination.

        Each section named is replaced wholesale rather than merged, so one
        call is enough to lock a sandbox down or to retag it, and a section not
        named is left alone. The machine shape is not updatable: a restore
        takes it from the snapshot.

        ```python
        sandbox.update(
            tags={"owner": "ci", "run": "482"},
            network_policy={"mode": "allowlist", "allow_domains": ["api.github.com"]},
            exec={"allow_exec": False},
        )
        ```
        """
        network = options.get("network_policy")
        if network is None:
            network = options.get("network")
        if options.get("tags") is not None:
            self.update_tags(options["tags"])
        if network is not None:
            self.update_network_policy(network)
        if options.get("exec") is not None or options.get("fs") is not None:
            self.update_access_policy(exec=options.get("exec"), fs=options.get("fs"))
        if any(
            options.get(key) is not None
            for key in ("max_lifetime_secs", "idle_suspend_secs", "suspended_ttl_secs")
        ):
            self.update_resources(
                max_lifetime_secs=options.get("max_lifetime_secs"),
                idle_suspend_secs=options.get("idle_suspend_secs"),
                suspended_ttl_secs=options.get("suspended_ttl_secs"),
            )
        return self._info

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

    def extend_timeout(self, secs: int) -> SandboxInfo:
        """Gives the sandbox `secs` more seconds of life, from when it was
        created.

        The familiar spelling of `update(max_lifetime_secs=...)`. Burrow
        measures a lifetime from creation rather than from now, so this sets a
        total rather than adding to what is left: pass the whole budget.
        """
        return self.update_resources(max_lifetime_secs=secs)

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

    def pause(self) -> SandboxInfo:
        """The same thing under its original name."""
        return self.stop()

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

    def kill(self) -> None:
        """Destroys the sandbox.

        Deprecated: use `delete`. Note that `stop` suspends rather than
        destroys, so it is not the replacement.
        """
        self.delete()

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
    """A connection to a burrow control plane, for listing or reattaching to
    sandboxes over one channel. `Sandbox.create` is the shortcut when you only
    need one."""

    def __init__(self, **options: Any):
        self._transport = Transport(**_transport_options(options))

    def health(self) -> Dict[str, str]:
        res = self._transport.unary("Health", api_pb2.HealthRequest())
        return {"version": res.version}

    def create(self, **options: Any) -> Sandbox:
        raw = self._transport.unary(
            "CreateSandbox", _to_create_request(options), options.get("timeout", 120.0)
        )
        return Sandbox._adopt(self._transport, raw)

    def list(self, tag: str = "") -> List[SandboxInfo]:
        """Lists sandboxes, optionally filtered by one `"key=value"` tag."""
        res = self._transport.unary(
            "ListSandboxes", api_pb2.ListSandboxesRequest(tag=tag)
        )
        return [_to_sandbox_info(raw) for raw in res.sandboxes]

    def get(self, ref: str) -> Sandbox:
        raw = self._transport.unary("GetSandbox", api_pb2.SandboxRef(id=ref))
        return Sandbox._adopt(self._transport, raw)

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
                allowed=raw.allowed,
                reason=raw.reason,
                bytes_sent=raw.bytes_sent,
                bytes_received=raw.bytes_received,
                node_id=raw.node_id,
            )
            for raw in self._transport.server_stream(
                "QueryAudit",
                api_pb2.AuditQuery(
                    sandbox_id=sandbox_id,
                    denied_only=denied_only,
                    since=since,
                    limit=limit,
                ),
            )
        ]

    def drain_node(
        self, node_id: str, drain: bool = True, suspend_sandboxes: bool = False
    ) -> int:
        """Stops (or resumes) placing new sandboxes on a node. Returns how many
        sandboxes were suspended."""
        res = self._transport.unary(
            "DrainNode",
            api_pb2.DrainNodeRequest(
                node_id=node_id, drain=drain, suspend_sandboxes=suspend_sandboxes
            ),
        )
        return res.suspended

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
                healthy=n.healthy,
                draining=n.status.draining,
                labels=dict(n.info.labels),
            )
            for n in res.nodes
        ]

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "Burrow":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
