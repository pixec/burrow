"""Templates: build a reusable guest image by running steps in a sandbox."""

from __future__ import annotations

import base64
import sys
from typing import Any, Callable, Dict, List, Optional, Union

from ._pb import api_pb2
from ._transport import Transport
from ._wire import kernel as to_kernel
from .errors import BurrowError
from .types import BuiltTemplate, TemplateInfo

# One build log event, as a dict: {"type": "step", "command": ...},
# {"type": "stdout"/"stderr", "data": ...} or
# {"type": "done", "template": ..., "size_bytes": ...}.
BuildLogEvent = Dict[str, Any]


def default_build_logger(
    write: Optional[Callable[[str], Any]] = None,
) -> Callable[[BuildLogEvent], None]:
    """Prints build logs the way a build tool would."""
    if write is None:
        write = sys.stdout.write

    def log(event: BuildLogEvent) -> None:
        if event["type"] == "step":
            write(f"\n→ {event['command']}\n")
        elif event["type"] in ("stdout", "stderr"):
            write(event["data"])
        elif event["type"] == "done":
            write(
                f"\n✓ built {event['template']} "
                f"({event['size_bytes'] / 1e6:.1f} MB)\n"
            )

    return log


def _quote(value: str) -> str:
    quoted = value.replace("'", "'\\''")
    return f"'{quoted}'"


def _to_list(packages: Union[str, List[str]]) -> List[str]:
    return [p for p in ([packages] if isinstance(packages, str) else packages) if p]


def to_template_info(raw: api_pb2.TemplateInfo) -> TemplateInfo:
    return TemplateInfo(
        name=raw.name,
        size_bytes=raw.size_bytes,
        warm=raw.is_warm,
        kit=raw.is_kit,
        systemd=raw.is_systemd,
        guest_os=raw.guest_os,
        hypervisor=raw.hypervisor,
        kernel=to_kernel(raw.kernel),
    )


def build_template(
    transport: Transport,
    template: "TemplateBuilder",
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
    """Runs a build over `transport` and reports what the server published."""
    if not (template._base or template._image or template._ipsw):
        raise BurrowError(
            "a template build needs a base: call from_template, from_image or from_ipsw",
            "invalid_argument",
        )
    request = api_pb2.BuildTemplateRequest(
        name=name,
        # An OCI base takes the place of a template base; sending both
        # would leave the node to guess which was meant.
        **{"from": "" if template._image or template._ipsw else template._base},
        from_image=template._image,
        from_ipsw=template._ipsw,
        steps=[api_pb2.BuildStep(run=step) for step in template._steps],
        # Zero is the node's default for the guest being built: 1 vCPU and
        # 1024 MiB for Linux, the restore image's minimum for macOS.
        vcpus=vcpus,
        mem_mib=memory_mib,
        # "firecracker", "cloud-hypervisor" or "vz"; empty is the base's.
        hypervisor=hypervisor,
        # The guest kernel by the node's name for it; empty is the base's,
        # else the node's default for the hypervisor (the Firecracker CI
        # kernel for Firecracker, Cloud Hypervisor's own for Cloud Hypervisor).
        kernel=kernel,
        # The build's root disk in MiB, which is the image it makes; for
        # `from_ipsw` the installed macOS disk.
        disk_mib=disk_mib,
        # Omitted means unrestricted, because a build that installs packages
        # needs the network by definition.
        allow_domains=allow_domains or [],
        # Boot the image's own systemd under the agent. The image has to ship
        # systemd.
        is_systemd=systemd,
    )
    result: Optional[BuiltTemplate] = None
    # Builds install packages; minutes, not seconds.
    for raw in transport.server_stream("BuildTemplate", request, timeout):
        event = _to_event(raw)
        if event is None:
            continue
        if on_build_logs:
            on_build_logs(event)
        if event["type"] == "done":
            result = BuiltTemplate(name=event["template"], size_bytes=event["size_bytes"])
    if result is None:
        raise BurrowError("build ended without producing an image", "internal")
    return result


class _Build:
    """`build` both ways: `template.build(name)` on a builder, and
    `Template.build(template, name)` on the class. Both open a connection of
    their own: `timeout` is the build's deadline, 30 minutes by default, and
    `call_timeout` the connection's default."""

    def __get__(self, builder: Optional["TemplateBuilder"], owner: Any) -> Callable[..., BuiltTemplate]:
        if builder is None:
            return _build_with_connection
        return lambda name, **options: _build_with_connection(builder, name, **options)


def _build_with_connection(
    template: "TemplateBuilder",
    name: str,
    *,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
    tls: Optional[bool] = None,
    call_timeout: Optional[float] = 60.0,
    route: Optional[str] = None,
    **options: Any,
) -> BuiltTemplate:
    from .client import Burrow

    with Burrow(
        endpoint=endpoint, api_key=api_key, tls=tls, timeout=call_timeout, route=route
    ) as burrow:
        return burrow.templates.build(template, name, **options)


class TemplateBuilder:
    """Describes a guest image as a base plus a list of steps.

    Steps run in a real sandbox and the resulting filesystem becomes the image,
    so anything a command can do is fair game: there is no separate build
    language to learn.

    ```python
    built = (
        Template()
        .from_template("python")
        .run_cmd("apk add --no-cache python3 py3-pip")
        .pip_install(["cowsay", "requests"])
        .build("python-tools", on_build_logs=default_build_logger())
    )
    ```
    """

    build = _Build()

    def __init__(self) -> None:
        self._base = ""
        self._image = ""
        self._ipsw = ""
        self._steps: List[str] = []

    def from_template(self, name: str) -> "TemplateBuilder":
        """Sets the burrow template to start from. A build needs a base: this,
        `from_image` or `from_ipsw`."""
        self._base = name
        self._image = ""
        self._ipsw = ""
        return self

    def from_ipsw(self, source: str) -> "TemplateBuilder":
        """Installs macOS from a restore image on a Mac node: a path on that
        node, or `"latest"`, which the node downloads from Apple and keeps.

        The template runs under `vz` and takes no steps; build on it with
        `from_template` to add some.
        """
        self._ipsw = source
        self._image = ""
        return self

    def from_image(self, reference: str) -> "TemplateBuilder":
        """Starts from an OCI image, e.g. `"python:3.12-slim"` or
        `"ghcr.io/org/tool@sha256:..."`.

        Its layers become the root filesystem and burrow's agent is installed
        as init, so the image's environment and working directory carry over
        but nothing belonging to a container runtime (entrypoint, user, signal
        handling) does.
        """
        self._image = reference
        self._ipsw = ""
        return self

    def run_cmd(self, *commands: str) -> "TemplateBuilder":
        """Runs a shell command."""
        for command in commands:
            if command.strip():
                self._steps.append(command)
        return self

    def pip_install(self, packages: Union[str, List[str]]) -> "TemplateBuilder":
        """Installs Python packages with pip."""
        names = _to_list(packages)
        if names:
            self.run_cmd(f"pip install --no-cache-dir {' '.join(names)}")
        return self

    def npm_install(self, packages: Union[str, List[str]]) -> "TemplateBuilder":
        """Installs Node packages globally, so they are on `PATH` for
        sandboxes."""
        names = _to_list(packages)
        if names:
            self.run_cmd(f"npm install -g {' '.join(names)}")
        return self

    def apt_install(self, packages: Union[str, List[str]]) -> "TemplateBuilder":
        """Installs system packages with apt."""
        names = _to_list(packages)
        if names:
            self.run_cmd(
                "apt-get update && apt-get install -y --no-install-recommends "
                f"{' '.join(names)} && rm -rf /var/lib/apt/lists/*"
            )
        return self

    def apk_install(self, packages: Union[str, List[str]]) -> "TemplateBuilder":
        """Installs system packages with apk (Alpine)."""
        names = _to_list(packages)
        if names:
            self.run_cmd(f"apk add --no-cache {' '.join(names)}")
        return self

    def write_file(self, path: str, contents: str) -> "TemplateBuilder":
        """Writes a file into the image."""
        # Base64 so quotes, newlines and shell metacharacters survive the
        # command.
        encoded = base64.b64encode(contents.encode("utf-8")).decode("ascii")
        return self.run_cmd(
            f'mkdir -p "$(dirname {_quote(path)})" && '
            f"echo {_quote(encoded)} | base64 -d > {_quote(path)}"
        )

    def mkdir(self, path: str) -> "TemplateBuilder":
        """Creates a directory in the image. Steps do not inherit a working
        directory, so `cd` inside the step that needs one."""
        return self.run_cmd(f"mkdir -p {_quote(path)}")

    @property
    def plan(self) -> List[str]:
        """The steps this template will run, in order."""
        return list(self._steps)


class Template(TemplateBuilder):
    """`Template()` starts a builder; `Template.list` and `Template.delete`
    talk to the fleet on a connection of their own."""

    @staticmethod
    def list(
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> List[TemplateInfo]:
        """Lists the templates available across the fleet."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.templates.list()

    @staticmethod
    def delete(
        name: str,
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> None:
        """Deletes a template."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            burrow.templates.delete(name)


def _to_event(raw: api_pb2.BuildLog) -> Optional[BuildLogEvent]:
    kind = raw.WhichOneof("event")
    if kind == "step":
        return {"type": "step", "command": raw.step}
    if kind == "stdout" and raw.stdout:
        return {"type": "stdout", "data": raw.stdout.decode("utf-8", "replace")}
    if kind == "stderr" and raw.stderr:
        return {"type": "stderr", "data": raw.stderr.decode("utf-8", "replace")}
    if kind == "done":
        return {
            "type": "done",
            "template": raw.done.template,
            "size_bytes": raw.done.size_bytes,
        }
    return None
