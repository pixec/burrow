"""Templates: build a reusable guest image by running steps in a sandbox."""

from __future__ import annotations

import base64
import sys
from typing import Any, Callable, Dict, List, Optional, Union

from ._pb import api_pb2
from ._transport import Transport, transport_options
from .errors import BurrowError
from .types import TemplateInfo

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


class TemplateBuilder:
    """Describes a guest image as a base plus a list of steps.

    Steps run in a real sandbox and the resulting filesystem becomes the image,
    so anything a command can do is fair game: there is no separate build
    language to learn.

    ```python
    template = (
        Template()
        .from_template("python")
        .run_cmd("apk add --no-cache python3 py3-pip")
        .pip_install(["cowsay", "requests"])
    )

    Template.build(template, "python-tools", on_build_logs=default_build_logger())
    ```
    """

    def __init__(self) -> None:
        self._base = "default"
        self._image = ""
        self._steps: List[str] = []

    def from_template(self, name: str) -> "TemplateBuilder":
        """Sets the burrow template to start from. Defaults to `"default"`."""
        self._base = name
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
        """Creates a directory in the image."""
        return self.run_cmd(f"mkdir -p {_quote(path)}")

    def workdir(self, path: str) -> "TemplateBuilder":
        """Creates the directory later steps are meant to work in. Steps do not
        inherit a working directory, so `cd` inside the step that needs it."""
        return self.run_cmd(f"mkdir -p {_quote(path)}")

    @property
    def plan(self) -> List[str]:
        """The steps this template will run, in order."""
        return list(self._steps)

    def _to_request(self, name: str, options: Dict[str, Any]) -> api_pb2.BuildTemplateRequest:
        return api_pb2.BuildTemplateRequest(
            name=name,
            # An OCI base takes the place of a template base; sending both
            # would leave the node to guess which was meant.
            **{"from": "" if self._image else self._base},
            from_image=self._image,
            steps=[api_pb2.BuildStep(run=step) for step in self._steps],
            vcpus=options.get("cpu_count") or 1,
            mem_mib=options.get("memory_mib") or 1024,
            # Omitted means unrestricted, because a build that installs
            # packages needs the network by definition.
            allow_domains=options.get("allow_domains") or [],
        )


class Template(TemplateBuilder):
    """`Template()` starts a builder; the static methods talk to the fleet."""

    @staticmethod
    def build(template: TemplateBuilder, name: str, **options: Any) -> TemplateInfo:
        """Builds a template and publishes it under `name`."""
        transport = Transport(**transport_options(options))
        on_build_logs = options.get("on_build_logs")
        try:
            result: Optional[TemplateInfo] = None
            for raw in transport.server_stream(
                "BuildTemplate",
                template._to_request(name, options),
                # Builds install packages; minutes, not seconds.
                options.get("timeout", 30 * 60.0),
            ):
                event = _to_event(raw)
                if event is None:
                    continue
                if on_build_logs:
                    on_build_logs(event)
                if event["type"] == "done":
                    result = TemplateInfo(
                        name=event["template"],
                        size_bytes=event["size_bytes"],
                        # A freshly built template has no snapshot until the
                        # node warms it.
                        warm=False,
                    )
            if result is None:
                raise BurrowError("build ended without producing an image", "internal")
            return result
        finally:
            transport.close()

    @staticmethod
    def list(**options: Any) -> List[TemplateInfo]:
        """Lists the templates available across the fleet."""
        transport = Transport(**transport_options(options))
        try:
            res = transport.unary("ListTemplates", api_pb2.ListTemplatesRequest())
            return [
                TemplateInfo(name=t.name, size_bytes=t.size_bytes, warm=t.warm)
                for t in res.templates
            ]
        finally:
            transport.close()

    @staticmethod
    def delete(name: str, **options: Any) -> None:
        """Deletes a template."""
        transport = Transport(**transport_options(options))
        try:
            transport.unary("DeleteTemplate", api_pb2.DeleteTemplateRequest(name=name))
        finally:
            transport.close()


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
