"""Volumes: storage that outlives the sandboxes mounting it."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ._pb import api_pb2, common_pb2
from ._transport import Transport
from ._wire import at
from .errors import BurrowError


class Volume:
    """Storage that outlives the sandboxes mounting it.

    ```python
    cache = Volume.create("build-cache", size_mib=20_480)
    sbx = Sandbox.create(
        template="python",
        volumes=[{"volume": "build-cache", "path": "/cache"}],
    )
    ```

    A volume is an ext4 image on one node, attached to the guest as a block
    device. Three things follow from that, and none of them are avoidable:

    - **Writable mounts are exclusive.** ext4 is not a cluster filesystem, so
      one sandbox at a time may mount a volume read-write. The claim is
      released when that sandbox stops.
    - **Read-only mounts are shared.** Any number of sandboxes may mount one
      read-only at once, even alongside the writer.
    - **A volume never moves.** A sandbox that mounts one is placed on the node
      holding it, and mounting one costs a cold boot rather than a warm
      restore.
    """

    def __init__(self, transport: Transport, raw: common_pb2.Volume):
        if not raw.name:
            raise BurrowError("server returned a volume with no name", "internal")
        self._transport = transport
        self._closed = False
        self.name = raw.name
        # The node holding it, and the only node it can be attached on.
        self.node_id = raw.node_id
        self.size_mib = raw.size_mib
        self.created_at = at(raw.created_at_unix_ms)
        # Sandbox holding the writable claim, or "" when free.
        self.attached_to = raw.attached_to
        self.labels = dict(raw.labels)

    @staticmethod
    def create(
        name: str,
        *,
        size_mib: int = 1024,
        node_labels: Optional[Dict[str, str]] = None,
        labels: Optional[Dict[str, str]] = None,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> "Volume":
        """`Burrow(...).volumes.create(...)` on a connection of its own."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.volumes.create(
                name, size_mib=size_mib, node_labels=node_labels, labels=labels
            )

    @staticmethod
    def get(
        name: str,
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> "Volume":
        """`Burrow(...).volumes.get(...)` on a connection of its own."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.volumes.get(name)

    @staticmethod
    def list(
        *,
        node_id: str = "",
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> List["Volume"]:
        """`Burrow(...).volumes.list(...)` on a connection of its own."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.volumes.list(node_id=node_id)

    def delete(self) -> None:
        """Deletes the volume and everything stored in it.

        Refused while a sandbox holds it writable; stop that sandbox first.
        """
        try:
            self._transport.unary("DeleteVolume", api_pb2.VolumeRef(name=self.name))
        finally:
            self.close()

    def close(self) -> None:
        """Releases this handle's share of the connection."""
        if not self._closed:
            self._closed = True
            self._transport.close()

    def __enter__(self) -> "Volume":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
