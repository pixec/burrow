"""Snapshots: a sandbox's saved state, addressable on its own."""

from __future__ import annotations

from typing import Any, List, Optional

from ._pb import api_pb2, common_pb2
from ._policy import from_resources
from ._transport import Transport
from ._wire import at, at_or_none
from .errors import BurrowError


class Snapshot:
    """A sandbox's saved state, addressable on its own.

    Obtained from `Sandbox.snapshot`, `burrow.snapshots` or the `Snapshot.get`
    and `Snapshot.list` shortcuts; not constructed directly.

    ```python
    snapshot = prepared.snapshot(expiration_secs=86_400)
    prepared.delete()

    # Outlives its source, and starts any number of sandboxes by restoring.
    worker = Sandbox.create(snapshot=snapshot.id)
    ```

    A snapshot encodes the host's cpu architecture and the exact hypervisor
    version. A create from one is placed on the node holding it. When the
    nodes run with an object store, the snapshot is also uploaded there and
    `durable` turns true; a create from a durable snapshot can then be placed
    on any node with the same `arch`, `hypervisor` and `hypervisor_version`,
    including when the node that took it is gone.
    """

    def __init__(self, transport: Transport, raw: common_pb2.Snapshot):
        if not raw.id:
            raise BurrowError("server returned a snapshot with no id", "internal")
        self._transport = transport
        self._closed = False
        self.id = raw.id
        # The sandbox the state was taken from. It may since have been deleted.
        self.sandbox_id = raw.sandbox_id
        self.template = raw.template
        # The node holding it locally. Empty when only the object store holds
        # it.
        self.node_id = raw.node_id
        # The machine the snapshot was taken on, and the only one it restores
        # as.
        self.resources = from_resources(raw.resources)
        self.created_at = at(raw.created_at_unix_ms)
        # Memory image, vmstate and disk, as the node's disk sees them.
        self.size_bytes = raw.size_bytes
        # None when the snapshot does not expire.
        self.expires_at = at_or_none(raw.expires_at_unix_ms)
        # A copy is in the fleet's object store, so a create from it can be
        # placed on any node matching `arch` and the hypervisor.
        self.durable = raw.is_durable
        self.arch = raw.arch
        self.hypervisor = raw.hypervisor
        self.hypervisor_version = raw.hypervisor_version

    @staticmethod
    def get(
        snapshot_id: str,
        *,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> "Snapshot":
        """`Burrow(...).snapshots.get(...)` on a connection of its own."""
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.snapshots.get(snapshot_id)

    @staticmethod
    def list(
        *,
        sandbox_id: str = "",
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ) -> List["Snapshot"]:
        """`Burrow(...).snapshots.list(...)` on a connection of its own.

        ```python
        for snapshot in Snapshot.list(sandbox_id="build-482"):
            snapshot.delete()
        ```
        """
        from .client import Burrow

        with Burrow(endpoint=endpoint, api_key=api_key, tls=tls, timeout=timeout, route=route) as burrow:
            return burrow.snapshots.list(sandbox_id=sandbox_id)

    def delete(self) -> None:
        """Deletes the snapshot, from the node holding it and from the object store."""
        try:
            self._transport.unary("DeleteSnapshot", api_pb2.SnapshotRef(id=self.id))
        finally:
            self.close()

    def close(self) -> None:
        """Releases this handle's share of the connection."""
        if not self._closed:
            self._closed = True
            self._transport.close()

    def __enter__(self) -> "Snapshot":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
