"""Snapshots: a sandbox's saved state, addressable on its own."""

from __future__ import annotations

from typing import Any, List

from ._pb import api_pb2, common_pb2
from ._transport import Transport, transport_options
from .errors import BurrowError


class Snapshot:
    """A sandbox's saved state, addressable on its own.

    Obtained from `Sandbox.snapshot`, `Snapshot.get` or `Snapshot.list`; not
    constructed directly.

    ```python
    snapshot = prepared.snapshot(expiration=86_400)
    prepared.delete()

    # Outlives its source, and starts any number of sandboxes by restoring.
    worker = Sandbox.create(snapshot=snapshot.id)
    ```

    A snapshot is **node-local**: it encodes the host's cpu features and the
    exact Firecracker version, so it can only be restored on the node that took
    it, and a sandbox created from one is placed there.
    """

    def __init__(self, transport: Transport, raw: common_pb2.Snapshot):
        if not raw.id:
            raise BurrowError("server returned a snapshot with no id", "internal")
        self._transport = transport
        self.id = raw.id
        # The sandbox the state was taken from. It may since have been deleted.
        self.sandbox_id = raw.sandbox_id
        self.template = raw.template
        # The node holding it, and the only node it can be restored on.
        self.node_id = raw.node_id
        # The machine the snapshot was taken on, and the only one it restores
        # as.
        self.vcpus = raw.vcpus
        self.memory_mib = raw.mem_mib
        self.disk_mib = raw.scratch_disk_mib
        # RFC 3339.
        self.created_at = raw.created_at
        # Memory image, vmstate and scratch disk, as the node's disk sees them.
        self.size_bytes = raw.size_bytes
        # RFC 3339, or "" when the snapshot does not expire.
        self.expires_at = raw.expires_at

    @staticmethod
    def _adopt(transport: Transport, raw: common_pb2.Snapshot) -> "Snapshot":
        """Lets a sandbox hand its own connection to the snapshot."""
        return Snapshot(transport, raw)

    @staticmethod
    def get(id: str, **options: Any) -> "Snapshot":
        """Returns a handle for a snapshot that already exists."""
        transport = Transport(**transport_options(options))
        try:
            raw = transport.unary("GetSnapshot", api_pb2.SnapshotRef(id=id))
            return Snapshot(transport, raw)
        except BaseException:
            transport.close()
            raise

    @staticmethod
    def list(sandbox: str = "", **options: Any) -> List["Snapshot"]:
        """Lists snapshots, newest first, optionally only those taken of one
        sandbox (by id or name).

        ```python
        for snapshot in Snapshot.list(sandbox="build-482"):
            snapshot.delete()
        ```
        """
        transport = Transport(**transport_options(options))
        try:
            res = transport.unary(
                "ListSnapshots", api_pb2.ListSnapshotsRequest(sandbox=sandbox)
            )
            # Retained per handle, so releasing one does not close the channel
            # the others still hold.
            return [Snapshot(transport.retain(), raw) for raw in res.snapshots]
        finally:
            transport.close()

    def delete(self) -> None:
        """Deletes the snapshot, freeing its disk on the node holding it."""
        try:
            self._transport.unary("DeleteSnapshot", api_pb2.SnapshotRef(id=self.id))
        finally:
            self._transport.close()

    def close(self) -> None:
        """Releases this handle's share of the connection."""
        self._transport.close()
