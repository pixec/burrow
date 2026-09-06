"""Volumes: storage that outlives the sandboxes mounting it."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ._pb import api_pb2, common_pb2
from ._transport import Transport, transport_options
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
        self.name = raw.name
        # The node holding it, and the only node it can be attached on.
        self.node_id = raw.node_id
        self.size_mib = raw.size_mib
        # RFC 3339.
        self.created_at = raw.created_at
        # Sandbox holding the writable claim, or "" when free.
        self.attached_to = raw.attached_to

    @staticmethod
    def create(
        name: str,
        size_mib: int = 1024,
        node_labels: Optional[Dict[str, str]] = None,
        **options: Any,
    ) -> "Volume":
        """Creates a volume, placing it on a node that satisfies `node_labels`.

        A volume never moves, so the labels are the only chance to influence
        where it lands, and where every sandbox that mounts it will therefore
        run.
        """
        transport = Transport(**transport_options(options))
        try:
            raw = transport.unary(
                "CreateVolume",
                api_pb2.CreateVolumeRequest(
                    name=name, size_mib=size_mib, node_labels=node_labels or {}
                ),
            )
            return Volume(transport, raw)
        except BaseException:
            transport.close()
            raise

    @staticmethod
    def get(name: str, **options: Any) -> "Volume":
        """Returns a handle for a volume that already exists.

        Read from the node holding it, so `attached_to` is current rather than
        whatever the orchestrator last cached.
        """
        transport = Transport(**transport_options(options))
        try:
            raw = transport.unary("GetVolume", api_pb2.VolumeRef(name=name))
            return Volume(transport, raw)
        except BaseException:
            transport.close()
            raise

    @staticmethod
    def list(node: str = "", **options: Any) -> List["Volume"]:
        """Lists volumes by name, optionally only those on one node."""
        transport = Transport(**transport_options(options))
        try:
            res = transport.unary("ListVolumes", api_pb2.ListVolumesRequest(node_id=node))
            # Retained per handle, so releasing one does not close the channel
            # the others still hold.
            return [Volume(transport.retain(), raw) for raw in res.volumes]
        finally:
            transport.close()

    def delete(self) -> None:
        """Deletes the volume and everything stored in it.

        Refused while a sandbox holds it writable; stop that sandbox first.
        """
        try:
            self._transport.unary("DeleteVolume", api_pb2.VolumeRef(name=self.name))
        finally:
            self._transport.close()

    def close(self) -> None:
        """Releases this handle's share of the connection."""
        self._transport.close()
