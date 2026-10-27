# `events()` maps the lifecycle log and only drops the deadline when following,
# since a follow is meant to stay open.

from burrow import Burrow, Snapshot
from burrow._pb import api_pb2, common_pb2
from burrow._transport import _DEFAULT


class _Streaming:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def server_stream(self, method, request, timeout=_DEFAULT):
        self.calls.append((method, request, timeout))
        return iter(self.rows)

    def close(self):
        pass


def burrow_streaming(rows):
    burrow = Burrow(endpoint="localhost:1")
    burrow.close()
    burrow._transport = _Streaming(rows)
    return burrow


def test_events_maps_the_request_and_each_row():
    burrow = burrow_streaming(
        [
            common_pb2.Event(
                seq=48,
                node_id="node-1",
                node_seq=7,
                at_unix_ms=1_790_000_000_000,
                sandbox_id="sbx_a",
                type="started",
                state=common_pb2.SANDBOX_STATE_RUNNING,
                detail="boot",
                template="python",
                metadata={"team": "ml"},
                cpu_usage_usec=1200,
                rx_bytes=10,
                tx_bytes=20,
                vcpus=2,
                mem_mib=1024,
            )
        ]
    )
    events = list(burrow.events(after=47, sandbox="build-482", limit=5))
    method, request, timeout = burrow._transport.calls[0]
    assert method == "TailEvents"
    assert request == api_pb2.TailEventsRequest(
        after_seq=47, sandbox="build-482", is_follow=False, limit=5
    )
    assert timeout is _DEFAULT
    [event] = events
    assert event.seq == 48
    assert event.state == "running"
    assert event.detail == "boot"
    assert event.metadata == {"team": "ml"}
    assert event.memory_mib == 1024


def test_a_follow_has_no_deadline():
    burrow = burrow_streaming([])
    assert list(burrow.events(follow=True)) == []
    _, request, timeout = burrow._transport.calls[0]
    assert request.is_follow
    assert timeout is None


def test_a_snapshot_surfaces_where_it_can_be_restored():
    snapshot = Snapshot._adopt(
        None,
        common_pb2.Snapshot(
            id="snap_a", is_durable=True, arch="aarch64", firecracker_version="1.13.1"
        ),
    )
    assert snapshot.is_durable
    assert snapshot.arch == "aarch64"
    assert snapshot.firecracker_version == "1.13.1"
    assert snapshot.node_id == ""
