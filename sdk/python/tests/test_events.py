# `events()` maps the lifecycle log and only drops the deadline when following,
# since a follow is meant to stay open.

from datetime import datetime, timezone

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
                kind=common_pb2.EVENT_KIND_STARTED,
                state=common_pb2.SANDBOX_STATE_RUNNING,
                detail="boot",
                template="python",
                tags={"team": "ml"},
                cpu_usage_usec=1200,
                rx_bytes=10,
                tx_bytes=20,
                vcpus=2,
                mem_mib=1024,
            )
        ]
    )
    events = list(burrow.events(after=47, sandbox_id="build-482", limit=5))
    method, request, timeout = burrow._transport.calls[0]
    assert method == "TailEvents"
    assert request == api_pb2.TailEventsRequest(
        after_seq=47, sandbox_id="build-482", is_follow=False, limit=5
    )
    assert timeout is _DEFAULT
    [event] = events
    assert event.seq == 48
    assert event.kind == "started"
    assert event.state == "running"
    assert event.detail == "boot"
    assert event.at == datetime(2026, 9, 21, 14, 13, 20, tzinfo=timezone.utc)
    assert event.tags == {"team": "ml"}
    assert event.memory_mib == 1024


def test_a_follow_has_no_deadline():
    burrow = burrow_streaming([])
    assert list(burrow.events(follow=True)) == []
    _, request, timeout = burrow._transport.calls[0]
    assert request.is_follow
    assert timeout is None


def test_a_snapshot_surfaces_where_it_can_be_restored():
    snapshot = Snapshot(
        None,
        common_pb2.Snapshot(
            id="snap_a",
            is_durable=True,
            arch="aarch64",
            hypervisor="firecracker",
            hypervisor_version="1.13.1",
            resources=common_pb2.ResourcePolicy(vcpus=2, mem_mib=1024),
            created_at_unix_ms=1_790_000_000_000,
        ),
    )
    assert snapshot.durable
    assert snapshot.arch == "aarch64"
    assert snapshot.hypervisor_version == "1.13.1"
    assert snapshot.resources.memory_mib == 1024
    assert snapshot.expires_at is None
    assert snapshot.created_at.year == 2026
    assert snapshot.node_id == ""


class _Unary:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def unary(self, method, request, timeout=_DEFAULT):
        self.calls.append((method, request))
        return self.response

    def close(self):
        pass


def test_usage_maps_the_query_and_the_report():
    burrow = Burrow(endpoint="localhost:1")
    burrow.close()
    burrow._transport = _Unary(
        api_pb2.QueryUsageResponse(
            sums=[
                api_pb2.UsageSum(
                    group="acme",
                    state=api_pb2.USAGE_STATE_RUNNING,
                    intervals=2,
                    duration_ms=2_400_000,
                    vcpu_ms=4_800_000,
                    mem_mib_ms=4_915_200_000,
                    cpu_usage_usec=1_092_000_000,
                    tx_bytes=1_395_864_371,
                )
            ]
        )
    )
    report = burrow.usage(
        start=datetime(2026, 10, 1, tzinfo=timezone.utc),
        end=datetime(2026, 11, 1, tzinfo=timezone.utc),
        group_by="tag:customer",
        tags={"plan": "team"},
    )
    method, request = burrow._transport.calls[0]
    assert method == "QueryUsage"
    assert request == api_pb2.QueryUsageRequest(
        from_unix_ms=1_790_812_800_000,
        to_unix_ms=1_793_491_200_000,
        group_by=api_pb2.USAGE_GROUP_TAG,
        group_by_tag="customer",
        tags={"plan": "team"},
        is_open_included=True,
    )
    assert report.intervals == []
    [total] = report.sums
    assert (total.group, total.state, total.intervals) == ("acme", "running", 2)
    assert total.memory_mib_ms == 4_915_200_000
    assert report.next_after_id == 0


def test_sandbox_handles_share_the_clients_connection():
    burrow = Burrow(endpoint="localhost:1")
    transport = burrow._transport
    transport.unary = lambda method, request, timeout=_DEFAULT: common_pb2.Sandbox(
        id="sbx_a", created_at_unix_ms=1_790_000_000_000
    )
    sandbox = burrow.sandboxes.get("sbx_a")
    assert transport._refs == 2
    burrow.close()
    assert transport._refs == 1
    sandbox.close()
    sandbox.close()
    assert transport._refs == 0
