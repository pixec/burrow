"""Nodes, as the control plane lists them."""

from burrow import Burrow, DiskCapacity
from burrow._pb import api_pb2, common_pb2
from burrow._transport import _DEFAULT


class _Unary:
    def __init__(self, response):
        self.response = response

    def unary(self, method, request, timeout=_DEFAULT):
        return self.response

    def close(self):
        pass


def test_a_node_reports_its_disk():
    burrow = Burrow(endpoint="localhost:1")
    burrow.close()
    burrow._transport = _Unary(
        api_pb2.ListNodesResponse(
            nodes=[
                api_pb2.Node(
                    info=common_pb2.NodeInfo(id="n1"),
                    status=common_pb2.NodeStatus(
                        is_disk_low=True,
                        disk=common_pb2.DiskCapacity(
                            free_bytes=10 << 30,
                            total_bytes=100 << 30,
                            reserve_bytes=5 << 30,
                            overcommit=1.5,
                            provisioned_bytes=120 << 30,
                        ),
                    ),
                )
            ]
        )
    )
    [node] = burrow.nodes()
    assert node.disk == DiskCapacity(
        free_bytes=10 << 30,
        total_bytes=100 << 30,
        reserve_bytes=5 << 30,
        overcommit=1.5,
        provisioned_bytes=120 << 30,
    )
    assert node.disk_low
