"""Ingress rules and public IPs, as they reach and come back from the wire."""

import pytest

from burrow import BurrowError, IngressRule, IpPool
from burrow._pb import common_pb2
from burrow._policy import from_network_policy, network_policy, to_network_policy
from burrow.ip import from_pool, to_pool, to_public_ip


def test_ingress_rules_reach_the_wire_and_read_back():
    wire = to_network_policy(
        network_policy(
            {
                "mode": "open",
                "ingress": [
                    {"protocol": "tcp", "ports": [25, 587]},
                    {"protocol": "tcp", "ports": [22], "sources": ["203.0.113.0/24"]},
                    {"protocol": "udp", "ports": ["27000-27015"]},
                    IngressRule(protocol="icmp"),
                    {},
                ],
            }
        )
    )
    assert wire.ingress[0].protocol == common_pb2.INGRESS_PROTOCOL_TCP
    assert [p.port for p in wire.ingress[0].ports] == [25, 587]
    assert wire.ingress[2].ports[0].port_end == 27015
    assert wire.ingress[4].protocol == common_pb2.INGRESS_PROTOCOL_UNSPECIFIED
    back = from_network_policy(wire).ingress
    assert back[1] == IngressRule(protocol="tcp", ports=[22], sources=["203.0.113.0/24"])
    assert back[2].ports == ["27000-27015"]
    assert back[3] == IngressRule(protocol="icmp")
    assert back[4] == IngressRule()


@pytest.mark.parametrize(
    "rule",
    [{"protocol": "sctp"}, {"port": 22}, {"ports": ["22-"]}, {"ports": [True]}],
)
def test_a_misspelt_ingress_rule_is_refused(rule):
    with pytest.raises(BurrowError):
        network_policy({"ingress": [rule]})


def test_a_pool_maps_its_friendly_keys():
    pool = to_pool(
        {
            "name": "rack-a",
            "node_id": "node-a",
            "ranges": ["203.0.113.16-203.0.113.30"],
            "on_link": True,
            "node_labels": {"rack": "b7"},
        }
    )
    assert pool.is_on_link and pool.ranges == ["203.0.113.16-203.0.113.30"]
    assert dict(pool.node_labels) == {"rack": "b7"}
    assert from_pool(pool) == IpPool(
        name="rack-a",
        node_id="node-a",
        node_labels={"rack": "b7"},
        ranges=["203.0.113.16-203.0.113.30"],
        on_link=True,
    )
    with pytest.raises(BurrowError):
        to_pool({"name": "rack-a", "mode": "nat"})
    with pytest.raises(BurrowError):
        to_pool({"name": "rack-a", "provider": "static"})


def test_a_public_ip_reads_back():
    ip = to_public_ip(
        common_pb2.PublicIp(
            address="203.0.113.17",
            family=4,
            sandbox_id="sbx_a",
            node_id="node-a",
            state=common_pb2.PUBLIC_IP_STATE_ALLOCATED,
            allocated_at_unix_ms=1_700_000_000_000,
        )
    )
    assert ip.address == "203.0.113.17" and ip.sandbox_id == "sbx_a"
    assert ip.node_id == "node-a" and ip.state == "allocated"
    assert int(ip.allocated_at.timestamp()) == 1_700_000_000
    assert ip.attached_at is None and not ip.node_prefix


def test_a_sandboxs_node_address_reads_back_as_a_public_ip():
    ip = to_public_ip(
        common_pb2.PublicIp(
            address="2001:db8:100:3::1",
            family=6,
            prefix_len=64,
            pool="node:node-a",
            is_node_prefix=True,
        )
    )
    assert ip.node_prefix and ip.pool == "node:node-a" and ip.prefix_len == 64


def test_a_drain_can_keep_sandboxes_pinned_by_their_public_ips():
    from burrow import Burrow
    from burrow._pb import api_pb2

    class Unary:
        calls = []

        def unary(self, method, request, timeout=None):
            self.calls.append((method, request))
            return api_pb2.DrainNodeResponse(suspended=2, pinned_sandbox_ids=["sbx_a"])

        def close(self):
            pass

    burrow = Burrow(endpoint="localhost:1")
    burrow.close()
    burrow._transport = Unary()
    res = burrow.drain_node("node-a", suspend=True, keep_pinned=True)
    method, request = burrow._transport.calls[0]
    assert method == "DrainNode" and request.is_pinned_kept and request.is_suspending
    assert res.suspended == 2 and res.pinned_sandbox_ids == ["sbx_a"]
