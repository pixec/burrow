# Policy conversion runs entirely client-side, so it is checked without a
# server: the options must land on the same wire shape the daemons read.

import pytest

from burrow._pb import common_pb2
from burrow._policy import from_network_policy, resolve_network, to_network_policy
from burrow.errors import BurrowError
from burrow.types import PortRule


def test_a_string_is_a_mode():
    assert resolve_network("open")["mode"] == "open"
    assert resolve_network("allowlist")["mode"] == "allowlist"


def test_the_old_shorthand_strings_are_unknown_modes():
    for gone in ("allow-all", "deny-all"):
        with pytest.raises(BurrowError, match="unknown mode"):
            to_network_policy(resolve_network(gone))


def test_the_old_shorthand_dict_is_refused_not_read_as_no_network():
    with pytest.raises(BurrowError, match="unknown key 'allow'"):
        resolve_network({"allow": ["pypi.org"]})
    with pytest.raises(BurrowError, match="unknown key 'subnets'"):
        resolve_network({"subnets": {"deny": ["169.254.0.0/16"]}})


def test_an_allowlist_carries_domains_and_denies():
    wire = to_network_policy(
        resolve_network(
            {
                "mode": "allowlist",
                "allow_domains": ["pypi.org", "*.pythonhosted.org"],
                "deny_cidrs": ["169.254.0.0/16"],
            }
        )
    )
    assert wire.mode == common_pb2.NETWORK_MODE_ALLOWLIST
    assert list(wire.allow_domains) == ["pypi.org", "*.pythonhosted.org"]
    assert list(wire.deny_cidrs) == ["169.254.0.0/16"]
    assert not wire.is_tls_inspected


def rule_policy(rule):
    return {
        "mode": "allowlist",
        "allow_domains": ["api.example.com"],
        "inspect_tls": True,
        "rules": [{"domain": "api.example.com", **rule}],
    }


def test_a_rule_reaches_the_wire():
    wire = to_network_policy(
        resolve_network(
            rule_policy(
                {
                    "match": {"path": {"starts_with": "/v1/"}, "method": "POST"},
                    "set_headers": {"Authorization": "Bearer t"},
                }
            )
        )
    )
    assert wire.is_tls_inspected
    rule = wire.rules[0]
    assert rule.domain == "api.example.com"
    assert rule.match.path.op == common_pb2.STRING_MATCH_OP_STARTS_WITH
    assert list(rule.match.methods) == ["POST"]
    assert rule.set_headers.headers[0].name == "Authorization"


def test_an_unknown_rule_key_is_refused_not_dropped():
    with pytest.raises(BurrowError, match="unknown key 'forward_url'"):
        to_network_policy(rule_policy({"forward_url": "https://x", "set_headers": {"A": "b"}}))


def test_an_unknown_match_key_is_refused_not_dropped():
    # Dropped, it would widen the rule to every request to the domain.
    with pytest.raises(BurrowError, match="unknown key 'paths'"):
        to_network_policy(
            rule_policy({"match": {"paths": "/v1/x"}, "set_headers": {"A": "b"}})
        )


def test_an_unknown_forward_key_is_refused():
    with pytest.raises(BurrowError, match="unknown key 'secrets'"):
        to_network_policy(rule_policy({"forward": {"url": "https://x", "secrets": "s"}}))


def test_a_rule_without_an_action_is_refused():
    with pytest.raises(BurrowError, match="needs either set_headers or forward"):
        to_network_policy(rule_policy({"match": {"path": "/v1/x"}}))


def test_a_bad_header_name_is_refused():
    with pytest.raises(BurrowError, match="not a valid header name"):
        to_network_policy(rule_policy({"set_headers": {"Bad Header": "x"}}))


def test_the_wire_policy_reads_back_as_it_was_written():
    wire = to_network_policy(resolve_network(rule_policy({"set_headers": {"X-Token": "secret"}})))
    back = from_network_policy(wire)
    assert back.mode == "allowlist"
    assert back.inspect_tls
    # A rule with no matcher is also readable in the pre-rules shape.
    assert back.inject_headers[0].domain == "api.example.com"
    assert back.inject_headers[0].name == "X-Token"


def test_denied_ports_and_ipv6_reach_the_wire_in_open_mode():
    wire = to_network_policy(
        resolve_network(
            {
                "mode": "open",
                "deny_ports": [
                    {"protocol": "tcp", "port": 25},
                    {"protocol": "tcp", "port": 465, "port_end": 587},
                    {"port": 5432, "cidrs": ["10.0.0.0/8", "2001:db8::/32"]},
                    PortRule(port=53, protocol="udp"),
                ],
                "deny_ipv6": True,
            }
        )
    )
    assert wire.mode == common_pb2.NETWORK_MODE_OPEN
    assert wire.is_ipv6_denied
    assert [
        (rule.protocol, rule.port, rule.port_end, list(rule.cidrs))
        for rule in wire.deny_ports
    ] == [
        (common_pb2.PORT_PROTOCOL_TCP, 25, 0, []),
        (common_pb2.PORT_PROTOCOL_TCP, 465, 587, []),
        (common_pb2.PORT_PROTOCOL_UNSPECIFIED, 5432, 0, ["10.0.0.0/8", "2001:db8::/32"]),
        (common_pb2.PORT_PROTOCOL_UDP, 53, 0, []),
    ]

    back = from_network_policy(wire)
    assert back.deny_ipv6
    assert back.deny_ports == [
        PortRule(port=25, protocol="tcp"),
        PortRule(port=465, protocol="tcp", port_end=587),
        PortRule(port=5432, protocol="any", cidrs=["10.0.0.0/8", "2001:db8::/32"]),
        PortRule(port=53, protocol="udp"),
    ]


def test_the_new_fields_default_to_the_old_behaviour():
    wire = to_network_policy(resolve_network("open"))
    assert not wire.is_ipv6_denied
    assert list(wire.deny_ports) == []
    back = from_network_policy(wire)
    assert back.deny_ports == [] and not back.deny_ipv6


def test_a_misspelt_port_rule_is_refused_not_widened():
    for bad, message in [
        ({"protocol": "tpc", "port": 25}, "unknown protocol"),
        ({"port": 25, "cidr": ["10.0.0.0/8"]}, "unknown key 'cidr'"),
        ({"protocol": "tcp"}, "port is an integer"),
        ({"port": "25"}, "port is an integer"),
    ]:
        with pytest.raises(BurrowError, match=message):
            to_network_policy({"mode": "open", "deny_ports": [bad]})


def test_an_expiring_rule_in_open_mode_reaches_the_wire_and_reads_back():
    wire = to_network_policy(
        {
            "mode": "open",
            "inspect_tls": True,
            "rules": [
                {
                    "domain": "api.example.com",
                    "match": {"method": ["GET", "POST"]},
                    "set_headers": {"authorization": "Bearer ${secret:api}"},
                    "expires_at_unix_ms": 1_800_000_000_000,
                }
            ],
        }
    )
    assert wire.mode == common_pb2.NETWORK_MODE_OPEN
    assert wire.is_tls_inspected
    assert wire.rules[0].expires_at_unix_ms == 1_800_000_000_000
    assert wire.rules[0].bound_sandbox_id == ""

    # What a node sends back: expired, and bound to the sandbox it was
    # resolved for.
    wire.rules[0].is_expired = True
    wire.rules[0].bound_sandbox_id = "sbx_a"
    back = from_network_policy(wire)
    assert back.rules[0].expires_at_unix_ms == 1_800_000_000_000
    assert back.rules[0].expired
    assert back.rules[0].bound_sandbox_id == "sbx_a"


def test_an_expiry_that_is_not_unix_milliseconds_is_refused():
    for bad in (-1, 1.5, "soon", True):
        with pytest.raises(BurrowError, match="expires_at_unix_ms"):
            to_network_policy(
                {
                    "mode": "open",
                    "inspect_tls": True,
                    "rules": [
                        {
                            "domain": "api.example.com",
                            "set_headers": {"authorization": "Bearer t"},
                            "expires_at_unix_ms": bad,
                        }
                    ],
                }
            )


def test_a_secret_scope_is_carried_onto_the_wire():
    from burrow._pb import api_pb2
    from burrow.sandbox import Burrow

    sent = []

    class Recording:
        def unary(self, method, request):
            sent.append((method, request))
            if method == "ListSecrets":
                return api_pb2.ListSecretsResponse(
                    names=["api"],
                    secrets=[
                        api_pb2.SecretInfo(
                            name="api", allowed_sandboxes=["sbx_a"], allowed_tags=["team=ml"]
                        )
                    ],
                )
            return None

    client = Burrow.__new__(Burrow)
    client._transport = Recording()
    client.set_secret("api", "token", allowed_sandboxes=["sbx_a"], allowed_tags=["team=ml"])
    method, request = sent[0]
    assert method == "SetSecret"
    assert list(request.allowed_sandboxes) == ["sbx_a"]
    assert list(request.allowed_tags) == ["team=ml"]

    scopes = client.list_secret_scopes()
    assert scopes[0].name == "api"
    assert scopes[0].allowed_sandboxes == ["sbx_a"]
    assert scopes[0].allowed_tags == ["team=ml"]
