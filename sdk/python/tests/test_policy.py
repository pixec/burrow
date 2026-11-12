# Policy conversion runs entirely client-side, so it is checked without a
# server: the options must land on the same wire shape the daemons read.

import pytest

from burrow import Sandbox
from burrow._pb import common_pb2
from burrow._policy import from_network_policy, network_policy, to_network_policy
from burrow.errors import BurrowError
from burrow.sandbox import _to_sandbox_info
from burrow.types import NetworkPolicy, PortRule


def wire(options):
    return to_network_policy(network_policy(options))


def test_a_string_is_a_mode():
    assert network_policy("open").mode == "open"
    assert network_policy("allowlist").mode == "allowlist"


def test_a_policy_read_back_is_accepted_as_it_is():
    policy = NetworkPolicy(mode="allowlist", allow_domains=["pypi.org"])
    assert network_policy(policy) is policy
    assert from_network_policy(wire(policy)) == policy


def test_the_old_shorthand_strings_are_unknown_modes():
    for gone in ("allow-all", "deny-all"):
        with pytest.raises(BurrowError, match="unknown mode"):
            network_policy(gone)


def test_the_old_shorthand_dict_is_refused_not_read_as_no_network():
    with pytest.raises(BurrowError, match="unknown key 'allow'"):
        network_policy({"allow": ["pypi.org"]})
    with pytest.raises(BurrowError, match="unknown key 'subnets'"):
        network_policy({"subnets": {"deny": ["169.254.0.0/16"]}})


def test_an_allowlist_carries_domains_and_denies():
    policy = wire(
        network_policy(
            {
                "mode": "allowlist",
                "allow_domains": ["pypi.org", "*.pythonhosted.org"],
                "deny_cidrs": ["169.254.0.0/16"],
            }
        )
    )
    assert policy.mode == common_pb2.NETWORK_MODE_ALLOWLIST
    assert list(policy.allow_domains) == ["pypi.org", "*.pythonhosted.org"]
    assert list(policy.deny_cidrs) == ["169.254.0.0/16"]
    assert not policy.is_tls_inspected


def rule_policy(rule):
    return {
        "mode": "allowlist",
        "allow_domains": ["api.example.com"],
        "inspect_tls": True,
        "rules": [{"domain": "api.example.com", **rule}],
    }


def test_a_rule_reaches_the_wire():
    policy = wire(
        network_policy(
            rule_policy(
                {
                    "match": {"path": {"starts_with": "/v1/"}, "method": "POST"},
                    "set_headers": {"Authorization": "Bearer t"},
                }
            )
        )
    )
    assert policy.is_tls_inspected
    rule = policy.rules[0]
    assert rule.domain == "api.example.com"
    assert rule.match.path.op == common_pb2.STRING_MATCH_OP_STARTS_WITH
    assert list(rule.match.methods) == ["POST"]
    assert rule.set_headers.headers[0].name == "Authorization"


def test_an_unknown_rule_key_is_refused_not_dropped():
    with pytest.raises(BurrowError, match="unknown key 'forward_url'"):
        wire(rule_policy({"forward_url": "https://x", "set_headers": {"A": "b"}}))


def test_an_unknown_match_key_is_refused_not_dropped():
    # Dropped, it would widen the rule to every request to the domain.
    with pytest.raises(BurrowError, match="unknown key 'paths'"):
        wire(
            rule_policy({"match": {"paths": "/v1/x"}, "set_headers": {"A": "b"}})
        )


def test_an_unknown_forward_key_is_refused():
    with pytest.raises(BurrowError, match="unknown key 'secrets'"):
        wire(rule_policy({"forward": {"url": "https://x", "secrets": "s"}}))


def test_a_rule_without_an_action_is_refused():
    with pytest.raises(BurrowError, match="needs either set_headers or forward"):
        wire(rule_policy({"match": {"path": "/v1/x"}}))


def test_a_bad_header_name_is_refused():
    with pytest.raises(BurrowError, match="not a valid header name"):
        wire(rule_policy({"set_headers": {"Bad Header": "x"}}))


def test_the_wire_policy_reads_back_as_it_was_written():
    policy = wire((rule_policy({"set_headers": {"X-Token": "secret"}})))
    back = from_network_policy(policy)
    assert back.mode == "allowlist"
    assert back.inspect_tls
    assert back.rules[0].domain == "api.example.com"
    assert back.rules[0].set_headers == {"X-Token": "secret"}


def test_denied_ports_and_ipv6_reach_the_wire_in_open_mode():
    policy = wire(
        network_policy(
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
    assert policy.mode == common_pb2.NETWORK_MODE_OPEN
    assert policy.is_ipv6_denied
    assert [
        (rule.protocol, rule.port, rule.port_end, list(rule.cidrs))
        for rule in policy.deny_ports
    ] == [
        (common_pb2.PORT_PROTOCOL_TCP, 25, 0, []),
        (common_pb2.PORT_PROTOCOL_TCP, 465, 587, []),
        (common_pb2.PORT_PROTOCOL_UNSPECIFIED, 5432, 0, ["10.0.0.0/8", "2001:db8::/32"]),
        (common_pb2.PORT_PROTOCOL_UDP, 53, 0, []),
    ]

    back = from_network_policy(policy)
    assert back.deny_ipv6
    assert back.deny_ports == [
        PortRule(port=25, protocol="tcp"),
        PortRule(port=465, protocol="tcp", port_end=587),
        PortRule(port=5432, protocol="any", cidrs=["10.0.0.0/8", "2001:db8::/32"]),
        PortRule(port=53, protocol="udp"),
    ]


def test_the_new_fields_default_to_the_old_behaviour():
    policy = wire(("open"))
    assert not policy.is_ipv6_denied
    assert list(policy.deny_ports) == []
    back = from_network_policy(policy)
    assert back.deny_ports == [] and not back.deny_ipv6


def test_a_misspelt_port_rule_is_refused_not_widened():
    for bad, message in [
        ({"protocol": "tpc", "port": 25}, "unknown protocol"),
        ({"port": 25, "cidr": ["10.0.0.0/8"]}, "unknown key 'cidr'"),
        ({"protocol": "tcp"}, "port"),
        ({"port": "25"}, "port is an integer"),
    ]:
        with pytest.raises(BurrowError, match=message):
            wire(({"mode": "open", "deny_ports": [bad]}))


def test_an_expiring_rule_in_open_mode_reaches_the_wire_and_reads_back():
    policy = wire(
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
    assert policy.mode == common_pb2.NETWORK_MODE_OPEN
    assert policy.is_tls_inspected
    assert policy.rules[0].expires_at_unix_ms == 1_800_000_000_000
    assert policy.rules[0].bound_sandbox_id == ""

    # What a node sends back: bound to the sandbox it was resolved for.
    policy.rules[0].bound_sandbox_id = "sbx_a"
    back = from_network_policy(policy)
    assert back.rules[0].expires_at_unix_ms == 1_800_000_000_000
    assert back.rules[0].bound_sandbox_id == "sbx_a"


def test_an_expiry_that_is_not_unix_milliseconds_is_refused():
    for bad in (-1, 1.5, "soon", True):
        with pytest.raises(BurrowError, match="expires_at_unix_ms"):
            wire(
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
    from burrow.client import Burrow

    sent = []

    class Recording:
        def unary(self, method, request):
            sent.append((method, request))
            if method == "ListSecrets":
                return api_pb2.ListSecretsResponse(
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

    scopes = client.list_secrets()
    assert scopes[0].name == "api"
    assert scopes[0].allowed_sandboxes == ["sbx_a"]
    assert scopes[0].allowed_tags == ["team=ml"]


def test_denied_domains_reach_the_wire_and_read_back():
    policy = wire({"mode": "open", "deny_domains": ["*.example.com", "evil.test"]})
    assert list(policy.deny_domains) == ["*.example.com", "evil.test"]
    assert from_network_policy(policy).deny_domains == ["*.example.com", "evil.test"]


class PolicyServer:
    def __init__(self, network):
        self.record = common_pb2.Sandbox(
            id="sbx_test", policy=common_pb2.Policy(network=network)
        )
        self.sent = []

    def route(self, sandbox_id):
        return self

    def unary(self, method, request, timeout=None):
        assert method == "UpdateNetworkPolicy"
        self.sent.append(request.network)
        self.record.policy.network.CopyFrom(request.network)
        return self.record


def test_a_policy_read_back_and_passed_to_update_keeps_its_deny_list():
    server = PolicyServer(
        common_pb2.NetworkPolicy(
            mode=common_pb2.NETWORK_MODE_OPEN, deny_domains=["*.example.com"]
        )
    )
    sandbox = Sandbox(server, _to_sandbox_info(server.record), False)
    policy = sandbox.policy.network
    policy.deny_cidrs = ["10.0.0.0/8"]
    sandbox.update_network_policy(policy)
    assert list(server.sent[0].deny_domains) == ["*.example.com"]
    assert sandbox.policy.network.deny_domains == ["*.example.com"]

