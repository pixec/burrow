# Policy conversion runs entirely client-side, so it is checked without a
# server: the shorthand and the flat options must land on the same wire shape
# the daemons read.

import pytest

from burrow._pb import common_pb2
from burrow._policy import from_network_policy, resolve_network, to_network_policy
from burrow.errors import BurrowError


def test_string_shorthands_map_to_modes():
    assert resolve_network("open")["mode"] == "open"
    assert resolve_network("allow-all")["mode"] == "open"
    assert resolve_network("deny-all")["mode"] == "none"
    assert resolve_network("allowlist")["mode"] == "allowlist"


def test_naming_a_domain_makes_an_allowlist():
    options = resolve_network({"allow": ["pypi.org", "*.pythonhosted.org"]})
    wire = to_network_policy(options)
    assert wire.mode == common_pb2.NETWORK_MODE_ALLOWLIST
    assert list(wire.allow_domains) == ["pypi.org", "*.pythonhosted.org"]
    assert not wire.inspect_tls


def test_subnets_shorthand_carries_denies():
    options = resolve_network(
        {"allow": ["pypi.org"], "subnets": {"deny": ["169.254.0.0/16"]}}
    )
    wire = to_network_policy(options)
    assert list(wire.deny_cidrs) == ["169.254.0.0/16"]


def test_a_transform_becomes_an_inspected_rule():
    options = resolve_network(
        {
            "allow": {
                "api.example.com": {
                    "match": {"path": {"starts_with": "/v1/"}, "method": "POST"},
                    "transform": [{"headers": {"Authorization": "Bearer t"}}],
                }
            }
        }
    )
    wire = to_network_policy(options)
    assert wire.inspect_tls
    rule = wire.rules[0]
    assert rule.domain == "api.example.com"
    assert rule.match.path.op == common_pb2.STRING_MATCH_OP_STARTS_WITH
    assert list(rule.match.methods) == ["POST"]
    assert rule.set_headers.headers[0].name == "Authorization"


def test_an_unknown_rule_key_is_refused_not_dropped():
    with pytest.raises(BurrowError, match="unknown key"):
        resolve_network({"allow": {"api.example.com": {"forwardURL": "x"}}})


def test_a_match_without_an_action_is_refused():
    with pytest.raises(BurrowError, match="needs a transform"):
        resolve_network(
            {"allow": {"api.example.com": {"match": {"path": "/v1/x"}}}}
        )


def test_legacy_allow_domains_still_compose_with_a_mode_string():
    options = resolve_network("allowlist", allow_domains=["pypi.org"])
    wire = to_network_policy(options)
    assert list(wire.allow_domains) == ["pypi.org"]


def test_the_wire_policy_reads_back_as_it_was_written():
    wire = to_network_policy(
        resolve_network(
            {
                "allow": {
                    "api.example.com": {
                        "transform": [{"headers": {"X-Token": "secret"}}]
                    }
                }
            }
        )
    )
    back = from_network_policy(wire)
    assert back.mode == "allowlist"
    assert back.inspect_tls
    # A rule with no matcher is also readable in the pre-rules shape.
    assert back.inject_headers[0].domain == "api.example.com"
    assert back.inject_headers[0].name == "X-Token"
