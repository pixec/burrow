# Policy conversion runs entirely client-side, so it is checked without a
# server: the options must land on the same wire shape the daemons read.

import pytest

from burrow._pb import common_pb2
from burrow._policy import from_network_policy, resolve_network, to_network_policy
from burrow.errors import BurrowError


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
