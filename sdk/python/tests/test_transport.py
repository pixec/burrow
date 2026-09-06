# Constructing a `Transport` never blocks on the network (grpc dials lazily),
# so these check the "should this even try to connect" decision on its own,
# without a server behind it.

import pytest

from burrow._transport import Transport
from burrow.errors import BurrowError


def transport(**options):
    """Constructs a transport and closes the channel it opened."""
    t = Transport(**options)
    t.close()
    return t


def test_an_api_key_over_a_bare_endpoint_with_no_scheme_is_refused():
    with pytest.raises(BurrowError, match="plaintext"):
        transport(endpoint="orchestrator.example.com:7070", api_key="secret")


def test_an_api_key_to_localhost_is_fine_with_no_tls_option():
    transport(endpoint="localhost:7070", api_key="secret")
    transport(endpoint="127.0.0.1:7070", api_key="secret")


def test_an_explicit_tls_choice_is_always_honoured_api_key_or_not():
    transport(endpoint="orchestrator.example.com:7070", api_key="secret", tls=False)
    transport(endpoint="orchestrator.example.com:7070", api_key="secret", tls=True)


def test_an_explicit_http_scheme_is_treated_as_the_callers_own_choice():
    transport(endpoint="http://orchestrator.example.com:7070", api_key="secret")


def test_an_https_endpoint_needs_no_api_key_opt_in():
    transport(endpoint="https://orchestrator.example.com", api_key="secret")


def test_no_api_key_at_all_is_never_refused_plaintext_or_not():
    transport(endpoint="orchestrator.example.com:7070")
