"""gRPC transport. Internal: the public surface in `sandbox.py` is hand-written
and does not mirror the RPC shapes."""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Callable, Dict, Iterator, Optional

import grpc

from ._pb import api_pb2, api_pb2_grpc
from .errors import BurrowError

# Sentinel distinguishing "use the transport default" from "no deadline at
# all", which long-lived streams like watches need.
_DEFAULT = object()

# A token is replaced this long before it expires, so a call made with it
# does not reach the node a moment too late.
_GRANT_MARGIN_SECS = 30

# What a node says about a token that no longer works there: expired, revoked,
# or for a sandbox that has moved to another node.
_STALE_GRANT = (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.NOT_FOUND)

# The connection options every public entry point accepts alongside its own.
_TRANSPORT_KEYS = ("endpoint", "api_key", "tls", "timeout", "route")

# Where exec, attach and file traffic goes: the node, or the orchestrator.
_ROUTES = ("direct", "orchestrator")


def transport_options(options: dict) -> dict:
    """The transport's share of a mixed option bag."""
    return {key: options[key] for key in _TRANSPORT_KEYS if key in options}


def _is_loopback_host(host: str) -> bool:
    """Whether `host` is plainly this machine, not some other one on the network."""
    bare = host.lstrip("[").rstrip("]")
    return (
        bare == "localhost"
        or bare == "::1"
        or bool(re.fullmatch(r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}", bare))
    )


class Transport:
    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        tls: Optional[bool] = None,
        timeout: Optional[float] = 60.0,
        route: Optional[str] = None,
    ):
        raw = endpoint or os.environ.get("BURROW_ENDPOINT") or "localhost:7070"
        # `direct` calls the node holding the sandbox with a token from the
        # orchestrator, and needs the node reachable from here; `orchestrator`
        # has the orchestrator relay the calls. Neither falls back to the other.
        self.route_mode = route or os.environ.get("BURROW_ROUTE") or "direct"
        if self.route_mode not in _ROUTES:
            raise BurrowError(
                f"route must be one of {', '.join(_ROUTES)}, not {self.route_mode!r}",
                "invalid_argument",
            )
        secure = tls if tls is not None else raw.startswith("https://")
        address = re.sub(r"^https?://", "", raw)

        # Host this client dials, without its port. A published port whose node
        # advertises no address of its own is reachable here, the single-node
        # case.
        self.host = re.sub(r":\d+$", "", address) or "localhost"
        self.timeout = timeout
        self._api_key = api_key or os.environ.get("BURROW_API_KEY")
        # Handles sharing this connection; the channel outlives the first
        # release.
        self._refs = 1

        # A bare `host:port` endpoint leaves `tls` off, which is fine with no
        # credential in play but an easy way to ship an API key in cleartext to
        # whatever `BURROW_ENDPOINT` is set to in production. Refused rather
        # than warned, unless the destination is obviously the caller's own
        # machine or `tls`/the endpoint scheme said so explicitly.
        if (
            self._api_key
            and not secure
            and tls is None
            and not raw.startswith("http://")
            and not _is_loopback_host(self.host)
        ):
            raise BurrowError(
                f"refusing to send an API key over a plaintext connection to "
                f"{self.host}; pass tls explicitly if that's intended",
                "invalid_argument",
            )

        options = [
            # Exec and file transfers can carry large payloads; the 4MB default
            # turns a big file into a confusing RESOURCE_EXHAUSTED.
            ("grpc.max_receive_message_length", 64 * 1024 * 1024),
            ("grpc.max_send_message_length", 64 * 1024 * 1024),
        ]
        if secure:
            self._channel = grpc.secure_channel(
                address, grpc.ssl_channel_credentials(), options
            )
        else:
            self._channel = grpc.insecure_channel(address, options)
        self._stub = api_pb2_grpc.BurrowStub(self._channel)
        self._options = options
        self._lock = threading.Lock()
        self._directs: Dict[str, "Direct"] = {}
        self._node_channels: Dict[str, grpc.Channel] = {}

    def _metadata(self):
        if self._api_key:
            return (("authorization", f"Bearer {self._api_key}"),)
        return ()

    def _timeout(self, timeout: Any) -> Optional[float]:
        return self.timeout if timeout is _DEFAULT else timeout

    def unary(self, method: str, request: Any, timeout: Any = _DEFAULT) -> Any:
        try:
            return getattr(self._stub, method)(
                request, timeout=self._timeout(timeout), metadata=self._metadata()
            )
        except grpc.RpcError as err:
            raise BurrowError.from_grpc(err) from None

    def server_stream(
        self, method: str, request: Any, timeout: Any = _DEFAULT
    ) -> Iterator[Any]:
        return _iterate(self.open_server_stream(method, request, timeout))

    def open_server_stream(
        self, method: str, request: Any, timeout: Any = _DEFAULT
    ) -> Any:
        """Server-streaming call, returned as the raw call: an iterator of
        responses that also cancels (`call.cancel()`), which stopping a watch
        from another thread needs."""
        return getattr(self._stub, method)(
            request, timeout=self._timeout(timeout), metadata=self._metadata()
        )

    def client_stream(self, method: str, requests: Any, timeout: Any = _DEFAULT) -> Any:
        """Client-streaming call whose single response is awaited (upload).
        `requests` is an iterator, or a function returning one."""
        if callable(requests):
            requests = requests()
        try:
            return getattr(self._stub, method)(
                requests, timeout=self._timeout(timeout), metadata=self._metadata()
            )
        except grpc.RpcError as err:
            raise BurrowError.from_grpc(err) from None

    def duplex(
        self, method: str, requests: Iterator[Any], timeout: Any = _DEFAULT
    ) -> Any:
        """Bidirectional call. Returns the raw call: an iterator of responses
        that also cancels (`call.cancel()`), which a terminal needs."""
        return getattr(self._stub, method)(
            requests, timeout=self._timeout(timeout), metadata=self._metadata()
        )

    def route(self, sandbox_id: str) -> "Any":
        """Where a sandbox's exec, attach and file calls go: its node, or this
        connection to the orchestrator. Both take the same calls."""
        if self.route_mode == "orchestrator":
            return self
        return self.direct(sandbox_id)

    def direct(self, sandbox_id: str) -> "Direct":
        """The way to a sandbox's exec, attach and file calls: its node."""
        with self._lock:
            direct = self._directs.get(sandbox_id)
            if direct is None:
                direct = Direct(self, sandbox_id)
                self._directs[sandbox_id] = direct
            return direct

    def _node_channel(self, endpoint: str) -> grpc.Channel:
        """One channel per node, shared by every sandbox on it."""
        with self._lock:
            channel = self._node_channels.get(endpoint)
            if channel is None:
                address = re.sub(r"^https?://", "", endpoint)
                if endpoint.startswith("https://"):
                    channel = grpc.secure_channel(
                        address, grpc.ssl_channel_credentials(), self._options
                    )
                elif endpoint.startswith("http://"):
                    # The node's operator advertised it as plain http, which is
                    # as explicit as a caller passing `http://` here.
                    channel = grpc.insecure_channel(address, self._options)
                else:
                    raise BurrowError(
                        f"node endpoint {endpoint!r} names no scheme", "internal"
                    )
                self._node_channels[endpoint] = channel
            return channel

    def retain(self) -> "Transport":
        """Claims a share of this connection. Undone by one `close`."""
        self._refs += 1
        return self

    def close(self) -> None:
        """Releases one share; the channel closes when the last one goes."""
        self._refs -= 1
        if self._refs <= 0:
            self._channel.close()
            for channel in self._node_channels.values():
                channel.close()


class Direct:
    """A sandbox's exec, attach and file calls, made on the node that holds it.

    The orchestrator carries none of that traffic: it issues a short-lived
    token for the sandbox's node, and the node is called with it. The token is
    reused until it nears expiry, and replaced when the node refuses it, as it
    does once it has expired, been revoked, or the sandbox has moved. A call
    that sends one message is then made once more; a stream is not, since what
    it already sent cannot be taken back, and the next one gets a fresh token.
    """

    def __init__(self, transport: Transport, sandbox_id: str):
        self._transport = transport
        self.sandbox_id = sandbox_id
        self._lock = threading.Lock()
        self._grant: Optional[api_pb2.AccessGrant] = None

    def _current(self, renew: bool = False) -> api_pb2.AccessGrant:
        with self._lock:
            grant = self._grant
            if (
                renew
                or grant is None
                or grant.expires_at - time.time() < _GRANT_MARGIN_SECS
            ):
                grant = self._transport.unary(
                    "IssueAccess",
                    api_pb2.IssueAccessRequest(
                        ref=api_pb2.SandboxRef(id=self.sandbox_id)
                    ),
                )
                self._grant = grant
            return grant

    def _stub(self, grant: api_pb2.AccessGrant) -> Any:
        return api_pb2_grpc.AccessStub(self._transport._node_channel(grant.endpoint))

    def _invoke(self, method: str, request: Any, timeout: Any) -> Any:
        grant = self._current()
        return getattr(self._stub(grant), method)(
            request,
            timeout=self._transport._timeout(timeout),
            metadata=(("authorization", f"Bearer {grant.token}"),),
        )

    def _once_more(self, call: Callable[[], Any]) -> Any:
        try:
            return call()
        except grpc.RpcError as err:
            if err.code() not in _STALE_GRANT:
                raise BurrowError.from_grpc(err) from None
        self._current(renew=True)
        try:
            return call()
        except grpc.RpcError as err:
            raise BurrowError.from_grpc(err) from None

    def unary(self, method: str, request: Any, timeout: Any = _DEFAULT) -> Any:
        return self._once_more(lambda: self._invoke(method, request, timeout))

    def server_stream(
        self, method: str, request: Any, timeout: Any = _DEFAULT
    ) -> Iterator[Any]:
        return _iterate(self.open_server_stream(method, request, timeout))

    def open_server_stream(
        self, method: str, request: Any, timeout: Any = _DEFAULT
    ) -> Any:
        return self._invoke(method, request, timeout)

    def client_stream(
        self, method: str, requests: Callable[[], Iterator[Any]], timeout: Any = _DEFAULT
    ) -> Any:
        """Client-streaming call whose single response is awaited (upload).
        `requests` is called afresh for a second attempt."""
        return self._once_more(lambda: self._invoke(method, requests(), timeout))

    def duplex(self, method: str, requests: Iterator[Any], timeout: Any = _DEFAULT) -> Any:
        return self._invoke(method, requests, timeout)


def _iterate(call: Any) -> Iterator[Any]:
    """Adapts a streaming call so its errors raise as `BurrowError`, and an
    abandoned loop (break, exception) cancels the call rather than leaking it."""
    try:
        for msg in call:
            yield msg
    except grpc.RpcError as err:
        raise BurrowError.from_grpc(err) from None
    finally:
        call.cancel()
