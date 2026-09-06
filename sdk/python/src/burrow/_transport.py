"""gRPC transport. Internal: the public surface in `sandbox.py` is hand-written
and does not mirror the RPC shapes."""

from __future__ import annotations

import os
import re
from typing import Any, Iterator, Optional

import grpc

from ._pb import api_pb2_grpc
from .errors import BurrowError

# Sentinel distinguishing "use the transport default" from "no deadline at
# all", which long-lived streams like watches need.
_DEFAULT = object()

# The connection options every public entry point accepts alongside its own.
_TRANSPORT_KEYS = ("endpoint", "api_key", "tls", "timeout")


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
    ):
        raw = endpoint or os.environ.get("BURROW_ENDPOINT") or "localhost:7070"
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

    def client_stream(
        self, method: str, requests: Iterator[Any], timeout: Any = _DEFAULT
    ) -> Any:
        """Client-streaming call whose single response is awaited (upload)."""
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

    def retain(self) -> "Transport":
        """Claims a share of this connection. Undone by one `close`."""
        self._refs += 1
        return self

    def close(self) -> None:
        """Releases one share; the channel closes when the last one goes."""
        self._refs -= 1
        if self._refs <= 0:
            self._channel.close()


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
