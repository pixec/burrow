"""Errors the SDK raises."""

from __future__ import annotations

import re

import grpc

# Stable, transport-independent error codes.
_CODES = {
    grpc.StatusCode.NOT_FOUND: "not_found",
    grpc.StatusCode.ALREADY_EXISTS: "already_exists",
    grpc.StatusCode.INVALID_ARGUMENT: "invalid_argument",
    grpc.StatusCode.FAILED_PRECONDITION: "failed_precondition",
    grpc.StatusCode.PERMISSION_DENIED: "permission_denied",
    grpc.StatusCode.UNAUTHENTICATED: "unauthenticated",
    grpc.StatusCode.RESOURCE_EXHAUSTED: "resource_exhausted",
    grpc.StatusCode.UNAVAILABLE: "unavailable",
    grpc.StatusCode.UNIMPLEMENTED: "unimplemented",
    grpc.StatusCode.DEADLINE_EXCEEDED: "deadline_exceeded",
    grpc.StatusCode.CANCELLED: "cancelled",
}


class BurrowError(Exception):
    """An error from burrow.

    gRPC status codes are mapped to stable string codes so callers can branch
    on ``err.code`` without importing grpc or knowing the transport.
    """

    def __init__(self, message: str, code: str = "internal"):
        super().__init__(message)
        self.message = message
        self.code = code

    @classmethod
    def from_grpc(cls, err: grpc.RpcError) -> "BurrowError":
        code = _CODES.get(err.code(), "internal")
        # Some paths prefix messages with their numeric code; strip it so the
        # message reads as the server wrote it.
        message = re.sub(
            r"^\d+\s+[A-Z_]+:\s*", "", err.details() or str(err) or "unknown error"
        )
        return cls(message, code)

    @property
    def is_suspended(self) -> bool:
        """True when the sandbox is suspended and must be resumed first."""
        return self.code == "failed_precondition" and bool(
            re.search("suspend", self.message, re.IGNORECASE)
        )

    @property
    def is_already_exited(self) -> bool:
        """True when a signal was refused because the command had already exited.

        The one refusal a ``kill()`` can ignore, since it asked for a state the
        command is already in. Narrower than the code alone: a suspended sandbox
        refuses a signal with ``failed_precondition`` too, and that one is a
        real failure to deliver.
        """
        return self.code == "failed_precondition" and not self.is_suspended


class CommandFailedError(BurrowError):
    """Raised when a command exits non-zero and ``check`` is set."""

    def __init__(self, command: str, exit_code: int, stdout: str, stderr: str):
        tail = f"\n{stderr.strip()}" if stderr.strip() else ""
        super().__init__(f"command exited with {exit_code}: {command}{tail}", "internal")
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
