"""What crosses between the SDK's shapes and the wire's: enum names and
timestamps."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


def label(enum: Any, value: int, prefix: str) -> str:
    """The lowercase name of an enum value without its type prefix, or
    "unknown" for one this SDK has no name for."""
    try:
        name = enum.Name(value)
    except ValueError:
        return "unknown"
    name = name[len(prefix):].lower()
    return name if name != "unspecified" else ""


def value(enum: Any, text: str, prefix: str, where: str) -> int:
    try:
        return enum.Value(prefix + text.upper())
    except ValueError:
        from .errors import BurrowError

        names = ", ".join(
            name[len(prefix):].lower() for name in enum.keys() if not name.endswith("_UNSPECIFIED")
        )
        raise BurrowError(f"{where}: unknown {text!r}; one of {names}", "invalid_argument") from None


def at(unix_ms: int) -> datetime:
    return datetime.fromtimestamp(unix_ms / 1000, tz=timezone.utc)


def at_or_none(unix_ms: int) -> Optional[datetime]:
    return at(unix_ms) if unix_ms else None


def unix_ms(when: Optional[datetime]) -> int:
    return int(when.timestamp() * 1000) if when else 0


def kernel(raw: Any) -> Any:
    """A `Kernel` message as a `KernelInfo`, or None for an unset one."""
    from .types import KernelCapabilities, KernelInfo

    if not raw.digest:
        return None
    caps = raw.capabilities
    return KernelInfo(
        name=raw.name,
        digest=raw.digest,
        version=raw.version,
        arch=raw.arch,
        capabilities=KernelCapabilities(
            kvm=caps.is_kvm_built_in,
            virtio_mem=caps.is_virtio_mem_built_in,
            vsock=caps.is_vsock_built_in,
            virtio_blk=caps.is_virtio_blk_built_in,
            ext4=caps.is_ext4_built_in,
        ),
        detected_from=raw.detected_from,
        hypervisors=list(raw.hypervisors),
        default_for=list(raw.default_for),
    )
