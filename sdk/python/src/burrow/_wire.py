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
