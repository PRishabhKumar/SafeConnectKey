from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Serialize protocol data deterministically for MACs and AEAD AAD."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 2_000_000:
        raise ValueError("invalid base64url value")
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("invalid base64url value") from exc


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must contain an offset")
    return parsed.astimezone(UTC)

