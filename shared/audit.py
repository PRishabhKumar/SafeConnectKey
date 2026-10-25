from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path

from shared.canonical import format_utc, utc_now


@dataclass(frozen=True, slots=True)
class AuditEvent:
    timestamp_utc: str
    event_type: str
    reason_code: str
    status: str
    subject: str = ""


class AuditLog:
    def __init__(self, path: Path | None = None, max_events: int = 1000) -> None:
        self.path = path
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._lock = threading.RLock()

    def record(self, event_type: str, reason_code: str, status: str, subject: str = "") -> None:
        event = AuditEvent(format_utc(utc_now()), event_type, reason_code, status, subject[:64])
        with self._lock:
            self._events.append(event)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")

    def snapshot(self) -> list[dict[str, str]]:
        with self._lock:
            return [asdict(event) for event in self._events]
