from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime

from shared.crypto import SessionKeys


@dataclass(slots=True)
class PendingHandshake:
    handshake_id: str
    nonce_s: bytes
    transcript: dict[str, str]
    expires_at: datetime


@dataclass(slots=True)
class SessionState:
    session_id: str
    host_id: str
    csd_id: str
    keys: SessionKeys
    key_fingerprint: str
    expires_at: datetime
    expected_host_sequence: int = 1
    next_csd_sequence: int = 1
    jobs_executed: int = 0


class SessionStore:
    def __init__(self) -> None:
        self._pending: dict[str, PendingHandshake] = {}
        self._consumed: dict[str, datetime] = {}
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.RLock()

    def cleanup(self, now: datetime) -> None:
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v.expires_at >= now}
            self._consumed = {k: v for k, v in self._consumed.items() if v >= now}
            self._sessions = {k: v for k, v in self._sessions.items() if v.expires_at >= now}

    def add_pending(self, pending: PendingHandshake) -> None:
        with self._lock:
            self._pending[pending.handshake_id] = pending

    def pending_status(self, handshake_id: str, now: datetime) -> tuple[str, PendingHandshake | None]:
        with self._lock:
            if handshake_id in self._consumed:
                return "replay", None
            pending = self._pending.get(handshake_id)
            if pending is None:
                return "unknown", None
            if pending.expires_at < now:
                self._pending.pop(handshake_id, None)
                return "expired", None
            return "pending", pending

    def establish(self, handshake_id: str, session: SessionState, replay_until: datetime) -> None:
        with self._lock:
            if handshake_id in self._consumed:
                raise KeyError("replay")
            if handshake_id not in self._pending:
                raise KeyError("unknown")
            self._pending.pop(handshake_id, None)
            self._consumed[handshake_id] = replay_until
            self._sessions[session.session_id] = session

    def get(self, session_id: str) -> SessionState | None:
        with self._lock:
            return self._sessions.get(session_id)

    def close(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {"pending": len(self._pending), "sessions": len(self._sessions), "consumed": len(self._consumed)}

