from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

@dataclass(frozen=True, slots=True)
class Settings:
    protocol: str = "SCK-1"
    host_id: str = "host-demo"
    csd_id: str = "csd-demo"
    handshake_ttl_seconds: int = 30
    session_ttl_seconds: int = 300
    max_clock_skew_seconds: int = 5
    max_request_bytes: int = 65_536
    data_root: Path = PROJECT_ROOT / "csd_data"
    results_root: Path = PROJECT_ROOT / "results"

DEFAULT_SETTINGS = Settings()
