from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _env_int(name: str, default: int) -> int:
    value = int(os.environ.get(name, default))
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value

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

load_dotenv(PROJECT_ROOT / ".env", override=False)
DEFAULT_SETTINGS = Settings(
    host_id=os.environ.get("SCK_HOST_ID", "host-demo"),
    csd_id=os.environ.get("SCK_CSD_ID", "csd-demo"),
    handshake_ttl_seconds=_env_int("SCK_HANDSHAKE_TTL_SECONDS", 30),
    session_ttl_seconds=_env_int("SCK_SESSION_TTL_SECONDS", 300),
    max_clock_skew_seconds=_env_int("SCK_MAX_CLOCK_SKEW_SECONDS", 5),
    max_request_bytes=_env_int("SCK_MAX_REQUEST_BYTES", 65_536),
    data_root=Path(os.environ.get("SCK_DATA_ROOT", str(PROJECT_ROOT / "csd_data"))),
    results_root=Path(os.environ.get("SCK_RESULTS_ROOT", str(PROJECT_ROOT / "results"))),
)
