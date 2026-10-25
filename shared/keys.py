from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from shared.canonical import b64u_decode, b64u_encode
from shared.config import PROJECT_ROOT


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    auth_key: bytes
    enc_key: bytes

    def __post_init__(self) -> None:
        if len(self.auth_key) != 32 or len(self.enc_key) != 32:
            raise ValueError("AuthK and EnK must each be exactly 32 bytes")
        if self.auth_key == self.enc_key:
            raise ValueError("AuthK and EnK must be independently generated")

    @classmethod
    def generate(cls) -> "KeyMaterial":
        return cls(secrets.token_bytes(32), secrets.token_bytes(32))


def load_key_material(env_file: Path | None = None) -> KeyMaterial:
    load_dotenv(env_file or PROJECT_ROOT / ".env", override=False)
    auth_value = os.getenv("SCK_AUTH_KEY")
    enc_value = os.getenv("SCK_ENC_KEY")
    if not auth_value or not enc_value:
        raise RuntimeError("SCK_AUTH_KEY and SCK_ENC_KEY must be set; run scripts/generate_demo_keys.py")
    return KeyMaterial(b64u_decode(auth_value), b64u_decode(enc_value))


def serialize_key_material(keys: KeyMaterial) -> tuple[str, str]:
    return b64u_encode(keys.auth_key), b64u_encode(keys.enc_key)

