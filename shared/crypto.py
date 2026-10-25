from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared.canonical import canonical_json


class AuthenticationError(ValueError):
    """A deliberately generic protocol authentication failure."""


def generate_nonce(length: int = 32) -> bytes:
    if length < 16:
        raise ValueError("nonce length is too short")
    return secrets.token_bytes(length)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(message)
    return mac.finalize()


def verify_hmac_sha256(key: bytes, message: bytes, token: bytes) -> None:
    expected = hmac_sha256(key, message)
    if not stdlib_hmac.compare_digest(expected, token):
        raise AuthenticationError("authentication failed")


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    actual_nonce = nonce if nonce is not None else secrets.token_bytes(12)
    if len(actual_nonce) != 12:
        raise ValueError("AES-GCM requires a 96-bit nonce")
    return actual_nonce, AESGCM(key).encrypt(actual_nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise AuthenticationError("authentication failed")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise AuthenticationError("authentication failed") from exc


def _hkdf(ikm: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def derive_session_key(
    auth_key: bytes,
    enc_key: bytes,
    nonce_s: bytes,
    nonce_r: bytes,
    *,
    protocol: str,
    host_id: str,
    csd_id: str,
    handshake_id: str,
) -> bytes:
    salt = hashlib.sha256(nonce_s + nonce_r).digest()
    info = canonical_json({
        "purpose": "SafeConnectKey session master",
        "protocol": protocol,
        "host_id": host_id,
        "csd_id": csd_id,
        "handshake_id": handshake_id,
    })
    return _hkdf(auth_key + enc_key, salt=salt, info=info)


@dataclass(frozen=True, slots=True)
class SessionKeys:
    confirmation: bytes
    host_to_csd: bytes
    csd_to_host: bytes


def derive_session_subkeys(session_key: bytes) -> SessionKeys:
    zero_salt = bytes(32)
    return SessionKeys(
        confirmation=_hkdf(session_key, salt=zero_salt, info=b"SCK-1 confirmation"),
        host_to_csd=_hkdf(session_key, salt=zero_salt, info=b"SCK-1 host-to-csd"),
        csd_to_host=_hkdf(session_key, salt=zero_salt, info=b"SCK-1 csd-to-host"),
    )


def session_fingerprint(session_key: bytes) -> str:
    return hashlib.sha256(session_key).hexdigest()[:16]


def sequence_nonce(session_id: str, direction: str, sequence: int) -> bytes:
    if sequence < 1 or sequence >= 2**64:
        raise ValueError("invalid sequence number")
    prefix = hashlib.sha256(f"{session_id}:{direction}".encode("utf-8")).digest()[:4]
    return prefix + sequence.to_bytes(8, "big")


def confirmation_token(key: bytes, transcript: dict[str, object], role: str) -> bytes:
    return hmac_sha256(key, canonical_json({"role": role, "transcript": transcript}))

