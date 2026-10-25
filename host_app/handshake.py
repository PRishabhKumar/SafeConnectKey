from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from shared.canonical import b64u_decode, b64u_encode, canonical_json, parse_utc, utc_now
from shared.config import Settings
from shared.crypto import (
    AuthenticationError, SessionKeys, aes_gcm_decrypt, aes_gcm_encrypt,
    confirmation_token, derive_session_key, derive_session_subkeys,
    generate_nonce, session_fingerprint, verify_hmac_sha256,
)
from shared.keys import KeyMaterial
from shared.protocol import challenge_transcript, handshake_aad, session_transcript
from shared.schemas import HandshakeChallenge, HandshakeCompleteRequest, HandshakeCompleteResponse


class HostProtocolError(ValueError):
    pass


@dataclass(slots=True)
class HostSession:
    session_id: str
    host_id: str
    csd_id: str
    keys: SessionKeys
    key_fingerprint: str
    expires_at: str
    next_host_sequence: int = 1
    expected_csd_sequence: int = 1


@dataclass(slots=True)
class PendingHostHandshake:
    challenge: dict[str, str]
    nonce_r: bytes
    session_id: str
    master_key: bytes
    subkeys: SessionKeys
    transcript: dict[str, object]


class HostHandshake:
    def __init__(self, settings: Settings, keys: KeyMaterial) -> None:
        self.settings = settings
        self.keys = keys

    def make_init_request(self) -> dict[str, str]:
        return {"protocol": self.settings.protocol, "host_id": self.settings.host_id, "csd_id": self.settings.csd_id}

    def process_challenge(self, raw: dict[str, Any]) -> tuple[HandshakeCompleteRequest, PendingHostHandshake]:
        try:
            challenge = HandshakeChallenge.model_validate(raw)
            if challenge.protocol != self.settings.protocol or challenge.host_id != self.settings.host_id or challenge.csd_id != self.settings.csd_id:
                raise AuthenticationError("authentication failed")
            aad = handshake_aad(
                protocol=challenge.protocol, handshake_id=challenge.handshake_id,
                host_id=challenge.host_id, csd_id=challenge.csd_id,
                direction="csd_to_host", message_type="challenge",
            )
            plaintext = aes_gcm_decrypt(self.keys.enc_key, b64u_decode(challenge.sess_td_nonce), b64u_decode(challenge.sess_td), aad)
            inner = json.loads(plaintext)
            fields = ("protocol", "handshake_id", "host_id", "csd_id", "nonce_s", "created_at", "expires_at")
            if set(inner) != set(fields) | {"auth_td"}:
                raise AuthenticationError("authentication failed")
            transcript = challenge_transcript(**{field: inner[field] for field in fields})
            outer_transcript = challenge_transcript(
                protocol=challenge.protocol, handshake_id=challenge.handshake_id,
                host_id=challenge.host_id, csd_id=challenge.csd_id,
                nonce_s=inner["nonce_s"], created_at=challenge.created_at, expires_at=challenge.expires_at,
            )
            if transcript != outer_transcript or inner["auth_td"] != challenge.auth_td:
                raise AuthenticationError("authentication failed")
            verify_hmac_sha256(self.keys.auth_key, canonical_json(transcript), b64u_decode(inner["auth_td"]))
            now = utc_now()
            created, expires = parse_utc(challenge.created_at), parse_utc(challenge.expires_at)
            if now < created - timedelta(seconds=self.settings.max_clock_skew_seconds) or now > expires:
                raise HostProtocolError("CHALLENGE_EXPIRED")
            nonce_s = b64u_decode(inner["nonce_s"])
            if len(nonce_s) != 32:
                raise AuthenticationError("authentication failed")
            nonce_r, session_id = generate_nonce(), secrets.token_hex(16)
            master = derive_session_key(
                self.keys.auth_key, self.keys.enc_key, nonce_s, nonce_r,
                protocol=challenge.protocol, host_id=challenge.host_id, csd_id=challenge.csd_id,
                handshake_id=challenge.handshake_id,
            )
            subkeys = derive_session_subkeys(master)
            session_tx = session_transcript(transcript, b64u_encode(nonce_r), session_id)
            response_inner = {
                "nonce_s": inner["nonce_s"], "nonce_r": b64u_encode(nonce_r),
                "session_id": session_id,
                "host_confirmation": b64u_encode(confirmation_token(subkeys.confirmation, session_tx, "host")),
            }
            response_aad = handshake_aad(
                protocol=challenge.protocol, handshake_id=challenge.handshake_id,
                host_id=challenge.host_id, csd_id=challenge.csd_id,
                direction="host_to_csd", message_type="response",
            )
            nonce, ciphertext = aes_gcm_encrypt(self.keys.enc_key, canonical_json(response_inner), response_aad)
            request = HandshakeCompleteRequest(
                protocol=challenge.protocol, handshake_id=challenge.handshake_id,
                host_id=challenge.host_id, csd_id=challenge.csd_id,
                sess_th_nonce=b64u_encode(nonce), sess_th=b64u_encode(ciphertext),
            )
            return request, PendingHostHandshake(transcript, nonce_r, session_id, master, subkeys, session_tx)
        except HostProtocolError:
            raise
        except Exception as exc:
            raise HostProtocolError("AUTHENTICATION_FAILED") from exc

    def finalize(self, raw: dict[str, Any], pending: PendingHostHandshake) -> HostSession:
        try:
            response = HandshakeCompleteResponse.model_validate(raw)
            if response.protocol != self.settings.protocol or response.session_id != pending.session_id:
                raise AuthenticationError("authentication failed")
            verify_hmac_sha256(
                pending.subkeys.confirmation,
                canonical_json({"role": "csd", "transcript": pending.transcript}),
                b64u_decode(response.csd_confirmation),
            )
            fingerprint = session_fingerprint(pending.master_key)
            if not secrets.compare_digest(fingerprint, response.key_fingerprint) or parse_utc(response.expires_at) <= utc_now():
                raise AuthenticationError("authentication failed")
            return HostSession(
                response.session_id, self.settings.host_id, self.settings.csd_id,
                pending.subkeys, fingerprint, response.expires_at,
            )
        except Exception as exc:
            raise HostProtocolError("AUTHENTICATION_FAILED") from exc

