from __future__ import annotations

import json
import secrets
import threading
import uuid
from datetime import timedelta
from typing import Any

from pydantic import ValidationError

from csd_app.data_store import DataStore
from csd_app.jobs import JobExecutor
from csd_app.sessions import PendingHandshake, SessionState, SessionStore
from shared.audit import AuditLog
from shared.canonical import b64u_decode, b64u_encode, canonical_json, format_utc, parse_utc, utc_now
from shared.config import Settings
from shared.crypto import (
    AuthenticationError, aes_gcm_decrypt, aes_gcm_encrypt, confirmation_token,
    derive_session_key, derive_session_subkeys, generate_nonce, hmac_sha256,
    sequence_nonce, session_fingerprint, verify_hmac_sha256,
)
from shared.keys import KeyMaterial
from shared.protocol import challenge_transcript, handshake_aad, secure_aad, session_transcript
from shared.schemas import (
    HandshakeChallenge, HandshakeCompleteRequest, HandshakeCompleteResponse,
    HandshakeInitRequest, JobCommand, JobResult, SecureEnvelope,
)


class ProtocolError(Exception):
    def __init__(self, code: str, status_code: int = 401) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class CSDService:
    def __init__(self, settings: Settings, keys: KeyMaterial, audit: AuditLog | None = None) -> None:
        self.settings = settings
        self.keys = keys
        self.audit = audit or AuditLog()
        self.sessions = SessionStore()
        self.executor = JobExecutor(DataStore(settings.data_root))
        self.jobs: dict[str, SecureEnvelope] = {}
        self._jobs_lock = threading.RLock()

    def init_handshake(self, request: HandshakeInitRequest) -> HandshakeChallenge:
        if request.protocol != self.settings.protocol or request.host_id != self.settings.host_id or request.csd_id != self.settings.csd_id:
            self.audit.record("handshake", "IDENTITY_OR_PROTOCOL", "rejected")
            raise ProtocolError("AUTHENTICATION_FAILED")
        now = utc_now()
        self.sessions.cleanup(now)
        handshake_id = uuid.uuid4().hex
        nonce_s = generate_nonce()
        created_at = format_utc(now)
        expires_at = format_utc(now + timedelta(seconds=self.settings.handshake_ttl_seconds))
        transcript = challenge_transcript(
            protocol=request.protocol, handshake_id=handshake_id,
            host_id=request.host_id, csd_id=request.csd_id,
            nonce_s=b64u_encode(nonce_s), created_at=created_at, expires_at=expires_at,
        )
        auth_td = hmac_sha256(self.keys.auth_key, canonical_json(transcript))
        inner = dict(transcript)
        inner["auth_td"] = b64u_encode(auth_td)
        aad = handshake_aad(
            protocol=request.protocol, handshake_id=handshake_id,
            host_id=request.host_id, csd_id=request.csd_id,
            direction="csd_to_host", message_type="challenge",
        )
        nonce, ciphertext = aes_gcm_encrypt(self.keys.enc_key, canonical_json(inner), aad)
        pending = PendingHandshake(handshake_id, nonce_s, transcript, parse_utc(expires_at))
        self.sessions.add_pending(pending)
        self.audit.record("handshake_init", "CHALLENGE_CREATED", "accepted", handshake_id[:12])
        return HandshakeChallenge(
            **{k: transcript[k] for k in ("protocol", "handshake_id", "host_id", "csd_id", "created_at", "expires_at")},
            auth_td=b64u_encode(auth_td), sess_td_nonce=b64u_encode(nonce), sess_td=b64u_encode(ciphertext),
        )

    def complete_handshake(self, request: HandshakeCompleteRequest) -> HandshakeCompleteResponse:
        now = utc_now()
        status, pending = self.sessions.pending_status(request.handshake_id, now)
        if status == "replay":
            self.audit.record("handshake_complete", "HANDSHAKE_REPLAY", "rejected", request.handshake_id[:12])
            raise ProtocolError("HANDSHAKE_REPLAY", 409)
        if status == "expired":
            self.audit.record("handshake_complete", "CHALLENGE_EXPIRED", "rejected", request.handshake_id[:12])
            raise ProtocolError("CHALLENGE_EXPIRED", 401)
        if status != "pending" or pending is None:
            self.audit.record("handshake_complete", "UNKNOWN_HANDSHAKE", "rejected")
            raise ProtocolError("AUTHENTICATION_FAILED", 401)
        if request.protocol != self.settings.protocol or request.host_id != pending.transcript["host_id"] or request.csd_id != pending.transcript["csd_id"]:
            self.audit.record("handshake_complete", "IDENTITY_OR_PROTOCOL", "rejected", request.handshake_id[:12])
            raise ProtocolError("AUTHENTICATION_FAILED", 401)
        aad = handshake_aad(
            protocol=request.protocol, handshake_id=request.handshake_id,
            host_id=request.host_id, csd_id=request.csd_id,
            direction="host_to_csd", message_type="response",
        )
        try:
            plaintext = aes_gcm_decrypt(self.keys.enc_key, b64u_decode(request.sess_th_nonce), b64u_decode(request.sess_th), aad)
            inner = json.loads(plaintext)
            expected_fields = {"nonce_s", "nonce_r", "session_id", "host_confirmation"}
            if set(inner) != expected_fields or inner["nonce_s"] != pending.transcript["nonce_s"]:
                raise AuthenticationError("authentication failed")
            nonce_r = b64u_decode(inner["nonce_r"])
            if len(nonce_r) != 32 or not isinstance(inner["session_id"], str) or len(inner["session_id"]) != 32:
                raise AuthenticationError("authentication failed")
            master = derive_session_key(
                self.keys.auth_key, self.keys.enc_key, pending.nonce_s, nonce_r,
                protocol=request.protocol, host_id=request.host_id, csd_id=request.csd_id,
                handshake_id=request.handshake_id,
            )
            subkeys = derive_session_subkeys(master)
            transcript = session_transcript(pending.transcript, inner["nonce_r"], inner["session_id"])
            verify_hmac_sha256(subkeys.confirmation, canonical_json({"role": "host", "transcript": transcript}), b64u_decode(inner["host_confirmation"]))
        except (AuthenticationError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            self.audit.record("handshake_complete", "AUTHENTICATION_FAILED", "rejected", request.handshake_id[:12])
            raise ProtocolError("AUTHENTICATION_FAILED", 401) from exc
        expires_at = now + timedelta(seconds=self.settings.session_ttl_seconds)
        session = SessionState(
            session_id=inner["session_id"], host_id=request.host_id, csd_id=request.csd_id,
            keys=subkeys, key_fingerprint=session_fingerprint(master), expires_at=expires_at,
        )
        try:
            self.sessions.establish(request.handshake_id, session, pending.expires_at + timedelta(seconds=self.settings.max_clock_skew_seconds))
        except KeyError as exc:
            raise ProtocolError("HANDSHAKE_REPLAY", 409) from exc
        csd_confirmation = confirmation_token(subkeys.confirmation, transcript, "csd")
        self.audit.record("handshake_complete", "SESSION_ESTABLISHED", "accepted", session.session_id[:12])
        return HandshakeCompleteResponse(
            protocol=request.protocol, session_id=session.session_id,
            expires_at=format_utc(expires_at), csd_confirmation=b64u_encode(csd_confirmation),
            key_fingerprint=session.key_fingerprint,
        )

    def submit_job(self, envelope: SecureEnvelope) -> tuple[str, SecureEnvelope]:
        session = self._validated_session(envelope.session_id)
        if envelope.protocol != self.settings.protocol or envelope.direction != "host_to_csd" or envelope.message_type != "job_request":
            self.audit.record("secure_job", "AAD_METADATA_REJECTED", "rejected", envelope.session_id[:12])
            raise ProtocolError("AUTHENTICATION_FAILED", 401)
        with self._jobs_lock:
            if envelope.sequence != session.expected_host_sequence:
                code = "MESSAGE_REPLAY" if envelope.sequence < session.expected_host_sequence else "OUT_OF_ORDER"
                self.audit.record("secure_job", code, "rejected", envelope.session_id[:12])
                raise ProtocolError(code, 409)
            aad = secure_aad(
                protocol=envelope.protocol, session_id=envelope.session_id,
                sequence=envelope.sequence, direction=envelope.direction,
                message_type=envelope.message_type,
            )
            expected_nonce = sequence_nonce(envelope.session_id, envelope.direction, envelope.sequence)
            try:
                supplied_nonce = b64u_decode(envelope.nonce)
                if supplied_nonce != expected_nonce:
                    raise AuthenticationError("authentication failed")
                plaintext = aes_gcm_decrypt(session.keys.host_to_csd, supplied_nonce, b64u_decode(envelope.ciphertext), aad)
                command = JobCommand.model_validate_json(plaintext)
            except (AuthenticationError, ValueError, ValidationError) as exc:
                self.audit.record("secure_job", "CIPHERTEXT_REJECTED", "rejected", envelope.session_id[:12])
                raise ProtocolError("AUTHENTICATION_FAILED", 401) from exc
            session.expected_host_sequence += 1
            job_id = uuid.uuid4().hex
            result = self.executor.execute(command, job_id)
            session.jobs_executed += 1
            response_sequence = session.next_csd_sequence
            session.next_csd_sequence += 1
            response_aad = secure_aad(
                protocol=self.settings.protocol, session_id=session.session_id,
                sequence=response_sequence, direction="csd_to_host", message_type="job_result",
            )
            response_nonce = sequence_nonce(session.session_id, "csd_to_host", response_sequence)
            _, response_ciphertext = aes_gcm_encrypt(
                session.keys.csd_to_host, result.model_dump_json().encode("utf-8"),
                response_aad, response_nonce,
            )
            response = SecureEnvelope(
                protocol=self.settings.protocol, session_id=session.session_id,
                sequence=response_sequence, direction="csd_to_host", message_type="job_result",
                nonce=b64u_encode(response_nonce), ciphertext=b64u_encode(response_ciphertext),
            )
            self.jobs[job_id] = response
            reason = "JOB_COMPLETED" if result.success else result.error_code
            self.audit.record("secure_job", reason, "accepted" if result.success else "rejected", job_id[:12])
            return job_id, response

    def get_job(self, job_id: str, session_id: str) -> SecureEnvelope:
        self._validated_session(session_id)
        with self._jobs_lock:
            envelope = self.jobs.get(job_id)
        if envelope is None or envelope.session_id != session_id:
            raise ProtocolError("JOB_NOT_FOUND", 404)
        return envelope

    def close_session(self, session_id: str) -> bool:
        closed = self.sessions.close(session_id)
        self.audit.record("session_close", "SESSION_CLOSED" if closed else "SESSION_NOT_FOUND", "accepted" if closed else "rejected", session_id[:12])
        return closed

    def _validated_session(self, session_id: str) -> SessionState:
        now = utc_now()
        session = self.sessions.get(session_id)
        if session is None:
            raise ProtocolError("SESSION_NOT_FOUND", 401)
        if session.expires_at < now:
            self.sessions.close(session_id)
            self.audit.record("session", "SESSION_EXPIRED", "rejected", session_id[:12])
            raise ProtocolError("SESSION_EXPIRED", 401)
        return session
