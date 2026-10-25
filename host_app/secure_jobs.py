from __future__ import annotations

from typing import Any

from host_app.handshake import HostProtocolError, HostSession
from shared.canonical import b64u_decode, b64u_encode
from shared.config import Settings
from shared.crypto import AuthenticationError, aes_gcm_decrypt, aes_gcm_encrypt, sequence_nonce
from shared.protocol import secure_aad
from shared.schemas import JobCommand, JobResult, SecureEnvelope


class SecureJobClient:
    def __init__(self, transport: Any, settings: Settings, session: HostSession) -> None:
        self.transport, self.settings, self.session = transport, settings, session

    def build_request(self, operation: str, path: str, sequence: int | None = None) -> SecureEnvelope:
        seq = sequence if sequence is not None else self.session.next_host_sequence
        command = JobCommand(operation=operation, path=path)
        aad = secure_aad(protocol=self.settings.protocol, session_id=self.session.session_id, sequence=seq, direction="host_to_csd", message_type="job_request")
        nonce = sequence_nonce(self.session.session_id, "host_to_csd", seq)
        _, ciphertext = aes_gcm_encrypt(self.session.keys.host_to_csd, command.model_dump_json().encode(), aad, nonce)
        return SecureEnvelope(
            protocol=self.settings.protocol, session_id=self.session.session_id, sequence=seq,
            direction="host_to_csd", message_type="job_request",
            nonce=b64u_encode(nonce), ciphertext=b64u_encode(ciphertext),
        )

    def submit(self, operation: str, path: str) -> JobResult:
        envelope = self.build_request(operation, path)
        response = self.transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
        if response.status_code != 202:
            raise HostProtocolError(response.json().get("detail", "SECURE_JOB_FAILED"))
        self.session.next_host_sequence += 1
        return self.decrypt_result(SecureEnvelope.model_validate(response.json()["envelope"]))

    def decrypt_result(self, envelope: SecureEnvelope) -> JobResult:
        if (envelope.protocol != self.settings.protocol or envelope.session_id != self.session.session_id or
            envelope.direction != "csd_to_host" or envelope.message_type != "job_result" or
            envelope.sequence != self.session.expected_csd_sequence):
            raise HostProtocolError("AUTHENTICATION_FAILED")
        aad = secure_aad(protocol=envelope.protocol, session_id=envelope.session_id, sequence=envelope.sequence, direction=envelope.direction, message_type=envelope.message_type)
        nonce = b64u_decode(envelope.nonce)
        if nonce != sequence_nonce(envelope.session_id, envelope.direction, envelope.sequence):
            raise HostProtocolError("AUTHENTICATION_FAILED")
        try:
            plaintext = aes_gcm_decrypt(self.session.keys.csd_to_host, nonce, b64u_decode(envelope.ciphertext), aad)
            result = JobResult.model_validate_json(plaintext)
        except (AuthenticationError, ValueError) as exc:
            raise HostProtocolError("AUTHENTICATION_FAILED") from exc
        self.session.expected_csd_sequence += 1
        return result

