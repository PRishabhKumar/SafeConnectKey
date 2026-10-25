from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Identity = str


class HandshakeInitRequest(StrictModel):
    protocol: str = Field(min_length=1, max_length=16)
    host_id: Identity = Field(min_length=1, max_length=64)
    csd_id: Identity = Field(min_length=1, max_length=64)


class HandshakeChallenge(StrictModel):
    protocol: str
    handshake_id: str
    host_id: str
    csd_id: str
    created_at: str
    expires_at: str
    auth_td: str
    sess_td_nonce: str
    sess_td: str


class HandshakeCompleteRequest(StrictModel):
    protocol: str
    handshake_id: str
    host_id: str
    csd_id: str
    sess_th_nonce: str
    sess_th: str


class HandshakeCompleteResponse(StrictModel):
    protocol: str
    session_id: str
    expires_at: str
    csd_confirmation: str
    key_fingerprint: str


class SecureEnvelope(StrictModel):
    protocol: str
    session_id: str = Field(min_length=16, max_length=64)
    sequence: int = Field(ge=1, lt=2**64)
    direction: str = Field(min_length=1, max_length=16)
    message_type: str = Field(min_length=1, max_length=32)
    nonce: str = Field(min_length=16, max_length=32)
    ciphertext: str = Field(min_length=16, max_length=100_000)


class JobCommand(StrictModel):
    operation: str = Field(min_length=1, max_length=32)
    path: str = Field(min_length=1, max_length=256)


class JobResult(StrictModel):
    job_id: str
    operation: str
    path: str
    success: bool
    result: dict[str, Any] = Field(default_factory=dict)
    error_code: str = ""
    source_bytes: int = Field(ge=0)
    returned_bytes: int = Field(ge=0)
    latency_ms: float = Field(ge=0)

