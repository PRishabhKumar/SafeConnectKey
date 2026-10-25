from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from csd_app.main import create_app
from host_app.client import HostClient
from host_app.handshake import HostHandshake, HostProtocolError
from shared.canonical import b64u_decode, b64u_encode, canonical_json, utc_now
from shared.config import DEFAULT_SETTINGS
from shared.crypto import aes_gcm_decrypt, aes_gcm_encrypt
from shared.keys import KeyMaterial
from shared.protocol import handshake_aad


pytestmark = pytest.mark.validation


def flip_b64(value: str) -> str:
    data = bytearray(b64u_decode(value))
    data[len(data) // 2] ^= 1
    return b64u_encode(bytes(data))


def connected(transport: TestClient, keys: KeyMaterial, settings=DEFAULT_SETTINGS) -> HostClient:
    host = HostClient(transport, settings, keys)
    host.connect()
    return host


def test_v01_valid_handshake(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    server = transport.app.state.sck_service.sessions.get(host.session.session_id)
    assert server is not None
    assert host.session.key_fingerprint == server.key_fingerprint


def test_v02_wrong_authentication_key(transport: TestClient, keys: KeyMaterial) -> None:
    wrong = KeyMaterial.generate()
    host = HostClient(transport, DEFAULT_SETTINGS, KeyMaterial(wrong.auth_key, keys.enc_key))
    with pytest.raises(HostProtocolError, match="AUTHENTICATION_FAILED"):
        host.connect()
    assert transport.app.state.sck_service.sessions.counts()["sessions"] == 0


def test_v03_wrong_encryption_key(transport: TestClient, keys: KeyMaterial) -> None:
    wrong = KeyMaterial.generate()
    host = HostClient(transport, DEFAULT_SETTINGS, KeyMaterial(keys.auth_key, wrong.enc_key))
    with pytest.raises(HostProtocolError, match="AUTHENTICATION_FAILED"):
        host.connect()
    assert transport.app.state.sck_service.sessions.counts()["sessions"] == 0


def test_v04_tampered_auth_td(transport: TestClient, keys: KeyMaterial) -> None:
    handshake = HostHandshake(DEFAULT_SETTINGS, keys)
    raw = transport.post("/api/v1/handshake/init", json=handshake.make_init_request()).json()
    aad = handshake_aad(protocol=raw["protocol"], handshake_id=raw["handshake_id"], host_id=raw["host_id"], csd_id=raw["csd_id"], direction="csd_to_host", message_type="challenge")
    inner = json.loads(aes_gcm_decrypt(keys.enc_key, b64u_decode(raw["sess_td_nonce"]), b64u_decode(raw["sess_td"]), aad))
    inner["auth_td"] = flip_b64(inner["auth_td"])
    raw["auth_td"] = inner["auth_td"]
    nonce, ciphertext = aes_gcm_encrypt(keys.enc_key, canonical_json(inner), aad)
    raw["sess_td_nonce"], raw["sess_td"] = b64u_encode(nonce), b64u_encode(ciphertext)
    with pytest.raises(HostProtocolError, match="AUTHENTICATION_FAILED"):
        handshake.process_challenge(raw)


def test_v05_tampered_sess_td(transport: TestClient, keys: KeyMaterial) -> None:
    handshake = HostHandshake(DEFAULT_SETTINGS, keys)
    raw = transport.post("/api/v1/handshake/init", json=handshake.make_init_request()).json()
    raw["sess_td"] = flip_b64(raw["sess_td"])
    with pytest.raises(HostProtocolError, match="AUTHENTICATION_FAILED"):
        handshake.process_challenge(raw)


def test_v06_expired_challenge(keys: KeyMaterial) -> None:
    settings = replace(DEFAULT_SETTINGS, handshake_ttl_seconds=-1)
    with TestClient(create_app(settings, keys)) as transport:
        handshake = HostHandshake(settings, keys)
        raw = transport.post("/api/v1/handshake/init", json=handshake.make_init_request()).json()
        with pytest.raises(HostProtocolError, match="CHALLENGE_EXPIRED"):
            handshake.process_challenge(raw)


def test_v07_handshake_replay(transport: TestClient, keys: KeyMaterial) -> None:
    handshake = HostHandshake(DEFAULT_SETTINGS, keys)
    raw = transport.post("/api/v1/handshake/init", json=handshake.make_init_request()).json()
    request, _pending = handshake.process_challenge(raw)
    assert transport.post("/api/v1/handshake/complete", json=request.model_dump()).status_code == 201
    replay = transport.post("/api/v1/handshake/complete", json=request.model_dump())
    assert replay.status_code == 409
    assert replay.json()["detail"] == "HANDSHAKE_REPLAY"


def test_v08_identity_substitution(transport: TestClient, keys: KeyMaterial) -> None:
    handshake = HostHandshake(DEFAULT_SETTINGS, keys)
    raw = transport.post("/api/v1/handshake/init", json=handshake.make_init_request()).json()
    raw["host_id"] = "substituted-host"
    with pytest.raises(HostProtocolError, match="AUTHENTICATION_FAILED"):
        handshake.process_challenge(raw)


def test_v09_valid_secure_job(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    result = host.jobs().submit("sha256", "sample.txt")
    expected = hashlib.sha256((DEFAULT_SETTINGS.data_root / "sample.txt").read_bytes()).hexdigest()
    assert result.success and result.result["sha256"] == expected


def test_v10_data_tampering(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    envelope = host.jobs().build_request("sha256", "sample.txt")
    envelope.ciphertext = flip_b64(envelope.ciphertext)
    response = transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
    assert response.status_code == 401
    server = transport.app.state.sck_service.sessions.get(host.session.session_id)
    assert server.jobs_executed == 0


def test_v11_message_replay(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    envelope = host.jobs().build_request("sha256", "sample.txt")
    assert transport.post("/api/v1/secure/jobs", json=envelope.model_dump()).status_code == 202
    replay = transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
    assert replay.status_code == 409 and replay.json()["detail"] == "MESSAGE_REPLAY"
    assert transport.app.state.sck_service.sessions.get(host.session.session_id).jobs_executed == 1


def test_v12_out_of_order_message(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    envelope = host.jobs().build_request("sha256", "sample.txt", sequence=2)
    response = transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
    assert response.status_code == 409 and response.json()["detail"] == "OUT_OF_ORDER"


def test_v13_session_expiry(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    session = transport.app.state.sck_service.sessions.get(host.session.session_id)
    session.expires_at = utc_now() - timedelta(seconds=1)
    envelope = host.jobs().build_request("sha256", "sample.txt")
    response = transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
    assert response.status_code == 401 and response.json()["detail"] == "SESSION_EXPIRED"


def test_v14_unsupported_operation(transport: TestClient, keys: KeyMaterial) -> None:
    result = connected(transport, keys).jobs().submit("run_program", "sample.txt")
    assert not result.success and result.error_code == "UNSUPPORTED_OPERATION"


def test_v15_path_traversal(transport: TestClient, keys: KeyMaterial) -> None:
    result = connected(transport, keys).jobs().submit("sha256", "../Implementation plan.md")
    assert not result.success and result.error_code == "PATH_REJECTED"


def test_v16_oversized_payload(transport: TestClient) -> None:
    response = transport.post("/api/v1/secure/jobs", content=b"x" * (DEFAULT_SETTINGS.max_request_bytes + 1), headers={"content-type": "application/json"})
    assert response.status_code == 413 and response.json()["detail"] == "PAYLOAD_TOO_LARGE"


def test_v17_concurrent_sessions(transport: TestClient, keys: KeyMaterial) -> None:
    def worker(_index: int) -> tuple[str, bool]:
        host = connected(transport, keys)
        result = host.jobs().submit("sha256", "sample.txt")
        return host.session.session_id, result.success
    with ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(worker, range(10)))
    assert len({session_id for session_id, _ in outcomes}) == 10
    assert all(success for _, success in outcomes)


def test_v18_restart_behavior(transport: TestClient, keys: KeyMaterial) -> None:
    old_host = connected(transport, keys)
    old_envelope = old_host.jobs().build_request("sha256", "sample.txt")
    with TestClient(create_app(DEFAULT_SETTINGS, keys)) as restarted:
        rejected = restarted.post("/api/v1/secure/jobs", json=old_envelope.model_dump())
        assert rejected.status_code == 401 and rejected.json()["detail"] == "SESSION_NOT_FOUND"
        new_host = connected(restarted, keys)
        assert new_host.jobs().submit("sha256", "sample.txt").success


def test_logs_exclude_plaintext_and_keys(transport: TestClient, keys: KeyMaterial) -> None:
    host = connected(transport, keys)
    host.jobs().submit("sha256", "sample.txt")
    events = json.dumps(transport.app.state.sck_service.audit.snapshot())
    assert "sample.txt" not in events
    assert b64u_encode(keys.auth_key) not in events
    assert b64u_encode(keys.enc_key) not in events
