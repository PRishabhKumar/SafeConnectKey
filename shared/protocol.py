from __future__ import annotations

from shared.canonical import canonical_json


def challenge_transcript(
    *, protocol: str, handshake_id: str, host_id: str, csd_id: str,
    nonce_s: str, created_at: str, expires_at: str,
) -> dict[str, str]:
    return {
        "protocol": protocol,
        "handshake_id": handshake_id,
        "host_id": host_id,
        "csd_id": csd_id,
        "nonce_s": nonce_s,
        "created_at": created_at,
        "expires_at": expires_at,
    }


def handshake_aad(
    *, protocol: str, handshake_id: str, host_id: str, csd_id: str,
    direction: str, message_type: str,
) -> bytes:
    return canonical_json({
        "protocol": protocol,
        "handshake_id": handshake_id,
        "host_id": host_id,
        "csd_id": csd_id,
        "direction": direction,
        "message_type": message_type,
    })


def session_transcript(challenge: dict[str, str], nonce_r: str, session_id: str) -> dict[str, object]:
    return {"challenge": challenge, "nonce_r": nonce_r, "session_id": session_id}


def secure_aad(
    *, protocol: str, session_id: str, sequence: int,
    direction: str, message_type: str,
) -> bytes:
    return canonical_json({
        "protocol": protocol,
        "session_id": session_id,
        "sequence": sequence,
        "direction": direction,
        "message_type": message_type,
    })

