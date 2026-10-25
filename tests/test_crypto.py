from __future__ import annotations

import pytest

from shared.canonical import b64u_decode, b64u_encode, canonical_json
from shared.crypto import (
    AuthenticationError, aes_gcm_decrypt, aes_gcm_encrypt,
    derive_session_key, derive_session_subkeys, generate_nonce,
    hmac_sha256, verify_hmac_sha256,
)
from shared.keys import KeyMaterial


def test_canonical_json_and_base64url_are_deterministic() -> None:
    assert canonical_json({"z": 1, "a": "x"}) == b'{"a":"x","z":1}'
    raw = bytes(range(32))
    assert b64u_decode(b64u_encode(raw)) == raw


def test_aes_256_gcm_round_trip_and_tamper_rejection() -> None:
    key, plaintext, aad = generate_nonce(), b"protected payload", b"bound metadata"
    nonce, ciphertext = aes_gcm_encrypt(key, plaintext, aad)
    assert aes_gcm_decrypt(key, nonce, ciphertext, aad) == plaintext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    with pytest.raises(AuthenticationError):
        aes_gcm_decrypt(key, nonce, bytes(tampered), aad)
    with pytest.raises(AuthenticationError):
        aes_gcm_decrypt(key, nonce, ciphertext, aad + b"!")


def test_hmac_sha256_and_key_separation() -> None:
    keys = KeyMaterial.generate()
    token = hmac_sha256(keys.auth_key, b"transcript")
    verify_hmac_sha256(keys.auth_key, b"transcript", token)
    with pytest.raises(AuthenticationError):
        verify_hmac_sha256(keys.auth_key, b"changed", token)
    master = derive_session_key(keys.auth_key, keys.enc_key, generate_nonce(), generate_nonce(), protocol="SCK-1", host_id="h", csd_id="c", handshake_id="x")
    subkeys = derive_session_subkeys(master)
    assert len(master) == 32
    assert len({subkeys.confirmation, subkeys.host_to_csd, subkeys.csd_to_host}) == 3

