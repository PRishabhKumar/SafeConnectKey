from __future__ import annotations

from dashboard.app import build_api_transport, embedded_csd_enabled
from host_app.client import HostClient
from shared.canonical import b64u_encode
from shared.config import DEFAULT_SETTINGS
from shared.keys import KeyMaterial


def test_embedded_cloud_transport_completes_handshake_and_job(monkeypatch):
    keys = KeyMaterial.generate()
    monkeypatch.setenv("SCK_CSD_MODE", "embedded")
    monkeypatch.setenv("SCK_AUTH_KEY", b64u_encode(keys.auth_key))
    monkeypatch.setenv("SCK_ENC_KEY", b64u_encode(keys.enc_key))

    assert embedded_csd_enabled()
    transport = build_api_transport()
    try:
        assert transport.get("/health").status_code == 200
        host = HostClient(transport, DEFAULT_SETTINGS, keys)
        session = host.connect()
        result = host.jobs().submit("sha256", "sample.txt")
        assert session.key_fingerprint
        assert result.result["sha256"] == "905b376bd71392bf6191cfa6baf85adb8dc83a288b4c3d97602d6f5ac85a62c7"
    finally:
        transport.close()


def test_external_mode_remains_default(monkeypatch):
    monkeypatch.delenv("SCK_CSD_MODE", raising=False)
    assert not embedded_csd_enabled()
