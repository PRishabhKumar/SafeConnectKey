from __future__ import annotations

from fastapi.testclient import TestClient

from csd_app.main import create_app
from host_app.client import check_csd, configured_base_url
from shared.audit import AuditLog
from shared.keys import KeyMaterial


def test_configured_base_url_uses_environment(monkeypatch) -> None:
    monkeypatch.setenv("SCK_CSD_BASE_URL", "http://192.168.1.25:8001")
    assert configured_base_url() == "http://192.168.1.25:8001"


def test_check_csd_accepts_compatible_health(monkeypatch) -> None:
    transport = TestClient(create_app(keys=KeyMaterial.generate(), audit=AuditLog()))

    class TestClientContext:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return transport

        def __exit__(self, *_args):
            transport.close()

    monkeypatch.setattr("host_app.client.httpx.Client", TestClientContext)
    health = check_csd("http://csd.test:8001")
    assert health["status"] == "ready"
    assert health["csd_id"] == "csd-demo"
