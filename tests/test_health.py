from fastapi.testclient import TestClient
from csd_app.main import create_app
from shared.keys import KeyMaterial

def test_health_is_ready() -> None:
    response = TestClient(create_app(keys=KeyMaterial.generate())).get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "protocol": "SCK-1",
        "profile": "recommended",
        "csd_id": "csd-demo",
    }
