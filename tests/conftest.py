from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from csd_app.main import create_app
from host_app.client import HostClient
from shared.audit import AuditLog
from shared.config import DEFAULT_SETTINGS
from shared.keys import KeyMaterial


@pytest.fixture
def keys() -> KeyMaterial:
    return KeyMaterial.generate()


@pytest.fixture
def app(keys: KeyMaterial):
    return create_app(DEFAULT_SETTINGS, keys, AuditLog())


@pytest.fixture
def transport(app) -> Iterator[TestClient]:
    with TestClient(app) as client:
        yield client


@pytest.fixture
def host(transport: TestClient, keys: KeyMaterial) -> HostClient:
    return HostClient(transport, DEFAULT_SETTINGS, keys)

