from __future__ import annotations

import argparse
import json
from typing import Any

import httpx

from host_app.handshake import HostHandshake, HostProtocolError, HostSession
from host_app.secure_jobs import SecureJobClient
from shared.config import DEFAULT_SETTINGS, Settings
from shared.keys import KeyMaterial, load_key_material


class HostClient:
    def __init__(self, transport: Any, settings: Settings = DEFAULT_SETTINGS, keys: KeyMaterial | None = None) -> None:
        self.transport, self.settings = transport, settings
        self.keys = keys or load_key_material()
        self.handshake = HostHandshake(settings, self.keys)
        self.session: HostSession | None = None

    def connect(self) -> HostSession:
        challenge = self.transport.post("/api/v1/handshake/init", json=self.handshake.make_init_request())
        if challenge.status_code != 201:
            raise HostProtocolError(challenge.json().get("detail", "HANDSHAKE_FAILED"))
        request, pending = self.handshake.process_challenge(challenge.json())
        completed = self.transport.post("/api/v1/handshake/complete", json=request.model_dump())
        if completed.status_code != 201:
            raise HostProtocolError(completed.json().get("detail", "HANDSHAKE_FAILED"))
        self.session = self.handshake.finalize(completed.json(), pending)
        return self.session

    def jobs(self) -> SecureJobClient:
        if self.session is None:
            raise HostProtocolError("SESSION_REQUIRED")
        return SecureJobClient(self.transport, self.settings, self.session)

    def close(self) -> None:
        if self.session:
            self.transport.delete(f"/api/v1/secure/sessions/{self.session.session_id}")
            self.session = None


def run_demo(base_url: str) -> None:
    with httpx.Client(base_url=base_url, timeout=10.0) as transport:
        client = HostClient(transport)
        session = client.connect()
        result = client.jobs().submit("sha256", "sample.txt")
        print(json.dumps({"session_authenticated": True, "key_fingerprint": session.key_fingerprint, "job": result.model_dump()}, indent=2))
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeConnectKey Host application")
    parser.add_argument("command", choices=["demo"], nargs="?", default="demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001")
    args = parser.parse_args()
    run_demo(args.base_url)


if __name__ == "__main__":
    main()
