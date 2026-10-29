from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx

from host_app.handshake import HostHandshake, HostProtocolError, HostSession
from host_app.secure_jobs import SecureJobClient
from shared.config import DEFAULT_SETTINGS, Settings
from shared.keys import KeyMaterial, load_key_material


DEFAULT_CSD_BASE_URL = "http://127.0.0.1:8001"


def configured_base_url() -> str:
    """Return the external CSD URL shared by the CLI and dashboard."""
    return os.getenv("SCK_CSD_BASE_URL", DEFAULT_CSD_BASE_URL).strip() or DEFAULT_CSD_BASE_URL


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


def check_csd(base_url: str, timeout: float = 10.0) -> dict[str, str]:
    """Verify TCP/HTTP reachability and return the remote CSD identity."""
    with httpx.Client(base_url=base_url, timeout=timeout) as transport:
        response = transport.get("/health")
        response.raise_for_status()
        health = response.json()
    if (
        health.get("status") != "ready"
        or health.get("protocol") != DEFAULT_SETTINGS.protocol
        or health.get("csd_id") != DEFAULT_SETTINGS.csd_id
    ):
        raise RuntimeError(f"Unexpected CSD health response: {health}")
    return health


def run_demo(base_url: str, timeout: float = 10.0) -> None:
    with httpx.Client(base_url=base_url, timeout=timeout) as transport:
        client = HostClient(transport)
        session = client.connect()
        result = client.jobs().submit("sha256", "sample.txt")
        print(json.dumps({"session_authenticated": True, "key_fingerprint": session.key_fingerprint, "job": result.model_dump()}, indent=2))
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SafeConnectKey Host application")
    parser.add_argument("command", choices=["check", "demo"], nargs="?", default="demo")
    parser.add_argument("--base-url", default=configured_base_url(), help="CSD URL (default: SCK_CSD_BASE_URL or loopback)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        if args.command == "check":
            health = check_csd(args.base_url, args.timeout)
            print(json.dumps({"reachable": True, "base_url": args.base_url, **health}, indent=2))
        else:
            run_demo(args.base_url, args.timeout)
    except (httpx.HTTPError, HostProtocolError, RuntimeError, ValueError) as exc:
        print(f"SafeConnectKey Host error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
