from __future__ import annotations

import os

import psutil
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from csd_app.service import CSDService, ProtocolError
from shared.audit import AuditLog
from shared.config import DEFAULT_SETTINGS, Settings
from shared.keys import KeyMaterial, load_key_material
from shared.schemas import HandshakeCompleteRequest, HandshakeInitRequest, SecureEnvelope


def create_app(settings: Settings = DEFAULT_SETTINGS, keys: KeyMaterial | None = None) -> FastAPI:
    service = CSDService(
        settings,
        keys or load_key_material(),
        AuditLog(settings.results_root / "raw" / "security_events.jsonl"),
    )
    app = FastAPI(title="SafeConnectKey CSD Emulator", version="1.0.0")
    app.state.sck_service = service

    @app.middleware("http")
    async def enforce_request_limit(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and int(length) > settings.max_request_bytes:
            service.audit.record("request", "PAYLOAD_TOO_LARGE", "rejected")
            return JSONResponse(status_code=413, content={"detail": "PAYLOAD_TOO_LARGE"})
        return await call_next(request)

    @app.exception_handler(ProtocolError)
    async def protocol_error_handler(_request: Request, exc: ProtocolError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.code})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ready", "protocol": settings.protocol, "profile": "recommended"}

    @app.post("/api/v1/handshake/init", status_code=201)
    def handshake_init(request: HandshakeInitRequest):
        return service.init_handshake(request)

    @app.post("/api/v1/handshake/complete", status_code=201)
    def handshake_complete(request: HandshakeCompleteRequest):
        return service.complete_handshake(request)

    @app.post("/api/v1/secure/jobs", status_code=202)
    def secure_job(envelope: SecureEnvelope):
        job_id, response = service.submit_job(envelope)
        return {"job_id": job_id, "envelope": response.model_dump()}

    @app.get("/api/v1/secure/jobs/{job_id}")
    def secure_job_result(job_id: str, session_id: str):
        return service.get_job(job_id, session_id)

    @app.delete("/api/v1/secure/sessions/{session_id}", status_code=204)
    def close_session(session_id: str):
        if not service.close_session(session_id):
            raise ProtocolError("SESSION_NOT_FOUND", 404)
        return Response(status_code=204)

    @app.get("/metrics/snapshot")
    def metrics_snapshot():
        process = psutil.Process(os.getpid())
        return {
            "cpu_pct": process.cpu_percent(interval=None),
            "rss_mb": round(process.memory_info().rss / (1024 * 1024), 3),
            "state": service.sessions.counts(),
            "security_events": service.audit.snapshot()[-50:],
            "profile": "recommended",
            "algorithms": ["AES-256-GCM", "HMAC-SHA-256", "HKDF-SHA-256"],
        }

    return app


app = create_app()
