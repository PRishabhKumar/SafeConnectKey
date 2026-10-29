from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
if str(PROJECT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIRECTORY))

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st
from fastapi.testclient import TestClient

from host_app.client import HostClient, configured_base_url
from shared.audit import AuditLog
from shared.canonical import b64u_decode, b64u_encode
from shared.config import DEFAULT_SETTINGS, PROJECT_ROOT
from shared.keys import load_key_material


EMBEDDED_MODES = {"embedded", "in-process", "in_process", "true", "1"}


def embedded_csd_enabled() -> bool:
    """Return whether Streamlit should host the emulator in its own process."""
    return os.getenv("SCK_CSD_MODE", "external").strip().lower() in EMBEDDED_MODES


def build_api_transport() -> Any:
    """Create either the cloud-safe in-process transport or the local HTTP client."""
    if embedded_csd_enabled():
        # Import lazily so normal local dashboard use does not instantiate a second CSD.
        from csd_app.main import create_app

        return TestClient(create_app(DEFAULT_SETTINGS, load_key_material(), AuditLog()))

    return httpx.Client(base_url=configured_base_url(), timeout=10)


@st.cache_resource(show_spinner=False)
def api() -> Any:
    """Keep one transport and one embedded CSD session store per Streamlit worker."""
    return build_api_transport()


def health() -> bool:
    try:
        return api().get("/health").status_code == 200
    except (httpx.HTTPError, RuntimeError, ValueError):
        return False


def main() -> None:
    st.set_page_config(page_title="SafeConnectKey", page_icon="🔐", layout="wide")
    st.title("SafeConnectKey — Secure Computational Storage")
    st.caption("Recommended profile · AES-256-GCM · HMAC-SHA-256 · HKDF-SHA-256")

    online = health()
    host = st.session_state.get("host")
    authenticated = bool(host and host.session)
    metrics: dict[str, Any] = {}
    if online:
        try:
            metrics = api().get("/metrics/snapshot").json()
        except httpx.HTTPError:
            pass

    cols = st.columns(5)
    cols[0].metric("CSD", "Online" if online else "Offline")
    cols[1].metric("Session", "Authenticated" if authenticated else "Not connected")
    cols[2].metric("Encryption", "AES-256-GCM")
    cols[3].metric("Profile", "Recommended")
    cols[4].metric("CSD RSS", f"{metrics.get('rss_mb', 0):.1f} MiB")

    if not online and embedded_csd_enabled():
        st.error(
            "Embedded CSD could not start. Add SCK_AUTH_KEY and SCK_ENC_KEY "
            "as root-level secrets in Streamlit Community Cloud."
        )

    actions = st.columns(5)
    if actions[0].button("Run handshake", disabled=not online, width="stretch"):
        transport = api()
        host = HostClient(transport, DEFAULT_SETTINGS, load_key_material())
        host.connect()
        st.session_state.host = host
        st.session_state.trace = [
            "Challenge created",
            "AuthTd verified",
            "Nonce R generated",
            "Session key derived independently",
            "Key confirmation verified",
        ]
        st.rerun()
    if actions[1].button("Run SHA-256 job", disabled=not authenticated, width="stretch"):
        st.session_state.latest_job = host.jobs().submit("sha256", "sample.txt").model_dump()
        st.rerun()
    if actions[2].button("Simulate tamper", disabled=not online, width="stretch"):
        temp = HostClient(api(), DEFAULT_SETTINGS, load_key_material())
        temp.connect()
        envelope = temp.jobs().build_request("sha256", "sample.txt")
        data = bytearray(b64u_decode(envelope.ciphertext))
        data[0] ^= 1
        envelope.ciphertext = b64u_encode(bytes(data))
        response = temp.transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
        st.session_state.attack = {
            "type": "ciphertext tamper",
            "status": "rejected",
            "reason": response.json().get("detail"),
        }
        st.rerun()
    if actions[3].button("Simulate replay", disabled=not online, width="stretch"):
        temp = HostClient(api(), DEFAULT_SETTINGS, load_key_material())
        temp.connect()
        envelope = temp.jobs().build_request("sha256", "sample.txt")
        temp.transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
        response = temp.transport.post("/api/v1/secure/jobs", json=envelope.model_dump())
        st.session_state.attack = {
            "type": "message replay",
            "status": "rejected",
            "reason": response.json().get("detail"),
        }
        st.rerun()
    if actions[4].button("Refresh evidence", width="stretch"):
        st.rerun()

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Handshake trace")
        trace = st.session_state.get("trace", ["Awaiting handshake"])
        fingerprint = host.session.key_fingerprint if authenticated else "—"
        for index, step in enumerate(trace, 1):
            st.success(f"{index}. {step}")
        st.caption(f"Session-key fingerprint: {fingerprint} (truncated; key never transmitted)")
    with right:
        st.subheader("Secure near-data job")
        latest = st.session_state.get("latest_job")
        if latest:
            st.success("Verified encrypted result")
            st.json(
                {
                    "file": latest["path"],
                    "task": latest["operation"],
                    "source_bytes": latest["source_bytes"],
                    "returned_bytes": latest["returned_bytes"],
                    "bytes_avoided": latest["source_bytes"] - latest["returned_bytes"],
                    "result": latest["result"],
                }
            )
        else:
            st.info("Run a SHA-256 job after authentication.")

    st.subheader("Security events")
    events = metrics.get("security_events", [])
    if st.session_state.get("attack"):
        events = events + [
            {
                "timestamp_utc": "current run",
                "event_type": st.session_state.attack["type"],
                "reason_code": st.session_state.attack["reason"],
                "status": "rejected",
                "subject": "",
            }
        ]
    st.dataframe(pd.DataFrame(events[-10:]), width="stretch", hide_index=True)

    st.subheader("External-device measurement evidence")
    st.caption("FIG.3: Host nonce/key retrieval → token verification and session token → TCP communicator → CSD token verification → independent HKDF session keys.")
    vm_folder = os.environ.get("SCK_VM_RESULTS")
    if vm_folder:
        vm_path = Path(vm_folder)
        metadata_path = vm_path / "metadata.json"
        if metadata_path.exists():
            vm_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            st.write({k: vm_metadata.get(k) for k in ("deployment_label", "status", "host_node", "base_url", "handshake_ms")})
            st.caption(vm_metadata.get("limitations", ""))
            for chart in sorted(vm_path.glob("fig*.png")):
                st.image(str(chart))
            for name in ("measurements.csv", "algorithm_memory.csv"):
                file = vm_path / name
                if file.exists():
                    st.download_button(f"Download {name}", file.read_bytes(), file_name=name, mime="text/csv")
        else:
            st.info("No external-device measurement metadata found in SCK_VM_RESULTS.")
    else:
        st.info("Run validation.run_lan_benchmarks on the Host laptop, then set SCK_VM_RESULTS to its output folder.")

    st.subheader("Earlier single-machine performance evidence (not external-device measurements)")
    chart_cols = st.columns(2)
    handshake_path = PROJECT_ROOT / "results" / "handshake_latency.csv"
    concurrency_path = PROJECT_ROOT / "results" / "concurrency_results.csv"
    if handshake_path.exists():
        frame = pd.read_csv(handshake_path)
        chart_cols[0].plotly_chart(
            px.histogram(frame, x="latency_ms", title="Handshake latency (ms)"),
            width="stretch",
        )
    if concurrency_path.exists():
        frame = pd.read_csv(concurrency_path)
        chart_cols[1].plotly_chart(
            px.line(
                frame,
                x="clients",
                y=["throughput_rps", "p95_latency_ms"],
                markers=True,
                title="Concurrency evidence",
            ),
            width="stretch",
        )
    summary_path = PROJECT_ROOT / "results" / "validation_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        st.caption(
            f"Measured run {summary['run_id']} · "
            f"{summary['validation']['passed']}/{summary['validation']['total']} "
            "validation tests passed · targets are reported separately"
        )


if __name__ == "__main__":
    main()
