from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
if str(PROJECT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIRECTORY))

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

from host_app.client import HostClient
from shared.canonical import b64u_decode, b64u_encode
from shared.config import DEFAULT_SETTINGS, PROJECT_ROOT
from shared.keys import load_key_material


st.set_page_config(page_title="SafeConnectKey", page_icon="🔐", layout="wide")
st.title("SafeConnectKey — Secure Computational Storage")
st.caption("Recommended profile · AES-256-GCM · HMAC-SHA-256 · HKDF-SHA-256")


def api() -> httpx.Client:
    return httpx.Client(base_url="http://127.0.0.1:8001", timeout=10)


def health() -> bool:
    try:
        return api().get("/health").status_code == 200
    except httpx.HTTPError:
        return False


online = health()
host = st.session_state.get("host")
authenticated = bool(host and host.session)
metrics = {}
if online:
    try: metrics = api().get("/metrics/snapshot").json()
    except httpx.HTTPError: pass

cols = st.columns(5)
cols[0].metric("CSD", "Online" if online else "Offline")
cols[1].metric("Session", "Authenticated" if authenticated else "Not connected")
cols[2].metric("Encryption", "AES-256-GCM")
cols[3].metric("Profile", "Recommended")
cols[4].metric("CSD RSS", f"{metrics.get('rss_mb', 0):.1f} MiB")

actions = st.columns(5)
if actions[0].button("Run handshake", disabled=not online, use_container_width=True):
    transport = api(); host = HostClient(transport, DEFAULT_SETTINGS, load_key_material()); host.connect(); st.session_state.host = host; st.session_state.trace = ["Challenge created", "AuthTd verified", "Nonce R generated", "Session key derived independently", "Key confirmation verified"]; st.rerun()
if actions[1].button("Run SHA-256 job", disabled=not authenticated, use_container_width=True):
    st.session_state.latest_job = host.jobs().submit("sha256", "sample.txt").model_dump(); st.rerun()
if actions[2].button("Simulate tamper", disabled=not online, use_container_width=True):
    temp = HostClient(api(), DEFAULT_SETTINGS, load_key_material()); temp.connect(); envelope=temp.jobs().build_request("sha256","sample.txt"); data=bytearray(b64u_decode(envelope.ciphertext)); data[0]^=1; envelope.ciphertext=b64u_encode(bytes(data)); response=temp.transport.post("/api/v1/secure/jobs",json=envelope.model_dump()); st.session_state.attack={"type":"ciphertext tamper","status":"rejected","reason":response.json().get("detail")}; st.rerun()
if actions[3].button("Simulate replay", disabled=not online, use_container_width=True):
    temp=HostClient(api(),DEFAULT_SETTINGS,load_key_material()); temp.connect(); envelope=temp.jobs().build_request("sha256","sample.txt"); temp.transport.post("/api/v1/secure/jobs",json=envelope.model_dump()); response=temp.transport.post("/api/v1/secure/jobs",json=envelope.model_dump()); st.session_state.attack={"type":"message replay","status":"rejected","reason":response.json().get("detail")}; st.rerun()
if actions[4].button("Refresh evidence", use_container_width=True): st.rerun()

left, right = st.columns([1,1])
with left:
    st.subheader("Handshake trace")
    trace = st.session_state.get("trace", ["Awaiting handshake"])
    fingerprint = host.session.key_fingerprint if authenticated else "—"
    for index, step in enumerate(trace,1): st.success(f"{index}. {step}")
    st.caption(f"Session-key fingerprint: {fingerprint} (truncated; key never transmitted)")
with right:
    st.subheader("Secure near-data job")
    latest = st.session_state.get("latest_job")
    if latest:
        st.success("Verified encrypted result")
        st.json({"file": latest["path"], "task": latest["operation"], "source_bytes": latest["source_bytes"], "returned_bytes": latest["returned_bytes"], "bytes_avoided": latest["source_bytes"]-latest["returned_bytes"], "result": latest["result"]})
    else: st.info("Run a SHA-256 job after authentication.")

st.subheader("Security events")
events = metrics.get("security_events", [])
if st.session_state.get("attack"): events = events + [{"timestamp_utc":"current run", "event_type":st.session_state.attack["type"], "reason_code":st.session_state.attack["reason"], "status":"rejected", "subject":""}]
st.dataframe(pd.DataFrame(events[-10:]), use_container_width=True, hide_index=True)

st.subheader("Measured performance evidence")
chart_cols = st.columns(2)
handshake_path, concurrency_path = PROJECT_ROOT/"results"/"handshake_latency.csv", PROJECT_ROOT/"results"/"concurrency_results.csv"
if handshake_path.exists():
    frame=pd.read_csv(handshake_path); chart_cols[0].plotly_chart(px.histogram(frame,x="latency_ms",title="Handshake latency (ms)"),use_container_width=True)
if concurrency_path.exists():
    frame=pd.read_csv(concurrency_path); chart_cols[1].plotly_chart(px.line(frame,x="clients",y=["throughput_rps","p95_latency_ms"],markers=True,title="Concurrency evidence"),use_container_width=True)
summary_path = PROJECT_ROOT/"results"/"validation_summary.json"
if summary_path.exists():
    summary=json.loads(summary_path.read_text(encoding="utf-8")); st.caption(f"Measured run {summary['run_id']} · {summary['validation']['passed']}/{summary['validation']['total']} validation tests passed · targets are reported separately")

