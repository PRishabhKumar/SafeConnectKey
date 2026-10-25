from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import psutil
from fastapi.testclient import TestClient

from csd_app.main import create_app
from host_app.client import HostClient
from shared.config import DEFAULT_SETTINGS, PROJECT_ROOT
from shared.crypto import aes_gcm_decrypt, aes_gcm_encrypt
from shared.keys import load_key_material


RAW_FIELDS = [
    "run_id", "test_id", "timestamp_utc", "profile", "host_id", "csd_id",
    "payload_type", "payload_bytes", "operation", "iteration", "success",
    "latency_ms", "cpu_pct", "rss_mb", "error_code", "git_commit",
    "python_version", "os_build",
]


def now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * percent / 100
    lower, upper = int(index), min(int(index) + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


class RawSink:
    def __init__(self, path: Path, common: dict[str, object]) -> None:
        self.handle = path.open("w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.handle, fieldnames=RAW_FIELDS)
        self.writer.writeheader()
        self.common = common
        self.lock = threading.Lock()

    def write(self, **values: object) -> None:
        row = dict(self.common)
        row.update({"timestamp_utc": now_text(), "payload_type": "", "payload_bytes": 0, "cpu_pct": "", "rss_mb": "", "error_code": ""})
        row.update(values)
        with self.lock:
            self.writer.writerow(row)
            self.handle.flush()

    def close(self) -> None:
        self.handle.close()


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True, capture_output=True, check=True).stdout.strip()
    except Exception:
        return "not-a-git-checkout"


def environment() -> dict[str, object]:
    return {
        "device_model": "Windows laptop (hostname withheld)",
        "cpu": platform.processor() or os.getenv("PROCESSOR_IDENTIFIER", "unavailable"),
        "ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "windows_build": platform.platform(),
        "python_version": platform.python_version(),
        "execution_profile": "local in-process FastAPI TestClient",
        "power_mode": "not captured automatically",
        "dependency_lock_hash": hashlib.sha256((PROJECT_ROOT / "requirements.txt").read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SafeConnectKey measured benchmarks")
    parser.add_argument("--full", action="store_true", help="use the implementation-plan iteration counts and three rounds")
    args = parser.parse_args()
    full = args.full
    rounds = 3 if full else 1
    warmups, measured = (20, 200) if full else (3, 20)
    crypto_iterations = {4096: 200, 524288: 100, 5242880: 30} if full else {4096: 20, 524288: 10, 5242880: 5}
    job_iterations = 100 if full else 5
    concurrency_seconds = 60.0 if full else 2.0
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    results, raw_dir = PROJECT_ROOT / "results", PROJECT_ROOT / "results" / "raw"
    results.mkdir(exist_ok=True); raw_dir.mkdir(exist_ok=True)
    env = environment()
    (PROJECT_ROOT / "evidence" / "environment.txt").write_text("\n".join(f"{k}: {v}" for k, v in env.items()) + "\n", encoding="utf-8")
    installed = subprocess.run([sys.executable, "-m", "pip", "freeze"], text=True, capture_output=True, check=True).stdout
    (PROJECT_ROOT / "evidence" / "dependency_versions.txt").write_text(installed, encoding="utf-8")
    common = {
        "run_id": run_id, "profile": "recommended", "host_id": DEFAULT_SETTINGS.host_id,
        "csd_id": DEFAULT_SETTINGS.csd_id, "git_commit": git_commit(),
        "python_version": platform.python_version(), "os_build": platform.platform(),
    }
    sink = RawSink(raw_dir / f"benchmark_records_{run_id}.csv", common)
    keys = load_key_material()
    app = create_app(DEFAULT_SETTINGS, keys)
    process = psutil.Process(os.getpid())
    handshake_rows: list[dict[str, object]] = []
    crypto_rows: list[dict[str, object]] = []
    job_rows: list[dict[str, object]] = []
    resource_rows: list[dict[str, object]] = []
    concurrency_rows: list[dict[str, object]] = []
    with TestClient(app) as transport:
        for round_index in range(1, rounds + 1):
            for _ in range(warmups):
                client = HostClient(transport, DEFAULT_SETTINGS, keys); client.connect(); client.close()
            for iteration in range(1, measured + 1):
                started = time.perf_counter_ns(); success = True; error = ""
                try:
                    client = HostClient(transport, DEFAULT_SETTINGS, keys); client.connect(); client.close()
                except Exception as exc:
                    success, error = False, type(exc).__name__
                latency = (time.perf_counter_ns() - started) / 1_000_000
                row = {"round": round_index, "iteration": iteration, "latency_ms": latency, "success": success}
                handshake_rows.append(row)
                sink.write(test_id="BENCH-HANDSHAKE", operation="handshake", iteration=f"r{round_index}-{iteration}", success=success, latency_ms=f"{latency:.6f}", error_code=error)
            for size, count in crypto_iterations.items():
                payload = bytes((index * 31 + size) % 256 for index in range(size))
                key, aad = bytes(range(32)), f"benchmark:{size}".encode()
                for iteration in range(1, count + 1):
                    started = time.perf_counter_ns(); nonce, ciphertext = aes_gcm_encrypt(key, payload, aad); enc_ms = (time.perf_counter_ns() - started) / 1_000_000
                    started = time.perf_counter_ns(); recovered = aes_gcm_decrypt(key, nonce, ciphertext, aad); dec_ms = (time.perf_counter_ns() - started) / 1_000_000
                    if recovered != payload: raise RuntimeError("crypto benchmark round trip failed")
                    for operation, latency in (("encrypt", enc_ms), ("decrypt", dec_ms)):
                        throughput = size / (1024 * 1024) / (latency / 1000) if latency else 0
                        crypto_rows.append({"round": round_index, "payload_bytes": size, "operation": operation, "iteration": iteration, "latency_ms": latency, "throughput_mbps": throughput})
                        sink.write(test_id="BENCH-CRYPTO", payload_type={4096:"text",524288:"image",5242880:"audio"}[size], payload_bytes=size, operation=operation, iteration=f"r{round_index}-{iteration}", success=True, latency_ms=f"{latency:.6f}")
            host = connected_host = HostClient(transport, DEFAULT_SETTINGS, keys); connected_host.connect()
            for operation, path in (("sha256","sample.txt"),("word_count","sample.txt"),("image_metadata","sample.png"),("audio_metadata","sample.wav"),("compression","sample.txt")):
                for iteration in range(1, job_iterations + 1):
                    started = time.perf_counter_ns(); result = connected_host.jobs().submit(operation, path); latency = (time.perf_counter_ns() - started) / 1_000_000
                    avoided = max(0, result.source_bytes - result.returned_bytes)
                    job_rows.append({"round": round_index, "operation": operation, "path": path, "iteration": iteration, "success": result.success, "latency_ms": latency, "source_bytes": result.source_bytes, "returned_bytes": result.returned_bytes, "bytes_avoided": avoided})
                    sink.write(test_id="BENCH-JOB", payload_type=path.rsplit(".",-1)[-1], payload_bytes=result.source_bytes, operation=operation, iteration=f"r{round_index}-{iteration}", success=result.success, latency_ms=f"{latency:.6f}", error_code=result.error_code)
            connected_host.close()
        process.cpu_percent(None)
        for workload in ("idle", "handshake", "job"):
            for sample in range(10 if full else 3):
                if workload == "handshake":
                    temp = HostClient(transport, DEFAULT_SETTINGS, keys); temp.connect(); temp.close()
                elif workload == "job":
                    temp = HostClient(transport, DEFAULT_SETTINGS, keys); temp.connect(); temp.jobs().submit("sha256", "sample.txt"); temp.close()
                if full: time.sleep(0.1)
                cpu, rss = process.cpu_percent(None), process.memory_info().rss / (1024*1024)
                timestamp = time.perf_counter()
                resource_rows.append({"workload": workload, "sample": sample + 1, "elapsed_s": timestamp, "cpu_pct": cpu, "rss_mb": rss})
                sink.write(test_id="BENCH-RESOURCE", operation=workload, iteration=sample+1, success=True, latency_ms="", cpu_pct=f"{cpu:.3f}", rss_mb=f"{rss:.3f}")
        for clients in (1, 5, 10, 25):
            deadline = time.perf_counter() + concurrency_seconds
            def worker(worker_id: int) -> tuple[int, list[float], int]:
                count, errors, latencies = 0, 0, []
                while time.perf_counter() < deadline:
                    started = time.perf_counter_ns()
                    try:
                        client = HostClient(transport, DEFAULT_SETTINGS, keys); client.connect(); client.jobs().submit("sha256", "sample.txt"); client.close(); count += 1
                    except Exception:
                        errors += 1
                    latencies.append((time.perf_counter_ns() - started) / 1_000_000)
                return count, latencies, errors
            process.cpu_percent(None); started_level = time.perf_counter()
            with ThreadPoolExecutor(max_workers=clients) as pool:
                outcomes = list(pool.map(worker, range(clients)))
            duration = time.perf_counter() - started_level
            all_latencies = [item for _, values, _ in outcomes for item in values]
            completed_count, errors = sum(item[0] for item in outcomes), sum(item[2] for item in outcomes)
            total = completed_count + errors
            row = {"clients": clients, "duration_s": duration, "requests": completed_count, "throughput_rps": completed_count/duration, "p95_latency_ms": percentile(all_latencies,95), "errors": errors, "error_rate_pct": errors/total*100 if total else 0, "peak_cpu_pct": process.cpu_percent(None), "peak_rss_mb": process.memory_info().rss/(1024*1024)}
            concurrency_rows.append(row)
            sink.write(test_id="BENCH-CONCURRENCY", operation=f"clients_{clients}", iteration=1, success=errors==0, latency_ms=f"{row['p95_latency_ms']:.6f}", cpu_pct=f"{row['peak_cpu_pct']:.3f}", rss_mb=f"{row['peak_rss_mb']:.3f}", error_code="" if errors==0 else f"{errors}_ERRORS")
    sink.close()
    def write_csv(name: str, rows: list[dict[str, object]]) -> None:
        if not rows: return
        with (results / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    write_csv("handshake_latency.csv", handshake_rows)
    write_csv("payload_crypto_results.csv", crypto_rows)
    write_csv("near_data_jobs.csv", job_rows)
    write_csv("resource_usage.csv", resource_rows)
    write_csv("concurrency_results.csv", concurrency_rows)
    metadata = {"run_id": run_id, "mode": "full" if full else "quick", "rounds": rounds, "handshake_warmups_per_round": warmups, "handshakes_per_round": measured, "crypto_iterations_per_round": crypto_iterations, "job_iterations_per_round": job_iterations, "concurrency_seconds_per_level": concurrency_seconds, "environment": env}
    (results / "benchmark_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
