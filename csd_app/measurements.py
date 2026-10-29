"""Bounded, authenticated near-data measurements. No source/key material returned."""
import hashlib
import os
import platform
import time
from pathlib import Path

import psutil

from shared.crypto import aes_gcm_encrypt, aes_gcm_decrypt, hmac_sha256
from csd_app.data_store import DataStoreError


def measure_file(path: Path) -> dict:
    # Keep this job bounded; this is an experiment, not an unbounded load endpoint.
    if path.stat().st_size > 16 * 1024 * 1024:
        raise DataStoreError("BENCHMARK_FILE_TOO_LARGE")
    data = path.read_bytes()
    key = os.urandom(32)
    process = psutil.Process()
    before = process.cpu_times()
    start = time.perf_counter()
    rows = []
    for algorithm in ("AES-256-GCM", "HMAC-SHA-256", "SHA-256"):
        rss_before = process.memory_info().rss
        t = time.perf_counter_ns()
        if algorithm == "AES-256-GCM":
            nonce, output = aes_gcm_encrypt(key, data, b"SCK benchmark")
        elif algorithm == "HMAC-SHA-256":
            output = hmac_sha256(key, data)
        else:
            output = hashlib.sha256(data).digest()
        elapsed = (time.perf_counter_ns() - t) / 1e6
        rows.append({"algorithm": algorithm, "operation_ms": elapsed,
                     "rss_mib": process.memory_info().rss / 2**20,
                     "rss_before_mib": rss_before / 2**20,
                     "output_bytes": len(output)})
        if algorithm == "AES-256-GCM":
            t = time.perf_counter_ns()
            restored = aes_gcm_decrypt(key, nonce, output, b"SCK benchmark")
            decryption_ms = (time.perf_counter_ns() - t) / 1e6
            if restored != data:
                raise RuntimeError("benchmark roundtrip failed")
            del restored
        del output
    after = process.cpu_times()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "encryption_ms": rows[0]["operation_ms"], "decryption_ms": decryption_ms,
            "real_seconds": time.perf_counter() - start,
            "user_seconds": after.user - before.user,
            "system_seconds": after.system - before.system,
            "algorithms": rows, "csd_node": platform.node(), "csd_os": platform.platform(),
            "csd_pid": os.getpid(), "csd_ram_bytes": psutil.virtual_memory().total,
            "csd_disk_total_bytes": psutil.disk_usage(str(path.parent)).total}
