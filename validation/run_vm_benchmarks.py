"""Run on Host; all dataset reads and crypto measurements run on an external CSD."""
import argparse
import csv
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psutil

from host_app.client import HostClient


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def charts(folder, rows, memory, label):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import statistics

    fig, ax = plt.subplots(figsize=(9, 4))
    for key, name in [("real_seconds", "Real Time"), ("user_seconds", "User Time"), ("system_seconds", "System Time")]:
        ax.plot(range(1, len(rows)+1), [r[key] for r in rows], label=name)
    ax.set(xlabel="Measurement number (Text, Image, Audio repeated)", ylabel="Seconds",
           title=f"FIG.4 Processor time at virtual storage — {label}")
    ax.legend(); fig.tight_layout(); fig.savefig(folder / "fig4_processor_time.png"); plt.close(fig)
    fig, ax = plt.subplots(figsize=(9, 4))
    names = ["AES-256-GCM", "HMAC-SHA-256", "SHA-256"]
    ax.barh(names, [statistics.mean(r["rss_mib"] for r in memory if r["algorithm"] == n) for n in names], color="black")
    ax.invert_yaxis()
    ax.set(xlabel="Mean whole CSD process RSS (MiB); not isolated algorithm allocation",
           title=f"FIG.5 Memory usage — {label}")
    fig.tight_layout(); fig.savefig(folder / "fig5_memory.png"); plt.close(fig)
    for number, field, title in [(6, "encryption_ms", "Encryption"), (7, "decryption_ms", "Decryption")]:
        fig, ax = plt.subplots(figsize=(8, 4))
        names = ["Text", "Image", "Audio"]
        ax.bar(names, [statistics.mean(r[field] for r in rows if r["media"] == n) for n in names], color="black")
        ax.set(ylabel="Mean time (ms)", title=f"FIG.{number} {title} Time — AES-256-GCM — {label}")
        fig.tight_layout(); fig.savefig(folder / f"fig{number}_{field}.png"); plt.close(fig)


def run(base_url, output, repetitions=19, warmups=3, label="two-laptop"):
    if repetitions < 1 or warmups < 0:
        raise ValueError("repetitions must be positive and warmups nonnegative")
    output.mkdir(parents=True, exist_ok=False)
    rows, memory = [], []
    metadata = {"started_utc": datetime.now(timezone.utc).isoformat(), "deployment_label": label,
                "transport": "real HTTP TCP", "base_url": base_url,
                "host_node": platform.node(), "host_os": platform.platform(),
                "host_ram_bytes": psutil.virtual_memory().total,
                "repetitions_per_media": repetitions, "warmups_per_media": warmups,
                "status": "running", "acceptance_targets": None,
                "limitations": "RSS is whole-process sampled memory, not peak or algorithm-only allocation. CPU deltas are process-wide; run one worker without other clients. PDF units unspecified; seconds and MiB chosen explicitly. No legacy algorithm comparison. The deployment label is operator-declared and is not independent attestation of the hardware or network topology."}
    meta_path = output / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    try:
        with httpx.Client(base_url=base_url, timeout=60) as transport:
            health_response = transport.get("/health")
            health_response.raise_for_status()
            metadata["csd_health"] = health_response.json()
            host = HostClient(transport)
            start = time.perf_counter()
            host.connect()
            metadata["handshake_ms"] = (time.perf_counter()-start)*1000
            try:
                for iteration in range(-warmups, repetitions):
                    for media, filename in [("Text", "sample.txt"), ("Image", "sample.png"), ("Audio", "sample.wav")]:
                        start = time.perf_counter()
                        result = host.jobs().submit("benchmark_crypto", filename)
                        rtt_ms = (time.perf_counter()-start)*1000
                        if not result.success:
                            raise RuntimeError(result.error_code)
                        data = result.result
                        if iteration < 0:
                            continue
                        row = {"iteration": iteration+1, "media": media, "path": filename,
                               "source_bytes": result.source_bytes, "result_payload_bytes": result.returned_bytes,
                               "host_roundtrip_ms": rtt_ms,
                               **{k: v for k, v in data.items() if k != "algorithms"}}
                        rows.append(row)
                        for m in data["algorithms"]:
                            memory.append({"iteration": iteration+1, "media": media, **m})
                        write_csv(output / "measurements.csv", rows)
                        write_csv(output / "algorithm_memory.csv", memory)
            finally:
                host.close()
            metrics_response = transport.get("/metrics/snapshot")
            metrics_response.raise_for_status()
            snapshot = metrics_response.json()
            metadata["csd_process_snapshot_after"] = {
                key: snapshot[key]
                for key in ("cpu_pct", "rss_mb", "state", "profile", "algorithms")
                if key in snapshot
            }
        charts(output, rows, memory, label)
        metadata["status"] = "complete"
    except Exception as exc:
        metadata["status"] = "failed"
        metadata["error"] = str(exc)
        raise
    finally:
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", required=True)
    p.add_argument("--output", type=Path, required=True, help="New directory; existing evidence is never overwritten")
    p.add_argument("--repetitions", type=int, default=19)
    p.add_argument("--warmups", type=int, default=3)
    p.add_argument("--label", choices=["two-laptop", "two-vm", "loopback-smoke"], default="two-laptop")
    args = p.parse_args()
    run(args.base_url, args.output, args.repetitions, args.warmups, args.label)


if __name__ == "__main__":
    main()
