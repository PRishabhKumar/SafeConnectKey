from __future__ import annotations

import json
import os
from pathlib import Path

from shared.config import PROJECT_ROOT

os.environ.setdefault("MPLCONFIGDIR", str(PROJECT_ROOT / "tmp" / "matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from validation.run_benchmarks import percentile


TARGETS = {
    "validation_pass_rate_pct": 100.0,
    "handshake_p95_ms_max": 100.0,
    "ten_client_error_rate_pct_max": 1.0,
    "direct_process_peak_rss_mb_max": 256.0,
}


def save_figure(path: Path) -> None:
    plt.tight_layout()
    plt.savefig(path, dpi=160, bbox_inches="tight")
    plt.close()


def main() -> None:
    results, charts, reports = PROJECT_ROOT / "results", PROJECT_ROOT / "results" / "charts", PROJECT_ROOT / "results" / "reports"
    charts.mkdir(parents=True, exist_ok=True); reports.mkdir(parents=True, exist_ok=True)
    validation = pd.read_csv(results / "functional_security_results.csv")
    handshake = pd.read_csv(results / "handshake_latency.csv")
    crypto = pd.read_csv(results / "payload_crypto_results.csv")
    resources = pd.read_csv(results / "resource_usage.csv")
    concurrency = pd.read_csv(results / "concurrency_results.csv")
    jobs = pd.read_csv(results / "near_data_jobs.csv")
    metadata = json.loads((results / "benchmark_metadata.json").read_text(encoding="utf-8"))
    successful_handshakes = handshake.loc[handshake.success.astype(str).str.lower() == "true", "latency_ms"].astype(float).tolist()
    ten = concurrency.loc[concurrency.clients == 10].iloc[-1]
    summary = {
        "run_id": metadata["run_id"],
        "measurement_mode": metadata["mode"],
        "environment": metadata["environment"],
        "validation": {"passed": int((validation.status == "PASS").sum()), "total": int(len(validation)), "pass_rate_pct": round((validation.status == "PASS").mean() * 100, 3)},
        "handshake": {
            "count": len(successful_handshakes), "failures": int(len(handshake) - len(successful_handshakes)),
            "median_ms": round(percentile(successful_handshakes, 50), 6), "p95_ms": round(percentile(successful_handshakes, 95), 6),
            "p99_ms": round(percentile(successful_handshakes, 99), 6), "minimum_ms": round(min(successful_handshakes), 6), "maximum_ms": round(max(successful_handshakes), 6),
        },
        "resource": {"peak_cpu_pct": round(float(resources.cpu_pct.max()), 3), "peak_rss_mb": round(float(resources.rss_mb.max()), 3)},
        "concurrency_10": {"throughput_rps": round(float(ten.throughput_rps), 3), "p95_latency_ms": round(float(ten.p95_latency_ms), 3), "error_rate_pct": round(float(ten.error_rate_pct), 3)},
        "near_data": {"jobs": int(len(jobs)), "successful": int(jobs.success.astype(str).str.lower().eq("true").sum()), "bytes_avoided": int(jobs.bytes_avoided.sum())},
        "targets": TARGETS,
        "limitations": ["Resource measurements include the Host and in-process FastAPI test harness, so they are not direct-process CSD-only measurements.", "No physical computational-storage hardware or resource-limited container was used.", "The narrated OBS video requires manual screen and microphone capture."],
    }
    crypto_summary = []
    for (size, operation), group in crypto.groupby(["payload_bytes", "operation"]):
        values = group.latency_ms.astype(float).tolist()
        crypto_summary.append({"payload_bytes": int(size), "operation": operation, "count": len(values), "median_ms": round(percentile(values,50),6), "p95_ms": round(percentile(values,95),6), "median_mbps": round(float(group.throughput_mbps.median()),3)})
    summary["payload_crypto"] = crypto_summary
    (results / "validation_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    plt.figure(figsize=(8,4.5)); plt.hist(successful_handshakes, bins=min(30,max(5,len(successful_handshakes)//10)), color="#2563eb", edgecolor="white"); plt.axvline(summary["handshake"]["p95_ms"], color="#ef4444", linestyle="--", label=f"p95 {summary['handshake']['p95_ms']:.2f} ms"); plt.title("Measured handshake latency distribution"); plt.xlabel("Latency (ms)"); plt.ylabel("Count"); plt.legend(); save_figure(charts / "handshake_latency.png")
    pivot = crypto.groupby(["payload_bytes","operation"]).latency_ms.median().unstack()
    ax = pivot.plot(kind="bar", figsize=(8,4.5), color=["#10b981","#2563eb"]); ax.set_title("Measured AES-256-GCM time by exact payload size"); ax.set_xlabel("Payload bytes"); ax.set_ylabel("Median time (ms)"); ax.legend(title="Operation"); save_figure(charts / "payload_crypto.png")
    fig, axes = plt.subplots(2,1,figsize=(8,5),sharex=True); elapsed=resources.elapsed_s-resources.elapsed_s.min(); axes[0].plot(elapsed,resources.cpu_pct,color="#f59e0b"); axes[0].set_ylabel("CPU (%)"); axes[1].plot(elapsed,resources.rss_mb,color="#7c3aed"); axes[1].set_ylabel("RSS (MiB)"); axes[1].set_xlabel("Elapsed (s)"); fig.suptitle("Measured process resources (Host + in-process CSD)"); save_figure(charts / "resource_usage.png")
    fig, axis = plt.subplots(figsize=(8,4.5)); axis.plot(concurrency.clients,concurrency.throughput_rps,marker="o",color="#10b981"); axis.set_xlabel("Concurrent clients"); axis.set_ylabel("Throughput (requests/s)",color="#10b981"); second=axis.twinx(); second.plot(concurrency.clients,concurrency.p95_latency_ms,marker="s",color="#ef4444"); second.set_ylabel("p95 latency (ms)",color="#ef4444"); axis.set_title("Measured concurrency performance"); save_figure(charts / "concurrency.png")
    counts=validation.status.value_counts().reindex(["PASS","FAIL"],fill_value=0); plt.figure(figsize=(6,4)); plt.bar(counts.index,counts.values,color=["#10b981","#ef4444"]); plt.title("V01-V18 validation outcomes"); plt.ylabel("Test count"); [plt.text(i,v+0.1,str(v),ha="center") for i,v in enumerate(counts.values)]; save_figure(charts / "security_summary.png")

    env = summary["environment"]
    payload_text = ", ".join(f"{row['payload_bytes']} B {row['operation']}={row['median_ms']} ms" for row in crypto_summary)
    report = f"""# SafeConnectKey Validation Report

Generated from executed local tests and raw records for run `{summary['run_id']}`.

## Measured results

Environment. The prototype ran on {env['cpu']}, {env['ram_gb']} GB RAM and {env['windows_build']} using Python {env['python_version']}. The CSD executed as a local in-process FastAPI test harness.

Correctness and security. {summary['validation']['passed']}/{summary['validation']['total']} required tests passed. The V01-V18 evidence is stored in `results/functional_security_results.csv` and `evidence/validation-junit.xml`.

Performance. Across {summary['handshake']['count']} measured handshakes after {metadata['handshake_warmups_per_round']} warm-ups per round, median latency was {summary['handshake']['median_ms']} ms and p95 latency was {summary['handshake']['p95_ms']} ms. Peak measured process resident memory was {summary['resource']['peak_rss_mb']} MiB. Raw operation records are stored under `results/raw/`.

Payload processing. Measured medians: {payload_text}. Near-data jobs completed {summary['near_data']['successful']}/{summary['near_data']['jobs']} times and avoided {summary['near_data']['bytes_avoided']} bytes of source-data transfer.

## Acceptance targets (not measurements)

| Criterion | Target | Measured | Outcome |
|---|---:|---:|---|
| V01-V18 pass rate | 100% | {summary['validation']['pass_rate_pct']}% | {'PASS' if summary['validation']['pass_rate_pct'] == 100 else 'FAIL'} |
| Handshake p95 | < 100 ms | {summary['handshake']['p95_ms']} ms | {'PASS' if summary['handshake']['p95_ms'] < 100 else 'FAIL'} |
| 10-client error rate | < 1% | {summary['concurrency_10']['error_rate_pct']}% | {'PASS' if summary['concurrency_10']['error_rate_pct'] < 1 else 'FAIL'} |
| Peak RSS | < 256 MiB | {summary['resource']['peak_rss_mb']} MiB* | {'PASS' if summary['resource']['peak_rss_mb'] < 256 else 'FAIL'} |

*RSS is the combined in-process validation harness measurement, not isolated CSD RSS.

## Limitations

- Resource measurements include the Host and test harness; use the normal-process launcher plus an external sampler for CSD-only RSS.
- This is a functional software emulator, not physical CSD hardware.
- The narrated OBS video must be recorded manually because microphone narration and visual privacy review require the operator.
- Benchmark mode was `{metadata['mode']}`. Only `--full` uses three rounds and every iteration/duration specified in the plan.
"""
    (reports / "validation_report.md").write_text(report, encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

