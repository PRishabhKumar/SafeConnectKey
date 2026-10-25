# SafeConnectKey Validation Report

Generated from executed local tests and raw records for run `20261025T164515Z-a718bdf7`.

## Measured results

Environment. The prototype ran on Intel64 Family 6 Model 154 Stepping 4, GenuineIntel, 15.73 GB RAM and Windows-11-10.0.26300-SP0 using Python 3.13.13. The CSD executed as a local in-process FastAPI test harness.

Correctness and security. 18/18 required tests passed. The V01-V18 evidence is stored in `results/functional_security_results.csv` and `evidence/validation-junit.xml`.

Performance. Across 600 measured handshakes after 20 warm-ups per round, median latency was 50.4439 ms and p95 latency was 59.493845 ms. Peak measured process resident memory was 81.141 MiB. Raw operation records are stored under `results/raw/`.

Payload processing. Measured medians: 4096 B decrypt=0.028 ms, 4096 B encrypt=0.0398 ms, 524288 B decrypt=0.5281 ms, 524288 B encrypt=0.5722 ms, 5242880 B decrypt=11.4646 ms, 5242880 B encrypt=11.4995 ms. Near-data jobs completed 1500/1500 times and avoided 1733643600 bytes of source-data transfer.

## Acceptance targets (not measurements)

| Criterion | Target | Measured | Outcome |
|---|---:|---:|---|
| V01-V18 pass rate | 100% | 100.0% | PASS |
| Handshake p95 | < 100 ms | 59.493845 ms | PASS |
| 10-client error rate | < 1% | 0.0% | PASS |
| Peak RSS | < 256 MiB | 81.141 MiB* | PASS |

*RSS is the combined in-process validation harness measurement, not isolated CSD RSS.

## Limitations

- Resource measurements include the Host and test harness; use the normal-process launcher plus an external sampler for CSD-only RSS.
- This is a functional software emulator, not physical CSD hardware.
- The narrated OBS video must be recorded manually because microphone narration and visual privacy review require the operator.
- Benchmark mode was `full`. Only `--full` uses three rounds and every iteration/duration specified in the plan.
