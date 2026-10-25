# SafeConnectKey

SafeConnectKey is a local, reproducible software prototype of secure communication between a Host and a Computational Storage Drive (CSD). It preserves the invention's nonce/token/session flow while using a current primary profile:

- AES-256-GCM for authenticated encryption
- HMAC-SHA-256 for authentication tokens
- HKDF-SHA-256 for session-key derivation and key separation
- 256-bit OS-generated challenges, five-minute sessions, explicit mutual key confirmation, handshake replay caching, and strict per-direction message sequences

MD5 and AES-ECB are not implemented. Keys and protected plaintext are never logged.

## What is included

- Separate FastAPI CSD process and HTTP Host client
- Independent Host/CSD session-key derivation; only a 16-hex-character fingerprint is exposed
- Encrypted SHA-256, word-count, image-metadata, WAV-metadata, and compression jobs over allowlisted files in `csd_data`
- Streamlit dashboard with session status, handshake trace, job result, security events, and measured charts
- V01–V18 validation suite, attack runner, benchmarks, analysis, charts, evidence capture, and submission exporter
- PowerShell setup/start/reset/validation flow for Windows

## Clean Windows setup

From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m scripts.generate_demo_keys
python -m scripts.generate_sample_data
```

Python 3.12 or newer is supported. The executed evidence in this checkout used the exact version recorded in `evidence/environment.txt`. `.env` contains two independently generated 32-byte keys and is ignored by Git. Do not submit it.

## Start the CSD, dashboard, and Host

Start the two long-running processes:

```powershell
.\scripts\start_demo.ps1
```

Open `http://127.0.0.1:8501`, click **Run handshake**, then **Run SHA-256 job**. The dashboard's tamper and replay buttons create safe negative demonstrations without displaying keys or protected plaintext.

Run the command-line Host in another PowerShell window:

```powershell
.\.venv\Scripts\python.exe -m host_app.client demo
```

Stop only the processes recorded by the launcher:

```powershell
.\scripts\reset_demo.ps1
```

The service binds to `127.0.0.1`. Its routes are:

| Route | Purpose |
|---|---|
| `GET /health` | Local readiness and protocol profile |
| `POST /api/v1/handshake/init` | CSD nonce challenge and encrypted AuthTd |
| `POST /api/v1/handshake/complete` | Host nonce response and mutual confirmation |
| `POST /api/v1/secure/jobs` | Authenticated near-data job command/result |
| `GET /api/v1/secure/jobs/{id}` | Retrieve the stored encrypted result envelope |
| `DELETE /api/v1/secure/sessions/{id}` | Invalidate a session |
| `GET /metrics/snapshot` | Local-only safe metrics and audit events |

## Run validation and benchmarks

Fast correctness pass:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m validation.run_validation
.\.venv\Scripts\python.exe -m validation.run_benchmarks
.\.venv\Scripts\python.exe -m validation.analyze_results
```

Plan-conformant benchmark run (three rounds, 20 warm-ups plus 200 measured handshakes per round, documented crypto/job counts, and 60 seconds per concurrency level):

```powershell
.\scripts\run_validation.ps1 --full
```

The full run takes several minutes. `run_benchmarks` writes each raw record immediately to `results/raw/` before summary analysis. Run only the negative attack set with:

```powershell
.\.venv\Scripts\python.exe -m validation.run_attacks
```

## Evidence and measured results

Acceptance criteria are maintained separately in `validation/acceptance.yaml`; they are proposed targets, not measurements. Executed measurements are in:

- `results/functional_security_results.csv` — expected vs observed V01–V18 outcomes
- `results/handshake_latency.csv` — every measured handshake
- `results/payload_crypto_results.csv` — exact byte sizes, operations, time, and throughput
- `results/near_data_jobs.csv` — correctness, latency, and bytes avoided
- `results/resource_usage.csv` — CPU and RSS samples
- `results/concurrency_results.csv` — client count, throughput, p95, errors, CPU, and RSS
- `results/raw/benchmark_records_*.csv` — immutable-style raw operation records
- `results/validation_summary.json` and `results/reports/validation_report.md` — summaries with targets and limitations clearly separated
- `results/charts/*.png` — five required charts
- `evidence/` — JUnit, pytest output, environment, dependencies, and exact sample hashes

Generate the 1920×1080 evidence view and package the submission:

```powershell
.\.venv\Scripts\python.exe -m validation.render_dashboard_snapshot
.\.venv\Scripts\python.exe -m validation.export_results
```

The generated snapshot is a deterministic evidence rendering for packaging. For the final evaluator screenshot, use the live Streamlit page at 1920×1080 after running handshake, job, tamper, and replay actions.

## Protocol summary

The CSD signs a canonical, versioned challenge transcript with AuthK and encrypts it with EnK. The Host verifies identity, protocol, time window, ciphertext, and HMAC; generates nonce R; derives a master session key from both provisioned keys and nonces; and sends an encrypted confirmation. The CSD independently derives the same master and verifies it. HKDF creates distinct confirmation, Host→CSD, and CSD→Host subkeys.

Application AAD binds protocol, session ID, direction, message type, and monotonically increasing sequence. The AES-GCM nonce is a deterministic four-byte session/direction prefix plus the 64-bit sequence, preventing reuse under a directional session key. Validation occurs before job dispatch, so tampered, replayed, out-of-order, oversized, traversing, and unsupported commands cannot invoke arbitrary code.

## Sample data

`scripts.generate_sample_data` deterministically creates:

| File | Exact bytes | Job use |
|---|---:|---|
| `sample.txt` | 4,096 | SHA-256, words, compression |
| `sample.png` | 524,288 | image metadata |
| `sample.wav` | 5,242,880 | WAV metadata |

The current digests are recorded in `evidence/sample_hashes.json` and are checked before evidence is interpreted.

## Security and scope limitations

This is a functional local emulator, not physical NVMe/FPGA firmware and not a production key-management system. The default benchmark uses an in-process FastAPI test transport for repeatability; its RSS includes Host, CSD, and test harness and is labeled accordingly. Use the normal-process launcher and an external sampler for isolated CSD-only resource claims. No formal cryptographic certification is claimed.

The final narrated video cannot be generated safely without the operator's microphone and visual privacy review. Record the live dashboard with OBS at 1920×1080, 30 fps, MKV, following the 2–3 minute sequence in `Implementation plan.md`, then remux to `SafeConnectKey_Prototype_Demo.mp4`. Raw recordings are excluded from the source archive.

## Repository layout

`shared/` holds schemas, canonical encoding, keys, cryptography, protocol metadata, and safe audit events. `csd_app/` owns handshakes, sessions, the data store, and jobs. `host_app/` independently verifies/derives the session and sends encrypted jobs. `dashboard/` is the live UI. `validation/`, `tests/`, and `scripts/` produce the reproducible evidence.
