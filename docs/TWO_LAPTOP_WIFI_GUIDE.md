# Two-laptop Wi-Fi experiment: complete runbook

This runbook uses two physical laptops on the same trusted private Wi-Fi network:

- **Host laptop**: runs the Host client, dashboard, and benchmark controller. It stores the benchmark CSV files, charts, and metadata.
- **CSD laptop**: runs the FastAPI CSD emulator and holds the data used by the remote jobs. It stores the CSD audit log.

The laptops communicate over real TCP/HTTP. This is a two-device software-CSD experiment, not physical computational-storage hardware. ICMP ping is a useful first check, but a successful `/health` request is the actual application-readiness test.

## 1. Before the experiment

On both laptops:

1. Connect to the same trusted Wi-Fi SSID. Do not use guest Wi-Fi; many guest networks enable client isolation.
2. Disconnect VPNs that change routing between local devices.
3. Set the Windows network profile to **Private**.
4. Ensure Windows time synchronization is enabled. The protocol permits only five seconds of clock skew.
5. Install Git and Python 3.12 or newer.
6. Clone the same commit of this repository.

Run in PowerShell from the repository on each laptop:

```powershell
git rev-parse HEAD
python --version
Get-Date
```

The commit hashes must match. The clocks should be within a few seconds. If required, run `w32tm /resync` from an Administrator PowerShell.

Create the environment independently on both laptops:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Optional but recommended before the real run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## 2. Find and verify the LAN addresses

On each laptop, find the Wi-Fi IPv4 address:

```powershell
Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi" | Where-Object { $_.IPAddress -notlike "169.254.*" } | Select-Object IPAddress
```

Record these values:

```text
HOST_IP = address of the Host laptop
CSD_IP  = address of the CSD laptop
PORT    = 8001
```

In the commands below, replace `<HOST_IP>` and `<CSD_IP>` with those numeric addresses and do not type the angle brackets.

From Host, test CSD:

```powershell
ping <CSD_IP>
```

From CSD, test Host:

```powershell
ping <HOST_IP>
```

A failed ping can mean that Windows blocks ICMP even when TCP works. Continue to the TCP and application checks after starting the CSD. If neither direction works, check that both addresses are in the same subnet, both network profiles are Private, the Wi-Fi access point does not use AP/client isolation, and no VPN is active.

## 3. Provision the shared demo keys

Generate keys **once, on the CSD laptop only**:

```powershell
.\.venv\Scripts\python.exe -m scripts.generate_demo_keys
```

This creates the ignored `.env` file. Copy that exact file to the repository root on the Host laptop using a trusted method such as an encrypted USB drive, an authenticated local SSH/SCP connection, or an approved encrypted file-transfer channel. Do not generate a second `.env`, commit it, paste it into chat/email, or put it in cloud storage.

On both laptops, verify that the files are identical without printing their contents:

```powershell
Get-FileHash .env -Algorithm SHA256
```

The two hashes must match. `.env` is already excluded by `.gitignore`.

## 4. Prepare and start the CSD laptop

Generate the deterministic experiment data on CSD:

```powershell
.\.venv\Scripts\python.exe -m scripts.generate_sample_data
```

Allow only the Host laptop to reach the CSD service. In an **Administrator PowerShell on CSD**, run:

```powershell
New-NetFirewallRule -DisplayName "SafeConnectKey CSD 8001" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8001 -RemoteAddress <HOST_IP> -Profile Private
```

Start one foreground CSD worker, binding only to the CSD Wi-Fi address:

```powershell
.\scripts\start_csd_lan.ps1 -BindAddress <CSD_IP> -Port 8001
```

Leave this PowerShell window running. The script deliberately does not start multiple workers because sessions and measurements are held in this process. The CSD audit file is written to `results\raw\security_events.jsonl` unless `SCK_RESULTS_ROOT` is set.

## 5. Verify from the Host laptop

First verify the TCP port:

```powershell
Test-NetConnection -ComputerName <CSD_IP> -Port 8001
```

`TcpTestSucceeded` must be `True`. Then perform the repository's protocol-aware readiness check:

```powershell
.\.venv\Scripts\python.exe -m host_app.client check --base-url http://<CSD_IP>:8001
```

The output must show `"reachable": true`, `"status": "ready"`, `"protocol": "SCK-1"`, and the expected `csd_id`. Finally run one authenticated handshake and encrypted job:

```powershell
.\.venv\Scripts\python.exe -m host_app.client demo --base-url http://<CSD_IP>:8001
```

The output must show `"session_authenticated": true` and a successful SHA-256 job. If readiness works but the handshake fails, the `.env` files differ, the IDs differ, or the clocks are too far apart.

## 6. Run the measured experiment on Host

Close the dashboard and other clients before measuring. Keep the laptops connected to power, use the same Wi-Fi location, and avoid downloads or other heavy network/CPU activity.

Run three independent benchmark rounds, always using a new output directory:

```powershell
.\.venv\Scripts\python.exe -m validation.run_lan_benchmarks --base-url http://<CSD_IP>:8001 --output results\laptop-run-001 --repetitions 19 --warmups 3 --label two-laptop
```

```powershell
.\.venv\Scripts\python.exe -m validation.run_lan_benchmarks --base-url http://<CSD_IP>:8001 --output results\laptop-run-002 --repetitions 19 --warmups 3 --label two-laptop
```

```powershell
.\.venv\Scripts\python.exe -m validation.run_lan_benchmarks --base-url http://<CSD_IP>:8001 --output results\laptop-run-003 --repetitions 19 --warmups 3 --label two-laptop
```

Each completed directory contains:

- `metadata.json`: device/OS context, external CSD health identity, handshake latency, run configuration, and completion state.
- `measurements.csv`: per-file CSD crypto timing plus Host-observed round-trip time.
- `algorithm_memory.csv`: sampled whole-CSD-process RSS observations.
- `fig4_processor_time.png` through `fig7_decryption_ms.png`: generated charts.

The source files are opened and measured by the CSD process. The Host sends an authenticated file name and receives only the encrypted result payload. A repository clone may contain deterministic sample fixtures, but the network benchmark does not read those Host-side copies.

## 7. Use the dashboard on Host

Do not run the dashboard during benchmark collection. After measuring, start it with:

```powershell
$env:SCK_VM_RESULTS = "results\laptop-run-001"
.\scripts\start_host_dashboard.ps1 -CsdAddress <CSD_IP> -CsdPort 8001
```

Open `http://127.0.0.1:8501` on the Host laptop. The launcher forces external mode and refuses to start the dashboard unless the remote CSD passes its health check.

## 8. Evidence to preserve

Save the following with the experiment results:

- `git rev-parse HEAD` from both laptops.
- The date/time, Wi-Fi SSID, `HOST_IP`, and `CSD_IP` (do not record Wi-Fi passwords).
- `python --version`, Windows version, CPU model, RAM, and power mode for both laptops.
- `Get-FileHash .env -Algorithm SHA256` from both laptops, but never the `.env` contents.
- The three Host `results\laptop-run-*` directories.
- The CSD `results\raw\security_events.jsonl` audit file.
- Screenshots of the successful readiness check and dashboard.

Do not claim that ping latency is protocol latency. `host_roundtrip_ms` is measured by the Host with a monotonic clock around the authenticated job request. CSD crypto timings are measured inside the remote CSD process. FIG.5 is whole-process RSS, not isolated per-algorithm allocation or peak memory.

## 9. Stop and clean up

Press `Ctrl+C` in the CSD and dashboard PowerShell windows. Remove the firewall exception from an Administrator PowerShell on CSD:

```powershell
Remove-NetFirewallRule -DisplayName "SafeConnectKey CSD 8001"
```

Keep `.env` out of Git. If the keys were exposed or the devices will no longer be used together, delete `.env` on both laptops and generate a fresh pair for the next experiment.

## Troubleshooting map

| Symptom | Most likely cause | Check |
|---|---|---|
| Ping fails both ways | Guest Wi-Fi/client isolation, VPN, wrong subnet, or ICMP blocked | Compare IP/subnet, disable VPN, then use `Test-NetConnection` |
| `TcpTestSucceeded` is false | CSD not running, wrong bind address/port, or firewall rule | CSD terminal, `CSD_IP`, port 8001, firewall remote address |
| `/health` works but handshake fails | Different `.env`, different IDs, or clock skew | Compare `.env` SHA-256 and `Get-Date` |
| `KEY_CONFIRMATION_FAILED` or authentication errors | Keys are not identical | Re-copy the CSD `.env`; do not regenerate on Host |
| Output directory already exists | Evidence overwrite protection | Use a new run number |
| Dashboard says CSD offline | Dashboard started in embedded mode or wrong URL | Use `start_host_dashboard.ps1` with the numeric CSD address |
| Connection stops after reconnecting Wi-Fi | DHCP changed a laptop address | Re-read both Wi-Fi IPv4 addresses and update the firewall/commands |
