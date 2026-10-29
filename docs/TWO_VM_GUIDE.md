# Two-VM SafeConnectKey experiment

## Scope and diagram mapping

This is a software CSD emulator, not physical flash hardware or a hardware accelerator.
Host and CSD run separate processes on separate Ubuntu VMs, communicating over TCP.
Never use embedded Streamlit mode for this experiment. Data resides only on the CSD.

| FIG.3 block | Host implementation | CSD implementation |
|---|---|---|
| Key retriever | shared/keys.py, locally provisioned .env | same loader, independent .env |
| Nonce generator | shared.crypto.generate_nonce, R | same function, S |
| Token generator/verifier | HostHandshake, HMAC verification and confirmation | CSDService, HMAC challenge and confirmation |
| Session token generator | AES-256-GCM SessTh | AES-256-GCM SessTd |
| Communicator | HostClient/httpx | FastAPI/uvicorn |
| Session key generator | HKDF-SHA-256, independent derivation | HKDF-SHA-256, independent derivation |
| Session established | verifies CSD confirmation | verifies Host confirmation |

Keys are provisioned out of band; neither the master nor directional session keys are transmitted.
The existing handshake implements these functional blocks; they do not need separate VMs or services each.

## 1. Create the VMs on Windows

Install Oracle VirtualBox and download an Ubuntu Server 24.04 LTS amd64 ISO.
See [Ubuntu installation](https://ubuntu.com/tutorials/install-ubuntu-server) and
[VirtualBox networking](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/networkingdetails.html).
Use two NEW VMs, not two terminals in the same VM:

| Setting | SCK-Host | SCK-CSD |
|---|---|---|
| RAM | 2048 MB | 4096 MB |
| CPUs | 2 | 2 |
| Dynamically allocated VDI disk | 20 GB | 80 GB |
| OS | Ubuntu Server 24.04 | Ubuntu Server 24.04 |
| Adapter 1 | NAT (package installation) | NAT |
| Adapter 2 | same Host-only network | same Host-only network |

RAM and disk storage are different: the CSD gets more of both. These are suggested
experimental allocations, not acceptance targets. Leave enough RAM/disk for Windows;
do not allocate all physical RAM. Dynamically allocated disks grow as used.

In VirtualBox Tools/Network create a host-only network, enable its DHCP server,
and attach Adapter 2 of BOTH VMs to it. Avoid bridged mode/public exposure.
Boot each ISO, install Ubuntu Server, use unique hostnames sck-host and sck-csd,
enable OpenSSH, and reboot/eject ISO. During installation enable DHCP on both adapters.
If the second interface has no IP, configure DHCP for it in Ubuntu netplan; use
`ip -br address` to identify its name rather than assuming enp0s8.

On each VM inspect its host-only IP (usually 192.168.56.x, distinct from NAT 10.0.2.x):

```bash
ip -br address
```

Record HOST_IP, CSD_IP and usernames. Replace angle-bracket placeholders below;
do not type the brackets literally. DHCP addresses may change after reboot.

## 2. Package the current working code (Windows PowerShell)

This includes uncommitted code changes but excludes .env, Git history, data and results.
No GitHub push is needed. Run from the repository directory.

```powershell
.\.venv\Scripts\python.exe -m scripts.package_vms
```

```powershell
scp .\dist\vm\sck-host.zip <host-user>@<HOST_IP>:sck.zip
```

```powershell
scp .\dist\vm\sck-csd.zip <csd-user>@<CSD_IP>:sck.zip
```

## 3. Install on BOTH VMs

Each block is one command. Use Ubuntu terminals, not Windows PowerShell.

```bash
sudo apt update
```

```bash
sudo apt install -y python3-venv python3-pip unzip
```

```bash
unzip sck.zip -d SafeConnectKey
```

```bash
cd SafeConnectKey
```

```bash
python3 -m venv .venv
```

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## 4. Provision keys ONCE on CSD

```bash
.venv/bin/python -m scripts.generate_demo_keys
```

Copy that same .env to Host over SSH (do NOT independently generate another pair):

```bash
scp .env <host-user>@<HOST_IP>:SafeConnectKey/.env
```

Run on each VM:

```bash
chmod 600 .env
```

Never commit or share these keys. The Host bundle contains no csd_data directory.

## 5. Start CSD (CSD VM only)

```bash
.venv/bin/python -m scripts.generate_sample_data
```

```bash
.venv/bin/python -m uvicorn csd_app.main:app --host <CSD_IP> --port 8001 --workers 1
```

Leave this terminal running. Bind only the private host-only address. No public port
forwarding. If a firewall is active, allow TCP 8001 only from HOST_IP; keep SSH allowed.
`SCK_DATA_ROOT` can select a separately mounted CSD disk; set it before BOTH data generation
and server startup. `SCK_RESULTS_ROOT` selects the audit destination.

## 6. Run Host and measure (Host VM only)

```bash
cd ~/SafeConnectKey
```

```bash
.venv/bin/python -m host_app.client demo --base-url http://<CSD_IP>:8001
```

```bash
.venv/bin/python -m validation.run_vm_benchmarks --base-url http://<CSD_IP>:8001 --output results/vm-run-001 --repetitions 19 --warmups 3 --label two-vm
```

Use a fresh output name each run; existing evidence is never overwritten.
Run three independent runs for repeatability (vm-run-002 and vm-run-003).
Stop other clients/dashboard polling during measurement. Save VM allocation screenshots,
OS versions, network mode, and both IPs alongside results. Label does NOT automatically
prove that two VMs were used. Timing uses local monotonic clocks, not cross-machine subtraction.

## 7. Dashboard on Host

```bash
export SCK_CSD_MODE=external
```

```bash
export SCK_CSD_BASE_URL=http://<CSD_IP>:8001
```

```bash
export SCK_VM_RESULTS=results/vm-run-001
```

```bash
.venv/bin/python -m streamlit run streamlit_app.py --server.address <HOST_IP> --server.port 8501
```

Open http://HOST_IP:8501 from the Windows browser. This is private, not a public URL.
The existing Cloud embedded demo does not represent this experiment.

## Measurement definitions and PDF correspondence

- FIG.4: real/user/system **seconds** for each CSD benchmark invocation. This is processor
  time, not CPU percentage. OS CPU accounting resolution can produce zero for short jobs.
- FIG.5: horizontal bars by AES-256-GCM, HMAC-SHA-256, SHA-256. Values are mean sampled
  **whole CSD process RSS in MiB**, NOT isolated algorithm allocations or peak usage.
  Dataset buffer, interpreter, caching and sequential execution affect RSS. Do not conclude
  one algorithm uses more memory from these absolute RSS measurements alone.
- FIG.6/7: mean AES-256-GCM encryption/decryption **milliseconds**, Text/Image/Audio.
  Source file read is outside crypto timings; nonce generation is inside encryption timing.
  Decryption checks equality. Sample sizes: 4 KiB, 512 KiB, 5 MiB. Different file sizes
  confound media-type comparisons; these bars characterize these specific files only.
- HKDF-SHA-256 remains the handshake KDF. SHA-256 here replaces the PDF's Hash-MD5 bar;
  HMAC-SHA-256 replaces HMAC-MD5, and AES-256-GCM replaces AES-ECB. No legacy values copied.
- measurements.csv and algorithm_memory.csv retain each measured sample; metadata.json
  records configuration/status. PDF gives no explicit units for memory and processor axes,
  no repeat-count methodology and no acceptance thresholds: no targets are invented.
- Source stays on CSD. `result_payload_bytes` is application result JSON size, not all
  encrypted wire traffic (which also includes envelope, Base64, HTTP and TCP overhead).
- This benchmark is an authenticated allowlisted job, bounded to 16 MiB per input.
  It encrypts transient copies with fresh experiment keys and never modifies the source.

## Verification limitation

Local TCP smoke results are NOT VM results or hardware-CSD results. Actual VM evidence
requires running step 6 after creating the VMs. This workspace had no VBoxManage/Get-VM
command available; VM creation and guest execution were not performed here.
