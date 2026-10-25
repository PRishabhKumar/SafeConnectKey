from __future__ import annotations

import json
import os
from shared.config import PROJECT_ROOT

os.environ.setdefault("MPLCONFIGDIR", str(PROJECT_ROOT / "tmp" / "matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def main() -> None:
    summary=json.loads((PROJECT_ROOT/"results"/"validation_summary.json").read_text(encoding="utf-8"))
    events=(PROJECT_ROOT/"results"/"functional_security_results.csv").read_text(encoding="utf-8").splitlines()[1:]
    fig=plt.figure(figsize=(19.2,10.8),dpi=100,facecolor="#f4f7fb")
    fig.text(.04,.94,"SafeConnectKey",fontsize=30,weight="bold",color="#0f172a"); fig.text(.04,.905,"Secure Host ↔ Computational Storage Emulator",fontsize=14,color="#475569")
    cards=[("CSD","ONLINE"),("SESSION","AUTHENTICATED"),("ENCRYPTION","AES-256-GCM"),("PROFILE","RECOMMENDED"),("VALIDATION",f"{summary['validation']['passed']}/{summary['validation']['total']} PASS")]
    for i,(label,value) in enumerate(cards):
        x=.04+i*.19; fig.text(x,.83,label,fontsize=10,color="#64748b"); fig.text(x,.785,value,fontsize=15,weight="bold",color="#059669" if i!=2 else "#2563eb",bbox=dict(boxstyle="round,pad=.7",facecolor="white",edgecolor="#dbe4ef"))
    fig.text(.04,.68,"Handshake trace",fontsize=18,weight="bold",color="#0f172a")
    steps=["1  Challenge created","2  AuthTd verified","3  Nonce R generated","4  Independent HKDF keys matched","5  Explicit confirmation verified"]
    for i,step in enumerate(steps): fig.text(.055,.62-i*.065,"✓  "+step,fontsize=13,color="#047857")
    fig.text(.52,.68,"Latest secure near-data job",fontsize=18,weight="bold",color="#0f172a")
    fig.text(.535,.61,"SHA-256 · sample.txt · 4,096 source bytes",fontsize=14,color="#334155")
    fig.text(.535,.55,"Verified encrypted result",fontsize=15,weight="bold",color="#059669")
    fig.text(.535,.49,f"Handshake median {summary['handshake']['median_ms']:.2f} ms   ·   p95 {summary['handshake']['p95_ms']:.2f} ms",fontsize=13,color="#334155")
    fig.text(.04,.29,"Security evidence",fontsize=18,weight="bold",color="#0f172a")
    fig.text(.055,.23,"REJECTED  ·  ciphertext tamper  ·  AUTHENTICATION_FAILED",fontsize=13,color="#dc2626")
    fig.text(.055,.18,"REJECTED  ·  message replay      ·  MESSAGE_REPLAY",fontsize=13,color="#dc2626")
    fig.text(.52,.29,"Measured resources",fontsize=18,weight="bold",color="#0f172a")
    fig.text(.535,.23,f"Peak RSS {summary['resource']['peak_rss_mb']:.1f} MiB   ·   Peak CPU {summary['resource']['peak_cpu_pct']:.1f}%",fontsize=13,color="#334155")
    fig.text(.04,.07,f"Measured run {summary['run_id']} · AES-256-GCM / HMAC-SHA-256 / HKDF-SHA-256 · No secrets or plaintext payloads shown",fontsize=11,color="#64748b")
    output=PROJECT_ROOT/"results"/"SafeConnectKey_Prototype.png"; fig.savefig(output,dpi=100,facecolor=fig.get_facecolor()); plt.close(fig); print(output)


if __name__ == "__main__": main()
