from __future__ import annotations

import csv
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

from shared.config import PROJECT_ROOT


NAVY = colors.HexColor("#0f172a")
BLUE = colors.HexColor("#2563eb")
GREEN = colors.HexColor("#059669")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#f1f5f9")


def footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.line(18 * mm, 15 * mm, 192 * mm, 15 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(SLATE)
    canvas.drawString(18 * mm, 10 * mm, "SafeConnectKey - measured prototype evidence")
    canvas.drawRightString(192 * mm, 10 * mm, f"Page {document.page}")
    canvas.restoreState()


def styled_table(data, widths=None, header=True, font_size=8) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("LEADING", (0, 0), (-1, -1), font_size + 2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    table.setStyle(TableStyle(commands))
    return table


def main() -> None:
    results = PROJECT_ROOT / "results"
    summary = json.loads((results / "validation_summary.json").read_text(encoding="utf-8"))
    metadata = json.loads((results / "benchmark_metadata.json").read_text(encoding="utf-8"))
    with (results / "functional_security_results.csv").open(encoding="utf-8", newline="") as handle:
        validation = list(csv.DictReader(handle))
    output_dir = PROJECT_ROOT / "output" / "pdf"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "SafeConnectKey_Validation_Report.pdf"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleCenter", parent=styles["Title"], alignment=TA_CENTER, textColor=NAVY, fontSize=24, leading=29, spaceAfter=8))
    styles.add(ParagraphStyle(name="Subtitle", parent=styles["Normal"], alignment=TA_CENTER, textColor=SLATE, fontSize=11, leading=15, spaceAfter=20))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=NAVY, fontSize=15, leading=18, spaceBefore=10, spaceAfter=8))
    styles.add(ParagraphStyle(name="BodySCK", parent=styles["BodyText"], textColor=colors.HexColor("#334155"), fontSize=9.5, leading=14, spaceAfter=7))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], textColor=SLATE, fontSize=8, leading=11))
    story = [
        Spacer(1, 15 * mm), Paragraph("SafeConnectKey", styles["TitleCenter"]),
        Paragraph("Validation Report - Secure Host and Computational Storage Communication", styles["Subtitle"]),
        styled_table([
            ["Profile", "Run", "Mode", "Generated evidence"],
            ["Recommended", summary["run_id"], summary["measurement_mode"], "Executed tests and raw CSV records"],
        ], [35*mm, 48*mm, 28*mm, 63*mm], font_size=8),
        Spacer(1, 8*mm), Paragraph("Executive summary", styles["Section"]),
        Paragraph(
            f"The local software prototype passed <b>{summary['validation']['passed']} of {summary['validation']['total']}</b> required V01-V18 tests. "
            f"Across {summary['handshake']['count']} measured handshakes, median latency was <b>{summary['handshake']['median_ms']} ms</b> and p95 was <b>{summary['handshake']['p95_ms']} ms</b>. "
            "AES-256-GCM, HMAC-SHA-256, and HKDF-SHA-256 are the only primary-profile cryptographic primitives.", styles["BodySCK"]),
        Paragraph("Environment", styles["Section"]),
        styled_table([
            ["Field", "Measured value"],
            ["CPU", summary["environment"]["cpu"]],
            ["RAM", f"{summary['environment']['ram_gb']} GB"],
            ["OS", summary["environment"]["windows_build"]],
            ["Python", summary["environment"]["python_version"]],
            ["Execution", summary["environment"]["execution_profile"]],
            ["Dependency hash", summary["environment"]["dependency_lock_hash"]],
        ], [38*mm, 136*mm], font_size=8),
        Spacer(1, 7*mm), Paragraph("Measurement discipline", styles["Section"]),
        Paragraph("Raw records were written per operation before analysis. Sample payloads have exact documented byte sizes and SHA-256 digests. Targets are shown separately from measured values. No key, full token, or protected plaintext is included in this report.", styles["BodySCK"]),
        PageBreak(), Paragraph("V01-V18 functional and security results", styles["Section"]),
    ]
    rows = [["ID", "Expected", "Observed", "Status"]]
    for row in validation:
        status = Paragraph(f"<font color='{'#059669' if row['status']=='PASS' else '#dc2626'}'><b>{row['status']}</b></font>", styles["Small"])
        rows.append([row["test_id"], Paragraph(row["expected_result"], styles["Small"]), row["observed_result"], status])
    story.extend([styled_table(rows, [13*mm, 105*mm, 35*mm, 20*mm], font_size=7.2), PageBreak(), Paragraph("Measured performance", styles["Section"])])
    hs = summary["handshake"]
    story.append(styled_table([
        ["Count", "Median ms", "p95 ms", "p99 ms", "Minimum ms", "Maximum ms", "Failures"],
        [hs["count"], hs["median_ms"], hs["p95_ms"], hs["p99_ms"], hs["minimum_ms"], hs["maximum_ms"], hs["failures"]],
    ], [20*mm,25*mm,25*mm,25*mm,27*mm,27*mm,20*mm], font_size=7.5))
    story.extend([Spacer(1,5*mm), Paragraph("Payload cryptography", styles["Section"])])
    crypto_rows = [["Exact bytes", "Operation", "Count", "Median ms", "p95 ms", "Median MiB/s"]]
    crypto_rows += [[r["payload_bytes"], r["operation"], r["count"], r["median_ms"], r["p95_ms"], r["median_mbps"]] for r in summary["payload_crypto"]]
    story.append(styled_table(crypto_rows, [30*mm,28*mm,22*mm,28*mm,28*mm,35*mm], font_size=7.5))
    story.extend([Spacer(1,5*mm), Paragraph("Near-data and concurrency", styles["Section"]), styled_table([
        ["Metric", "Measured value"],
        ["Verified near-data jobs", f"{summary['near_data']['successful']} / {summary['near_data']['jobs']}"],
        ["Source bytes avoided", summary["near_data"]["bytes_avoided"]],
        ["10-client throughput", f"{summary['concurrency_10']['throughput_rps']} requests/s"],
        ["10-client p95", f"{summary['concurrency_10']['p95_latency_ms']} ms"],
        ["10-client error rate", f"{summary['concurrency_10']['error_rate_pct']}%"],
        ["Peak combined RSS", f"{summary['resource']['peak_rss_mb']} MiB"],
    ], [65*mm,105*mm], font_size=8), PageBreak(), Paragraph("Measured charts", styles["Section"])])
    charts = results / "charts"
    for first, second in (("handshake_latency.png","payload_crypto.png"),("resource_usage.png","concurrency.png"),("security_summary.png",None)):
        pair = [Image(str(charts/first), width=76*mm, height=43*mm)]
        if second: pair.append(Image(str(charts/second), width=76*mm, height=43*mm))
        chart_table = Table([pair], colWidths=[82*mm]*len(pair), hAlign="LEFT")
        chart_table.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),3*mm),("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)]))
        story.extend([chart_table, Spacer(1,5*mm)])
    story.extend([PageBreak(), Paragraph("Acceptance targets versus measurements", styles["Section"])])
    target_rows = [["Criterion", "Target (not measured)", "Measured", "Outcome"],
        ["V01-V18 pass rate", "100%", f"{summary['validation']['pass_rate_pct']}%", "PASS" if summary['validation']['pass_rate_pct']==100 else "FAIL"],
        ["Handshake p95", "< 100 ms", f"{hs['p95_ms']} ms", "PASS" if hs['p95_ms']<100 else "FAIL"],
        ["10-client error rate", "< 1%", f"{summary['concurrency_10']['error_rate_pct']}%", "PASS" if summary['concurrency_10']['error_rate_pct']<1 else "FAIL"],
        ["Peak RSS", "< 256 MiB", f"{summary['resource']['peak_rss_mb']} MiB*", "PASS" if summary['resource']['peak_rss_mb']<256 else "FAIL"],
    ]
    story.extend([styled_table(target_rows,[55*mm,45*mm,40*mm,30*mm],font_size=8), Spacer(1,7*mm), Paragraph("Limitations", styles["Section"])])
    for limitation in summary["limitations"]: story.append(Paragraph(f"- {limitation}", styles["BodySCK"]))
    story.append(Paragraph(f"Benchmark mode was <b>{metadata['mode']}</b>. A plan-conformant full run uses the --full option: three rounds, 200 measured handshakes after 20 warm-ups per round, documented crypto/job iterations, and 60 seconds at each concurrency level.", styles["BodySCK"]))
    document = SimpleDocTemplate(str(output), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=17*mm, bottomMargin=20*mm, title="SafeConnectKey Validation Report", author="SafeConnectKey")
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    print(output)


if __name__ == "__main__": main()
