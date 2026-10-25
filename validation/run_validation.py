from __future__ import annotations

import csv
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from shared.config import PROJECT_ROOT


EXPECTED = {
    "V01": "Session established and key fingerprints match.",
    "V02": "Wrong AuthK is rejected; no session is created.",
    "V03": "Wrong EnK fails authenticated decryption.",
    "V04": "Modified AuthTd is rejected.",
    "V05": "Modified SessTd is rejected by AES-GCM.",
    "V06": "Expired challenge is rejected.",
    "V07": "Consumed handshake is rejected as replay.",
    "V08": "Substituted identity fails authentication.",
    "V09": "Encrypted SHA-256 job returns the correct digest.",
    "V10": "Modified job ciphertext is rejected without execution.",
    "V11": "Repeated message sequence is rejected without duplicate execution.",
    "V12": "Skipped sequence is rejected as out of order.",
    "V13": "Expired session requires re-authentication.",
    "V14": "Unknown operation returns a validated error.",
    "V15": "Traversal outside csd_data is rejected.",
    "V16": "Oversized request is rejected before processing.",
    "V17": "Ten concurrent sessions remain isolated and complete.",
    "V18": "Old session fails after restart and new handshake succeeds.",
}


def main() -> int:
    evidence = PROJECT_ROOT / "evidence"
    results = PROJECT_ROOT / "results"
    evidence.mkdir(exist_ok=True)
    results.mkdir(exist_ok=True)
    junit = evidence / "validation-junit.xml"
    command = [sys.executable, "-m", "pytest", "tests/test_validation_matrix.py", "-q", f"--junitxml={junit}"]
    completed = subprocess.run(command, cwd=PROJECT_ROOT, text=True, capture_output=True, check=False)
    output = completed.stdout + completed.stderr
    (evidence / "pytest_output.txt").write_text(output, encoding="utf-8")
    tree = ET.parse(junit)
    root = tree.getroot()
    for suite in root.iter("testsuite"):
        if "hostname" in suite.attrib:
            suite.set("hostname", "withheld")
    tree.write(junit, encoding="utf-8", xml_declaration=True)
    observed: dict[str, tuple[bool, str]] = {}
    for case in root.iter("testcase"):
        match = re.search(r"test_v(\d{2})_", case.attrib.get("name", ""))
        if not match:
            continue
        test_id = f"V{match.group(1)}"
        failure = case.find("failure")
        if failure is None:
            failure = case.find("error")
        observed[test_id] = (failure is None, "passed" if failure is None else (failure.attrib.get("message") or "failed")[:240])
    target = results / "functional_security_results.csv"
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["test_id", "expected_result", "observed_result", "status", "evidence_file"])
        writer.writeheader()
        for test_id, expected in EXPECTED.items():
            passed, detail = observed.get(test_id, (False, "not collected"))
            writer.writerow({
                "test_id": test_id, "expected_result": expected,
                "observed_result": detail, "status": "PASS" if passed else "FAIL",
                "evidence_file": "evidence/validation-junit.xml",
            })
    print(output, end="")
    print(f"Wrote {target}")
    return completed.returncode if completed.returncode else (0 if len(observed) == 18 and all(value[0] for value in observed.values()) else 1)


if __name__ == "__main__":
    raise SystemExit(main())

