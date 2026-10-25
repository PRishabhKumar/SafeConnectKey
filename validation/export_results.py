from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from shared.config import PROJECT_ROOT


EXCLUDED_PARTS = {
    ".venv", ".git", "__pycache__", ".pytest_cache", ".run",
    "SafeConnectKey_Submission", "results", "evidence", "output", "tmp",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".mkv", ".mp4", ".pdf", ".docx"}


def include_source(path: Path) -> bool:
    relative = path.relative_to(PROJECT_ROOT)
    return (
        not any(part in EXCLUDED_PARTS for part in relative.parts)
        and path.suffix.lower() not in EXCLUDED_SUFFIXES
        and path.name != ".env"
        and not path.name.startswith("Implementation plan")
    )


def main() -> None:
    destination = PROJECT_ROOT / "SafeConnectKey_Submission"
    destination.mkdir(exist_ok=True)
    for name in ("README.md",):
        shutil.copy2(PROJECT_ROOT / name, destination / name)
    for folder in ("results", "evidence"):
        target = destination / folder
        if target.exists(): shutil.rmtree(target)
        shutil.copytree(PROJECT_ROOT / folder, target)
    snapshot = PROJECT_ROOT / "results" / "SafeConnectKey_Prototype.png"
    if snapshot.exists(): shutil.copy2(snapshot, destination / snapshot.name)
    report = PROJECT_ROOT / "output" / "pdf" / "SafeConnectKey_Validation_Report.pdf"
    if report.exists(): shutil.copy2(report, destination / report.name)
    archive = destination / "SafeConnectKey_Source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in PROJECT_ROOT.rglob("*"):
            if path.is_file() and include_source(path):
                bundle.write(path, path.relative_to(PROJECT_ROOT))
    print(destination)


if __name__ == "__main__": main()

