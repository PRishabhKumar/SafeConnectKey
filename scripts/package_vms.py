"""Build source-only role bundles; never include secrets, datasets or old evidence."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from shared.config import PROJECT_ROOT


def main():
    destination = PROJECT_ROOT / "dist" / "vm"
    destination.mkdir(parents=True, exist_ok=True)
    for role in ("host", "csd"):
        folders = ["shared", "host_app", "dashboard", "validation"] if role == "host" else ["shared", "csd_app"]
        files = [PROJECT_ROOT / "requirements.txt", PROJECT_ROOT / "streamlit_app.py"]
        files += [PROJECT_ROOT / "scripts" / name for name in ("__init__.py", "generate_demo_keys.py", "generate_sample_data.py")]
        for folder in folders:
            files += sorted((PROJECT_ROOT / folder).rglob("*.py"))
        with ZipFile(destination / f"sck-{role}.zip", "w", ZIP_DEFLATED) as z:
            for file in files:
                if "__pycache__" not in file.parts:
                    z.write(file, file.relative_to(PROJECT_ROOT))
        print(destination / f"sck-{role}.zip")


if __name__ == "__main__":
    main()
