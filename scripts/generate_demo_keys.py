from __future__ import annotations

import argparse
from pathlib import Path

from shared.config import PROJECT_ROOT
from shared.keys import KeyMaterial, serialize_key_material


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate independent SafeConnectKey demo keys")
    parser.add_argument("--force", action="store_true", help="replace an existing .env")
    args = parser.parse_args()
    target = PROJECT_ROOT / ".env"
    if target.exists() and not args.force:
        print(".env already exists; leaving it unchanged")
        return
    auth_key, enc_key = serialize_key_material(KeyMaterial.generate())
    target.write_text(
        "\n".join([
            "SCK_HOST_ID=host-demo", "SCK_CSD_ID=csd-demo",
            f"SCK_AUTH_KEY={auth_key}", f"SCK_ENC_KEY={enc_key}",
            "SCK_SESSION_TTL_SECONDS=300", "SCK_HANDSHAKE_TTL_SECONDS=30",
            "SCK_MAX_REQUEST_BYTES=65536", "",
        ]), encoding="utf-8",
    )
    print("Generated .env with independent 256-bit AuthK and EnK values")


if __name__ == "__main__":
    main()

