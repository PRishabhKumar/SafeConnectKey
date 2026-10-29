from __future__ import annotations

import hashlib
import json
import math
import struct
import wave
from pathlib import Path

from PIL import Image

from shared.config import PROJECT_ROOT, DEFAULT_SETTINGS


SIZES = {"sample.txt": 4 * 1024, "sample.png": 512 * 1024, "sample.wav": 5 * 1024 * 1024}


def make_text(path: Path) -> None:
    seed = b"SafeConnectKey keeps source data inside the computational storage emulator.\n"
    path.write_bytes((seed * (SIZES[path.name] // len(seed) + 1))[: SIZES[path.name]])


def make_png(path: Path) -> None:
    image = Image.new("RGB", (512, 320))
    pixels = image.load()
    for y in range(image.height):
        for x in range(image.width):
            pixels[x, y] = ((x * 3) % 256, (y * 5) % 256, ((x + y) * 2) % 256)
    image.save(path, format="PNG", optimize=False)
    current = path.stat().st_size
    if current > SIZES[path.name]:
        raise RuntimeError("generated PNG exceeds target size")
    with path.open("ab") as handle:
        handle.write(bytes(SIZES[path.name] - current))


def make_wav(path: Path) -> None:
    target_data_bytes = SIZES[path.name] - 44
    rate = 44_100
    one_second = b"".join(struct.pack("<h", int(9000 * math.sin(2 * math.pi * 440 * i / rate))) for i in range(rate))
    pcm = (one_second * (target_data_bytes // len(one_second) + 1))[:target_data_bytes]
    with wave.open(str(path), "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(rate)
        audio.writeframes(pcm)


def main() -> None:
    data_root = DEFAULT_SETTINGS.data_root
    data_root.mkdir(parents=True, exist_ok=True)
    make_text(data_root / "sample.txt")
    make_png(data_root / "sample.png")
    make_wav(data_root / "sample.wav")
    hashes = {}
    for name, expected in SIZES.items():
        path = data_root / name
        actual = path.stat().st_size
        if actual != expected:
            raise RuntimeError(f"{name}: expected {expected} bytes, got {actual}")
        hashes[name] = {"bytes": actual, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    evidence = PROJECT_ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    (evidence / "sample_hashes.json").write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8")
    (evidence / "sample_hashes.txt").write_text("\n".join(f"{name} {item['bytes']} bytes sha256={item['sha256']}" for name, item in hashes.items()) + "\n", encoding="utf-8")
    print(json.dumps(hashes, indent=2))


if __name__ == "__main__":
    main()

