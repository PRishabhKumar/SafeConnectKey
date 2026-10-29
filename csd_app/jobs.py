from __future__ import annotations

import hashlib
import time
import wave
import zlib
from pathlib import Path

from PIL import Image

from csd_app.data_store import DataStore, DataStoreError
from shared.canonical import canonical_json
from shared.schemas import JobCommand, JobResult


ALLOWED_OPERATIONS = {"sha256", "word_count", "image_metadata", "audio_metadata", "compression", "benchmark_crypto"}


class JobExecutor:
    def __init__(self, store: DataStore) -> None:
        self.store = store

    def execute(self, command: JobCommand, job_id: str) -> JobResult:
        started = time.perf_counter_ns()
        try:
            if command.operation not in ALLOWED_OPERATIONS:
                raise DataStoreError("UNSUPPORTED_OPERATION")
            path = self.store.resolve(command.path)
            source_bytes = path.stat().st_size
            result = self._dispatch(command.operation, path)
            returned_bytes = len(canonical_json(result))
            return JobResult(
                job_id=job_id, operation=command.operation, path=command.path,
                success=True, result=result, source_bytes=source_bytes,
                returned_bytes=returned_bytes,
                latency_ms=(time.perf_counter_ns() - started) / 1_000_000,
            )
        except DataStoreError as exc:
            return JobResult(
                job_id=job_id, operation=command.operation, path=command.path,
                success=False, error_code=str(exc), source_bytes=0, returned_bytes=0,
                latency_ms=(time.perf_counter_ns() - started) / 1_000_000,
            )
        except (OSError, ValueError, wave.Error) as exc:
            return JobResult(
                job_id=job_id, operation=command.operation, path=command.path,
                success=False, error_code="INVALID_DATA", source_bytes=0,
                returned_bytes=0,
                latency_ms=(time.perf_counter_ns() - started) / 1_000_000,
            )

    def _dispatch(self, operation: str, path: Path) -> dict[str, object]:
        if operation == "benchmark_crypto":
            from csd_app.measurements import measure_file
            return measure_file(path)
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if operation == "sha256":
            return {"sha256": digest, "bytes": len(data)}
        if operation == "word_count":
            text = data.decode("utf-8")
            return {"words": len(text.split()), "lines": len(text.splitlines()), "bytes": len(data), "sha256": digest}
        if operation == "image_metadata":
            with Image.open(path) as image:
                return {"width": image.width, "height": image.height, "format": image.format, "bytes": len(data), "sha256": digest}
        if operation == "audio_metadata":
            with wave.open(str(path), "rb") as audio:
                frames, rate = audio.getnframes(), audio.getframerate()
                return {
                    "duration_seconds": round(frames / rate, 6), "sample_rate": rate,
                    "channels": audio.getnchannels(), "sample_width": audio.getsampwidth(),
                    "bytes": len(data), "sha256": digest,
                }
        if operation == "compression":
            compressed = zlib.compress(data, level=6)
            return {"source_bytes": len(data), "compressed_bytes": len(compressed), "ratio": round(len(compressed) / len(data), 6), "sha256": digest}
        raise DataStoreError("UNSUPPORTED_OPERATION")

