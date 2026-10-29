import hashlib
import pytest
from csd_app.measurements import measure_file
from csd_app.data_store import DataStoreError


def test_measurement_roundtrip_and_units(tmp_path):
    path = tmp_path / "text.txt"
    path.write_bytes(b"data" * 1024)
    result = measure_file(path)
    assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["bytes"] == 4096
    for key in ["encryption_ms", "decryption_ms", "real_seconds", "user_seconds", "system_seconds"]:
        assert result[key] >= 0
    assert [r["algorithm"] for r in result["algorithms"]] == ["AES-256-GCM", "HMAC-SHA-256", "SHA-256"]
    assert result["algorithms"][0]["output_bytes"] == 4112
    assert "key" not in result


def test_benchmark_size_bound(tmp_path):
    path = tmp_path / "large.bin"
    with path.open("wb") as f:
        f.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(DataStoreError, match="BENCHMARK_FILE_TOO_LARGE"):
        measure_file(path)


def test_measurement_through_secure_session(host):
    host.connect()
    try:
        result = host.jobs().submit("benchmark_crypto", "sample.txt")
        assert result.success
        assert result.source_bytes == 4096
        assert result.result["bytes"] == 4096
        assert result.returned_bytes < result.source_bytes
    finally:
        host.close()
