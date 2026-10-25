from __future__ import annotations

from pathlib import Path, PurePosixPath


class DataStoreError(ValueError):
    pass


class DataStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, requested: str) -> Path:
        normalized = requested.replace("\\", "/")
        pure = PurePosixPath(normalized)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise DataStoreError("PATH_REJECTED")
        candidate = (self.root / Path(*pure.parts)).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise DataStoreError("PATH_REJECTED")
        if not candidate.is_file():
            raise DataStoreError("FILE_NOT_FOUND")
        return candidate

