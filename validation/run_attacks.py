from __future__ import annotations

import subprocess
import sys


ATTACK_EXPRESSION = " or ".join([
    "v02", "v03", "v04", "v05", "v06", "v07", "v08",
    "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v18",
])


if __name__ == "__main__":
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", "tests/test_validation_matrix.py", "-q", "-k", ATTACK_EXPRESSION]))

