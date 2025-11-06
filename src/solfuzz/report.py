from __future__ import annotations

import os
from typing import Any, Dict

from .utils import write_json


def write_summary(run_dir: str, *, steps: int, failures: int) -> None:
    write_json(os.path.join(run_dir, "summary.json"), {"steps": steps, "failures": failures})


