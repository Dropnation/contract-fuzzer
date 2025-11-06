from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
from typing import Any, Dict


def ensure_dir(path: str) -> str:
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    return path


def timestamp_slug() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S.%fZ")


def create_run_artifacts_dir(base_dir: str = "artifacts") -> str:
    ensure_dir(base_dir)
    run_dir = os.path.join(base_dir, f"run-{timestamp_slug()}")
    ensure_dir(run_dir)
    return run_dir


def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


