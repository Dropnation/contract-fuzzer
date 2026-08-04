from __future__ import annotations
 
import glob
import os
from typing import Any, Dict, Iterable, List, Tuple


def _collect_source_files(inputs: Iterable[str]) -> List[str]:
    files: List[str] = []
    for item in inputs:
        if os.path.isdir(item):
            for path in glob.glob(os.path.join(item, "**", "*.sol"), recursive=True):
                files.append(path)
        elif os.path.isfile(item) and item.endswith(".sol"):
            files.append(item)
    # Deduplicate while preserving order
    seen = set()
    uniq: List[str] = []
    for p in files:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def _ensure_solc_for_sources(source_files: List[str]) -> str:
    import solcx  # type: ignore

    installed_before = set(str(v) for v in solcx.get_installed_solc_versions())
    target_version: str | None = None

    for path in source_files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            # Install a version matching the pragma in this file (best effort)
            solcx.install_solc_pragma(content)
        except Exception:
            continue

    installed_after = sorted((str(v) for v in solcx.get_installed_solc_versions()), reverse=True)
    if installed_after:
        target_version = installed_after[0]
        solcx.set_solc_version(target_version)  # type: ignore[arg-type]
    else:
        # Fallback to a commonly available compiler
        target_version = "0.8.20"
        solcx.install_solc(target_version)
        solcx.set_solc_version(target_version)
    return target_version


def compile_contracts(
    inputs: Iterable[str],
    *,
    evm_version: str | None = None,
    optimize: bool = True,
    runs: int = 200,
) -> Dict[str, Any]:
    """Compile Solidity contracts with py-solc-x.

    Returns the solc output mapping keyed by "<path>:<ContractName>".
    """
    from solcx import compile_files  # type: ignore

    source_files = _collect_source_files(inputs)
    if not source_files:
        raise FileNotFoundError("No .sol sources found in inputs")

    _ensure_solc_for_sources(source_files)

    output = compile_files(
        source_files=source_files,
        output_values=["abi", "bin", "bin-runtime", "metadata"],
        optimize=optimize,
        optimize_runs=runs,
        evm_version=evm_version,
    )
    return output


