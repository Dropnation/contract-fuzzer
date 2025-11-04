from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .abi import discover_properties, discover_targets
from .generator import args_strategy_for_function
from .runtime import deploy_contract, make_evm, send_tx
from .utils import write_json
from .report import write_summary


@dataclass
class FuzzConfig:
    max_steps: int = 1000
    gas_limit: Optional[int] = None
    stop_on_fail: bool = True
    seed: Optional[int] = None


def _evaluate_properties(contract: Any, props_abi: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for prop in props_abi:
        name = prop["name"]
        try:
            ok: bool = getattr(contract.functions, name)().call()
        except Exception as exc:  # revert or runtime error -> violation
            return {"property": name, "error": f"{type(exc).__name__}: {exc}", "ok": False}
        if not ok:
            return {"property": name, "ok": False}
    return None


def run_fuzz(
    compiled_contract: Dict[str, Any],
    *,
    contract_name: str,
    run_dir: str,
    cfg: FuzzConfig,
) -> None:
    abi = compiled_contract["abi"]
    bytecode = compiled_contract["bytecode"]

    w3, _sender = make_evm()
    contract = deploy_contract(w3, abi=abi, bytecode=bytecode, args=None, gas=cfg.gas_limit)

    props = discover_properties(abi)
    targets = discover_targets(abi)
    if not targets:
        return

    if cfg.seed is not None:
        random.seed(cfg.seed)

    failures = 0
    last_step = 0
    for step in range(1, int(cfg.max_steps) + 1):
        target = random.choice(targets)
        fn_name = target["name"]
        args = args_strategy_for_function(target).example()

        try:
            send_tx(contract, fn_name, args=args, gas=cfg.gas_limit)
        except Exception as exc:
            # Treat reverts as normal outcomes; continue fuzzing
            pass

        violation = _evaluate_properties(contract, props)
        if violation is not None:
            failure = {
                "seed": cfg.seed,
                "step": step,
                "contract": contract_name,
                "function": fn_name,
                "args": args,
                "violation": violation,
            }
            write_json(os.path.join(run_dir, "failure.json"), failure)
            failures += 1
            if cfg.stop_on_fail:
                write_summary(run_dir, steps=step, failures=failures)
                return
        last_step = step

    write_summary(run_dir, steps=last_step, failures=failures)


