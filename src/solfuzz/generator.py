from __future__ import annotations
 
import binascii
import os
from typing import Any, Dict, List

from hypothesis import strategies as st


def _rand_address() -> str:
    return "0x" + binascii.hexlify(os.urandom(20)).decode()


def strategy_for_type(sol_type: str) -> st.SearchStrategy[Any]:
    # Basic, common types first
    if sol_type == "bool":
        return st.booleans()
    if sol_type.startswith("uint"):
        bits = int(sol_type[4:] or 256)
        max_val = 2 ** bits - 1
        return st.integers(min_value=0, max_value=max_val)
    if sol_type.startswith("int"):
        bits = int(sol_type[3:] or 256)
        min_val = -(2 ** (bits - 1))
        max_val = 2 ** (bits - 1) - 1
        return st.integers(min_value=min_val, max_value=max_val)
    if sol_type == "address":
        return st.builds(_rand_address)
    if sol_type.startswith("bytes") and sol_type != "bytes":
        # fixed-size bytesN
        size = int(sol_type[5:])
        return st.binary(min_size=size, max_size=size)
    if sol_type == "bytes":
        return st.binary(min_size=0, max_size=128)
    if sol_type == "string":
        return st.text(min_size=0, max_size=64)

    # Arrays (one-dimensional)
    if sol_type.endswith("[]"):
        inner = sol_type[:-2]
        return st.lists(strategy_for_type(inner), min_size=0, max_size=5)

    # Fallback: opaque bytes
    return st.binary(min_size=0, max_size=64)


def args_strategy_for_function(func_abi: Dict[str, Any]) -> st.SearchStrategy[List[Any]]:
    inputs = func_abi.get("inputs") or []
    strats = [strategy_for_type(inp.get("type", "bytes")) for inp in inputs]
    if not strats:
        return st.just([])
    return st.tuples(*strats).map(list)


