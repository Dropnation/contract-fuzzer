from __future__ import annotations
 
from typing import Any, Dict, Iterable, List, Tuple


def split_contract_id(qualified: str) -> Tuple[str, str]:
    # format from solcx.compile_files key: "path:ContractName"
    if ":" in qualified:
        path, name = qualified.split(":", 1)
        return path, name
    return "", qualified


def discover_properties(abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    props: List[Dict[str, Any]] = []
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name", "")
        if not name.startswith("echidna_"):
            continue
        outputs = entry.get("outputs") or []
        if len(outputs) == 1 and outputs[0].get("type") == "bool":
            props.append(entry)
    return props


def discover_targets(abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name", "")
        if name.startswith("echidna_"):
            continue
        # Skip pure/view? keep them callable to mutate not required; focus external/public
        if entry.get("stateMutability") in {"view", "pure"}:
            continue
        targets.append(entry)
    return targets


def extract_contracts(compiled: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Flatten solcx output into a mapping by contract name.

    Returns: name -> { abi, bytecode }
    """
    out: Dict[str, Dict[str, Any]] = {}
    for qual, data in compiled.items():
        _, name = split_contract_id(qual)
        abi = data.get("abi")
        bytecode = data.get("bin")
        if abi and bytecode is not None:
            out[name] = {"abi": abi, "bytecode": bytecode}
    return out


