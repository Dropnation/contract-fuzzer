from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider


def make_evm() -> Tuple[Web3, str]:
    """Create an in-process EVM using eth-tester + PyEVM.

    Returns a tuple (web3, default_sender).
    """
    w3 = Web3(EthereumTesterProvider())
    default_sender = w3.eth.accounts[0]
    w3.eth.default_account = default_sender
    return w3, default_sender


def deploy_contract(
    w3: Web3,
    *,
    abi: List[Dict[str, Any]],
    bytecode: str,
    args: Optional[Sequence[Any]] = None,
    gas: Optional[int] = None,
) -> Any:
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(*tuple(args or ())).build_transaction({})
    if gas is not None:
        tx["gas"] = gas
    tx_hash = w3.eth.send_transaction(tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)


def send_tx(
    contract: Any,
    function_name: str,
    args: Optional[Sequence[Any]] = None,
    *,
    gas: Optional[int] = None,
) -> Any:
    fn = getattr(contract.functions, function_name)
    tx = fn(*tuple(args or ())).build_transaction({})
    if gas is not None:
        tx["gas"] = gas
    tx_hash = contract.web3.eth.send_transaction(tx)
    receipt = contract.web3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


