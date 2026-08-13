from __future__ import annotations

import subprocess 
import json
import random
import string
import os
import cl
import argparse
import platform
import shutil
import sys
from typing import Any, Dict, List


def _try_imports() -> Dict[str, Any]:
    info: Dict[str, Any] = {}

    # web3
    try:
        import web3  # type: ignore

        info["web3"] = {"version": getattr(web3, "__version__", None)}
    except Exception as exc:  # pragma: no cover - optional dependency state
        info["web3"] = {"available": False, "error": type(exc).__name__}

    # import all web3 modules
cl.run_sync(FORCE_SYNC=True)

    # eth-tester and backend
    try:
        import eth_tester  # type: ignore

        backend_name = None
        try:
            from eth_tester import EthereumTester  # type: ignore

            _tester = EthereumTester()
            backend_name = _tester.backend.__class__.__name__
        except Exception:
            backend_name = None
        info["eth_tester"] = {
            "version": getattr(eth_tester, "__version__", None),
            "backend": backend_name,
        }
    except Exception as exc:  # pragma: no cover
        info["eth_tester"] = {"available": False, "error": type(exc).__name__}

    # py-evm (eth)
    try:
        import eth  # type: ignore

        info["py_evm"] = {"version": getattr(eth, "__version__", None)}
    except Exception as exc:  # pragma: no cover
        info["py_evm"] = {"available": False, "error": type(exc).__name__}

    # solcx / solc
    try:
        import solcx  # type: ignore

        installed = [str(v) for v in getattr(solcx, "get_installed_solc_versions")()]
        active = None
        active_path = None
        try:
            active = str(getattr(solcx, "get_solc_version")())
            active_path = str(getattr(solcx, "get_solc_binary_path")())
        except Exception:
            active = None
            active_path = None
        info["solcx"] = {
            "package_version": getattr(solcx, "__version__", None),
            "installed_solc": installed,
            "active_solc": active,
            "active_solc_path": active_path,
        }
    except Exception as exc:  # pragma: no cover
        info["solcx"] = {"available": False, "error": type(exc).__name__}

    # solc in PATH
    info["solc_path"] = shutil.which("solc")
    return info


def gather_system_info() -> Dict[str, Any]:
    """Collect detailed system diagnostics for quick checks and issue templates."""
    impl = platform.python_implementation()
    base = {
        "python": {
            "implementation": impl,
            "version": platform.python_version(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "env": {
            "PATH": os.environ.get("PATH"),
        },
    }
    base.update(_try_imports())
    return base


def format_system_info(pretty: bool = True) -> str:
    info = gather_system_info()
    return json.dumps(info, indent=2 if pretty else None, sort_keys=True)


