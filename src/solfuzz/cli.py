from __future__ import annotations
 
import sys
import os
import typing as t

import click
import yaml  # type: ignore

from . import __version__
from .system_info import format_system_info, gather_system_info
from .utils import create_run_artifacts_dir, write_json
from .compiler import compile_contracts
from .abi import extract_contracts
from .fuzzer import run_fuzz, FuzzConfig


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="solfuzz")
def main() -> None:
    """Solfuzz CLI.

    Run `solfuzz doctor` to print system diagnostics.
    """


@main.command()
def doctor() -> None:
    """Print basic system diagnostics (OS/Python).

    A fuller report will be added in the diagnostics task.
    """
    click.echo(format_system_info())


@main.command()
@click.option("--config", "config_path", type=click.Path(path_type=str), help="Path to YAML config")
@click.option("--report-dir", default=None, help="Artifacts output directory (default from config or 'artifacts')")
@click.option("--seed", type=int, default=None, help="Seed for fuzzing RNG")
@click.option("--max-steps", type=int, default=None, help="Max steps to run")
@click.argument("sources", nargs=-1, type=click.Path(path_type=str))
def run(config_path: t.Optional[str], report_dir: t.Optional[str], seed: t.Optional[int], max_steps: t.Optional[int], sources: t.Tuple[str, ...]) -> None:
    """Run the fuzzer (scaffold stub)."""
    cfg = {}
    if config_path:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

    report_base = report_dir or cfg.get("report", {}).get("dir", "artifacts")

    # Create run dir and dump environment info at startup
    run_dir = create_run_artifacts_dir(report_base)
    env_info = gather_system_info()
    write_json(os.path.join(run_dir, "env.json"), env_info)  # type: ignore[name-defined]
    click.echo(format_system_info())

    resolved_sources: list[str] = list(sources)
    if not resolved_sources:
        resolved_sources = list(cfg.get("solidity", {}).get("sources", []) or [])
        if not resolved_sources:
            resolved_sources = ["contracts/"]

    try:
        comp = compile_contracts(
            resolved_sources,
            evm_version=cfg.get("solidity", {}).get("evm_version"),
            optimize=bool(cfg.get("solidity", {}).get("optimize", True)),
            runs=int(cfg.get("solidity", {}).get("runs", 200)),
        )
        click.echo(f"compiled_contracts={len(comp)}")
    except Exception as exc:
        click.echo(f"compile_failed={type(exc).__name__}: {exc}")
        click.echo("solfuzz run aborted before fuzzing due to compile error")
        return

    contracts = extract_contracts(comp)
    if not contracts:
        click.echo("no_contracts_found_after_compile")
        return

    # Select the first contract by name
    first_name = sorted(contracts.keys())[0]
    selected = contracts[first_name]

    fc = FuzzConfig(
        max_steps=int(max_steps or cfg.get("fuzz", {}).get("max_steps", 1000)),
        gas_limit=int(cfg.get("fuzz", {}).get("gas_limit", 8_000_000)),
        stop_on_fail=bool(cfg.get("fuzz", {}).get("stop_on_fail", True)),
        seed=seed if seed is not None else cfg.get("fuzz", {}).get("seed"),
    )
    click.echo(f"fuzzing_contract={first_name} steps={fc.max_steps} seed={fc.seed}")
    run_fuzz(selected, contract_name=first_name, run_dir=run_dir, cfg=fc)
    click.echo("solfuzz run finished")


@main.command()
@click.argument("failure_artifact", type=click.Path(path_type=str))
def replay(failure_artifact: str) -> None:
    """Replay a failure artifact (best-effort)."""
    try:
        with open(failure_artifact, "r", encoding="utf-8") as f:
            failure = yaml.safe_load(f)  # supports JSON as YAML subset
    except Exception as exc:
        click.echo(f"failed_to_read_artifact={type(exc).__name__}: {exc}")
        return

    contract_name = failure.get("contract")
    fn = failure.get("function")
    args = failure.get("args", [])
    if not contract_name or not fn:
        click.echo("invalid_failure_artifact_missing_fields")
        return

    try:
        comp = compile_contracts(["contracts/"])
        contracts = extract_contracts(comp)
        if contract_name not in contracts:
            click.echo(f"contract_not_found={contract_name}")
            return
        selected = contracts[contract_name]
    except Exception as exc:
        click.echo(f"compile_failed={type(exc).__name__}: {exc}")
        return

    from .runtime import make_evm, deploy_contract, send_tx
    from .abi import discover_properties

    w3, _sender = make_evm()
    c = deploy_contract(w3, abi=selected["abi"], bytecode=selected["bytecode"], args=None)
    try:
        send_tx(c, fn, args=args)
    except Exception as exc:
        click.echo(f"tx_failed={type(exc).__name__}: {exc}")
    props = discover_properties(selected["abi"])
    statuses = {}
    for p in props:
        name = p["name"]
        ok = False
        try:
            ok = getattr(c.functions, name)().call()
        except Exception as exc:
            statuses[name] = f"revert:{type(exc).__name__}"
            continue
        statuses[name] = bool(ok)
    click.echo("replay_property_statuses=" + str(statuses))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


