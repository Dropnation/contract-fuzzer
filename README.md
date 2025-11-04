# Solfuzz

Python-based smart contract fuzzer for EVM. It compiles Solidity sources, discovers property functions named `echidna_*`, executes random sequences of public/external calls, and checks that all properties hold after each step. Runs locally without Docker; Docker files are included only for convenience.

## Quick start

Requirements:
- Python 3.9+
- Windows/macOS/Linux

Install in editable mode:

```bash
pip install -e .
```

Print diagnostics (attach to bug reports):

```bash
solfuzz doctor
```

Fuzz example contract:

```bash
solfuzz run --config configs/example.yaml
```

Replay a failure (best-effort):

```bash
solfuzz replay artifacts/run-*/failure.json
```

## Concepts

- Properties: Solidity functions named `echidna_*` returning `bool`. If any returns `false` or reverts, Solfuzz reports a violation.
- Targets: All other public/external non-view functions are fuzzed.
- Reproducibility: Seeds can be provided via `--seed`. Failures are saved under `artifacts/run-*/failure.json`.

## Configuration

See `configs/example.yaml` for a reference. Key options:
- `solidity.sources`: file(s) or directories with `.sol` files
- `solidity.optimize`, `solidity.runs`, `solidity.evm_version`
- `fuzz.max_steps`, `fuzz.stop_on_fail`, `fuzz.seed`, `fuzz.gas_limit`
- `report.dir`: artifacts directory

## Windows notes

- Uses in-process EVM (`eth-tester` + `py-evm`), no external binaries required.
- Solidity compiler is managed by `py-solc-x` and downloaded on first compile per pragma.

## Limitations

- Input shrinking/minimization is basic and will be improved.
- Coverage-guided scheduling and parallel workers are on the roadmap.

## Development

Run a short smoke:

```bash
solfuzz run contracts/Counter.sol --max-steps 50 --seed 123
```

## Docker (optional)

Build and run inside a container (not required for normal use):

```bash
docker build -t solfuzz .
docker run --rm -it solfuzz solfuzz doctor
```
