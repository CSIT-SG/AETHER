# Contributing

Requires:
    - `python 3.12 or 3.13`
    - `ida >= 9.2`
    - `mypy` IDE extension

## IDE setup
1. Set your language server's option `Extra Paths` to `C:\Program Files\IDA Professional 9.x\python` (replace as needed). 
2. Run `uv sync --all-packages` (`--allow-insecure-host <host>` if any ssl error).

TODO: update the install script to install deps into the ida python interpreter.

## Developer tooling

- Lint: `ruff check`
- Format: `ruff format`
- Unit tests: `uv run pytest apps/*/tests/unit packages/*/tests/unit`
- Integration tests: `uv run pytest apps/*/tests/integration packages/*/tests/integration`
  - You should set the environment variable `IDADIR="C:\Program Files\IDA Professional 9.2"` (or your ida install directory).