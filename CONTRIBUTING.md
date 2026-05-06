# Contributing

Thanks for contributing to AETHER Next.

## Prerequisites

- Python 3.10+
- uv installed
- ida >= 9.0

## Setup

From the repository root:

```bash
uv sync
```

in your ide configure `python.analysis.extraPaths` to `C:\Program Files\IDA Professional 9.x\python`. this is to allow for type checking.

## Development Commands

Use the root scripts to keep checks consistent:

```bash
# Lint
uv run ruff check .

# Format
uv run ruff format .

# Run tests
uv run pytest
```


## Build Packages

```bash
uv build --all-packages --out-dir dist --clear
```
