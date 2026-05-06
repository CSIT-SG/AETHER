# AETHER Core

Core library containing shared utilities, configuration, and base classes for the AETHER project.

## Installation

```bash
uv add aether-core
```

## Usage

```python
from src import Config

config = Config()
print(config.version)
```

## Development

From the root monorepo directory:

```bash
# Run tests
uv run pytest packages/core/

# Run linter
uv run ruff check packages/core/
```
