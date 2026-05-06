# AETHER Next

AETHER Next is a Python monorepo managed with uv workspaces.

## Project Structure

```text
AETHER-next/
├── apps/
│   ├── cli/                 # CLI app
│   ├── gui/                 # GUI app
│   └── docs/                # Docs app/content area
├── packages/
│   ├── core/                # Core shared package
│   │   ├── chatbot/
│   │   ├── flattener/
│   │   ├── function-gatherer/
│   │   ├── memory/
│   │   ├── skills/
│   │   └── src/
│   ├── ui/                  # Shared UI package
│   └── utils/               # Shared utilities package
├── dist/                    # Build artifacts
├── pyproject.toml           # Workspace + tool configuration
└── uv.lock                  # Locked dependency resolution
```

## Build and Validation

- Build all workspace packages: `uv build --all-packages --out-dir dist --clear`
- Lint: `./lint.sh`
- Format: `./format.sh`
- Test: `./test.sh`
