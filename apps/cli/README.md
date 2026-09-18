# AETHER CLI

CLI application for the AETHER project.

> Run these with Python 3.12 or 3.13, other versions are not supported.
> Please ensure the Python version downloaded matches your Python version.
> You can check your Python version with `python --version`.

## Installation
```bash
# Install the wheel bundle
python ./install.py

# Run the MCP Server
python entrypoint.py --idb <path-to-binary> --ida-dir <path-to-ida-dir>
```

## Offline Docs Setup Guide
Download docs from [releases](https://github.com/CSIT-SG/AETHER/releases).

Install [bun](https://bun.com/docs/installation).
```bash
# Run bun in the docs-standalone dir
bun run server.js
```

## Uninstall
```bash
python ./uninstall.py
```
