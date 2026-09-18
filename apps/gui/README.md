# AETHER GUI

GUI application for the AETHER project.

> Run these with Python 3.12 or 3.13, other versions are not supported.
> Please ensure the Python version downloaded matches your Python version.
> You can check your Python version with `python --version`.

```bash
# Install the wheel bundle and copy the entrypoint into the IDA plugins folder
# On Windows, default IDA plugins directpory is %appdata%\Hex-Rays\IDA Pro\plugins
python ./install_prod.py [--plugin-path] <path-to-you-ida-plugins-directory>

# Run the MCP Server
python ./run_prod_backend.py
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
python ./uninstall_prod.py
```
