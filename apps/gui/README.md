# AETHER GUI

GUI application for the AETHER project.

## Development

From the root monorepo directory:

```bash
# Run GUI package entry point
uv run --package aether-gui aether-gui
```

## IDA Plugin

From the root monorepo directory:

```powershell
# Dev: link the plugin entrypoint into the IDA plugins folder
./apps/gui/scripts/install-dev.ps1

# Prod: build all packages and copy artifacts into the IDA plugins folder
./apps/gui/scripts/install-prod.ps1
```
