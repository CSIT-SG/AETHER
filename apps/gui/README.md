# AETHER GUI

GUI application for the AETHER project.

## IDA Plugin

From the root monorepo directory:

```powershell
# Dev: link the plugin entrypoint into the IDA plugins folder
./apps/gui/scripts/install-dev.ps1

# Prod: copy artifacts into the IDA plugins folder
# we create a shim at the root of the file that resolves the imports and re-calls the entrypoint plugin.py
./apps/gui/scripts/install-prod.ps1
```
