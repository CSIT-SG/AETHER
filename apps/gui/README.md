# AETHER GUI

GUI application for the AETHER project.

## IDA Plugin

From the this package's root directory:

```powershell
# Dev: export requirements and link the plugin entrypoint into the IDA plugins folder
python .\scripts\install-dev.py

# Prod: install the wheel bundle and copy the entrypoint into the IDA plugins folder
python .\scripts\install-prod.py

# If the plugins directory is not %APPDATA%\Roaming\Hex-Rays\IDA Pro\plugins,
# specify it with: python .\scripts\install-dev.py --plugin-path Path\To\Plugins\Folder

# formatter used: https://marketplace.visualstudio.com/items?itemName=shakram02.bash-beautify
```

```bash
# Dev: export requirements and link the plugin entrypoint into the IDA plugins folder
python ./scripts/install-dev.py

# Prod: install the wheel bundle and copy the entrypoint into the IDA plugins folder
python ./scripts/install-prod.py

# Usage: python ./scripts/install-dev.py --plugin-path /path/to/plugins/dir

# Formatter Used: https://marketplace.visualstudio.com/items?itemName=Tooark.ark-format-powershell
```

Read more in `apps/docs` (follow their setup guide).