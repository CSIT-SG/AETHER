# AETHER GUI

GUI application for the AETHER project.

## IDA Plugin

From the root monorepo directory:

```powershell
# Dev: link the plugin entrypoint into the IDA plugins folder
./apps/gui/scripts/PS/install-dev.ps1

# Prod: copy artifacts into the IDA plugins folder
# we create a shim at the root of the file that resolves the imports and re-calls the entrypoint plugin.py
./apps/gui/scripts/PS/install-prod.ps1
# If plugins directory is not %APPDATA%\Roaming\Hex-Rays\IDA Pro, specify with .\install-prod.ps1 -IdaPluginsDir Path\To\Plugins\Folder

# formatter used: https://marketplace.visualstudio.com/items?itemName=shakram02.bash-beautify
```

```bash
# IMPORTANT!!!
# Ensure to run ./idapyswitch to point ida pro to your python installation. AETHER plugin may not work otherwise

# Dev: link the plugin entrypoint into the IDA plugins folder
./apps/gui/scripts/Bash/install-dev.sh

# Prod: copy artifacts into the IDA plugins folder
# we create a shim at the root of the file that resolves the imports and re-calls the entrypoint plugin.py
./apps/gui/scripts/Bash/install-prod.sh
# Usage: ./install-prod.sh --ida-plugins-dir Path/To/Plugins/Folder

# Formatter Used: https://marketplace.visualstudio.com/items?itemName=Tooark.ark-format-powershell
```
