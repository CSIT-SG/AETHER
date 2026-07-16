# AETHER GUI

GUI application for the AETHER project.

> Run these with Python 3.12 or 3.13 — other versions are not supported.

```bash
# Install the wheel bundle and copy the entrypoint into the IDA plugins folder
python ./install_prod.py

# You can also specify the IDA plugin directory with --plugin-path /path/to/ida/plugins
# On windows, by default it is %appdata%\Hex-Rays\IDA Pro\plugins
```

Read more in `apps/docs` (follow the setup guide).

To uninstall,

```bash
pip uninstall -r requirements.txt
rm /path/to/ida/plugins/aether-next.py
```
