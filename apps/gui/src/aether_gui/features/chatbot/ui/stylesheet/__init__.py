from pathlib import Path

package_dir = Path(__file__).resolve().parent

# Resolve the absolute file paths to your Jinja templates
THEMES_PATH = Path(package_dir.joinpath("themes.qss.jinja"))
FORMATTING_PATH = Path(package_dir.joinpath("formatting.qss.jinja"))

# Control what gets exported when someone writes 'from my_style_package import *'
__all__ = ["THEMES_PATH", "FORMATTING_PATH"]