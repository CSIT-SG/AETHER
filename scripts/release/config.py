from pathlib import Path
from typing import TypedDict, NotRequired

ROOT_DIR = Path(__file__).parent.parent.parent  # scripts/release/config.py, 3 layers
OUTPUT_DIR = ROOT_DIR / "dist"

WHEELS_DIRNAME = "wheels"
REQUIREMENTS_FILENAME = "requirements.txt"


class _AppBuildConfig(TypedDict):
    extra_inodes: list[Path]  # extra files to include in the output for this app
    provided_deps: NotRequired[list[str]]  # deps supplied by the runtime host, excluded from requirements.txt


_apps_path = ROOT_DIR / "apps"

APPS: dict[str, _AppBuildConfig] = {
    "aether_gui": {
        "extra_inodes": [
            _apps_path / "gui" / "src" / "plugin.py",
            _apps_path / "gui" / "scripts" / "install_prod.py",
            _apps_path / "gui" / "README.md",
        ],
        "provided_deps": ["pyside6", "pyside6-addons", "pyside6-essentials", "shiboken6"],
    },
    "aether_cli": {
        "extra_inodes": [
            _apps_path / "cli" / "src" / "entrypoint.py",
            _apps_path / "cli" / "scripts" / "install_prod.py",
            _apps_path / "cli" / "README.md",
        ],
    },
}
