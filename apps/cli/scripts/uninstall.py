#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from platformdirs import user_data_dir

SOURCE_DIR = Path(__file__).resolve().parent
PYTHON_VERSIONS = {(3, 12), (3, 13)}
APP_AUTHOR = "AETHER-next"


def resolve_command(*names: str) -> None:
    for name in names:
        if shutil.which(name) is not None:
            return
    raise SystemExit(f"None of these commands are available on PATH: {', '.join(names)}")


def run(command: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, text=True)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def resource_dir() -> Path:
    if (SOURCE_DIR / "requirements.txt").exists() and (SOURCE_DIR / "wheels").exists():
        return SOURCE_DIR
    raise SystemExit("Production wheel bundle was not found")


def uninstall_requirements(bundle_dir: Path) -> None:
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "uninstall",
            "-y",
            "-r",
            str(bundle_dir / "requirements.txt"),
        ],
        cwd=bundle_dir,
    )


def remove_data_dirs() -> None:
    shutil.rmtree(
        user_data_dir(appname=APP_AUTHOR, appauthor=False),
        ignore_errors=True,
    )


def main() -> None:
    resolve_command("python", "python3")
    resolve_command("pip")

    if sys.version_info[:2] not in PYTHON_VERSIONS:
        raise SystemExit("Python 3.12 or 3.13 is required")

    bundle_dir = resource_dir()
    remove_data_dirs()
    uninstall_requirements(bundle_dir)
    print("Uninstalled AETHER CLI")


if __name__ == "__main__":
    main()
