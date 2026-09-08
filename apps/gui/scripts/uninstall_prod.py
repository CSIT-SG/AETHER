#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from platformdirs import user_data_dir

SOURCE_DIR = Path(__file__).resolve().parent
ENTRYPOINT_NAME = "aether-next.py"
PYTHON_VERSIONS = {(3, 12), (3, 13)}
APP_AUTHOR = "AETHER-next"
APP_NAMES = ("gui", "rpc", "mcp", "_global")


def default_plugin_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / "Hex-Rays" / "IDA Pro" / "plugins"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Uninstall the AETHER GUI production plugin")
    parser.add_argument(
        "--plugin-path",
        type=Path,
        default=default_plugin_path(),
        help="IDA plugins directory to uninstall from",
    )
    return parser.parse_args()


def resolve_command(*names: str) -> str:
    for name in names:
        command = shutil.which(name)
        if command is not None:
            return command
    raise SystemExit(f"None of these commands are available on PATH: {', '.join(names)}")


def run(command: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, text=True)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


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


def remove_entrypoint(plugin_path: Path) -> None:
    destination = plugin_path / ENTRYPOINT_NAME
    if not destination.exists():
        print(f"Plugin entry point not found, skipping: {destination}")
        return
    remove_path(destination)


def remove_data_dirs() -> None:
    for appname in APP_NAMES:
        shutil.rmtree(
            user_data_dir(appname=appname, appauthor=APP_AUTHOR),
            ignore_errors=True,
        )


def main() -> None:
    args = parse_args()
    resolve_command("python", "python3")
    resolve_command("pip")

    if sys.version_info[:2] not in PYTHON_VERSIONS:
        raise SystemExit("Python 3.12 or 3.13 is required")

    bundle_dir = resource_dir()
    remove_entrypoint(args.plugin_path)
    remove_data_dirs()
    uninstall_requirements(bundle_dir)
    print(f"Uninstalled AETHER GUI production plugin from: {args.plugin_path}")


if __name__ == "__main__":
    main()
