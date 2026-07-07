#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
GUI_DIR = ROOT_DIR / "apps" / "gui"
ENTRYPOINT_SOURCE = GUI_DIR / "src" / "plugin.py"
DEV_REQUIREMENTS = GUI_DIR / "scripts" / "utils" / "requirements.txt"
BUILD_SCRIPT = ROOT_DIR / "scripts" / "build.py"
BUILD_OUTPUT_DIR = ROOT_DIR / "dist" / "aether-gui"
BUILD_REQUIREMENTS = BUILD_OUTPUT_DIR / "requirements.txt"
BUILD_WHEELS_DIR = BUILD_OUTPUT_DIR / "wheels"
ENTRYPOINT_NAME = "aether-next.py"


def default_plugin_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / "AppData" / "Roaming" / "Hex-Rays" / "IDA Pro" / "plugins"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install the AETHER GUI IDA plugin")
    parser.add_argument("--dev", action="store_true", help="Install in development mode")
    parser.add_argument(
        "--plugin-path",
        type=Path,
        default=default_plugin_path(),
        help="IDA plugins directory to install into",
    )
    return parser.parse_args()


def resolve_command(name: str) -> str:
    command = shutil.which(name)
    if command is None:
        raise SystemExit(f"{name} is not installed or not on PATH")
    return command


def run(command: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, text=True)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def ensure_plugin_path(plugin_path: Path) -> None:
    plugin_path.mkdir(parents=True, exist_ok=True)


def install_requirements(pip_path: str, requirements_file: Path) -> None:
    run([pip_path, "install", "--user", "-r", str(requirements_file)], cwd=requirements_file.parent)


def build_production_artifacts(python_path: str) -> None:
    run([python_path, str(BUILD_SCRIPT)], cwd=ROOT_DIR)
    if not BUILD_REQUIREMENTS.exists():
        raise SystemExit(f"Production requirements file not found: {BUILD_REQUIREMENTS}")
    if not BUILD_WHEELS_DIR.exists():
        raise SystemExit(f"Production wheels directory not found: {BUILD_WHEELS_DIR}")


def copy_entrypoint(plugin_path: Path) -> None:
    destination = plugin_path / ENTRYPOINT_NAME
    remove_path(destination)
    shutil.copy2(ENTRYPOINT_SOURCE, destination)


def link_entrypoint(plugin_path: Path) -> None:
    destination = plugin_path / ENTRYPOINT_NAME
    remove_path(destination)
    os.symlink(ENTRYPOINT_SOURCE, destination)


def copy_wheels(plugin_path: Path) -> None:
    destination = plugin_path / "wheels"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    wheels = sorted(BUILD_WHEELS_DIR.glob("*.whl"))
    if not wheels:
        raise SystemExit(f"No wheels were built in {BUILD_WHEELS_DIR}")

    for wheel in wheels:
        shutil.copy2(wheel, destination / wheel.name)


def main() -> None:
    args = parse_args()
    resolve_command("python")
    pip_path = resolve_command("pip")
    python_path = sys.executable

    if sys.version_info < (3, 12):
        raise SystemExit("Python 3.12 or newer is required")

    if not ENTRYPOINT_SOURCE.exists():
        raise SystemExit(f"Entry point source not found: {ENTRYPOINT_SOURCE}")

    ensure_plugin_path(args.plugin_path)

    if args.dev:
        install_requirements(pip_path, DEV_REQUIREMENTS)
        link_entrypoint(args.plugin_path)
        print(f"Installed AETHER GUI dev entrypoint in: {args.plugin_path}")
        return

    build_production_artifacts(python_path)
    install_requirements(pip_path, BUILD_REQUIREMENTS)
    copy_wheels(args.plugin_path)
    copy_entrypoint(args.plugin_path)
    print(f"Installed AETHER GUI production artifacts in: {args.plugin_path}")


if __name__ == "__main__":
    main()
