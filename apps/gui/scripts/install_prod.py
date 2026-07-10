#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent
ROOT_DIR = Path(__file__).resolve().parents[3]
DIST_DIR = ROOT_DIR / "dist" / "aether_gui"
ENTRYPOINT_NAME = "aether-next.py"


def default_plugin_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / "Hex-Rays" / "IDA Pro" / "plugins"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install the AETHER GUI production plugin")
    parser.add_argument(
        "--plugin-path",
        type=Path,
        default=default_plugin_path(),
        help="IDA plugins directory to install into",
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


def ensure_plugin_path(plugin_path: Path) -> None:
    plugin_path.mkdir(parents=True, exist_ok=True)


def remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def resource_dir() -> Path:
    if (SOURCE_DIR / "requirements.txt").exists() and (SOURCE_DIR / "wheels").exists():
        return SOURCE_DIR
    if (DIST_DIR / "requirements.txt").exists() and (DIST_DIR / "wheels").exists():
        return DIST_DIR
    raise SystemExit("Production wheel bundle was not found")


def install_requirements(bundle_dir: Path) -> None:
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--user",
            "-r",
            str(bundle_dir / "requirements.txt"),
        ],
        cwd=bundle_dir,
    )


def copy_entrypoint(plugin_path: Path, bundle_dir: Path) -> None:
    source = bundle_dir / "plugin.py"
    if not source.exists():
        raise SystemExit(f"Entry point source not found: {source}")
    destination = plugin_path / ENTRYPOINT_NAME
    remove_path(destination)
    shutil.copy2(source, destination)


def main() -> None:
    args = parse_args()
    resolve_command("python", "python3")
    resolve_command("pip")

    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        raise SystemExit("Python 3.12 or 3.13 is required")

    bundle_dir = resource_dir()
    ensure_plugin_path(args.plugin_path)
    install_requirements(bundle_dir)
    copy_entrypoint(args.plugin_path, bundle_dir)
    print(f"Installed AETHER GUI production plugin in: {args.plugin_path}")


if __name__ == "__main__":
    main()
