#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
GUI_DIR = ROOT_DIR / "apps" / "gui"
ENTRYPOINT_SOURCE = GUI_DIR / "src" / "plugin_dev.py"
ENTRYPOINT_NAME = "aether-next-dev.py"


def default_plugin_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / "Hex-Rays" / "IDA Pro" / "plugins"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install the AETHER GUI development plugin")
    parser.add_argument(
        "--plugin-path",
        type=Path,
        default=default_plugin_path(),
        help="IDA plugins directory to install into",
    )
    parser.add_argument(
        "--force-reinstall",
        help="Force reinstall even if the dependencies already exist",
        action="store_true",
        default=False,
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


def export_requirements(uv_path: str) -> Path:
    with tempfile.NamedTemporaryFile(
        prefix="aether-gui-dev-", suffix=".txt", delete=False
    ) as temp_handle:
        requirements_path = Path(temp_handle.name)

    requirements_path = Path(temp_handle.name)
    run(
        [
            uv_path,
            "export",
            "--all-packages",
            "--no-emit-workspace",
            "--no-hashes",
            "--output-file",
            str(requirements_path),
        ],
        cwd=ROOT_DIR,
    )
    return requirements_path


def install_requirements(
    uv_path: str, requirements_path: Path, *, force_reinstall: bool = False
) -> None:
    cmd = [uv_path, "pip", "install", "--user", "-r", str(requirements_path)]
    if force_reinstall:
        cmd.append("--reinstall")
    run(cmd, cwd=requirements_path.parent)


def link_entrypoint(plugin_path: Path) -> None:
    destination = plugin_path / ENTRYPOINT_NAME
    remove_path(destination)
    os.symlink(ENTRYPOINT_SOURCE, destination)


def main() -> None:
    args = parse_args()
    resolve_command("python", "python3")
    resolve_command("pip")
    uv_path = resolve_command("uv")

    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        raise SystemExit("Python 3.12 or 3.13 is required")

    if not ENTRYPOINT_SOURCE.exists():
        raise SystemExit(f"Entry point source not found: {ENTRYPOINT_SOURCE}")

    ensure_plugin_path(args.plugin_path)
    requirements_path = export_requirements(uv_path)

    try:
        install_requirements(uv_path, requirements_path, force_reinstall=args.force_reinstall)
    finally:
        requirements_path.unlink(missing_ok=True)

    link_entrypoint(args.plugin_path)
    print(f"Installed AETHER GUI dev plugin in: {args.plugin_path}")


if __name__ == "__main__":
    main()
