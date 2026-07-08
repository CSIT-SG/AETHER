#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent
ROOT_DIR = Path(__file__).resolve().parents[3]
DIST_DIR = ROOT_DIR / "dist" / "aether_cli"


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


def main() -> None:
    resolve_command("python", "python3")
    resolve_command("pip")

    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        raise SystemExit("Python 3.12 or 3.13 is required")

    bundle_dir = resource_dir()
    install_requirements(bundle_dir)
    print("Installed AETHER CLI dependencies")


if __name__ == "__main__":
    main()
