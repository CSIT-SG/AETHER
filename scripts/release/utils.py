import shutil
import subprocess
import sys
from pathlib import Path

from .config import ROOT_DIR


def sh(cmd: list[str]) -> str:
    result = subprocess.run(cmd, text=True, capture_output=True, cwd=ROOT_DIR)
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout


def mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def cp_r(src: Path, dst: Path) -> None:
    if src.is_file():
        shutil.copy2(src, dst)
    elif src.is_dir():
        shutil.copytree(src, dst)
    else:
        raise ValueError(f"Extra inode {src} is neither a file nor a directory")
