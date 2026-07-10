import re
import shutil
import tempfile
import uuid
from pathlib import Path

from .config import (
    APPS,
    OUTPUT_DIR,
    REQUIREMENTS_FILENAME,
    WHEELS_DIRNAME,
)
from .utils import cp_r, mkdir, sh

EDITABLE_RE = re.compile(r"^-e\s+(?P<path>\S+)")  # "-e ./packages/backend" -> "./packages/backend"
DEP_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)")  # "pyside6==6.11.1 ; marker" -> "pyside6"


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def drop_provided(lines: list[str], provided: set[str]) -> list[str]:
    """Drop host-provided deps (e.g. PySide6, supplied by IDA) and their `# via` blocks."""
    kept: list[str] = []
    skipping = False
    for line in lines:
        is_spec = bool(line) and not line[0].isspace() and not line.lstrip().startswith("#")
        if is_spec:
            match = DEP_NAME_RE.match(line)
            skipping = match is not None and _normalize(match.group("name")) in provided
        if not skipping:
            kept.append(line)
    return kept


def split_export(text: str) -> tuple[list[str], list[str]]:
    """split local deps from external deps"""
    local_paths: list[str] = []
    kept_lines: list[str] = []
    for line in text.splitlines():
        match = EDITABLE_RE.match(line.strip())
        if match:
            local_paths.append(match.group("path"))
        else:
            kept_lines.append(line)
    return local_paths, kept_lines


def prune_app_deps(
    app: str, requirements_path: Path, wheels_dir: Path, provided_deps: list[str]
) -> None:

    with tempfile.TemporaryDirectory() as tmp:
        raw_path = Path(tmp) / f"reqs-raw-{uuid.uuid4().hex}.txt"

        # export just this app's dependency closure
        sh(
            [
                "uv",
                "export",
                "--package",
                app,
                "--no-dev",
                "--no-hashes",
                "--output-file",
                str(raw_path),
            ]
        )

        local_deps, external_deps = split_export(raw_path.read_text())

    external_deps = drop_provided(external_deps, {_normalize(d) for d in provided_deps})

    ext = "\n".join(external_deps)

    for pkg_path in local_deps:
        sh(["uv", "build", "--wheel", "--out-dir", str(wheels_dir), pkg_path])
        print(f"Built wheel for {pkg_path} in {wheels_dir}")

    with requirements_path.open("a") as f:
        f.write(f"--find-links {WHEELS_DIRNAME}\n")
        for whl in wheels_dir.glob("*.whl"):
            f.write(
                f"{WHEELS_DIRNAME}/{whl.name}\n"
            )  # pip accepts posix-style paths on all platforms
        f.write(ext)


def main() -> None:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)

    for app, cfg in APPS.items():
        # create output directories
        app_out = OUTPUT_DIR / app
        mkdir(app_out)

        wheels_dir = app_out / WHEELS_DIRNAME
        requirements_path = app_out / REQUIREMENTS_FILENAME
        mkdir(wheels_dir)

        # prune the app's dependencies and build wheels
        prune_app_deps(app, requirements_path, wheels_dir, cfg["provided_deps"])

        for inode in cfg["extra_inodes"]:
            cp_r(inode, app_out / inode.name)
            print(f"Copied extra inode {inode} to {app_out / inode.name}")


if __name__ == "__main__":
    main()
