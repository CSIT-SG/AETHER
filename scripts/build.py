import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

APPS = ["aether-gui"]
ROOT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = ROOT_DIR / "dist"

WHEELS_DIRNAME = "wheels"
REQUIREMENTS_FILENAME = "requirements.txt"

EDITABLE_RE = re.compile(r"^-e\s+(?P<path>\S+)")  # "-e ./packages/backend" -> "./packages/backend"


def sh(cmd: list[str]) -> str:
    result = subprocess.run(cmd, text=True, capture_output=True, cwd=ROOT_DIR)
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout


def mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


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


def prune_app_deps(app: str) -> None:

    app_out = OUTPUT_DIR / app

    wheels_dir = app_out / WHEELS_DIRNAME
    requirements_path = app_out / REQUIREMENTS_FILENAME
    mkdir(wheels_dir)

    with tempfile.TemporaryDirectory() as tmp:
        raw_path = Path(tmp) / f"reqs-raw-{uuid.uuid4().hex}.txt"

        # 1. PRUNE: export just this app's dependency closure
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

    for app in APPS:
        mkdir(OUTPUT_DIR / app)
        prune_app_deps(app)


if __name__ == "__main__":
    main()
