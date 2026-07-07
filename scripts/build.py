import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

APPS = ["aether-gui"]
OUTPUT_DIR = Path(__file__).parent.parent / "dist"
WHEELS_DIRNAME = "wheels"
REQUIREMENTS_FILENAME = "requirements.txt"

EDITABLE_RE = re.compile(r"^-e\s+(?P<path>\S+)")  # "-e ./packages/backend" -> "./packages/backend"


def sh(cmd: list[str]) -> None:
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        sys.exit(result.returncode)


def split_export(text: str) -> tuple[list[str], str]:
    """Pull out the -e workspace paths; leave every other line untouched."""
    local_paths: list[str] = []
    kept_lines: list[str] = []
    for line in text.splitlines():
        match = EDITABLE_RE.match(line.strip())
        if match:
            local_paths.append(match.group("path"))
        else:
            kept_lines.append(line)
    return local_paths, "\n".join(kept_lines)


def prune_app(app: str) -> None:
    app_out = OUTPUT_DIR / app
    wheels_dir = app_out / WHEELS_DIRNAME
    requirements_path = app_out / REQUIREMENTS_FILENAME
    app_out.mkdir(parents=True, exist_ok=True)
    wheels_dir.mkdir(parents=True, exist_ok=True)

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
                "--no-emit-package",
                app,
                "--output-file",
                str(raw_path),
            ]
        )

        local_paths, external_text = split_export(raw_path.read_text())

    # 2. write everything that isn't a -e workspace path
    requirements_path.write_text(external_text)

    # 3. COPY: build a real wheel for every internal workspace package needed
    for pkg_path in local_paths:
        sh(["uv", "build", "--wheel", "--out-dir", str(wheels_dir), pkg_path])

    # 4. append the built wheels to requirements.txt so one `pip install -r` installs everything
    with requirements_path.open("a") as f:
        f.write("\n# local wheels\n")
        for wheel_path in sorted(wheels_dir.glob("*.whl")):
            f.write(f"{wheel_path.resolve().as_posix()}\n")


def main() -> None:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)

    for app in APPS:
        prune_app(app)
        wheel_count = len(list((OUTPUT_DIR / app / WHEELS_DIRNAME).glob("*.whl")))
        print(f"{app}: wrote {OUTPUT_DIR / app / REQUIREMENTS_FILENAME} and {wheel_count} wheel(s)")


if __name__ == "__main__":
    main()
