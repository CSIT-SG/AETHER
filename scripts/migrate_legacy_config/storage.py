import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from .workspace import ensure_utils_src_on_path

ensure_utils_src_on_path()

from aether_utils.json import load_json_object  # noqa: E402


def read_json(path: Path) -> dict[str, Any]:
    return load_json_object(path.read_text(encoding="utf-8"))


def stable_digest(config: dict[str, Any]) -> str:
    text = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def backup_existing_config(path: Path) -> Path | None:
    if not path.is_file():
        return None

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    backup_path = path.with_name(f"{path.name}.bak-{timestamp}")
    shutil.copy2(path, backup_path)
    return backup_path
