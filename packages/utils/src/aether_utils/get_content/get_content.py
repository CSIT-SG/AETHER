from pathlib import Path

CONTENT_DIR = "content"


def get_content(cwd: Path, filename: str, *, content_dir: str = CONTENT_DIR) -> str:
    """Load the content of a file from the content directory."""
    instructions_path = cwd / content_dir / filename
    if not instructions_path.exists():
        raise FileNotFoundError(
            f"Content file '{filename}' not found in '{content_dir}' directory."
        )
    return instructions_path.read_text(encoding="utf-8")
