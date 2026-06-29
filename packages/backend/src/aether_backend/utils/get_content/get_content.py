from pathlib import Path

CONTENT_DIR = "content"


def get_content(cwd: Path, filename: str) -> str:
    """Load the content of a file from the content directory."""
    instructions_path = cwd / CONTENT_DIR / filename
    if not instructions_path.exists():
        raise FileNotFoundError(
            f"Content file '{filename}' not found in '{CONTENT_DIR}' directory."
        )
    return instructions_path.read_text(encoding="utf-8")
