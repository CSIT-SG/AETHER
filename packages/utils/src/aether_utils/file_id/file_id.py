import time
from pathlib import Path


def file_id(file_path: str) -> str:
    """
    Combines file path + current timestamp into an LLM-readable ID.
    Format: {cleaned_filename}_{timestamp}
    Example: "firmware-20230601-153000"
    """
    path = Path(file_path)

    # Clean stem (remove special chars, lowercase, max 20 chars)
    stem = path.stem.lower()
    stem = "".join(c if c.isalnum() else "-" for c in stem).strip("-")[:20]

    # Human-readable timestamp
    timestamp = time.strftime("%Y%m%d-%H%M%S")

    return f"{stem}_{timestamp}"
