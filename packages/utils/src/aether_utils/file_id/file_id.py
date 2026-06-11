import hashlib
import time
from pathlib import Path


def file_id(file_path: str) -> str:
    """
    Combines file path + current timestamp into an LLM-readable ID.
    Format: {cleaned_filename}_{timestamp}_{short_hash}
    Example: "firmware-20230601-153000_a1b2c3"
    """
    path = Path(file_path)

    # Clean stem (remove special chars, lowercase, max 20 chars)
    stem = path.stem.lower()
    stem = "".join(c if c.isalnum() else "-" for c in stem).strip("-")[:20]

    # Human-readable timestamp
    timestamp = time.strftime("%Y%m%d-%H%M%S")

    # Short hash from path + timestamp for uniqueness
    raw = f"{file_path}:{timestamp}"
    short_hash = hashlib.sha256(raw.encode()).hexdigest()[:6]

    return f"{stem}_{timestamp}_{short_hash}"
