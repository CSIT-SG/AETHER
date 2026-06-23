import os
import threading
from datetime import datetime


_LOG_LOCK = threading.Lock()


def _get_log_dir() -> str:
    """Resolve a cross-platform writable directory for Fanalysis logs."""
    if os.name == "nt":
        base_dir = os.getenv("LOCALAPPDATA")
        if not base_dir:
            base_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    else:
        base_dir = os.getenv("XDG_STATE_HOME") or os.getenv("XDG_DATA_HOME")
        if not base_dir:
            base_dir = os.path.join(os.path.expanduser("~"), ".local", "share")

    return os.path.join(base_dir, "AETHER-IDA")


def get_fanalysis_error_log_path() -> str:
    """Return the path to the persistent Fanalysis error log file."""
    return os.path.join(_get_log_dir(), "fanalysis_error.log")


def log_fanalysis_error(message: str) -> None:
    """Append an error message to the Fanalysis error log and keep console visibility."""
    text = (message or "").strip()
    if not text:
        return

    try:
        log_dir = _get_log_dir()
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "fanalysis_error.log")

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        with _LOG_LOCK:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"[{timestamp}] {text}\n")
    except Exception:
        # Logging should never break the main analysis flow.
        pass
