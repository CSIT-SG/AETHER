import os
import threading
import time
from typing import Optional, Tuple

_RUN_STATE_LOCK = threading.Lock()
_VERBOSE_RUN_COUNTER = 0
_CURRENT_CTX_PATH: Optional[str] = None
_CURRENT_VERBOSE_PATH: Optional[str] = None
_CURRENT_CTX_ID: Optional[str] = None
_CURRENT_VERBOSE_ID: Optional[int] = None


def start_new_run(data_dir: str) -> Tuple[str, str]:
    """Start a new gatherer/annotator run and return ctx/verbose paths."""
    global _VERBOSE_RUN_COUNTER, _CURRENT_CTX_PATH, _CURRENT_VERBOSE_PATH
    global _CURRENT_CTX_ID, _CURRENT_VERBOSE_ID
    with _RUN_STATE_LOCK:
        _VERBOSE_RUN_COUNTER += 1
        _CURRENT_VERBOSE_ID = _VERBOSE_RUN_COUNTER
        timestamp_id = time.strftime("%d%m%Y%H%M")
        _CURRENT_CTX_ID = f"{timestamp_id}_{_CURRENT_VERBOSE_ID}"
        _CURRENT_CTX_PATH = os.path.join(data_dir, f"ctx{_CURRENT_CTX_ID}.txt")
        _CURRENT_VERBOSE_PATH = os.path.join(data_dir, f"verbose{_CURRENT_VERBOSE_ID}.txt")
        return _CURRENT_CTX_PATH, _CURRENT_VERBOSE_PATH


def get_current_run_paths() -> Tuple[Optional[str], Optional[str]]:
    """Return current ctx/verbose paths if a run is active."""
    return _CURRENT_CTX_PATH, _CURRENT_VERBOSE_PATH


def clear_current_run() -> Optional[str]:
    """Clear current run state and return the ctx path for cleanup."""
    global _CURRENT_CTX_PATH, _CURRENT_VERBOSE_PATH, _CURRENT_CTX_ID, _CURRENT_VERBOSE_ID
    with _RUN_STATE_LOCK:
        ctx_path = _CURRENT_CTX_PATH
        _CURRENT_CTX_PATH = None
        _CURRENT_VERBOSE_PATH = None
        _CURRENT_CTX_ID = None
        _CURRENT_VERBOSE_ID = None
        return ctx_path
