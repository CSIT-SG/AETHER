"""Shared helpers for gatherer/annotator run-specific logging paths."""

import os
import threading
import time
from typing import Optional, Tuple

from . import get_data_directory

_CTX_CONFIG_KEY = "_analysis_ctx_file_path"
_VERBOSE_CONFIG_KEY = "_analysis_verbose_log_path"
_VERBOSE_INDEX_CONFIG_KEY = "_analysis_verbose_index"

_VERBOSE_COUNTER_LOCK = threading.Lock()
_VERBOSE_COUNTER = 0


def _next_verbose_index() -> int:
    global _VERBOSE_COUNTER
    with _VERBOSE_COUNTER_LOCK:
        _VERBOSE_COUNTER += 1
        return _VERBOSE_COUNTER


def start_new_run_paths(config: Optional[dict] = None) -> Tuple[str, str]:
    """Create a new ctx/verbose path pair for this analysis run."""
    timestamp = time.strftime("%d%m%Y%H%M%S", time.localtime())
    data_dir = get_data_directory()
    ctx_dir = os.path.join(data_dir, "context temp")
    verbose_dir = os.path.join(data_dir, "verbose files")
    os.makedirs(ctx_dir, exist_ok=True)
    os.makedirs(verbose_dir, exist_ok=True)
    ctx_path = os.path.join(ctx_dir, f"ctx{timestamp}.txt")
    verbose_index = _next_verbose_index()
    verbose_path = os.path.join(verbose_dir, f"verbose{verbose_index}.txt")

    if config is not None:
        config[_CTX_CONFIG_KEY] = ctx_path
        config[_VERBOSE_CONFIG_KEY] = verbose_path
        config[_VERBOSE_INDEX_CONFIG_KEY] = verbose_index

    return ctx_path, verbose_path


def ensure_run_paths(config: Optional[dict] = None) -> Tuple[str, str]:
    """Return existing run paths from config or create a new pair."""
    if config is not None:
        ctx_path = config.get(_CTX_CONFIG_KEY)
        verbose_path = config.get(_VERBOSE_CONFIG_KEY)
        if ctx_path and verbose_path:
            return ctx_path, verbose_path

    return start_new_run_paths(config)


def cleanup_ctx_file(config: Optional[dict] = None) -> bool:
    """Delete the run-scoped ctx file after annotation completes."""
    if config is None:
        return False

    ctx_path = config.pop(_CTX_CONFIG_KEY, None)
    config.pop(_VERBOSE_CONFIG_KEY, None)
    config.pop(_VERBOSE_INDEX_CONFIG_KEY, None)

    if not ctx_path:
        return False

    try:
        if os.path.exists(ctx_path):
            os.remove(ctx_path)
            print(f"[AETHER] Removed analysis context file: {ctx_path}")
            return True
    except FileNotFoundError:
        return False
    except OSError as e:
        print(f"[AETHER] Warning: Could not remove analysis context file {ctx_path}: {e}")

    return False