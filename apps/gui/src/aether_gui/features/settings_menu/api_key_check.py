from __future__ import annotations

import asyncio
from collections.abc import Callable

from aether_utils.get_support import AgentSupport
from aether_utils.get_support.verify import verify_provider
from aether_utils.logger import get_logger
from PySide6 import QtCore

logger = get_logger("settings_api_key_check")

# Keep tasks referenced until their queued result is delivered on the UI thread.
_active: set[_ApiKeyCheckTask] = set()


class _Signals(QtCore.QObject):
    finished = QtCore.Signal(object)  # AgentSupport


class _ApiKeyCheckTask(QtCore.QRunnable):
    def __init__(self) -> None:
        super().__init__()
        self.setAutoDelete(False)  # lifetime managed via _active, not the thread pool
        self.signals = _Signals()

    def run(self) -> None:
        try:
            result = asyncio.run(verify_provider())
        except Exception as e:  # noqa: BLE001 - a worker thread must never crash the UI
            logger.exception("API key check failed to run")
            result = AgentSupport(False, f"Could not run the API key check: {e}")
        self.signals.finished.emit(result)


def run_check(on_finished: Callable[[AgentSupport], None]) -> None:
    """Probe the configured provider off the UI thread."""
    task = _ApiKeyCheckTask()
    _active.add(task)

    def _deliver(result: AgentSupport) -> None:
        _active.discard(task)
        on_finished(result)

    task.signals.finished.connect(_deliver)
    QtCore.QThreadPool.globalInstance().start(task)
