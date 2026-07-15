from __future__ import annotations

import asyncio

from aether_utils.logger import get_logger
from aether_utils.provider_check import CheckResult, ResultCallback
from aether_utils.provider_check.verify import verify_provider
from PySide6 import QtCore

logger = get_logger("settings_api_key_check")

# TODO:
# This runs the probe on a bespoke QThreadPool task (driven by the API-key field's
# Check button). Once Asher's GUI async runner lands, schedule verify_provider() on it
# instead of QThreadPool.

_active: set[_ApiKeyCheckTask] = set()


class _Signals(QtCore.QObject):
    finished = QtCore.Signal(object)  # CheckResult


class _ApiKeyCheckTask(QtCore.QRunnable):
    def __init__(self, api_key: str | None = None) -> None:
        super().__init__()
        self.setAutoDelete(False)
        self.signals = _Signals()
        self._api_key = api_key

    def run(self) -> None:
        try:
            result = asyncio.run(verify_provider(self._api_key))
        except Exception as e:  # noqa: BLE001
            logger.exception("API key check failed to run")
            result = CheckResult(False, f"Could not run the API key check: {e}", None)
        self.signals.finished.emit(result)


def run_check(api_key: str, on_finished: ResultCallback) -> None:
    """Validate ``api_key`` against the configured gateway off the UI thread, delivering
    the :class:`CheckResult` result to ``on_finished`` on the UI thread.

    Conforms to the field's ``CheckTask`` contract so it can be injected as the default
    gateway check; swap in another callable for a different provider or in tests.
    """
    task = _ApiKeyCheckTask(api_key)
    _active.add(task)

    def _deliver(result: CheckResult) -> None:
        _active.discard(task)
        on_finished(result)

    task.signals.finished.connect(_deliver)
    QtCore.QThreadPool.globalInstance().start(task)
