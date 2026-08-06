from __future__ import annotations

from collections.abc import AsyncIterator

from aether_gui.runner import get_shared_worker_manager
from aether_gui.runner.base_task import BaseTask
from aether_utils.logger import get_logger
from aether_utils.provider_check import CheckResult, ResultCallback
from aether_utils.provider_check.verify import verify_provider

logger = get_logger("settings_api_key_check")


class ApiKeyCheckTask(BaseTask[CheckResult]):
    """Validates an API key against the configured gateway."""

    async def run(self, api_key: str | None = None) -> AsyncIterator[CheckResult]:
        try:
            result = await verify_provider(api_key)
        except Exception as e:  # noqa: BLE001
            logger.exception("API key check failed to run")
            result = CheckResult(False, f"Could not run the API key check: {e}", None)
        yield result

    async def close(self) -> None:
        return None


def run_check(api_key: str, on_finished: ResultCallback) -> None:
    """Validate ``api_key`` against the configured gateway off the UI thread."""
    worker_manager = get_shared_worker_manager()
    handle = worker_manager.submit(ApiKeyCheckTask(), api_key=api_key)

    def _on_error(err: BaseException) -> None:
        logger.exception("API key check failed to run")
        on_finished(CheckResult(False, f"Could not run the API key check: {err}", None))

    worker_manager.consume(handle, on_event=on_finished, on_error=_on_error)
