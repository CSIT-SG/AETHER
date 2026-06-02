from collections.abc import Callable
from functools import partial
from typing import Any

import ida_kernwin

from .base import IDAExecutor


class GUIExecutor(IDAExecutor):
    async def execute(self, callback: Callable[..., Any], arguments: dict[str, Any]) -> Any:
        apply = partial(callback, **arguments)
        # run the callback in the main thread and wait for the result, since IDA's API is not thread safe
        return ida_kernwin.execute_sync(apply, ida_kernwin.MFF_FAST)

    async def startup(self) -> None:
        pass  # plugin already loaded IDA

    async def shutdown(self) -> None:
        pass  # don't kill IDA when the RPC server stops
