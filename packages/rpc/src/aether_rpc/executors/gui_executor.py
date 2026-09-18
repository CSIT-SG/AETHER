from collections.abc import Callable
from functools import partial
from typing import Any

import ida_kernwin
import idc

from .base import IDAExecutor


class _CaptureCallable:
    """wrapper for execution, returns result in result property"""

    def __init__(self, func: Callable[..., Any], args: dict[str, Any]):
        self._apply = partial(func, **args)
        self.result: Any = None

    def __call__(self) -> None:
        self.result = self._apply()


class GUIExecutor(IDAExecutor):
    def execute(
        self,
        callback: Callable[..., Any],
        arguments: dict[str, Any],
    ) -> Any:
        result = None
        func_call = _CaptureCallable(callback, arguments)
        prev = idc.batch(1)
        try:
            ida_kernwin.execute_sync(func_call, ida_kernwin.MFF_FAST)
        finally:
            idc.batch(prev)
        result = func_call.result
        return result

    def startup(self) -> None:
        pass

    def shutdown(self) -> None:
        pass
