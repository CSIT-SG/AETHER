from collections.abc import Callable
from functools import partial
from typing import Any

import ida_kernwin

from .base import IDAExecutor


class GUIExecutor(IDAExecutor):
    def execute(
        self,
        callback: Callable[..., Any],
        arguments: dict[str, Any],
    ) -> Any:
        apply = partial(callback, **arguments)

        return ida_kernwin.execute_sync(
            apply,
            ida_kernwin.MFF_FAST,
        )

    def startup(self) -> None:
        pass

    def shutdown(self) -> None:
        pass
