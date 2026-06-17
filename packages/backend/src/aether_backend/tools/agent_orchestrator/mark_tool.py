import functools
from collections.abc import Callable
from typing import Any, ParamSpec

P = ParamSpec("P")


def subagent(fn: Callable[P, Any]) -> Callable[P, Any]:
    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        # TODO: add a check in configuration to ensure that the router has keys set
        return fn(*args, **kwargs)

    return wrapper
