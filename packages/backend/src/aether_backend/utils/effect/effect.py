import asyncio
import functools
from collections.abc import Callable, Coroutine
from typing import Any, ParamSpec

from fastmcp.server.dependencies import get_context

from .models import Log, Progress, Return, Sleep
from .types import Program

P = ParamSpec("P")


def effectful(  # noqa: UP047
    fn: Callable[P, Program],
) -> Callable[P, Coroutine[Any, Any, Any]]:
    """
    Wrap an async-generator tool function that yields Effects.

    eg:
    ```python

    async def process_items_cb(p: int, db_conn: Connection, rpc_registry: Registry) -> Program:
        ...

    @mcp.tool
    @effectful
    async def process_items(p: int, conn: Connection = Depends(get_db_connection), ctx: Context = CurrentContext()) -> Program:
        \"\"\"Process p items with streaming progress.\"\"\"
        async for effect in process_items_cb(p, conn, ctx.lifespan_context["rpc_registry"]):
            yield effect

    ```
    """

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        ctx = get_context()
        result: Any = None
        async for effect in fn(*args, **kwargs):
            match effect:
                case Progress(current, total, message):
                    await ctx.report_progress(current, total, message or None)
                case Log(message, level):
                    await ctx.log(message, level=level)
                case Sleep(seconds):
                    await asyncio.sleep(seconds)
                case Return(value):
                    result = value
                    break
            print(effect)
        return result

    return wrapper
