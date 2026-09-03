import asyncio
from typing import Any

from aether_rpc.capabilities.function.types import FuncNameAddr, ListFunctionResult
from aether_rpc.capabilities.result import Result

from .is_non_common_function import is_non_common_function


async def collect_functions(
    service: Any,
    min_size: int = 0x10,
    max_size: int = 0x10000,
) -> list[FuncNameAddr]:

    try:
        list_result: Result[ListFunctionResult] = await asyncio.to_thread(service.list_functions)
    except (EOFError, ConnectionError, OSError):
        raise

    if not list_result.success:
        raise RuntimeError(f"Failed to list functions: {list_result.result}")

    assert not isinstance(list_result.result, str), (
        "Invariant violation: list_result.result should not be a string on success"
    )

    functions: list[FuncNameAddr] = list_result.result["functions"]

    candidates = [
        f
        for f in functions
        if is_non_common_function(
            name=f["function_name"],
            is_lib=f["is_lib"],
            is_thunk=f["is_thunk"],
        )
        and f["size"] <= max_size
        and f["size"] >= min_size
    ]

    return candidates
