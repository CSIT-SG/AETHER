from collections.abc import AsyncIterator
from typing import Any

from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import FuncNameAddr, FunctionPseudocode, ListFunctionResult

from .is_non_common_function import is_non_common_function
from .types import PseudocodeYield


async def collect_pseudocode(
    service: Any,
    min_size: int = 16,
) -> AsyncIterator[PseudocodeYield]:
    """Return pseudocode for every non-common function in the binary.

    Composes service.list_functions() -> is_non_common_function filter ->
    service.get_function_pseudocode() over RPC. Individual decompile
    failures are skipped rather than failing the whole batch.

    Args:
        service: RPC client/server handle exposing `list_functions()` and
            `get_function_pseudocode(function_name: str)`, each returning
            a Result as defined in this package.
        min_size: Minimum function size in bytes to be considered worth
            analyzing (passed to is_non_common_function).

    Returns:
        An async iterator yielding PseudocodeYield objects for each function.
    """
    list_result: Result[ListFunctionResult] = service.list_functions()
    print(f"list_result: {list_result}")
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
            size=f["size"],
            min_size=min_size,
        )
    ]

    for func in candidates:
        pc_result: Result[FunctionPseudocode] = service.get_function_pseudocode(
            function_name=func["function_name"]
        )

        if pc_result.success is False:
            yield PseudocodeYield(success=False, result=pc_result.result)
        else:
            yield PseudocodeYield(success=True, result=pc_result.result["pseudocode"])
