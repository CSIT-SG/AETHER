from typing import Any

from aether_rpc.capabilities.types import FunctionPseudocode

from .is_non_common_function import is_non_common_function


def collect_functions_with_pseudocode(
    service: Any,
    min_size: int = 16,
) -> tuple[list[FunctionPseudocode], list[FunctionPseudocode]]:
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
        A tuple containing the list of successfully decompiled functions and the list of failed functions.
    """
    list_result = service.list_functions()
    if not list_result.success:
        raise RuntimeError(f"Failed to list functions: {list_result.result}")

    candidates = [
        f
        for f in list_result.result.functions
        if is_non_common_function(
            name=f.function_name,
            is_lib=f.is_lib,
            is_thunk=f.is_thunk,
            size=f.size,
            min_size=min_size,
        )
    ]

    decompiled: list[FunctionPseudocode] = []
    failed: list[FunctionPseudocode] = []

    for func in candidates:
        pc_result = service.get_function_pseudocode(function_name=func.function_name)
        if pc_result.success is False:
            failed.append(func)
            continue
        decompiled.append(pc_result.result)

    return decompiled, failed
