"""Function context and metadata helpers for capabilities."""

import ida_funcs
from aether_rpc.capabilities.types import FunctionInfo, FunctionMetadata


def function_info(ea: int) -> FunctionInfo | None:
    """Return brief identifying info for the function containing ``ea``.

    Lightweight companion to ``get_function``: returns just the name and
    entry address, suitable for embedding as context inside larger
    result structures (e.g. xref entries or address lookups) where the
    full function metadata would be excessive.

    Args:
        ea: Effective address. May be the function's entry point or any
            address within its body; IDA resolves the containing function.

    Returns:
        A dict with ``name`` and ``start_address`` (hex string), or
        ``None`` if no function contains ``ea``.
    """

    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return {
        "name": ida_funcs.get_func_name(func.start_ea),
        "start_address": hex(func.start_ea),
    }


def get_function(ea: int) -> FunctionMetadata | None:
    """Return metadata for the function containing ``ea``.

    Looks up the ``func_t`` containing the given address and extracts the
    fields used across tools that report function information. Returns
    ``None`` when ``ea`` is not inside any recognized function.

    Args:
        ea: Effective address. May be the function's entry point or any
            address within its body; IDA resolves the containing function.

    Returns:
        A dict with ``name``, ``start_address`` (hex string), ``end_address``
        (hex string), ``size_bytes`` (int), and ``flags`` (hex string), or
        ``None`` if no function contains ``ea``.
    """

    func = ida_funcs.get_func(ea)
    if func is None:
        return None

    return {
        "name": ida_funcs.get_func_name(func.start_ea),
        "start_address": hex(func.start_ea),
        "end_address": hex(func.end_ea),
        "size_bytes": func.size(),
        "flags": hex(func.flags),
    }
