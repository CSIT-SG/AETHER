"""Function context and metadata helpers for capabilities."""

import ida_funcs
import ida_idaapi
import idc


def function_info(ea: int) -> tuple[str, bool]:
    """Return (context string, is_function_start) for ea in a single IDA call.

    Args:
        ea: Effective address to inspect.

    Returns:
        Tuple of a readable context string and a boolean indicating
        whether ea is the start of a function.
    """
    try:
        func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if func_start == ida_idaapi.BADADDR:
            return "outside_function", False
        func_name = idc.get_func_name(ea) or f"0x{func_start:X}"
        is_start = ea == func_start
        context = (
            f"function_start:{func_name}"
            if is_start
            else f"in_function:{func_name}+0x{ea - func_start:X}"
        )
        return context, is_start
    except Exception:
        return "outside_function", False

def get_function(ea: int) -> dict[str, str | int] | None:
    func = ida_funcs.get_func(ea)
    if func is None:
        return None

    return {
        "name": idc.get_func_name(func.start_ea),
        "start_address": hex(func.start_ea),
        "end_address": hex(func.end_ea),
        "size_bytes": func.size(),
        "flags": hex(func.flags),
    }
