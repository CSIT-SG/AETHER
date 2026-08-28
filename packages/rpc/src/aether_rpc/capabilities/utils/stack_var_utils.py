"""functions to help process stack variables"""

import ida_frame
import ida_funcs
import ida_name
import ida_typeinf
from ida_funcs import func_t

from ..types import StackVariableInfo, XrefEntry
from .address_utils import resolve_effective_address
from .function_utils import function_info


def resolve_stack_variable(
    func_location: str | int,
    var_name: str,
) -> StackVariableInfo | None:
    """Resolve a local/stack variable name within a given function to its
    (start_offset, end_offset) in the function's frame UDT.

    Args:
        func_location: Function name, hex address string, or effective
            address identifying the function that owns the stack variable.
        var_name: The name of the local/stack variable (e.g. "var_10",
            or a user-renamed local).

    Returns:
        A tuple (func, start_off, end_off) in bytes if found, else None.
    """
    func_ea: int | None = resolve_effective_address(func_location)
    if func_ea is None:
        return None

    func: func_t | None = ida_funcs.get_func(func_ea)
    if func is None:
        return None

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        return None

    frame_udt = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(frame_udt):
        return None

    for udm in frame_udt:
        if udm.is_gap():
            continue
        if udm.name == var_name:
            start_off: int = udm.begin() // 8
            end_off: int = udm.end() // 8
            return StackVariableInfo(function=func, start_off=start_off, end_off=end_off)

    return None


def collect_stkvar_xrefs(stack_vars: StackVariableInfo) -> list[XrefEntry] | None:
    """Collect xrefs to a stack variable's offset range
    and normalize entries to a shape similar to
    collect_xrefs()'s output.

    Args:
        func: The func_t owning the frame.
        start_off: Start offset (bytes) of the variable within the frame.
        end_off: End offset (bytes) of the variable within the frame.

    Returns:
        A list of strings, each represents an xref.
    """
    func: func_t = stack_vars["function"]
    start_off: int = stack_vars["start_off"]
    end_off: int = stack_vars["end_off"]
    xreflist = ida_frame.xreflist_t()
    ida_frame.build_stkvar_xrefs(xreflist, func, start_off, end_off)
    if len(xreflist) == 0:
        return None
    owner = function_info(func.start_ea)
    result: list[XrefEntry] = []
    for entry in xreflist:
        xref = XrefEntry(
            from_address=hex(entry.ea),
            type=entry.type,
            is_code=True,
            from_name=ida_name.get_name(entry.ea),
            from_function=owner,
        )
        result.append(xref)
    return result
