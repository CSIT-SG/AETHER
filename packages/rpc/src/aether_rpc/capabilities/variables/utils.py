"""functions to help process stack variables"""

import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idautils
from aether_rpc.capabilities.function.utils import function_info
from aether_rpc.capabilities.types import StackVariableInfo, XrefEntry
from ida_funcs import func_t


def resolve_stack_variable(var_name: str, func_ea: int) -> StackVariableInfo | None:
    """Resolve a local/stack variable name within a given function to its
    (start_offset, end_offset) in the function's frame UDT.

    Args:
        var_name: The name of the local/stack variable (e.g. "var_10",
            or a user-renamed local).
        func_ea: The resolved effective address of the function that owns
            the stack variable.

    Returns:
        A StackVariableInfo containing the function, start_off, and end_off
        (in bytes) if found, else None.
    """
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
            return StackVariableInfo(caller_func_ea=func_ea, start_off=start_off, end_off=end_off)

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
    func_ea: int = stack_vars["caller_func_ea"]
    start_off: int = stack_vars["start_off"]
    end_off: int = stack_vars["end_off"]
    xreflist = ida_frame.xreflist_t()

    func: func_t | None = ida_funcs.get_func(func_ea)
    if func is None:
        return None

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


def resolve_stack_variable_name(func_ea: int, variable: str) -> str | None:
    """Resolve a Hex-Rays pseudocode variable name to its underlying stack
    frame member name (e.g. "var_120"), by stack offset rather than name match.

    Args:
        func_ea: Address of the function to inspect.
        variable: Name of the pseudocode (decompiler) local variable.

    Returns:
        The frame member name corresponding to the pseudocode variable, or
        None if the function/lvar can't be resolved, the lvar isn't a stack
        variable, or no frame member exists at the computed offset.
    """
    pfn = ida_funcs.get_func(func_ea)
    if pfn is None:
        return None

    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        return None

    lvar: ida_hexrays.lvar_t | None = None
    for candidate in cfunc.get_lvars():
        if candidate.name == variable:
            lvar = candidate
            break

    if lvar is None or not lvar.is_stk_var():
        return None

    # cfunc.get_stkoff_delta() is the documented conversion factor between
    # decompiler lvar stack offsets and true frame-struct offsets.
    frame_offset: int = lvar.get_stkoff() + cfunc.get_stkoff_delta()

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, pfn):
        return None

    udt_data = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(udt_data):
        return None

    for member in udt_data:
        if member.offset // 8 == frame_offset:
            return member.name

    return None


def collect_xrefs(xref) -> XrefEntry:
    """Build a structured entry describing a single cross-reference.

    Flattens an IDA xref object into a serializable dict that includes
    both the raw reference data and contextual information about the
    source address (its symbol name and containing function, if any).

    Args:
        xref: An xref object yielded by ``idautils.XrefsTo`` or
            ``idautils.XrefsFrom``. Expected to expose ``frm``, ``type``,
            and ``iscode`` attributes.

    Returns:
        A dict with ``from_address`` (hex string of the referencing
        address), ``type`` (readable xref type name such as
        ``"Code_Near_Call"`` or ``"Data_Read"``), ``is_code`` (whether
        the reference is a code xref), ``from_name`` (symbol at the
        source address, or ``None``), and ``from_function`` (metadata
        for the containing function, or ``None`` if the source is not
        inside a function).
    """

    return {
        "from_address": hex(xref.frm),
        "type": idautils.XrefTypeName(xref.type),
        "is_code": bool(xref.iscode),
        "from_name": ida_name.get_name(xref.frm) or None,
        "from_function": function_info(xref.frm),
    }
