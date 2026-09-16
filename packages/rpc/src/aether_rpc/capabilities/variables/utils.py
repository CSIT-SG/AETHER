"""functions to help process stack variables"""

import logging

import ida_name
import idautils
from aether_rpc.capabilities.function.utils import function_info
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import XrefEntry, XrefsResult


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


def collect_xrefs_result(func_ea: int, logger: logging.Logger) -> Result[XrefsResult]:
    """Collect every cross-reference pointing at ``func_ea``.

    Args:
        func_ea: The resolved effective address of the target.
        logger: Logger of the calling capability, used to report failures.

    Returns:
        Ok[XrefsResult] describing the target and its cross-references, or
        Err if IDA raised while walking the xrefs.
    """

    try:
        xrefs = [collect_xrefs(x) for x in idautils.XrefsTo(func_ea)]
    except Exception as e:
        logger.exception("Failed to collect xrefs at %s: %s", hex(func_ea), e)
        return Err(result=f"Failed to collect xrefs at {hex(func_ea)}: {e}")

    return Ok(
        result=XrefsResult(
            target_address=hex(func_ea),
            target_name=ida_name.get_name(func_ea) or None,
            count=len(xrefs),
            xrefs=xrefs,
        )
    )
