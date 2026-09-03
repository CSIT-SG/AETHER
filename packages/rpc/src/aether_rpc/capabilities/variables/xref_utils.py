import ida_name
import idautils
from aether_rpc.capabilities.function.function_utils import function_info
from aether_rpc.capabilities.variables.types import XrefEntry


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
