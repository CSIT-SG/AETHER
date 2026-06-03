"""Symbol-related helper utilities for IDA capability modules."""

import idc


def name_or_address(ea: int) -> str:
    """Return the symbol name at ea, or its hex address if unnamed."""
    try:
        name = idc.get_name(ea)
        return name if name else f"0x{ea:X}"
    except Exception:
        return f"0x{ea:X}"


def symbol_hints(name: str) -> str:
    """Return a hint derived from IDA's auto-naming conventions."""
    if not name:
        return "none"
    if name.startswith("sub_"):
        return "auto_function"
    if name.startswith("unk_"):
        return "unknown_symbol"
    if name.startswith("off_"):
        return "offset_symbol"
    if name.startswith(("byte_", "word_", "dword_", "qword_")):
        return "typed_data_symbol"
    if name.startswith("asc_"):
        return "string_like_symbol"
    return "none"


def xref_type(xref_type: int) -> str:
    """Convert a numeric xref type to a readable label."""
    return {
        1: "Data_Offset",
        2: "Data_Write",
        3: "Data_Read",
        16: "Code_Call",
        17: "Code_Call",
        21: "Code_Jump",
    }.get(xref_type, "Unknown")
