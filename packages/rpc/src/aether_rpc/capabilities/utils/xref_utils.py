from typing import Any

import idautils

from .function_utils import function_info
from .symbol_utils import name_or_address, xref_type


def collect_xrefs(ea: int, limit: int = 10) -> tuple[list[dict[str, Any]], int, list[str]]:
    """Collect xrefs to ea up to a preview limit.

    Args:
        ea: Target address to collect xrefs for.
        limit: Maximum number of xrefs to collect in the preview.

    Returns:
        Tuple of (preview list, total count, warnings list).
    """
    preview: list[dict[str, Any]] = []
    warnings: list[str] = []
    total = 0

    for xref in idautils.XrefsTo(ea):  # type: ignore[assignment]
        total += 1
        if len(preview) < limit:
            try:
                context, is_start = function_info(xref.frm)  # type: ignore[attr-defined]
                preview.append({
                    "from": hex(xref.frm),  # type: ignore[attr-defined]
                    "name": name_or_address(xref.frm),  # type: ignore[attr-defined]
                    "type": xref_type(xref.type),  # type: ignore[attr-defined]
                    "context": context,
                    "is_function_start": is_start,
                })
            except Exception as e:
                warnings.append(f"xref entry failed: {e}")

    return preview, total, warnings
