"""Data extraction from IDA databases using idapro.

This module opens an IDB file via Hex-Rays' official idapro package and
extracts the function-level information needed for rubric evaluation.

Note on imports: `idapro` must be imported at module level, but the IDA
submodules (`idc`, `ida_funcs`, ...) only become importable *after*
`idapro.open_database()` has been called. They are therefore imported inside
`extract_function_state`, after the database is open.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── IDA discovery ──────────────────────────────────────────────────────────────
# idapro needs IDADIR set to find IDA's Python modules. Try the env var, then
# common install locations, and set IDADIR before importing idapro so it works
# even when run from a plain system Python (not IDA's bundled interpreter).
_COMMON_IDA_DIRS = [
    Path(os.environ.get("IDADIR", "")),
    Path(os.environ.get("AETHER_IDA_DIR", "")),
    Path(r"C:\Program Files\IDA Professional 9.2"),
    Path(r"C:\Program Files\IDA Professional"),
    Path(r"C:\Program Files\idaPro 9.2"),
    Path(r"C:\Program Files\idaPro"),
    Path(r"C:\Program Files\Hex-Rays\IDA Pro 9.2"),
    Path(r"C:\Program Files\IDA Pro 9.2"),
    Path(r"C:\Program Files\IDA Pro"),
    Path(r"C:\IDA Pro 9.2"),
    Path("/opt/ida-pro"),
]


def _set_ida_dir() -> str | None:
    if os.environ.get("IDADIR"):
        return os.environ["IDADIR"]
    for candidate in _COMMON_IDA_DIRS:
        if candidate.is_dir():
            os.environ["IDADIR"] = str(candidate)
            return str(candidate)
    return None


_ida_dir = _set_ida_dir()
if _ida_dir and _ida_dir not in sys.path:
    sys.path.insert(0, _ida_dir)

try:
    from idapro import close_database, open_database

    _IDA_AVAILABLE = True
except ImportError:
    _IDA_AVAILABLE = False


@dataclass
class FunctionState:
    """All extracted state for a single function relevant to rubric evaluation."""

    address: str
    function_name: str
    pseudocode: str = ""
    local_variables: list[dict[str, Any]] = field(default_factory=list)
    has_header_comment: bool = False
    inline_comments: list[str] = field(default_factory=list)
    callee_names: list[str] = field(default_factory=list)
    is_renamed: bool = False
    error: str | None = None


def is_auto_generated_name(name: str) -> bool:
    """Check if a function name looks auto-generated (sub_, nullsub_, j_)."""
    return bool(re.match(r"^(sub_|nullsub_|j_|loc_|def_|unknown_lib)", name, re.IGNORECASE))


def is_auto_generated_var_name(name: str) -> bool:
    """Check if a variable name looks like an auto-generated placeholder."""
    patterns = [
        r"^v\d+$",  # v1, v2, ...
        r"^a\d+$",  # a1, a2, ...
        r"^s\d+$",  # s1, s2, ...
        r"^arg_\d+$",  # arg_0, arg_4, ...
        r"^var_\d+$",  # var_10, var_20, ...
        r"^result$",  # result
        r"^anonymous_\d+$",  # anonymous_0, ...
        r"^[A-Z]{2,4}$",  # RAX, EAX, RCX, XMM0, ...
    ]
    return any(re.match(p, name) for p in patterns)


def extract_function_state(
    idb_path: str | Path, address: str | int, ida_dir: str | None = None
) -> FunctionState:
    """Open the IDB and extract all state for the function at *address*.

    Parameters
    ----------
    idb_path:
        Path to the .i64 / .idb / binary to open.
    address:
        Hex string (``"0x14E373"``) or integer address of the target function.
    ida_dir:
        Optional path to the IDA installation directory. Set ``IDADIR`` env
        var if not provided.

    Returns
    -------
    FunctionState
        All extracted information for the given function.
    """
    if not _IDA_AVAILABLE:
        return FunctionState(
            address=str(address),
            function_name="",
            error="idapro package not available — cannot open IDB.",
        )

    if ida_dir:
        os.environ.setdefault("IDADIR", ida_dir)

    addr = int(address, 16) if isinstance(address, str) else address

    result = open_database(str(idb_path), run_auto_analysis=False)
    if result != 0:
        return FunctionState(
            address=hex(addr),
            function_name="",
            error=f"Failed to open database (code {result}).",
        )

    try:
        # IDA submodules only become importable after the database is open.
        import ida_funcs
        import ida_hexrays
        import ida_xref
        import idc

        func = ida_funcs.get_func(addr)
        if not func:
            return FunctionState(
                address=hex(addr),
                function_name="",
                error=f"No function found at address {hex(addr)}.",
            )

        func_name = idc.get_func_name(addr) or ""

        # ── Pseudocode ────────────────────────────────────────────────────
        pseudocode = ""
        if ida_hexrays.init_hexrays_plugin():
            try:
                hf = ida_hexrays.hexrays_failure_t()
                cfunc = ida_hexrays.decompile(func, hf)
                if cfunc:
                    pseudocode = str(cfunc)
            except Exception:
                pseudocode = "(decompilation failed)"

        # ── Local variables ───────────────────────────────────────────────
        local_vars: list[dict[str, Any]] = []
        if ida_hexrays.init_hexrays_plugin():
            try:
                hf = ida_hexrays.hexrays_failure_t()
                cfunc = ida_hexrays.decompile(func, hf)
                if cfunc:
                    for var in cfunc.lvars:
                        local_vars.append(
                            {
                                "name": var.name,
                                "type": str(var.type) if var.type else "(unknown)",
                                "is_arg": var.is_arg_var(),
                            }
                        )
            except Exception:
                pass

        # ── Comments (header / inline) ────────────────────────────────────
        has_header = False
        inline: list[str] = []

        # Check for function header comment at the function's start address
        try:
            header_cmt = ida_funcs.get_func_cmt(func, 1)  # 1 = repeatable comment
            if header_cmt and len(header_cmt.strip()) > 10:
                has_header = True
        except Exception:
            pass

        # Scan for inline comments within the function body
        try:
            for ea in range(func.start_ea, func.end_ea):
                cmt = idc.get_cmt(ea, 0)  # 0 = non-repeatable
                if cmt:
                    inline.append((hex(ea), cmt))
                rcmt = idc.get_cmt(ea, 1)  # 1 = repeatable
                if rcmt and rcmt != cmt:
                    inline.append((hex(ea), rcmt))
        except Exception:
            pass

        # ── Callees (called functions) ────────────────────────────────────
        callees: list[str] = []
        try:
            xref = ida_xref.xrefblk_t()
            ok = xref.first_to(func.start_ea, ida_xref.XREF_FAR)
            while ok:
                if xref.iscode and idc.get_func_name(xref.to):
                    cname = idc.get_func_name(xref.to)
                    if cname and cname not in callees:
                        callees.append(cname)
                ok = xref.next_to()
        except Exception:
            pass

        is_renamed = not is_auto_generated_name(func_name)

        return FunctionState(
            address=hex(addr),
            function_name=func_name,
            pseudocode=pseudocode,
            local_variables=local_vars,
            has_header_comment=has_header,
            inline_comments=[c for _, c in inline],
            callee_names=callees,
            is_renamed=is_renamed,
        )

    finally:
        close_database()
