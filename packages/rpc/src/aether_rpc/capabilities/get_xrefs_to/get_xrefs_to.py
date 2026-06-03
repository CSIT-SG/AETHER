from typing import Any, Dict
import ida_idaapi
import ida_kernwin
import idautils

from ..base import Capability

# Helper dependencies mapped locally to protect execution autonomy
def _resolve_location_to_ea(location: str) -> int:
    if location is None: return ida_idaapi.BADADDR
    try: return int(str(location), 16)
    except (ValueError, TypeError):
        import idc
        try: return idc.get_name_ea_simple(str(location))
        except: return ida_idaapi.BADADDR

def _xref_type_to_text(xref_type: int) -> str:
    if xref_type == 1: return "Data_Offset"
    if xref_type == 2: return "Data_Write"
    if xref_type == 3: return "Data_Read"
    if xref_type in [16, 17]: return "Code_Call"
    if xref_type == 21: return "Code_Jump"
    return "Unknown"

def _name_or_address(ea: int) -> str:
    import idc
    try:
        name = idc.get_name(ea)
        return name if name else f"0x{ea:X}"
    except: return f"0x{ea:X}"

def _symbol_hints(name: str) -> str:
    if not name: return "none"
    hints = []
    if name.startswith("sub_"): hints.append("auto_function")
    if name.startswith("unk_"): hints.append("unknown_symbol")
    if name.startswith("off_"): hints.append("offset_symbol")
    if name.startswith("byte_") or name.startswith("word_") or name.startswith("dword_") or name.startswith("qword_"):
        hints.append("typed_data_symbol")
    if name.startswith("asc_"): hints.append("string_like_symbol")
    return ", ".join(hints) if hints else "none"

def _function_context(ea: int) -> Dict[str, Any]:
    import idc
    ctx = {"in_function": False, "is_function_start": False, "function_name": None, "function_start": None, "offset": None}
    try:
        func = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if func == ida_idaapi.BADADDR: return ctx
        ctx["in_function"] = True
        ctx["is_function_start"] = (ea == func)
        ctx["function_name"] = idc.get_func_name(ea) or f"0x{func:X}"
        ctx["function_start"] = func
        ctx["offset"] = ea - func
    except: return ctx
    return ctx

def _format_function_context(ctx: Dict[str, Any]) -> str:
    if not ctx.get("in_function"): return "outside_function"
    if ctx.get("is_function_start"): return f"function_start:{ctx.get('function_name')}"
    return f"in_function:{ctx.get('function_name')}+0x{ctx.get('offset', 0):X}"


class GetXrefsTo(Capability):
    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def execute(self, state, location: str) -> str:
        xrefs_found = []
        target_info: Dict[str, Any] = {
            "ea": None, "name": None, "symbol_hints": "none",
            "context": "outside_function", "warnings": [],
        }

        def _get_xrefs_sync():
            try:
                ea = _resolve_location_to_ea(location)
                if ea == ida_idaapi.BADADDR:
                    target_info["warnings"].append("target could not be resolved")
                    return 0 

                target_name = _name_or_address(ea)
                target_info["ea"] = hex(ea)
                target_info["name"] = target_name
                target_info["symbol_hints"] = _symbol_hints(target_name)
                target_info["context"] = _format_function_context(_function_context(ea))

                for xref in idautils.XrefsTo(ea):
                    try:
                        ref_type = _xref_type_to_text(xref.type)
                        caller_name = _name_or_address(xref.frm)
                        caller_ctx = _function_context(xref.frm)

                        xrefs_found.append({
                            "from": hex(xref.frm), "name": caller_name, "type": ref_type,
                            "from_context": _format_function_context(caller_ctx),
                            "from_is_function_start": bool(caller_ctx.get("is_function_start")),
                        })
                    except Exception as xref_error:
                        target_info["warnings"].append(f"xref entry parse failed: {xref_error}")
                return 1
            except Exception as e:
                target_info["warnings"].append(f"xref scan failed: {e}")
                return 0

        ida_kernwin.execute_sync(_get_xrefs_sync, ida_kernwin.MFF_READ)
        

        if not target_info.get("ea"):
            return f"Error: Could not resolve address/name '{location}'."

        if not xrefs_found:
            summary = [
                f"Target {target_info.get('name')} @ {target_info.get('ea')} [{target_info.get('context')}]",
                f"Target symbol hints: {target_info.get('symbol_hints', 'none')}",
                f"No cross-references found for '{location}'.",
            ]
            return "\n".join(summary)

        output = [
            f"Target {target_info.get('name')} @ {target_info.get('ea')} [{target_info.get('context')}]",
            f"Target symbol hints: {target_info.get('symbol_hints', 'none')}",
            f"Found {len(xrefs_found)} Xrefs to '{location}':",
        ]
        for x in xrefs_found:
            func_start_flag = "yes" if x.get("from_is_function_start") else "no"
            output.append(f"  - {x['from']} in {x['name']} ({x['type']}) [{x.get('from_context')}] [from_is_function_start:{func_start_flag}]")

        state.last_result = {"target": target_info, "xrefs": xrefs_found}
        return "\n".join(output)