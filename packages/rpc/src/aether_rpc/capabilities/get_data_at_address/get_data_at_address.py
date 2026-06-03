from typing import Any, Dict
import ida_bytes
import ida_idaapi
import ida_kernwin
import idautils
import idc

from ..base import Capability

# Reusing your standalone formatting/helpers mapping to keep code self-contained or importable
def _resolve_location_to_ea(location: str) -> int:
    if location is None:
        return ida_idaapi.BADADDR
    try:
        return int(str(location), 16)
    except (ValueError, TypeError):
        try:
            return idc.get_name_ea_simple(str(location))
        except Exception:
            return ida_idaapi.BADADDR

def _xref_type_to_text(xref_type: int) -> str:
    if xref_type == 1: return "Data_Offset"
    if xref_type == 2: return "Data_Write"
    if xref_type == 3: return "Data_Read"
    if xref_type in [16, 17]: return "Code_Call"
    if xref_type == 21: return "Code_Jump"
    return "Unknown"

def _name_or_address(ea: int) -> str:
    try:
        name = idc.get_name(ea)
        return name if name else f"0x{ea:X}"
    except Exception:
        return f"0x{ea:X}"

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
    ctx = {"in_function": False, "is_function_start": False, "function_name": None, "function_start": None, "offset": None}
    try:
        func = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if func == ida_idaapi.BADADDR: return ctx
        func_name = idc.get_func_name(ea)
        ctx["in_function"] = True
        ctx["is_function_start"] = (ea == func)
        ctx["function_name"] = func_name if func_name else f"0x{func:X}"
        ctx["function_start"] = func
        ctx["offset"] = ea - func
    except Exception:
        return ctx
    return ctx

def _format_function_context(ctx: Dict[str, Any]) -> str:
    if not ctx.get("in_function"): return "outside_function"
    if ctx.get("is_function_start"): return f"function_start:{ctx.get('function_name')}"
    return f"in_function:{ctx.get('function_name')}+0x{ctx.get('offset', 0):X}"


class GetDataAtAddress(Capability):
    @property
    def name(self) -> str:
        return "get_data_at_address"

    def execute(self, state, location: str, count: str = "16") -> str:
        data_container: Dict[str, Any] = {
            "ea": None, "name": None, "symbol_hints": "none", "segment": None,
            "item_kind": "unknown", "item_head": None, "item_end": None, "item_size": 0,
            "function_context": "outside_function", "bytes": "No bytes found",
            "string": "No string found", "disasm": None, "pointer_candidate": None,
            "pointer_target": None, "repeat_pattern": None, "xrefs_to_total": 0,
            "xrefs_to": [], "warnings": [],
        }
        
        def _get_data_sync():
            try:
                ea = _resolve_location_to_ea(location)
                if ea == ida_idaapi.BADADDR:
                    return 0

                data_container["ea"] = hex(ea)
                data_container["name"] = _name_or_address(ea)
                data_container["symbol_hints"] = _symbol_hints(data_container["name"])
                data_container["segment"] = idc.get_segm_name(ea) or "unknown"

                flags = idc.get_full_flags(ea)
                if idc.is_code(flags): data_container["item_kind"] = "code"
                elif idc.is_data(flags): data_container["item_kind"] = "data"
                elif idc.is_unknown(flags): data_container["item_kind"] = "unknown"

                item_head = idc.get_item_head(ea)
                item_end = idc.get_item_end(ea)
                data_container["item_head"] = hex(item_head) if item_head != ida_idaapi.BADADDR else None
                data_container["item_end"] = hex(item_end) if item_end != ida_idaapi.BADADDR else None
                if item_head != ida_idaapi.BADADDR and item_end != ida_idaapi.BADADDR and item_end >= item_head:
                    data_container["item_size"] = item_end - item_head

                data_container["function_context"] = _format_function_context(_function_context(ea))
                data_container["disasm"] = idc.generate_disasm_line(ea, 0)

                try: num = int(count)
                except: num = 16
                num = max(1, min(num, 1024))

                try:
                    raw_bytes = ida_bytes.get_bytes(ea, num)
                    if raw_bytes:
                        data_container["bytes"] = raw_bytes.hex()
                        ptr_size = 8 if getattr(idc, "__EA64__", False) else 4
                        if len(raw_bytes) >= ptr_size:
                            ptr_val = int.from_bytes(raw_bytes[:ptr_size], byteorder="little", signed=False)
                            data_container["pointer_candidate"] = f"0x{ptr_val:X}"
                            if ida_bytes.is_loaded(ptr_val):
                                data_container["pointer_target"] = _name_or_address(ptr_val)

                        first_byte = ida_bytes.get_byte(ea)
                        if first_byte >= 0:
                            max_scan, run_len = 0x1000, 1
                            while run_len < max_scan:
                                b = ida_bytes.get_byte(ea + run_len)
                                if b != first_byte: break
                                run_len += 1
                            if run_len > 1:
                                data_container["repeat_pattern"] = {
                                    "byte": f"0x{first_byte:02X}", "length": run_len,
                                    "end_ea": hex(ea + run_len - 1), "scan_truncated": (run_len == max_scan),
                                }
                except Exception as e:
                    data_container["bytes"] = f"Error reading bytes: {str(e)}"

                try:
                    string_value = idc.get_strlit_contents(ea)
                    if string_value: data_container["string"] = string_value.decode('utf-8', errors='replace')
                except Exception as e:
                    data_container["string"] = f"Error decoding: {str(e)}"

                preview, total_xrefs = [], 0
                try:
                    for xref in idautils.XrefsTo(ea):
                        total_xrefs += 1
                        if len(preview) < 10:
                            preview.append({
                                "from": hex(xref.frm), "name": _name_or_address(xref.frm),
                                "type": _xref_type_to_text(xref.type),
                                "from_context": _format_function_context(_function_context(xref.frm)),
                            })
                except Exception as xref_error:
                    data_container["warnings"].append(f"xref scan failed: {xref_error}")

                data_container["xrefs_to_total"] = total_xrefs
                data_container["xrefs_to"] = preview
                return 1
            except Exception as e:
                data_container["warnings"].append(f"unexpected data error: {str(e)}")
                return 1 if data_container["ea"] else 0

        ida_kernwin.execute_sync(_get_data_sync, ida_kernwin.MFF_READ)
        state.last_result = data_container
        
        if data_container["ea"]:
            lines = [
                f"Data at {data_container['ea']} ({data_container.get('name') or 'unknown'}):",
                f"Symbol hints: {data_container.get('symbol_hints', 'none')}",
                f"Item: kind={data_container.get('item_kind')}, head={data_container.get('item_head')}, end={data_container.get('item_end')}, size={data_container.get('item_size')}",
                f"Segment: {data_container.get('segment')}",
                f"Function context: {data_container.get('function_context')}",
                f"Disasm: {data_container.get('disasm') or 'N/A'}",
                f"Hex: {data_container['bytes']}",
                f"String: {data_container['string']}",
            ]
            if data_container.get("pointer_candidate"):
                ptr_line = f"Pointer candidate: {data_container['pointer_candidate']}"
                if data_container.get("pointer_target"): ptr_line += f" -> {data_container['pointer_target']}"
                lines.append(ptr_line)
            
            repeat = data_container.get("repeat_pattern")
            if repeat:
                trunc = " (scan capped)" if repeat.get("scan_truncated") else ""
                lines.append(f"Repeat pattern: {repeat.get('byte')} x {repeat.get('length')} until {repeat.get('end_ea')}{trunc}")

            xrefs_preview = data_container.get("xrefs_to") or []
            lines.append(f"Xrefs to this address: total={data_container.get('xrefs_to_total', len(xrefs_preview))}, preview={len(xrefs_preview)}")
            for x in xrefs_preview:
                lines.append(f"  - {x.get('from')} in {x.get('name')} ({x.get('type')}) [{x.get('from_context')}]")

            return "\n".join(lines)
        else:
            return f"Error: Could not resolve address/name '{location}'."