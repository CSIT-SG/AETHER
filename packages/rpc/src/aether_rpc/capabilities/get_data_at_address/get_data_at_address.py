import ida_bytes
import ida_idaapi
import idc

from ..base import Capability
from ..utils import (
    collect_xrefs,
    function_info,
    name_or_address,
    resolve_effective_address,
    symbol_hints,
)

# --- Item Metadata ---

def _item_kind(ea: int) -> str:
    """Return whether the item at ea is code, data, or unknown."""
    flags = idc.get_full_flags(ea)
    if idc.is_code(flags):
        return "code"
    if idc.is_data(flags):
        return "data"
    return "unknown"


def _item_head(ea: int) -> str | None:
    """Return the hex address of the item head, or None."""
    head = idc.get_item_head(ea)
    return hex(head) if head != ida_idaapi.BADADDR else None


def _item_end(ea: int) -> str | None:
    """Return the hex address of the item end, or None."""
    end = idc.get_item_end(ea)
    return hex(end) if end != ida_idaapi.BADADDR else None


def _item_size(ea: int) -> int:
    """Return the size of the item in bytes."""
    head = idc.get_item_head(ea)
    end = idc.get_item_end(ea)
    if head != ida_idaapi.BADADDR and end != ida_idaapi.BADADDR and end >= head:
        return end - head
    return 0


# --- Byte Reading ---

def _read_bytes(ea: int, num: int) -> str:
    """Read num bytes at ea and return as a hex string."""
    try:
        raw = ida_bytes.get_bytes(ea, num)
        return raw.hex() if raw else "No bytes found"
    except Exception as e:
        return f"Error reading bytes: {e}"


def _read_string(ea: int) -> str:
    """Attempt to read a string literal at ea."""
    try:
        value = idc.get_strlit_contents(ea)
        return value.decode("utf-8", errors="replace") if value else "No string found"
    except Exception as e:
        return f"Error decoding: {e}"


# --- Pointer Analysis ---

def _pointer_lines(ea: int, num: int) -> list[str]:
    """Return pointer candidate lines if the bytes look like a pointer."""
    try:
        raw = ida_bytes.get_bytes(ea, num)
        if not raw:
            return []
        ptr_size = 8 if getattr(idc, "__EA64__", False) else 4
        if len(raw) < ptr_size:
            return []
        ptr_val = int.from_bytes(raw[:ptr_size], byteorder="little", signed=False)
        line = f"Pointer candidate: 0x{ptr_val:X}"
        if ida_bytes.is_loaded(ptr_val):
            line += f" -> {name_or_address(ptr_val)}"
        return [line]
    except Exception:
        return []


# --- Repeat Pattern Detection ---

def _repeat_pattern_lines(ea: int) -> list[str]:
    """Return a repeat pattern line if a repeated byte run is detected."""
    try:
        first_byte = ida_bytes.get_byte(ea)
        if first_byte < 0:
            return []
        max_scan, run_len = 0x1000, 1
        while run_len < max_scan:
            if ida_bytes.get_byte(ea + run_len) != first_byte:
                break
            run_len += 1
        if run_len <= 1:
            return []
        trunc = " (scan capped)" if run_len == max_scan else ""
        return [f"Repeat pattern: 0x{first_byte:02X} x {run_len} until {hex(ea + run_len - 1)}{trunc}"]
    except Exception:
        return []


# --- Xref Summary ---

def _xref_lines(ea: int) -> list[str]:
    """Return xref summary lines for the given address."""
    preview, total, warnings = collect_xrefs(ea)

    lines = [f"Xrefs: total={total}, preview={len(preview)}"]
    for x in preview:
        lines.append(f"  - {x['from']} in {x['name']} ({x['type']}) [{x['context']}]")
    if warnings:
        lines += [f"Warnings: {len(warnings)}"] + [f"  - {w}" for w in warnings[:5]]

    return lines


class GetDataAtAddress(Capability):
    """Retrieves raw data, disassembly, string, pointer, and xref context at a given address."""

    @property
    def name(self) -> str:
        return "get_data_at_address"

    def execute(self, location: str, count: str = "16") -> str:
        """Collect and return all available data at the given address or symbol.

        Args:
            location: Hex address or symbol name of the target.
            count: Number of bytes to read, clamped to 1–1024. Defaults to 16.

        Returns:
            Formatted string of all collected data, or an error message
            if the address could not be resolved.
        """
        ea = resolve_effective_address(location)
        if ea == ida_idaapi.BADADDR:
            return f"Error: Could not resolve '{location}'."

        num = max(1, min(int(count) if count.isdigit() else 16, 1024))
        name = name_or_address(ea)
        context, _ = function_info(ea)

        lines = [
            f"Data at {hex(ea)} ({name}):",
            f"Symbol hints: {symbol_hints(name)}",
            f"Item: kind={_item_kind(ea)}, head={_item_head(ea)}, end={_item_end(ea)}, size={_item_size(ea)}",
            f"Segment: {idc.get_segm_name(ea) or 'unknown'}",
            f"Function context: {context}",
            f"Disasm: {idc.generate_disasm_line(ea, 0) or 'N/A'}",
            f"Hex: {_read_bytes(ea, num)}",
            f"String: {_read_string(ea)}",
        ]

        lines += _pointer_lines(ea, num)
        lines += _repeat_pattern_lines(ea)
        lines += _xref_lines(ea)

        return "\n".join(lines)
