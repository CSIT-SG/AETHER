import os
from typing import Any, Iterable

import idaapi
import ida_kernwin
import ida_hexrays

def check_and_add_intranet_headers(request_params: dict) -> None:
    """
    Check if intranet.txt exists in ainalyse/ directory and add User-Agent header if it does.
    
    Args:
        request_params: Dictionary of request parameters to modify in-place
    """
    intranet_file = os.path.join(os.path.dirname(__file__), "intranet.txt")
    
    if os.path.exists(intranet_file):
        # Read version from version.txt
        version_file = os.path.join(os.path.dirname(__file__), "version.txt")
        version = "unknown"
        try:
            with open(version_file, "r") as ver_file:
                version = ver_file.read().strip()
        except Exception as e:
            print(f"[AETHER] Warning: Could not read version file: {e}")
        
        # Add extra_headers to request_params
        if "extra_headers" not in request_params:
            request_params["extra_headers"] = {}
        
        request_params["extra_headers"]["User-Agent"] = f"AETHER (IDA)/alpha{version}"
        print(f"[AETHER] Added intranet User-Agent header: AETHER (IDA)/alpha{version}")

def _extract_function_eas(functions: Iterable[Any] | None) -> list[int]:
    """Extract function addresses from a list of dicts/strings/ints."""
    function_eas: list[int] = []
    for function_info in functions or []:
        try:
            if isinstance(function_info, dict):
                address_value = function_info.get("address")
            else:
                address_value = function_info

            if isinstance(address_value, int):
                function_eas.append(address_value)
            elif isinstance(address_value, str) and address_value.strip():
                function_eas.append(int(address_value, 16))
        except Exception:
            continue
    return function_eas

def refresh_functions(functions: Iterable[Any] | None = None, fallback_func_addr: str | int | None = None, log_prefix: str = "[AETHER]") -> int:
    """Refresh/decompile changed functions so IDA and Hex-Rays register updates."""
    refreshed_count = 0

    def _refresh_sync():
        nonlocal refreshed_count
        seen_starts = set()
        function_eas = _extract_function_eas(functions)

        if not function_eas and fallback_func_addr is not None:
            try:
                if isinstance(fallback_func_addr, int):
                    function_eas.append(fallback_func_addr)
                elif isinstance(fallback_func_addr, str) and fallback_func_addr.strip():
                    function_eas.append(int(fallback_func_addr, 16))
            except Exception:
                pass

        if not function_eas:
            try:
                current_ea = ida_kernwin.get_screen_ea()
                current_func = idaapi.get_func(current_ea)
                if current_func:
                    function_eas.append(current_func.start_ea)
            except Exception:
                pass

        for function_ea in function_eas:
            function = idaapi.get_func(function_ea)
            if not function:
                continue

            start_ea = function.start_ea
            if start_ea in seen_starts:
                continue
            seen_starts.add(start_ea)

            try:
                ida_hexrays.mark_cfunc_dirty(start_ea)
            except Exception:
                pass

            try:
                ida_hexrays.decompile(start_ea)
            except Exception:
                pass

            refreshed_count += 1

        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

        try:
            widget = ida_kernwin.get_current_widget()
            if widget:
                vu = ida_hexrays.get_widget_vdui(widget)
                if vu:
                    vu.refresh_view(True)
        except Exception:
            pass

        return refreshed_count

    ida_kernwin.execute_sync(_refresh_sync, ida_kernwin.MFF_WRITE)
    print(f"{log_prefix} Refreshed {refreshed_count} function(s) in IDA/Hex-Rays.")
    return refreshed_count