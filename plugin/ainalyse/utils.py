import os
from typing import Any, Iterable, Callable
import threading

import ida_funcs
import idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs


_REFRESH_GUARD_LOCK = threading.Lock()
_REFRESH_IN_PROGRESS = False


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

    global _REFRESH_IN_PROGRESS
    with _REFRESH_GUARD_LOCK:
        if _REFRESH_IN_PROGRESS:
            print(f"{log_prefix} Skipping refresh: another refresh is already in progress.")
            return 0
        _REFRESH_IN_PROGRESS = True

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

        old_batch = idaapi.cvar.batch
        idaapi.cvar.batch = 1

        try:
            for function_ea in function_eas:
                function = idaapi.get_func(function_ea)
                if not function:
                    continue

                start_ea = function.start_ea
                if start_ea in seen_starts:
                    continue
                seen_starts.add(start_ea)

                try:
                    # 1. Force completely flush the old broken cache out of memory
                    # This gives the "restart IDA" effect natively without actually closing it.
                    if hasattr(ida_hexrays, "clear_cached_cfunc"):
                        ida_hexrays.clear_cached_cfunc(start_ea)
                    else:
                        ida_hexrays.mark_cfunc_dirty(start_ea)
                except Exception:
                    pass

                try:
                    # 2. Programmatically regenerate the AST fresh right now so background processes can see it
                    flags = getattr(ida_hexrays, "DECOMP_NO_WAIT", 0x20)
                    hf = ida_hexrays.hexrays_failure_t()
                    df = ida_hexrays.decompile_func(ida_funcs.get_func(start_ea), hf, flags)
                except Exception:
                    pass

                refreshed_count += 1

            # Fix Print Order: Print inside the sync execution so it prints AFTER any potential inner HexRays logs are exhausted.
            print(f"{log_prefix} Refreshed {refreshed_count} function(s) in IDA/Hex-Rays.")

        finally:
            idaapi.cvar.batch = old_batch

        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

        try:
            # Only refresh view if IDA is not in a weird state
            widget = ida_kernwin.get_current_widget()
            if widget:
                # Basic check to see if widget is still valid
                if hasattr(ida_kernwin, "get_widget_type") and ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_UNKNOWN:
                    vu = ida_hexrays.get_widget_vdui(widget)
                    if vu and hasattr(vu, "refresh_view"):
                        vu.refresh_view(True)
        except Exception:
            pass

        return refreshed_count

    try:
        ida_kernwin.execute_sync(_refresh_sync, ida_kernwin.MFF_WRITE)
        print(f"{log_prefix} Refreshed {refreshed_count} function(s) in IDA/Hex-Rays.")
        return refreshed_count
    finally:
        with _REFRESH_GUARD_LOCK:
            _REFRESH_IN_PROGRESS = False

def prepare_activate_context(
    load_config_fn: Callable,
    validate_basic_config_fn: Callable,
    config_updater: Callable | None = None,
):
    """
    Shared activate() setup for handlers that need validated config and current function context.

    Returns:
        tuple[dict | None, str | None, str | None]:
            (config, current_func_addr_hex, current_func_name). Any None means setup failed.
    """
    config = load_config_fn()
    is_valid, error_msg = validate_basic_config_fn(config)
    if not is_valid:
        def _show_config_error_sync():
            ida_kernwin.warning(error_msg)
            return 1

        ida_kernwin.execute_sync(_show_config_error_sync, ida_kernwin.MFF_WRITE)
        return None, None, None

    config = load_config_fn()
    if config_updater:
        config_updater(config)

    context = {"addr": None, "name": None, "error": None}

    def _resolve_current_function_sync():
        try:
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if not func:
                context["error"] = "No function found at current location."
                return 0

            context["addr"] = hex(func.start_ea)
            context["name"] = ida_funcs.get_func_name(func.start_ea)
            return 1
        except Exception as e:
            context["error"] = f"Unable to get current function information: {e}"
            return 0

    ida_kernwin.execute_sync(_resolve_current_function_sync, ida_kernwin.MFF_READ)

    if context["error"]:
        def _show_context_error_sync():
            ida_kernwin.warning(context["error"])
            return 1

        ida_kernwin.execute_sync(_show_context_error_sync, ida_kernwin.MFF_WRITE)
        return None, None, None
    return config, context["addr"], context["name"]