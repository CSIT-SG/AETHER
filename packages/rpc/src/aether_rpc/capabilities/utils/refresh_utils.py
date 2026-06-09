import ida_hexrays
import ida_kernwin
from aether_utils.is_headless_ida import is_headless_ida


def refresh_pseudocode(ea: int):
    if not is_headless_ida():
        ida_kernwin.refresh_idaview_anyway()
        ida_hexrays.open_pseudocode(ea, ida_hexrays.OPF_REUSE)
