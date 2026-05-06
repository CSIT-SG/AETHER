"""
Custom set_comment implementation for IDA Pro decompiler.
This module provides a robust way to set and clear comments in the decompiler view.
"""

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi
import idc


def custom_get_pseudocode(function_name_or_address):
    """
    Gets pseudocode for a function with line numbers and addresses.
    
    Args:
        function_name_or_address: Function name (str) or address (int/str)
        
    Returns:
        str: Pseudocode with line and address annotations, or None if failed
    """
    try:
        # Handle different input types
        if isinstance(function_name_or_address, str):
            if function_name_or_address.startswith("0x"):
                # Hex address string
                address = int(function_name_or_address, 16)
            else:
                # Function name
                address = idc.get_name_ea_simple(function_name_or_address)
                if address == idaapi.BADADDR:
                    print(f"[custom_get_pseudocode] Function '{function_name_or_address}' not found")
                    return None
        else:
            # Assume it's an integer address
            address = int(function_name_or_address)
        
        # Decompile the function
        cfunc = ida_hexrays.decompile(address)
        if not cfunc:
            print(f"[custom_get_pseudocode] Failed to decompile function at {hex(address)}")
            return None
        
        pseudocode = ""
        sv = cfunc.get_pseudocode()

        for i, sl in enumerate(sv):
            sl: ida_kernwin.simpleline_t
            item = ida_hexrays.ctree_item_t()
            addr = None if i > 0 else cfunc.entry_ea
            if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                ds = item.dstr().split(": ")
                if len(ds) == 2:
                    try:
                        addr = int(ds[0], 16)
                    except ValueError:
                        pass
            line = ida_lines.tag_remove(sl.line)
            if len(pseudocode) > 0:
                pseudocode += "\n"
            if not addr:
                pseudocode += f"/* line: {i} */ {line}"
            else:
                pseudocode += f"/* line: {i}, address: {hex(addr)} */ {line}"
        return pseudocode
    except Exception as e:
        print(f"[custom_get_pseudocode] Error getting pseudocode: {e}")
        return None


def scmt(address, comment):
    """
    Sets or clears a comment in the IDA decompiler view at a specific address.

    Args:
        address (int or str): The address for the comment, can be a hex string.
        comment (str): The comment text. If an empty string, the comment is cleared.
    """
    try:
        ea = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address)
    except: return

    ea = ida_bytes.get_item_head(ea)
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc: return

    # 1. Handle Function Header
    if ea == cfunc.entry_ea:
        idc.set_func_cmt(ea, comment, 1)
        cfunc.refresh_func_ctext()
        return

    # 2. Map Validation & Snap
    eamap = cfunc.get_eamap()
    if ea not in eamap:
        # Snap logic (Backward search is most reliable for logic blocks)
        f = ida_funcs.get_func(ea)
        if not f: return
        curr = ea
        found = False
        while curr >= f.start_ea:
            if curr in eamap:
                ea = curr
                found = True
                break
            curr = ida_bytes.prev_head(curr, f.start_ea)
        if not found: return

    # 3. Apply Comment with Fallback
    tl = idaapi.treeloc_t()
    tl.ea = ea
    
    # Clear existing
    for itp in [idaapi.ITP_SEMI, idaapi.ITP_BLOCK1]:
        tl.itp = itp
        cfunc.set_user_cmt(tl, "")

    if comment:
        # ATTEMPT 1: Semicolon (End of line)
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        
        # If it becomes an orphan, we MUST remove it from SEMI before trying the fallback to prevent duplicates.
        if cfunc.has_orphan_cmts():
            # 1. Clear the failed semicolon comment
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, "") 
            # 2. Try the fallback slot
            tl.itp = idaapi.ITP_BLOCK1
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()

    cfunc.refresh_func_ctext()

def decompile_checked(address: int) -> "ida_hexrays.cfunc_t":
    """
    A helper function to decompile a function at a given address, with robust error checking.
    """
    if not ida_hexrays.init_hexrays_plugin():
        raise Exception("Hex-Rays decompiler is not available")
    
    error = ida_hexrays.hexrays_failure_t()
    cfunc: "ida_hexrays.cfunc_t" = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
    
    if not cfunc:
        if error.code == ida_hexrays.MERR_LICENSE:
            raise Exception("Decompiler licence is not available.")

        message = f"Decompilation failed at {hex(address)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise Exception(message)
    
    return cfunc
