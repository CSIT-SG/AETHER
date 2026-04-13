"""
Custom set_comment implementation for IDA Pro decompiler.
This module provides a robust way to set and clear comments in the decompiler view.
"""

import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi
import idc
import re


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

        switch_case_dict = {}
        if_list = []
        class SwitchVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_insn(self, insn):
                if insn.op == ida_hexrays.cit_switch:
                    self.handle_switch(insn)
                if insn.op == ida_hexrays.cit_if:
                    if_list.append(insn.ea)
                return 0
            def handle_switch(self, insn):
                sw = insn.cswitch
                for case in sw.cases:
                    values = list(case.values)
                    target_ea = case.ea
                    for value in values:
                        if value not in switch_case_dict:
                            switch_case_dict[value] = []
                        if target_ea != idaapi.BADADDR:
                            switch_case_dict[value].append(target_ea)
                        else:
                            switch_case_dict[value].append(None)
        v = SwitchVisitor()
        v.apply_to(cfunc.body, None)
        next_addr = None
        label = None
        if_count = 0
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
            # Label both case and first line of case with address
            if next_addr:
                addr = next_addr
                next_addr = None

            # Get address for case
            if re.search("case .+", line):
                # Find case number
                case_value = re.findall("[ABCDEF\d]+", line)[-1]
                if case_value.isnumeric():
                    case_value = int(case_value)
                else:
                    new_case_value = int(case_value, 16)
                    if case_value.startswith("F"):
                        case_value = (new_case_value - 2**(len(case_value)*4)) % 2**64

                if switch_case_dict[case_value] != None:
                    if isinstance(switch_case_dict[case_value], list):
                        # If multiple switch case, pop address
                        try:
                            next_addr = switch_case_dict[case_value].pop(0)
                        except IndexError:
                            next_addr = None
                    else:
                        next_addr = switch_case_dict[case_value]
                    addr = next_addr
            if label:
                # Add label along with address
                pseudocode += "\n"
                if not addr:
                    pseudocode += f"/* line: {i-1} */ {label}"
                else:
                    pseudocode += f"/* line: {i-1}, address: {hex(addr)} */ {label}"
                label = None
            if line.lstrip().startswith("LABEL_"):
                # Store label till next line to get address
                label = line
                continue
            if line.lstrip().startswith("if"):
                # Add address for if statements
                addr = if_list[if_count]
                if_count += 1
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