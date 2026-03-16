import idaapi
import idc
import ida_hexrays
import ida_kernwin
import ida_lines

import re


def extract_pseudocode(text, function_name):
    """
    Extracts the pseudocode for a specific function from a formatted text block.
    """
    # Escape function name for regex safety and build the pattern
    # It looks for the header, captures everything until the next header or EOF
    pattern = rf"=====\s*\n{re.escape(function_name)}\(\.\.\.\)\s*\n=====\s*\n(.*?)(?=\n+=====|$)"
    
    # re.DOTALL allows the dot (.) to match newline characters
    match = re.search(pattern, text, re.DOTALL)
    
    if match:
        return match.group(1).strip()
    else:
        return None

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


def get_pseudocode_with_struct_comments(function_name_or_address, comment_dict):
    """
    Gets pseudocode for a function with added comments for structs
    
    Args:
        function_name_or_address: Function name (str) or address (int/str)
        
    Returns:
        str: Pseudocode with line and struct annotations, or None if failed
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
                pseudocode += line
            else:
                comments = None
                if addr in comment_dict:
                    comments = comment_dict[addr]
                    pseudocode += f"{line.rsplit('//',1)} // {comments}"
                else:
                    pseudocode += line
        return pseudocode
    except Exception as e:
        print(f"[custom_get_pseudocode] Error getting pseudocode: {e}")
        return None
    return

def get_pseudocode(function_name_or_address):
    """
    Gets pseudocode for a function
    
    Args:
        function_name_or_address: Function name (str) or address (int/str)
        
    Returns:
        str: Pseudocode
    """
    try:
        # Handle different input types
        #print(function_name_or_address)
        #print(type(function_name_or_address))
        
        if isinstance(function_name_or_address, str):

            if function_name_or_address.startswith("0x"):
                # Hex address string
                address = int(function_name_or_address, 16)
            else:
                # Function name
                address = idc.get_name_ea_simple(function_name_or_address)
                if address == idaapi.BADADDR:
                    print(f"[get_pseudocode] Function '{function_name_or_address}' not found")
                    return None
        else:
            # Assume it's an integer address

            address = int(function_name_or_address)
        ida_hexrays.clear_cached_cfuncs()
        # Decompile the function
        cfunc = decompile_checked(address)
        if not cfunc:
            print(f"[get_pseudocode] Failed to decompile function at {hex(address)}")
            return None 

        return str(cfunc)
    except Exception as e:
        print(f"[get_pseudocode] Error getting pseudocode: {repr(e)}")
        return None

