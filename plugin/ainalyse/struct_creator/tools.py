import ida_typeinf
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_name
import ida_idaapi
import idc

def declare_c_struct_old(type_name, c_declaration):
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if c_declaration[-1] != ";":
        c_declaration = c_declaration +";"
    # parse_decl returns the remainder of the string if successful
    # It populates the 'tif' object with the parsed type
    if ida_typeinf.parse_decl(tif, til, c_declaration, 0):
        # NTF_REPLACE (0x1): Overwrite if it already exists
        # NTF_TYPE (0x2): It is a type definition
        res = tif.set_named_type(til, type_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE)
        if res == 0:
            print(f"Type '{type_name}' registered successfully.")
            return True
            
    msg = f"Failed to add type '{type_name}'."
    print(msg)
    return False

def get_struct_definition(struct_name):
    # 1. Get the TINFO for the struct name
    # This looks in the local til (Type Information Library)
    ti = ida_typeinf.tinfo_t()
    if not ti.get_named_type(ida_typeinf.get_idati(), struct_name):
        print(f"Error: Could not find type '{struct_name}'")
        return None, None

    # 2. Ensure it's actually a structure/UDT
    if not ti.is_udt():
        print(f"Error: '{struct_name}' is not a structure.")
        return struct_name, None

    udt_data = ida_typeinf.udt_type_data_t()
    ti.get_udt_details(udt_data)

    struct_info = []

    # 3. Iterate through members using the UDT data
    for member in udt_data:
        m_name = member.name
        m_offset = member.offset // 8  # Offset is in bits, convert to bytes
        m_type = str(member.type)
        
        struct_info.append((m_type, m_name, m_offset))

    return struct_name, struct_info

def sort_fields_by_offset(fields_list):
    """
    Sorts a list of (name, type, offset) tuples by the offset (3rd column).
    """
    # key=lambda x: x[2] tells Python to look at the index 2 (the offset)
    return sorted(fields_list, key=lambda x: x[2])

def declare_c_struct(struct_name, fields_list, struct_size=0):
    """
    Updates or creates a struct using a list of tuples.
    :param struct_name: Name of the struct (e.g., "MyStruct")
    :param fields_list: List of (name, type_str, offset) 
                         e.g., [("magic", "uint32_t", 0x0), ("version", "uint16_t", 0x4)]
    """
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    udt_data = ida_typeinf.udt_type_data_t()
    max_bit_reached = struct_size * 8
    failed_list = []
    # 1. Initialize or Load Struct
    if tif.get_named_type(til, struct_name):
        tif.get_udt_details(udt_data)
        print(f"[*] Updating existing struct: {struct_name}")
    else:
        print(f"[*] Creating new struct: {struct_name}")
        tif.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
        tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE)
        
    udt_data.taudt_bits |= ida_typeinf.TAUDT_FIXED     
    # 2. Prepare new members and track bit-ranges for overlap cleaning
    new_members_to_add = []
    occupied_ranges = [] 
    
    for name, t_str, offset in fields_list:
        tmp_tif = ida_typeinf.tinfo_t()
        # parse_decl handles complex types like "int[10]" or "void*"
        x = ida_typeinf.parse_decl(tmp_tif, til, t_str + ";", 0)
        if len(str(tmp_tif)) == 0:
            failed_list.append((name,t_str,offset))
            continue
        start_bits = offset * 8
        size_bits = tmp_tif.get_size() * 8
        end_bits = start_bits + size_bits
        if end_bits > max_bit_reached:
            max_bit_reached = end_bits
        new_members_to_add.append((name, tmp_tif, start_bits))
        occupied_ranges.append((start_bits, end_bits))

    # 3. Filter existing members to prevent collisions
    final_udt = ida_typeinf.udt_type_data_t()
    # Preserve existing struct attributes (like alignment or packed status)
    final_udt.taudt_bits = udt_data.taudt_bits

    for member in udt_data:
        if member.type.get_size() == 0xffffffffffffffff:
            continue
        m_start = member.offset 
        m_end = m_start + (member.type.get_size() * 8) & 0xFFFFFFFF

        if m_end > max_bit_reached:
            max_bit_reached = m_end
        # If the existing member overlaps with ANY of our new fields, skip it
        overlap = any(m_start < n_end and m_end > n_start for n_start, n_end in occupied_ranges)
        
        if not overlap:
            new_members_to_add.append((member.name, member.type, member.offset))
        else:
            print(f"[!] Removing overlapping member '{member.name}' at {m_start//8:#x}")
    new_members_to_add = sort_fields_by_offset(new_members_to_add)
    # 4. Add the new members from our list
    for name, m_tif, m_offset in new_members_to_add:
        new_member = ida_typeinf.udt_member_t()
        new_member.name = name
        new_member.type = m_tif
        new_member.offset = m_offset
        final_udt.push_back(new_member)

    final_udt.total_size = max_bit_reached // 8
    # 5. Commit changes to the Local Types (TIL)
    if tif.create_udt(final_udt, ida_typeinf.BTF_STRUCT):
        # NTF_REPLACE (0x1): Overwrite existing name
        # NTF_TYPE (0x2): Add as a proper type definition
        success = tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE)

        print(f"[+] Successfully upserted '{struct_name}' with {len(new_members_to_add)} fields.")
        return failed_list

    print(f"[-] Error: Could not save struct '{struct_name}'")
    return failed_list


def set_variable_type(func_name, var_name, new_type_str = 0):
    # 1. Resolve Function Name to Address
    func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
    func = ida_funcs.get_func(func_ea)
    
    if not func:
        print(f"[-] Function '{func_name}' not found.")
        return False

    # 2. Decompile the function
    cfunc = ida_hexrays.decompile(func.start_ea)
    if not cfunc:
        print(f"[-] Failed to decompile '{func_name}'")
        return False

    # 3. PRIORITY: Check Local Variables
    lvars = cfunc.get_lvars()
    target_lvar = next((v for v in lvars if v.name == var_name), None)

    # Prepare the tinfo object
    tinfo = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tinfo, None, new_type_str + ";", 0)


    if target_lvar:
        print(f"[+] Found LOCAL variable '{var_name}' in '{func_name}'.")
        
        # Create the info object
        info = ida_hexrays.lvar_saved_info_t()
        
        # FIX: Populate the locator (ll) sub-fields correctly
        # info.ll is an lvar_locator_t. We set its internal vdloc_t and def_ea.
        global test
        test = target_lvar
        info.ll.location = target_lvar.location
        info.ll.defea = target_lvar.defea
        
        info.type = tinfo
        info.name = var_name
        
        # Apply the update
        if ida_hexrays.modify_user_lvar_info(func.start_ea, ida_hexrays.MLI_TYPE, info):
            print(f"[+] Successfully updated local variable type.")
            
            # Refresh Pseudocode
            vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
            if vdui:
                vdui.refresh_view(True)
            return True
        else:
            print(f"[-] modify_user_lvar_info failed.")
            return False

    # 4. FALLBACK: Check Global Variables
    global_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, var_name)
    if global_ea != ida_idaapi.BADADDR and not ida_funcs.get_func(global_ea):
        print(f"[*] '{var_name}' is GLOBAL at {hex(global_ea)}.")
        if ida_typeinf.apply_tinfo(global_ea, tinfo, ida_typeinf.TINFO_DEFINITE):
            print(f"[+] Successfully updated global variable type.")
            return True

    print(f"[-] Variable '{var_name}' not found.")
    return False

# Usage
#set_variable_type("aire_concatenate_strings", "a1", "void*")




