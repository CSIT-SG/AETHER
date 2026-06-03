import ida_typeinf

from ..base import Capability


class DeclareCStruct(Capability):
    @property
    def name(self) -> str:
        return "declare_c_struct"

    def execute(self, struct_name: str, fields_list, struct_size: int = 0):
        """
        Updates or creates a struct using a list of tuples via safe structural upsert.
        :param struct_name: Name of the struct (e.g., "MyStruct")
        :param fields_list: List of (name, type_str, offset)
        """
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        udt_data = ida_typeinf.udt_type_data_t()
        max_bit_reached = struct_size * 8
        failed_list = []

        if tif.get_named_type(til, struct_name):
            tif.get_udt_details(udt_data)
            self.logger.info(f"Updating existing struct: {struct_name}")
        else:
            self.logger.info(f"Creating new struct: {struct_name}")
            tif.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
            tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE)

        udt_data.taudt_bits |= ida_typeinf.TAUDT_FIXED     
        new_members_to_add = []
        occupied_ranges = [] 
        
        for name, t_str, offset in fields_list:
            tmp_tif = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tmp_tif, til, t_str + ";", 0)
            if len(str(tmp_tif)) == 0:
                failed_list.append((name, t_str, offset))
                continue
            start_bits = offset * 8
            size_bits = tmp_tif.get_size() * 8
            end_bits = start_bits + size_bits
            if end_bits > max_bit_reached:
                max_bit_reached = end_bits
            new_members_to_add.append((name, tmp_tif, start_bits))
            occupied_ranges.append((start_bits, end_bits))

        final_udt = ida_typeinf.udt_type_data_t()
        final_udt.taudt_bits = udt_data.taudt_bits

        for member in udt_data:
            if member.type.get_size() == 0xffffffffffffffff:
                continue
            m_start = member.offset 
            m_end = m_start + (member.type.get_size() * 8) & 0xFFFFFFFF

            if m_end > max_bit_reached:
                max_bit_reached = m_end
            
            overlap = any(m_start < n_end and m_end > n_start for n_start, n_end in occupied_ranges)
            
            if not overlap:
                new_members_to_add.append((member.name, member.type, member.offset))
            else:
                self.logger.warning(f"Removing overlapping member '{member.name}' at {m_start//8:#x}")
        
        # Internal logical sorting execution
        new_members_to_add = sorted(new_members_to_add, key=lambda x: x[2])
        
        for name, m_tif, m_offset in new_members_to_add:
            new_member = ida_typeinf.udt_member_t()
            new_member.name = name
            new_member.type = m_tif
            new_member.offset = m_offset
            final_udt.push_back(new_member)

        final_udt.total_size = max_bit_reached // 8
        if tif.create_udt(final_udt, ida_typeinf.BTF_STRUCT):
            tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE | ida_typeinf.NTF_NOBASE)
            self.logger.info(f"Successfully upserted '{struct_name}' with {len(new_members_to_add)} fields")
            return failed_list

        self.logger.error(f"Could not save struct '{struct_name}'")
        return failed_list