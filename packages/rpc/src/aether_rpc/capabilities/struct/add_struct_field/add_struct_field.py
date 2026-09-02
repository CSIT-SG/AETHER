import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.add_struct_field.constants import TYPE_MAP
from aether_rpc.capabilities.struct.utils import get_struct
from aether_rpc.capabilities.types import StructFieldResult


class AddStructField(Capability):
    @property
    def name(self) -> str:
        return "add_struct_field"

    def execute(
        self,
        struct: str | int,
        field_name: str,
        field_type: str,
        offset: int,
        array_length: int | None,
    ) -> Result[StructFieldResult]:
        """Add a field to a structure.

        Args:
            struct: The name or id of the struct to add the field to.
            field_name: Name of the new field.
            field_type: Type of the new field.
            offset: Byte offset at which to add the field.
            array_length: Number of elements if the field is an array.

        Returns:
            A Result whose ``success`` reports whether the add succeeded and
            whose ``result`` carries struct id, struct name, field name, field
            type, and array length if applicable.
        """
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result
        # Check for duplicate field name
        if any(member.name == field_name for member in struct_info.udt):
            return Err(
                result=f"Field '{field_name}' already exists in '{struct_info.struct_name}'."
            )

        til = ida_typeinf.get_idati()
        new_type = ida_typeinf.tinfo_t()

        if not new_type.get_named_type(til, field_type):
            type_code = TYPE_MAP.get(field_type)

            if type_code is None or not new_type.create_simple_type(type_code):
                return Err(
                    result=f"Unable to resolve field type '{field_type}'. Please provide a user-defined type or use one of the following supported types: uint8_t, uint16_t, word, uint32_t, dword, uint64_t, int8_t, int16_t, short, int32_t, long, int64_t, char, bool, byte, float, double, or void."
                )

        try:
            # Check if offset provided is an integer
            offset = int(offset)
        except ValueError:
            return Err(result=f"Invalid offset provided: '{offset}'.")

        if array_length is not None:
            # Create as array if array length given
            try:
                if int(array_length) <= 0:
                    return Err(result="Array length must be greater than zero.")

                array_type = ida_typeinf.tinfo_t()
                if not array_type.create_array(new_type, int(array_length)):
                    return Err(
                        result=f"Unable to create array type '{field_type}[{array_length}]'."
                    )
            except ValueError:
                return Err(result=f"Invalid array length provided: '{array_length}'.")

            new_type = array_type

        new_member_size = new_type.get_size()

        if new_member_size <= 0:
            return Err(result=f"Unable to determine size of field type '{field_type}'.")

        insert_index = len(struct_info.udt)
        insert_offset = offset

        for i, member in enumerate(struct_info.udt):
            member_offset = member.offset // 8
            member_size = member.type.get_size()

            if member_size <= 0:
                continue

            member_end = member_offset + member_size

            if member_offset < offset < member_end:
                # Offset points into this member.
                # Insert after this member.
                insert_index = i + 1
                insert_offset = member_end
                break

            if offset <= member_offset:
                # Offset falls before this member.
                insert_index = i
                insert_offset = offset
                break

        for i in range(insert_index, len(struct_info.udt)):
            # Create space for new member
            struct_info.udt[i].offset += new_member_size * 8

        new_member = ida_typeinf.udt_member_t()
        new_member.name = field_name
        new_member.type = new_type
        new_member.offset = insert_offset * 8

        new_udt = ida_typeinf.udt_type_data_t()

        for i, member in enumerate(struct_info.udt):
            if i == insert_index:
                new_udt.append(new_member)

            new_udt.append(member)

        if insert_index == len(struct_info.udt):
            new_udt.append(new_member)

        new_tif = ida_typeinf.tinfo_t()

        if not new_tif.create_udt(new_udt):
            return Err(result="Failed to rebuild structure.")

        if new_tif.set_named_type(
            til,
            struct_info.struct_name,
            ida_typeinf.NTF_REPLACE,
        ):
            return Err(result=f"Failed to add struct field '{field_name}'.")

        return Ok(
            result=StructFieldResult(
                struct_id=struct_info.struct_id,
                struct_name=struct_info.struct_name,
                field_name=field_name,
            )
        )
