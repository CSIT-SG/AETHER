import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructFieldResult
from ..utils import get_struct_id_by_name
from .constants import TYPE_MAP


class AddStructField(Capability):
    """"""

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
        if isinstance(struct, int):
            struct_id = struct
        else:
            struct_id = get_struct_id_by_name(str(struct))

        if struct_id is None:
            return Err(result=f"Struct with the specified name {struct} does not exist.")

        tif = ida_typeinf.tinfo_t()

        if not tif.get_type_by_tid(struct_id):
            return Err(result=f"Struct with the specified id {struct_id} does not exist.")

        if not tif.is_struct():
            return Err(result=f"{struct} is not a struct.")

        struct_name = str(tif.get_type_name())

        # Get UDT members
        udt = ida_typeinf.udt_type_data_t()

        if not tif.get_udt_details(udt):
            return Err(result=f"{struct_name} is not a structure.")

        # Check for duplicate field name
        if any(member.name == field_name for member in udt):
            return Err(result=f"Field '{field_name}' already exists in '{struct_name}'.")

        til = ida_typeinf.get_idati()
        new_type = ida_typeinf.tinfo_t()

        type_code = TYPE_MAP.get(field_type)

        if type_code is not None:
            # Primitive type from TYPE_MAP.
            if not new_type.create_simple_type(type_code):
                return Err(result=f"Unable to create field type '{field_type}'.")
        else:
            # Fall back to an IDA named type, e.g. a user-defined struct.
            if not new_type.get_named_type(til, field_type):
                return Err(result=f"Unable to resolve field type '{field_type}'.")

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
                    return Err(result=f"Unable to create array type '{field_type}[{array_length}]'.")
            except ValueError:
                return Err(result=f"Invalid array length provided: '{array_length}'.")

            new_type = array_type

        new_member_size = new_type.get_size()

        if new_member_size <= 0:
            return Err(result=f"Unable to determine size of field type '{field_type}'.")

        insert_index = len(udt)
        insert_offset = offset

        for i, member in enumerate(udt):
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

        for i in range(insert_index, len(udt)):
            # Create space for new member
            udt[i].offset += new_member_size * 8

        new_member = ida_typeinf.udt_member_t()
        new_member.name = field_name
        new_member.type = new_type
        new_member.offset = insert_offset * 8

        new_udt = ida_typeinf.udt_type_data_t()

        for i, member in enumerate(udt):
            if i == insert_index:
                new_udt.append(new_member)

            new_udt.append(member)

        if insert_index == len(udt):
            new_udt.append(new_member)

        new_tif = ida_typeinf.tinfo_t()

        if not new_tif.create_udt(new_udt):
            return Err(result="Failed to rebuild structure.")

        if new_tif.set_named_type(
            til,
            struct_name,
            ida_typeinf.NTF_REPLACE,
        ):
            return Err(result=f"Failed to add struct field '{field_name}'.")

        return Ok(
            result=StructFieldResult(
                struct_id=struct_id,
                struct_name=struct_name,
                field_name=field_name,
            )
        )
