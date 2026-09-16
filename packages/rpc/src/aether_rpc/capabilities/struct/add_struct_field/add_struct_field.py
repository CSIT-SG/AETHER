import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.add_struct_field.constants import TYPE_MAP
from aether_rpc.capabilities.struct.utils import InternalStructInfo, get_struct
from aether_rpc.capabilities.types import StructFieldResult


class AddStructField(Capability):
    @property
    def name(self) -> str:
        return "add_struct_field"

    def _resolve_field_type(
        self, field_type: str, array_length: int | None
    ) -> Result[ida_typeinf.tinfo_t]:
        """Resolve field_type to a sized type, wrapped in an array if requested."""
        new_type = ida_typeinf.tinfo_t()

        if not new_type.get_named_type(ida_typeinf.get_idati(), field_type):
            type_code = TYPE_MAP.get(field_type)

            if type_code is None or not new_type.create_simple_type(type_code):
                return Err(
                    result=f"Unable to resolve field type '{field_type}'. Please provide a user-defined type or use one of the following supported types: {', '.join(TYPE_MAP.keys())}."
                )

        if array_length is not None:
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

        if new_type.get_size() <= 0:
            return Err(result=f"Unable to determine size of field type '{field_type}'.")

        return Ok(result=new_type)

    def _find_insert_position(
        self, udt: ida_typeinf.udt_type_data_t, offset: int
    ) -> tuple[int, int]:
        """Return the (index, byte offset) a member placed at offset should take.

        An offset landing inside an existing member is pushed to just past it;
        one beyond the last member keeps the requested offset.
        """
        for i, member in enumerate(udt):
            member_offset = member.offset // 8
            member_size = member.type.get_size()

            if member_size <= 0:
                continue

            member_end = member_offset + member_size

            if member_offset < offset < member_end:
                return i + 1, member_end

            if offset <= member_offset:
                return i, offset

        return len(udt), offset

    def _build_udt(
        self,
        struct_info: InternalStructInfo,
        new_member: ida_typeinf.udt_member_t,
        insert_index: int,
        insert_offset: int,
        offset: int,
    ) -> ida_typeinf.udt_type_data_t:
        """Rebuild the member list with new_member spliced in at insert_index.

        A member landing past the end of the struct is preceded by a char array
        named after offset, expanding the struct to reach insert_offset.
        """
        new_udt = ida_typeinf.udt_type_data_t()
        new_udt.pack = 1

        for i, member in enumerate(struct_info.udt):
            if i == insert_index:
                new_udt.append(new_member)

            new_udt.append(member)

        if insert_index == len(struct_info.udt):
            current_size = struct_info.tif.get_size()

            if insert_offset > current_size:
                char_type = ida_typeinf.tinfo_t()
                char_type.create_simple_type(ida_typeinf.BTF_CHAR)

                array_type = ida_typeinf.tinfo_t()
                array_type.create_array(char_type, insert_offset - current_size)

                padding = ida_typeinf.udt_member_t()
                padding.name = "padding_" + hex(offset)
                padding.type = array_type

                new_udt.append(padding)

            new_udt.append(new_member)

        return new_udt

    def _commit(
        self,
        struct_info: InternalStructInfo,
        new_udt: ida_typeinf.udt_type_data_t,
        field_name: str,
    ) -> Result[StructFieldResult]:
        """Store new_udt over the existing named type."""
        new_tif = ida_typeinf.tinfo_t()

        if not new_tif.create_udt(new_udt):
            return Err(result="Failed to rebuild structure.")

        if new_tif.set_named_type(
            ida_typeinf.get_idati(),
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

        if any(member.name == field_name for member in struct_info.udt):
            return Err(
                result=f"Field '{field_name}' already exists in '{struct_info.struct_name}'."
            )

        type_result = self._resolve_field_type(field_type, array_length)
        if isinstance(type_result, Err):
            return Err(result=type_result.result)

        new_type = type_result.result
        new_member_size = new_type.get_size()

        try:
            offset = int(offset)
        except ValueError:
            return Err(result=f"Invalid offset provided: '{offset}'.")

        insert_index, insert_offset = self._find_insert_position(struct_info.udt, offset)

        # Create space for the new member
        for i in range(insert_index, len(struct_info.udt)):
            struct_info.udt[i].offset += new_member_size * 8

        new_member = ida_typeinf.udt_member_t()
        new_member.name = field_name
        new_member.type = new_type
        new_member.offset = insert_offset * 8

        new_udt = self._build_udt(struct_info, new_member, insert_index, insert_offset, offset)

        return self._commit(struct_info, new_udt, field_name)
