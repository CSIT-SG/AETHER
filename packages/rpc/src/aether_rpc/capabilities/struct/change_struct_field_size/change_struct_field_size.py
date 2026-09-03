import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.struct_utils import get_struct
from aether_rpc.capabilities.types import ChangeStructFieldSizeResult


class ChangeStructFieldSize(Capability):
    @property
    def name(self) -> str:
        return "change_struct_field_size"

    def execute(
        self, struct: str | int, field_name: str, new_size: str
    ) -> Result[ChangeStructFieldSizeResult]:
        """Change struct field size.

        Args:
            struct: The name or id of the struct to add the field to.
            field_name: Name of field to be resized.
            new_size: New size of field.

        Returns:
            A Result object whose ``result`` attribute contains the outcome.
        """
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result
        struct_name = struct_info.struct_name
        struct_id = struct_info.struct_id
        udt = struct_info.udt

        # Locate member
        member_index = next((i for i, member in enumerate(udt) if member.name == field_name), -1)
        if member_index == -1:
            return Err(result=f"Field '{field_name}' does not exist in '{struct_name}'.")

        member = udt[member_index]

        # Old size
        old_size = member.type.get_size()
        if old_size <= 0:
            return Err(result="Unable to determine old member size.")

        if member.type.is_array():
            if not member.type.get_array_element():
                return Err(result="Failed to get array element type.")
            elem_type = member.type.get_array_element()
        else:
            elem_type = ida_typeinf.tinfo_t(member.type)

        array_type = ida_typeinf.tinfo_t()
        try:
            array_type.create_array(elem_type, int(new_size))
        except ValueError:
            return Err(result=f"Invalid size provided: '{new_size}'.")
        new_member_size = array_type.get_size()
        delta = new_member_size - old_size

        # Update member type
        member.type = array_type

        # Shift subsequent members
        if delta != 0:
            for i in range(member_index + 1, len(udt)):
                udt[i].offset += delta * 8  # offsets are in bits

        # Rebuild the UDT
        new_tif = ida_typeinf.tinfo_t()
        if not new_tif.create_udt(udt):
            return Err(result="Failed to rebuild structure.")

        # Preserve the original name
        til = ida_typeinf.get_idati()
        new_tif.set_named_type(
            til,
            struct_name,
            ida_typeinf.NTF_REPLACE,
        )

        return Ok(
            result=ChangeStructFieldSizeResult(
                struct_id=struct_id,
                struct_name=struct_name,
                field_name=field_name,
                new_size=new_size,
            )
        )
