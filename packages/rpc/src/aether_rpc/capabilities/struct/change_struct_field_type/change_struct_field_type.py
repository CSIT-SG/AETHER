import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.change_struct_field_type.constants import TYPE_MAP
from aether_rpc.capabilities.struct.struct_utils import get_struct
from aether_rpc.capabilities.struct.types import ChangeStructFieldTypeResult


class ChangeStructFieldType(Capability):
    @property
    def name(self) -> str:
        return "change_struct_field_type"

    def execute(
        self, struct: str | int, field_name: str, new_type: str
    ) -> Result[ChangeStructFieldTypeResult]:
        """Change struct field type.

        Args:
            struct: The name or id of the struct to add the field to.
            field_name: Name of field which type is to be changed.
            new_type: New type of field.

        Returns:
            A Result object whose ``result`` attribute contains the outcome.
        """
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result

        # Locate member
        member_index = next(
            (i for i, member in enumerate(struct_info.udt) if member.name == field_name),
            -1,
        )

        if member_index == -1:
            return Err(
                result=f"Field '{field_name}' does not exist in '{struct_info.struct_name}'."
            )

        old_member = struct_info.udt[member_index]
        old_size = old_member.type.get_size()

        if old_size == ida_typeinf.BADSIZE or old_size <= 0:
            return Err(result="Unable to determine old member size.")

        # Resolve new type
        til = ida_typeinf.get_idati()
        field_tif = ida_typeinf.tinfo_t()

        if not field_tif.get_named_type(til, new_type):
            type_code = TYPE_MAP.get(new_type)

            if type_code is None or not field_tif.create_simple_type(type_code):
                return Err(
                    result=f"Unable to resolve field type '{new_type}'. Please provide a user-defined type or use one of the following supported types: uint8_t, uint16_t, word, uint32_t, dword, uint64_t, int8_t, int16_t, short, int32_t, long, int64_t, char, bool, byte, float, double, or void."
                )

        new_size = field_tif.get_size()

        if new_size == ida_typeinf.BADSIZE or new_size <= 0:
            return Err(result=f"Unable to determine size of new type '{new_type}'.")

        # Offset change for members after the changed member.
        delta = (new_size - old_size) * 8

        # Rebuild UDT
        new_udt = ida_typeinf.udt_type_data_t()
        new_udt.pack = 1

        previous_end = 0
        padding_index = 0

        for i, old_member in enumerate(struct_info.udt):
            offset = old_member.offset

            if i > member_index:
                offset += delta

            offset_bytes = offset // 8
            gap = offset_bytes - previous_end

            # Add explicit padding for gaps.
            if gap > 0:
                padding_tif = ida_typeinf.tinfo_t()

                if not padding_tif.create_array(
                    ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR),
                    gap,
                ):
                    return Err(result="Failed to create padding type.")

                padding_name = f"__padding_{padding_index}"

                if not new_udt.add_member(
                    padding_name,
                    padding_tif,
                    previous_end * 8,
                ):
                    return Err(result="Failed to add padding member.")

                padding_index += 1

            # Add actual member.
            member_type = field_tif if i == member_index else old_member.type

            if not new_udt.add_member(
                old_member.name,
                member_type,
                offset,
            ):
                return Err(result=f"Failed to add member '{old_member.name}'.")

            previous_end = offset_bytes + member_type.get_size()

        # Create and replace structure.
        new_tif = ida_typeinf.tinfo_t()

        if not new_tif.create_udt(new_udt):
            return Err(result="Failed to rebuild structure.")

        result = new_tif.set_named_type(
            til,
            struct_info.struct_name,
            ida_typeinf.NTF_REPLACE,
        )
        final_tif = ida_typeinf.tinfo_t()
        if not final_tif.get_named_type(til, struct_info.struct_name):
            return Err(result=f"Failed to retrieve structure '{struct_info.struct_name}'.")
        final_udt = ida_typeinf.udt_type_data_t()
        if not final_tif.get_udt_details(final_udt):
            return Err(result=f"Failed to get details for '{struct_info.struct_name}'.")
        for i in range(len(final_udt) - 1, -1, -1):
            member = final_udt[i]
            if member.name.startswith("__padding_") or (
                member.name.startswith("gap")
                and member.type.is_array()
                and member.type.get_size() > 0
            ):
                result = final_tif.del_udm(i)
                if result != ida_typeinf.TERR_OK:
                    return Err(
                        result=(
                            f"Failed to delete '{member.name}': "
                            f"{ida_typeinf.tinfo_errstr(result)} "
                            f"(code={result})"
                        )
                    )

        return Ok(
            result=ChangeStructFieldTypeResult(
                struct_id=struct_info.struct_id,
                struct_name=struct_info.struct_name,
                field_name=field_name,
                new_type=new_type,
            )
        )
