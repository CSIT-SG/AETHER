import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import ChangeStructFieldTypeResult
from ..utils import get_struct_id_by_name
from .constants import TYPE_MAP


class ChangeStructFieldType(Capability):
    """"""

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

        # Get original UDT
        old_udt = ida_typeinf.udt_type_data_t()

        if not tif.get_udt_details(old_udt):
            return Err(result=f"{struct_name} is not a structure.")

        # Locate member
        member_index = next(
            (i for i, member in enumerate(old_udt) if member.name == field_name),
            -1,
        )

        if member_index == -1:
            return Err(result=f"Field '{field_name}' does not exist in '{struct_name}'.")

        old_member = old_udt[member_index]
        old_size = old_member.type.get_size()

        if old_size == ida_typeinf.BADSIZE or old_size <= 0:
            return Err(result="Unable to determine old member size.")

        # Resolve new type
        til = ida_typeinf.get_idati()
        field_tif = ida_typeinf.tinfo_t()

        if not field_tif.get_named_type(til, new_type):
            type_code = TYPE_MAP.get(new_type)

            if type_code is None or not field_tif.create_simple_type(type_code):
                return Err(result=f"Unable to resolve field type '{new_type}'.")

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

        for i, old_member in enumerate(old_udt):
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

                padding_name = f"padding_{padding_index}"

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
            struct_name,
            ida_typeinf.NTF_REPLACE,
        )

        if result != ida_typeinf.TERR_OK:
            return Err(
                result=(
                    f"Failed to replace structure '{struct_name}': "
                    f"{ida_typeinf.tinfo_errstr(result)} "
                    f"(code={result})"
                )
            )

        return Ok(
            result=ChangeStructFieldTypeResult(
                struct_id=struct_id,
                struct_name=struct_name,
                field_name=field_name,
                new_type=new_type,
            )
        )
