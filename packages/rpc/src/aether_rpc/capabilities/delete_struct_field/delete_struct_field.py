import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructFieldResult
from ..utils import get_struct_id_by_name


class DeleteStructField(Capability):
    """"""

    @property
    def name(self) -> str:
        return "delete_struct_field"

    def execute(
        self,
        struct: str | int,
        field_name: str,
    ) -> Result[StructFieldResult]:
        """Delete a field from a structure and compact the remaining fields.

        Args:
            struct: The name or id of the struct to delete the field from.
            field_name: Name of the field to delete.

        Returns:
            A Result whose ``success`` reports whether the deletion succeeded
            and whose ``result`` carries struct id, struct name, and field name.
        """
        if isinstance(struct, int):
            struct_id = struct
        else:
            struct_id = get_struct_id_by_name(str(struct))

        if struct_id is None:
            return Err(result=f"Struct with the specified name {struct} does not exist.")

        tif = ida_typeinf.tinfo_t()

        if not tif.get_type_by_tid(struct_id):
            return Err(result=(f"Struct with the specified id {struct_id} does not exist."))

        if not tif.is_struct():
            return Err(result=f"{struct} is not a struct.")

        struct_name = str(tif.get_type_name())

        # Get UDT members.
        udt = ida_typeinf.udt_type_data_t()

        if not tif.get_udt_details(udt):
            return Err(result=f"{struct_name} is not a structure.")

        # Find the field and its size.
        delete_index = None
        delete_size_bits = None

        for i, member in enumerate(udt):
            if member.name == field_name:
                delete_index = i
                delete_size_bits = member.type.get_size() * 8
                break

        if delete_index is None:
            return Err(result=(f"Field '{field_name}' does not exist in '{struct_name}'."))

        # Build the new UDT.
        new_udt = ida_typeinf.udt_type_data_t()

        # Preserve the UDT layout properties.
        new_udt.is_union = udt.is_union
        new_udt.sda = udt.sda
        new_udt.pack = udt.pack
        new_udt.taudt_bits = udt.taudt_bits

        for i, member in enumerate(udt):
            if i == delete_index:
                continue

            # Everything after the deleted field moves left.
            if i > delete_index:
                member.offset -= delete_size_bits

            new_udt.append(member)

        delete_size_bytes = delete_size_bits // 8

        new_udt.total_size = max(
            0,
            udt.total_size - delete_size_bytes,
        )

        # Rebuild the type.
        new_tif = ida_typeinf.tinfo_t()

        if not new_tif.create_udt(new_udt):
            return Err(result="Failed to rebuild structure.")

        # Replace the existing named type.
        if new_tif.set_named_type(
            ida_typeinf.get_idati(),
            struct_name,
            ida_typeinf.NTF_REPLACE,
        ):
            return Err(result=f"Failed to delete struct field '{field_name}'.")

        return Ok(
            result=StructFieldResult(
                struct_id=struct_id,
                struct_name=struct_name,
                field_name=field_name,
            )
        )
