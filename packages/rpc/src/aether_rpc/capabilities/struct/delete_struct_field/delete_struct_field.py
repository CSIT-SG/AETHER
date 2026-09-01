import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import StructFieldResult
from aether_rpc.capabilities.utils import get_struct


class DeleteStructField(Capability):
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
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result

        # Find the field and its size.
        delete_index = None
        delete_size_bits = None

        for i, member in enumerate(struct_info.udt):
            if member.name == field_name:
                delete_index = i
                delete_size_bits = member.type.get_size() * 8
                break

        if delete_index is None:
            return Err(
                result=(f"Field '{field_name}' does not exist in '{struct_info.struct_name}'.")
            )

        # Build the new UDT.
        new_udt = ida_typeinf.udt_type_data_t()

        # Preserve the UDT layout properties.
        new_udt.is_union = struct_info.udt.is_union
        new_udt.sda = struct_info.udt.sda
        new_udt.pack = struct_info.udt.pack
        new_udt.taudt_bits = struct_info.udt.taudt_bits

        for i, member in enumerate(struct_info.udt):
            if i == delete_index:
                continue

            # Everything after the deleted field moves left.
            if i > delete_index:
                member.offset -= delete_size_bits

            new_udt.append(member)

        if delete_size_bits is None:
            return Err(result="Failed to determine size of deleted field.")

        delete_size_bytes = delete_size_bits // 8

        new_udt.total_size = max(
            0,
            struct_info.udt.total_size - delete_size_bytes,
        )

        # Rebuild the type.
        new_tif = ida_typeinf.tinfo_t()

        if not new_tif.create_udt(new_udt):
            return Err(result="Failed to rebuild structure.")

        # Replace the existing named type.
        if new_tif.set_named_type(
            ida_typeinf.get_idati(),
            struct_info.struct_name,
            ida_typeinf.NTF_REPLACE,
        ):
            return Err(result=f"Failed to delete struct field '{field_name}'.")

        return Ok(
            result=StructFieldResult(
                struct_id=struct_info.struct_id,
                struct_name=struct_info.struct_name,
                field_name=field_name,
            )
        )
