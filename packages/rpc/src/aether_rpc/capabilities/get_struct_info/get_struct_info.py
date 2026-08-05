import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructFieldWithOffset, StructInfo
from ..utils import get_struct_id_by_name


class GetStructInfo(Capability):
    """"""

    @property
    def name(self) -> str:
        return "get_struct_info"

    def execute(self, struct: str | int) -> Result[StructInfo]:
        """Get struct info.

        Args:
            struct: The name or id of the struct to obtain info on.

        Returns:
            A Result whose ``success`` reports whether the get succeeded and
            whose ``result`` carries info about the struct.
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

        struct_name = tif.get_type_name()

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return Err(result=f"Unable to get struct members for {struct_name}.")

        fields = []

        for member in udt:
            fields.append(
                StructFieldWithOffset(
                    name=member.name,
                    type=member.type.dstr(),
                    size=member.type.get_size(),
                    offset=member.offset // 8,
                )
            )
        if len(fields) > 0:
            return Ok(
                result=StructInfo(
                    struct_id=struct_id,
                    struct_name=struct_name,
                    struct_fields=fields,
                )
            )
        else:
            return Err(result=f"Struct {struct_name} has no fields.")
