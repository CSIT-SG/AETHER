from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructFieldWithOffset, StructInfo
from ..utils import get_struct


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
        status, output = get_struct(struct)
        if status:
            struct_name, struct_id, _, udt = output
        else:
            return Err(result=output)

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
