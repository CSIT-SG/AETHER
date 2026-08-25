import ida_xref

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructInfo
from ..utils import get_struct_info_util


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
            whose ``result`` carries info about the struct. Each field returned
            is in the format of [name, type, size, offset]
        """
        error, struct_id, struct_name, fields = get_struct_info_util(struct)
        xrefs = []
        xb = ida_xref.xrefblk_t()

        if not error:
            if len(fields) > 0:
                if xb.first_to(struct_id, ida_xref.XREF_ALL):
                    while True:
                        xrefs.append(hex(xb.frm))

                        if not xb.next_to():
                            break
                return Ok(
                    result=StructInfo(
                        struct_id=struct_id,
                        struct_name=struct_name,
                        applied_to=xrefs,
                        struct_fields=fields,
                    )
                )
            else:
                return Err(result=f"Struct {struct_name} has no fields.")
        else:
            return Err(result=error)
