import ida_xref
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.utils import get_struct, get_struct_fields
from aether_rpc.capabilities.types import StructInfo


class GetStructInfo(Capability):
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
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result
        fields = get_struct_fields(struct_info.udt)
        xrefs = []
        xb = ida_xref.xrefblk_t()

        if len(fields) > 0:
            if xb.first_to(struct_info.struct_id, ida_xref.XREF_ALL):
                while True:
                    xrefs.append(hex(xb.frm))

                    if not xb.next_to():
                        break
            return Ok(
                result=StructInfo(
                    struct_id=struct_info.struct_id,
                    struct_name=struct_info.struct_name,
                    applied_to=xrefs,
                    struct_fields=fields,
                )
            )

        return Err(result=f"Struct {struct_info.struct_name} has no fields.")
