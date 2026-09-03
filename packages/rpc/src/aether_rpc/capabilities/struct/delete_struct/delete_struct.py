import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.struct_utils import get_struct
from aether_rpc.capabilities.struct.types import StructResult


class DeleteStruct(Capability):
    @property
    def name(self) -> str:
        return "delete_struct"

    def execute(self, struct: str | int) -> Result[StructResult]:
        """Deletes the struct.

        Args:
            struct: The name or id of the struct containing field to be changed.

        Returns:
            A Result whose ``success`` reports whether the deletion succeeded and
            whose ``result`` carries the struct id and name.
        """
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, struct_info.struct_name)
        if ida_typeinf.del_numbered_type(til, ordinal):
            return Ok(
                result=StructResult(
                    struct_id=struct_info.struct_id,
                    struct_name=struct_info.struct_name,
                )
            )
        else:
            return Err(result=f"Unable to delete struct {struct_info.struct_name}.")
