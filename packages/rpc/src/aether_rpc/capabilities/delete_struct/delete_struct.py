import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import StructResult
from ..utils import get_struct_id_by_name


class DeleteStruct(Capability):
    """"""

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
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, struct_name)
        if ida_typeinf.del_numbered_type(til, ordinal):
            return Ok(
                result=StructResult(
                    struct_id=struct_id,
                    struct_name=struct_name,
                )
            )
        else:
            return Err(result=f"Unable to delete struct {struct_name}.")
