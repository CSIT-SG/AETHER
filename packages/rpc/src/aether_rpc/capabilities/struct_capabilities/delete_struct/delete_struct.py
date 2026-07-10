import ida_typeinf

from ...base import Capability
from ...result import Err, Ok, Result
from ...types import DeleteStructResult
from ...utils import get_type_id_by_name


class DeleteStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "delete_struct"

    def execute(self, type: str | int) -> Result[DeleteStructResult]:
        """Deletes the struct.

        Args:
            type: The id of the type containing field to be changed.

        Returns:
            A Result whose ``success`` reports whether the deletion succeeded and
            whose ``result`` carries the struct id and name.
        """
        try:
            type_id = int(type)
        except ValueError:
            type_id = get_type_id_by_name(str(type))
            if not type_id:
                return Err(result=f"Type with the specified id {type} does not exist.")
        tif = ida_typeinf.tinfo_t()
        if not tif.get_type_by_tid(type_id):
            return Err(result=f"Type with the specified id {type_id} does not exist.")

        type_name = str(tif.get_type_name())
        ordinal = ida_typeinf.get_type_ordinal(None, type_name)
        if ida_typeinf.del_numbered_type(None, ordinal):
            return Ok(
                result=DeleteStructResult(
                    type_id=type_id,
                    type_name=type_name,
                )
            )
        else:
            return Err(result=f"Unable to delete Type {type_name}.")
