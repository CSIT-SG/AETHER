from ..base import Capability
from ..result import Err, Ok, Result
from ..types import RenameStructResult
from ..utils import get_struct


class RenameStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "rename_struct"

    def execute(self, struct: str | int, new_name: str) -> Result[RenameStructResult]:
        """Rename struct.

        Args:
            struct: The name or id of the struct to rename.
            new_name: The new name for struct to be renamed to.

        Returns:
            A Result whose ``success`` reports whether the rename succeeded and
            whose ``result`` carries struct id, old and new name
        """
        status, output = get_struct(struct)
        if status:
            struct_name, struct_id, tif, _ = output
        else:
            return Err(result=output)

        struct_name = tif.get_type_name()
        status = tif.rename_type(new_name)

        if not status:
            return Ok(
                result=RenameStructResult(
                    struct_id=struct_id,
                    old_struct_name=struct_name,
                    new_struct_name=new_name,
                )
            )
        else:
            return Err(
                result=f"Rename for Struct {struct_name} has failed, ensure new name provided is valid."
            )
