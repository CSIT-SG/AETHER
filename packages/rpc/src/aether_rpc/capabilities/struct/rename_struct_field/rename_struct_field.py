import ida_typeinf

from ...base import Capability
from ...result import Err, Ok, Result
from ...types import RenameStructFieldResult
from ...utils import get_struct


class RenameStructField(Capability):
    @property
    def name(self) -> str:
        return "rename_struct_field"

    def execute(
        self, struct: str | int, old_field_name: str, new_field_name: str
    ) -> Result[RenameStructFieldResult]:
        """Rename struct field.

        Args:
            struct: The name or id of the struct containing field to be changed.
            old_field_name: Original name of field to be renamed.
            new_field_name: New name of field to be renamed.

        Returns:
            A Result whose ``success`` reports whether the rename succeeded and
            whose ``result`` carries the struct id, name, old field name and new field name.
        """
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result

        udm = ida_typeinf.udm_t()
        udm.name = old_field_name

        idx = struct_info.tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
        if idx >= 0:
            struct_info.tif.rename_udm(idx, new_field_name)
        else:
            return Err(
                result=f"Field {old_field_name} does not exist in struct {struct_info.struct_name}."
            )

        return Ok(
            result=RenameStructFieldResult(
                struct_id=struct_info.struct_id,
                struct_name=struct_info.struct_name,
                old_field_name=old_field_name,
                new_field_name=new_field_name,
            )
        )
