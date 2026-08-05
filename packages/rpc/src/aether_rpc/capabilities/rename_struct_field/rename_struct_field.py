import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import RenameStructFieldResult
from ..utils import get_struct_id_by_name


class RenameStructField(Capability):
    """"""

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
        udm = ida_typeinf.udm_t()
        udm.name = old_field_name

        idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
        if idx >= 0:
            tif.rename_udm(idx, new_field_name)
        else:
            return Err(result=f"Field {old_field_name} does not exist in struct {struct_name}.")

        return Ok(
            result=RenameStructFieldResult(
                struct_id=struct_id,
                struct_name=struct_name,
                old_field_name=old_field_name,
                new_field_name=new_field_name,
            )
        )
