import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import RenameStructFieldResult
from ..utils import get_type_id_by_name


class RenameStructField(Capability):
    """"""

    @property
    def name(self) -> str:
        return "rename_struct_field"

    def execute(
        self, type: str | int, old_field_name: str, new_field_name: str
    ) -> Result[RenameStructFieldResult]:
        """Rename struct field.

        Args:
            type_id: The id of the type containing field to be changed.
            old_field_name: Original name of field to be renamed.
            new_field_name: New name of field to be renamed.

        Returns:
            A Result whose ``success`` reports whether the rename succeeded and
            whose ``result`` carries the struct id, name, old field name and new field name.
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
        udm = ida_typeinf.udm_t()
        udm.name = old_field_name

        idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
        if idx >= 0:
            tif.rename_udm(idx, new_field_name)
        else:
            return Err(result=f"Field {old_field_name} does not exist in Type {type_name}.")

        return Ok(
            result=RenameStructFieldResult(
                type_id=type_id,
                type_name=type_name,
                old_field_name=old_field_name,
                new_field_name=new_field_name,
            )
        )
