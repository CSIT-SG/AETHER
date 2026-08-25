import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import AllStructs, StructInfo
from ..utils import get_struct_info_util


class ListStructs(Capability):
    """"""

    @property
    def name(self) -> str:
        return "list_structs"

    def execute(self) -> Result[AllStructs]:
        """List structs.

        Returns:
            A Result whose ``success`` reports whether the get succeeded and
            whose ``result`` carries the name of all of the structs.
        """
        structs = []
        limit = ida_typeinf.get_ordinal_limit()
        for ordinal in range(1, limit):
            tif = ida_typeinf.tinfo_t()

            if not tif.get_numbered_type(None, ordinal):
                continue

            name = tif.get_type_name()
            if not name or not tif.is_struct():
                continue

            error, struct_id, struct_name, fields = get_struct_info_util(name)
            if error:
                continue

            structs.append(
                StructInfo(
                    struct_id=struct_id,
                    struct_name=struct_name,
                    struct_fields=fields,
                )
            )
        if len(structs) > 0:
            return Ok(
                AllStructs(
                    number_of_structs=len(structs),
                    structs=structs,
                )
            )
        else:
            return Err(result="Binary has no structs.")
