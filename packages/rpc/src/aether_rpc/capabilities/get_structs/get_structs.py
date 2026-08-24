import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import AllStructs, StructInfo
from ..utils import get_struct_info_util


class GetStructs(Capability):
    """"""

    @property
    def name(self) -> str:
        return "get_structs"

    def execute(self) -> Result[AllStructs]:
        """Get structs.

        Returns:
            A Result whose ``success`` reports whether the get succeeded and
            whose ``result`` carries the name of all of the structs.
        """
        structs = []
        limit = ida_typeinf.get_ordinal_limit()
        for ordinal in range(1, limit):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal):
                name = tif.get_type_name()
                if name and tif.is_struct():
                    error, struct_id, struct_name, fields = get_struct_info_util(name)
                    if not error:
                        structs.append(
                            StructInfo(
                                struct_id=struct_id,
                                struct_name=struct_name,
                                struct_fields=fields,
                            )
                        )
                    else:
                        pass
        if len(structs) > 0:
            return Ok(
                AllStructs(
                    number_of_structs=len(structs),
                    structs=structs,
                )
            )
        else:
            return Err(result="Binary has no structs.")
