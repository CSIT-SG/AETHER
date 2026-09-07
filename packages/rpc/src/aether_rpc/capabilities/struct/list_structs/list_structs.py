import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.utils import get_struct, get_struct_fields
from aether_rpc.capabilities.types import AllStructs, StructInfo


class ListStructs(Capability):
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

            struct_result = get_struct(name)
            if isinstance(struct_result, Err):
                continue

            struct_info = struct_result.result
            fields = get_struct_fields(struct_info.udt)

            structs.append(
                StructInfo(
                    struct_id=struct_info.struct_id,
                    struct_name=struct_info.struct_name,
                    applied_to=[],
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
