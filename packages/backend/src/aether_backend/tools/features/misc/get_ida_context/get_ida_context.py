from typing import Any

from aether_backend.utils.effect import Program, Return

from .types import IDAContext


async def exec_code(service: Any, address: str | int) -> Program:
    data_at_address = dict(service.get_data_at_address(location=address).result)
    res = service.get_function_pseudocode(function_name=data_at_address["name"])
    pseudocode = res.result if res.success else None
    pseudocode_str = dict(pseudocode)["pseudocode"] if pseudocode is not None else None

    result = IDAContext(
        name=data_at_address["name"],
        pseudocode=pseudocode_str,
        function=data_at_address["function"],
        disassembly=data_at_address["disassembly"],
        is_code=data_at_address["is_code"],
        is_data=data_at_address["is_data"],
        xrefs_to=data_at_address["xrefs_to"],
        xrefs_from=data_at_address["xrefs_from"],
    )
    yield Return(result)
