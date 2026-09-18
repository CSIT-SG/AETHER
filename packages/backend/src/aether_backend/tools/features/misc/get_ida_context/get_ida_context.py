from typing import Any

from aether_backend.utils.effect import Program, Return

from .types import IDAContext


async def get_context(service: Any, address: str | int) -> Program:
    data_at_address = service.get_data_at_address(location=address)
    if not data_at_address.success:
        yield Return(f"Failed to fetch data from address: {data_at_address.result}")

    data_at_address = data_at_address.result
    function = data_at_address["function"]
    res = service.get_function_pseudocode(
        function_name=function["name"] if function else data_at_address["name"]
    )
    pseudocode_str = res.result["pseudocode"] if res.success else res.result

    result = IDAContext(
        name=data_at_address["name"],
        function=data_at_address["function"],
        disassembly=data_at_address["disassembly"],
        is_code=data_at_address["is_code"],
        is_data=data_at_address["is_data"],
        xrefs_to=data_at_address["xrefs_to"],
        xrefs_from=data_at_address["xrefs_from"],
        pseudocode=pseudocode_str,
    )
    yield Return(result)
