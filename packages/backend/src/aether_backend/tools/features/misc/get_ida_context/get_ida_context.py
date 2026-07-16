from typing import Any

from aether_backend.utils.effect import Program, Return

from .types import IDAContext


async def get_context(service: Any, address: str | int) -> Program:
    data_at_address = service.get_data_at_address(location=address)
    if not data_at_address.success:
        raise RuntimeError(f"Failed to fetch data from address: {data_at_address.result}")

    data_at_address = data_at_address.result
    res = service.get_function_pseudocode(function_name=data_at_address["name"])
    pseudocode_str = res.result["pseudocode"] if res.success is not None else res.result

    result = IDAContext(**data_at_address, pseudocode=pseudocode_str)
    yield Return(result)
