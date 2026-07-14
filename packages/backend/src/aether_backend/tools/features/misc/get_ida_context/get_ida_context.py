from typing import Any

from aether_backend.utils.effect import Program, Return


async def exec_code(service: Any, address: str | int) -> Program:
    data_at_address = dict(service.get_data_at_address(location=address).result)
    pseudocode = (
        service.get_function_pseudocode(function_name=data_at_address["name"]).result
        if data_at_address["name"]
        else None
    )

    result = str({"data": data_at_address, "pseudocode": pseudocode})
    yield Return(result)
