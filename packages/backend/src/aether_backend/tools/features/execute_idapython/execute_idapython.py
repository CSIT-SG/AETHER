from typing import Any, cast

from aether_backend.utils.effect import Program, Return


async def exec_code(service: Any, code: str) -> Program:
    result = cast(str, service.execute_idapython(code=code))
    yield Return(result)
