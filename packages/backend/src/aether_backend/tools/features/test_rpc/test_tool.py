from typing import Any

from aether_backend.utils.effect import Program, Return


async def test(service: Any, func_name: str, **kwargs) -> Program:
    if hasattr(service, func_name):
        tool = getattr(service, func_name)
        yield Return(tool(**kwargs))

    else:
        yield Return("Invalid tool name")
