from typing import Any

from aether_backend.utils.effect import Program, Return


async def gather(service: Any, function_address: str | int) -> Program:
    
    yield Return(None)
