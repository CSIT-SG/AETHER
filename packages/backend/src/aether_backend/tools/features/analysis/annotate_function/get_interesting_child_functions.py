from typing import Any

from aether_backend.forwarded_rpc import (
    get_data_at_address,
    get_functions_called_recursively,
)
from aether_backend.utils.effect import Program, Return
from aether_backend.utils.get_content import get_content
from aether_utils.config import get_config


async def get_interesting_child_functions(service: Any, function_address: str | int) -> Program:
    # should return Array<{ address: number; reason: string }>
    yield Return(None)
