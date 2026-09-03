from typing import Any

from aether_backend.utils.effect import Program, Return
from aether_rpc.capabilities.result import Err, Ok

from .constants import MAX_OUTPUT_CHARS


def cap_output(output: str) -> str:
    """Bound captured stdout so a runaway script cannot exceed the endpoint limit."""
    if len(output) <= MAX_OUTPUT_CHARS:
        return output
    return (
        output[:MAX_OUTPUT_CHARS]
        + f"\n\n[output truncated: {len(output)} chars total, showing the first "
        f"{MAX_OUTPUT_CHARS}. Narrow the query, add filters or limits, or print a "
        f"summary instead of raw dumps, then re-run.]"
    )


async def exec_code(service: Any, code: str) -> Program:
    result = service.execute_idapython(code=code)
    output = cap_output(str(result.result))
    capped = Ok(output) if result.success else Err(output)
    yield Return(capped)
