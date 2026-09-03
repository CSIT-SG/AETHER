import asyncio
from typing import Any

from aether_rpc.capabilities.function.types import FunctionPseudocode
from aether_rpc.capabilities.result import Result
from rpyc import async_

from .models import DecompileResult


async def decompile_function(
    service: Any,
    function_name: str,
) -> DecompileResult:

    aget = async_(service.get_function_pseudocode)
    call_result = aget(function_name=function_name)

    try:
        pc_result: Result[FunctionPseudocode] = await asyncio.to_thread(lambda: call_result.value)
    except (EOFError, ConnectionError, OSError):
        raise
    except Exception as e:
        return DecompileResult(success=False, result=str(e))

    if pc_result.success is False:
        return DecompileResult(success=False, result=pc_result.result)
    else:
        return DecompileResult(success=True, result=pc_result.result["pseudocode"])
