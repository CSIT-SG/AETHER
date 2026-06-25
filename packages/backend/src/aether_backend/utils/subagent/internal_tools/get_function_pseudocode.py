from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import FunctionPseudocode
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry



@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_function_pseudocode(
    ctx: RunContextWrapper[ToolDependencies], *, function_name: str
) -> Result[FunctionPseudocode]:
    """"Retrieves the Hex-Rays decompiled pseudocode for a function by name.

    Args:
        function_name: The symbolic name of the target function.
    """
    service = ctx.context.service
    return service.get_function_pseudocode(function_name=function_name)
