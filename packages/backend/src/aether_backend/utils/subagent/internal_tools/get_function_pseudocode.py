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
    """Decompile a function and return its pseudocode.

    Args:
        function_name (str): The symbolic name of the target function.

    Returns:
        Ok[FunctionPseudocode]: Contains the function name, start address,
            and pseudocode string.
        Err[str]: If the symbol is not found, or decompilation fails.
    """
    service = ctx.context.service
    return service.get_function_pseudocode(function_name=function_name)
