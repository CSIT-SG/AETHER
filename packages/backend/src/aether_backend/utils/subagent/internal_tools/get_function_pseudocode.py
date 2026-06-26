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
        Ok[FunctionPseudocode]: A structured object containing:
            - name (str): The function name as passed in.
            - start_address (str): The hex string of the function's entry point, e.g. "0x140001000".
            - pseudocode (str): The full decompiled pseudocode as a plain text string.
        Err[str]: An error message string in the following cases:
            - The symbol could not be resolved to a known address.
            - IDA Hex-Rays raised a DecompilationFailure during decompilation.
            - Decompilation succeeded but returned no result.

    Examples:
            get_function_pseudocode("assign_buffer")
            get_function_pseudocode("sub_DEADBEEF")

    """
    service = ctx.context.service
    return service.get_function_pseudocode(function_name=function_name)
