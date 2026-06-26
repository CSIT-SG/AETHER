from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import SetCommentResult
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def set_comment(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, comment: str
) -> Result[SetCommentResult]:
    """Set a comment at the given address in the Hex-Rays decompiler view.

    Args:
        address (str | int): Hex or decimal address of the comment target.
        comment (str): Text to write. Pass an empty string to clear.

    Returns:
        Ok[SetCommentResult]: Contains the target address and comment text.
        Err[str]: If the address is invalid, not inside a function, or the comment fails.
    """
    service = ctx.context.service
    return service.set_comment(address=address, comment=comment)
