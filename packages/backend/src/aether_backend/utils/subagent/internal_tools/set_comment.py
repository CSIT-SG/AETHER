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
    """Resolve the address and dispatch to the appropriate comment strategy.

        Args:
            address: Hex or decimal string address of the comment target.
            comment: Text to write. Pass an empty string to clear.
    """
    service = ctx.context.service
    return service.set_comment(address=address, comment=comment)
