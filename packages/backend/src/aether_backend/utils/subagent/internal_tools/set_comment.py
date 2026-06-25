from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import SetCommentResult
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@function_tool
@registry.tag(SubagentTool.ANNOTATOR)
async def set_comment(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, comment: str
) -> Result[SetCommentResult]:
    service = ctx.context.service
    return service.set_comment(address=address, comment=comment)
