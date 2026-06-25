from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import AddressData
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@function_tool
@registry.tag(SubagentTool.ANNOTATOR)
async def get_data_at_address(
    ctx: RunContextWrapper[ToolDependencies], *, location: str | int
) -> Result[AddressData]:
    service = ctx.context.service
    return service.get_data_at_address(location=location)
