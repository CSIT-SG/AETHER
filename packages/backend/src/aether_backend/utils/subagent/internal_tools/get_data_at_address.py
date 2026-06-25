from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import AddressData
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry



@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def get_data_at_address(
    ctx: RunContextWrapper[ToolDependencies], *, location: str | int
) -> Result[AddressData]:
    """ Retrieves raw data, disassembly, string, pointer, and xref context at a given address.

    Args:
        location: Hex address or symbol name of the target.
    """
    service = ctx.context.service
    return service.get_data_at_address(location=location)
