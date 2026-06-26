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
    """Collect and return all available data at the given address or symbol.

    Args:
        location (str | int): Hex address or symbol name of the target.

    Returns:
        Ok[AddressData]: Contains address, name, function info, raw bytes,
            disassembly, string, pointer, and xrefs.
        Err[str]: If the address could not be resolved or is not loaded.
    """
    service = ctx.context.service
    return service.get_data_at_address(location=location)
