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
        location (str | int): Hex address string or symbol name of the target.

    Returns:
        Ok[AddressData]: A structured object containing:
            - address (str): The resolved hex address string.
            - name (str | None): The symbol name at the address, if any.
            - function (dict | None): Info about the containing function, if any.
            - item_size (int): The size in bytes of the item at the address.
            - raw_bytes (str): The raw bytes at the address as a hex string.
            - is_code (bool): Whether the address is marked as code.
            - is_data (bool): Whether the address is marked as data.
            - disassembly (str | None): The plain-text disassembly line at the address, if code.
            - string (str | None): The decoded string literal at the address, if explicitly defined as one in the database.
            - pointer (PointerInfo | None): Pointer value and symbol it resolves to. Contains:
                - value (str): Value of the pointer e.g. 0xDEADBEEF
                - name (str): Name of the symbol it resolves to e.g. dynamic_buffer_allocation
            - xrefs_to (list): Cross-references pointing to this address.
            - xrefs_from (list): Cross-references originating from this address.
        Err[str]: An error message string in the following cases:
            - The location could not be resolved to a valid effective address.
            - The resolved address is not loaded in the IDA database.

    Examples:
        get_data_at_address(0xDEADBEEF)
        get_data_at_address("my_func")
    """
    service = ctx.context.service
    return service.get_data_at_address(location=location)
