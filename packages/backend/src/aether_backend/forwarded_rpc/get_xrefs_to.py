from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import XrefsResult


async def get_xrefs_to(service: AnyService, *, location: str | int) -> Result[XrefsResult]:
    """Find all locations that reference the given address or symbol name.

    Args:
        location (str | int): The target to look up cross-references for.
            Accepts a hex address string (e.g. "0x140001000"), a plain
            symbol name (e.g. "assign_buffer"), an IDA auto-generated name
            (e.g. "sub_DEADBEEF"), or an integer effective address.

    Returns:
        Ok[XrefsResult]: A structured object containing:
            - target_address (str): The resolved hex address of the target,
              e.g. "0x140001000".
            - target_name (str | None): The symbolic name of the target
              address, or None if no name is defined at that address.
            - count (int): The number of cross-references found.
            - xrefs (list): The collected cross-reference entries pointing
              to the target.
        Err[str]: An error message string in the following cases:
            - The location could not be resolved to a valid effective
              address.
            - An exception was raised while collecting cross-references
              (e.g. an invalid or corrupted address).

    Examples:
        get_xrefs_to("assign_buffer")
        get_xrefs_to("0x140001000")
        get_xrefs_to("sub_DEADBEEF")
    """

    return service.get_xrefs_to(location=location)
