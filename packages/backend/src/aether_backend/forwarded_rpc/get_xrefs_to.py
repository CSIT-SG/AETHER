from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import XrefsResult


async def get_xrefs_to(service: AnyService, *, location: str | int) -> Result[XrefsResult]:
    """Find all locations that reference the given address or symbol.

    Args:
        location (str | int): Hex address ("0x140001000"), symbol name
            ("assign_buffer", "sub_DEADBEEF"), or effective address.

    Returns:
        Ok[XrefsResult]: target_address, target_name, count, and xrefs —
            the entries pointing at `location`.
        Err[str]: `location` could not be resolved, or IDA raised while
            collecting xrefs.

    Examples:
        get_xrefs_to("assign_buffer")
        get_xrefs_to("0x140001000")
    """

    return service.get_xrefs_to(location=location)
