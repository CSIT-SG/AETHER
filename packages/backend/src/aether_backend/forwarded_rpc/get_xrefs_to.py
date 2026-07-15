from aether_backend.utils.get_rpc_service import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import XrefsResult

async def get_xrefs_to(
        service: AnyService, *, location: str | int
) -> Result[XrefsResult]:
    """Find all locations that reference the given address or symbol name.

        Args:
            location: Hex address or symbol name of the target.

        Returns:
            A Result whose ``result`` holds the target address, name, and a list
            of xrefs on success, or an error message if the target could not be
            resolved.
        """

    return service.get_xrefs_to(location=location)
