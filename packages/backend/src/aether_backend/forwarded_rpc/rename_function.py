from aether_backend.forwarded_rpc.get_data_at_address import AnyService
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import RenameFuncResult


async def rename_function(
    service: AnyService, *, address: str | int, new_name: str
) -> Result[RenameFuncResult]:
    """Rename the function at the given address.

    Resolves the address to a function and applies the new name using IDA's
    naming API. The rename is applied to the function's start address regardless
    of whether the provided address points to the start or interior of the function.

    Args:
        address (str | int): Hex address within the target function.
        new_name (str): The new name to assign to the function.

    Returns:
        Ok[RenameFuncResult]: A structured object containing:
            - address (str): The hex string of the function's start address.
            - new_name (str): The name that was successfully applied.
        Err[str]: An error message string in the following cases:
            - The address could not be resolved to a valid effective address.
            - No function exists at or containing the resolved address.
            - IDA's naming API rejected the new name or the rename otherwise failed.

    Example:
        rename_function(0xDEADBEEF, "find_strlen")
    """
    return service.rename_function(address=address, new_name=new_name)
