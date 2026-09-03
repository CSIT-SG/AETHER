from aether_backend.utils.get_rpc_service.types import AnyService
from aether_rpc.capabilities.comments.types import SetCommentResult
from aether_rpc.capabilities.result import Result


async def set_summary_comment(
    service: AnyService, *, address: str | int, comment: str
) -> Result[SetCommentResult]:
    """Set the function header comment shown above the signature in the
    Hex-Rays decompiler view.

    Resolves the address and confirms it is a function's start address,
    then writes the comment as a repeatable function comment above the
    pseudocode signature. Refreshes the pseudocode view after a
    successful write.

    Args:
        address (str | int): Hex address of the function's start.
        comment (str): Text to write. Pass an empty string to clear an existing comment.

    Returns:
        Ok[SetCommentResult]: A structured object containing:
            - address (str): The hex string of the resolved target address.
            - comment (str): The comment text that was written, or an empty
                string if the comment was cleared.
        Err[str]: An error message string in the following cases:
            - The address could not be resolved to a valid effective address.
            - The resolved address is not inside any known function.
            - The resolved address is not the function's start address.
            - The comment could not be written due to a decompilation failure
                or an internal IDA API error.

    Example:
        set_function_header_comment(0xDEADBEEF, "parses incoming packet headers")
    """
    return service.set_summary_comment(address=address, comment=comment)
