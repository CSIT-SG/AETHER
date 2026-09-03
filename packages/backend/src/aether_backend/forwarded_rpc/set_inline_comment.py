from aether_backend.utils.get_rpc_service.types import AnyService
from aether_rpc.capabilities.comments.types import SetCommentResult
from aether_rpc.capabilities.result import Result


async def set_inline_comment(
    service: AnyService, *, address: str | int, comment: str
) -> Result[SetCommentResult]:
    """Set an inline comment on a statement inside the Hex-Rays decompiler view.

    Resolves the address and confirms it falls inside a function's body
    (not its start address), then attaches the comment as a user comment
    on the AST node at that address. Refreshes the pseudocode view after
    a successful write.

    Args:
        address (str | int): Hex address of the comment target, inside
            a function's body.
        comment (str): Text to write. Pass an empty string to clear an existing comment.

    Returns:
        Ok[SetCommentResult]: A structured object containing:
            - address (str): The hex string of the resolved target address.
            - comment (str): The comment text that was written, or an empty
                string if the comment was cleared.
        Err[str]: An error message string in the following cases:
            - The address could not be resolved to a valid effective address.
            - The resolved address is not inside any known function.
            - The resolved address is the function's start address (use
                set_function_header_comment instead).
            - The comment could not be written due to a decompilation failure
                or an internal IDA API error.

    Example:
        set_pseudocode_comment(0xDEADBEEF, "determines required buffer size")
    """
    return service.set_inline_comment(address=address, comment=comment)
