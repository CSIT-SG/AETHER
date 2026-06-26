from aether_backend.utils.subagent.constants import SubagentTool
from aether_rpc.capabilities.result import Result
from aether_rpc.capabilities.types import SetCommentResult
from agents import RunContextWrapper, function_tool

from .tags import ToolDependencies, registry


@registry.tag(SubagentTool.ANNOTATOR)
@function_tool
async def set_comment(
    ctx: RunContextWrapper[ToolDependencies], *, address: str | int, comment: str
) -> Result[SetCommentResult]:
    """Set a comment at the given address in the Hex-Rays decompiler view.

    Resolves the address and dispatches to the appropriate comment strategy:
    if the address is the function's start, the comment is written as a
    function header comment above the signature; otherwise it is attached
    as an inline user comment on the AST node at that address. Refreshes
    the pseudocode view after a successful write.

    Args:
        address (str | int): Hex or decimal address of the comment target.
        comment (str): Text to write. Pass an empty string to clear an existing comment.

    Returns:
        Ok[SetCommentResult]: A structured object containing:
            - address (str): The hex string of the resolved target address.
            - comment (str): The comment text that was written, or an empty
                string if the comment was cleared.
        Err[str]: An error message string in the following cases:
            - The address could not be resolved to a valid effective address.
            - The resolved address is not inside any known function.
            - The comment could not be written due to a decompilation failure
                or an internal IDA API error.

    Raises:
        ida_hexrays.DecompilationFailure: Caught internally if Hex-Rays
            fails to decompile the function when writing an inline comment;
            returned as an Err result.

    Example:
        set_comment(0xDEADBEEF, "determines required buffer size")
    """
    service = ctx.context.service
    return service.set_comment(address=address, comment=comment)
