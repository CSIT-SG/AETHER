import ida_bytes
import ida_funcs
import ida_hexrays

from ...base import Capability
from ...result import Err, Ok, Result
from ...types import SetCommentResult
from ...utils import resolve_effective_address


class SetSummaryComment(Capability):
    """Attaches or updates the comment shown above a function's signature
    in the IDA decompiler view (the function header / summary comment).
    """

    @property
    def name(self) -> str:
        return "set_summary_comment"

    def execute(self, address: str | int, comment: str) -> Result[SetCommentResult]:
        """Resolve the address and write the function header comment.

        Args:
            address: Hex or decimal string address of the function. Must
                resolve to a function's start address.
            comment: Text to write. Pass an empty string to clear.

        Returns:
            A Result whose ``success`` reports whether the comment was written
            and whose ``result`` carries the target address and comment.
        """

        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return Err(result=f"Invalid address: {address}")

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error("Address %s is not inside a function", hex(ea))
            return Err(result=f"Address {hex(ea)} is not inside a function")

        if ea != func.start_ea:
            self.logger.error(
                "Address %s is not the start of function at %s",
                hex(ea),
                hex(func.start_ea),
            )
            return Err(
                result=f"Address {hex(ea)} is not the start of function at {hex(func.start_ea)}"
            )

        success = self._set_summary_comment(func, ea, comment)
        if not success:
            return Err(result=f"Failed to set comment at {hex(ea)}")

        return Ok(result=SetCommentResult(address=hex(ea), comment=comment))

    def _set_summary_comment(self, func: ida_funcs.func_t, ea: int, comment: str) -> bool:
        """Write a comment that appears above the function signature in pseudocode.

        Args:
            func: The function whose header is being annotated.
            ea: Effective address of the function head.
            comment: Text to write. Empty string clears the comment.
        """

        ea = ida_bytes.get_item_head(ea)
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            self.logger.error("Failed to decompile function at %s", hex(ea))
            return False

        ida_funcs.set_func_cmt(func, comment, True)

        cfunc.refresh_func_ctext()
        return True
