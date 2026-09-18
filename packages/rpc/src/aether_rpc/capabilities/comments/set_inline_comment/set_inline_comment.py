import ida_funcs
import ida_hexrays
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.comments.set_inline_comment.constants import OP_TO_ITP
from aether_rpc.capabilities.misc.utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import SetCommentResult


class SetInlineComment(Capability):
    """Attaches or updates a Hex-Rays user comment on a specific statement
    inside a decompiled function body (an inline pseudocode comment).
    """

    @property
    def name(self) -> str:
        return "set_inline_comment"

    def execute(self, address: str | int, comment: str) -> Result[SetCommentResult]:
        """Resolve the address and write the inline pseudocode comment.

        Args:
            address: Hex or decimal string address of the comment target.
                Must resolve to an address inside a function's body (not
                the function's start address).
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

        if ea == func.start_ea:
            self.logger.error(
                "Address %s is the function header; use set_function_header_comment instead",
                hex(ea),
            )
            return Err(
                result=(
                    f"Address {hex(ea)} is the function header; "
                    "use set_function_header_comment instead"
                )
            )

        success = self._set_inline_comment(func, ea, comment)
        if not success:
            return Err(result=f"Failed to set comment at {hex(ea)}")

        return Ok(result=SetCommentResult(address=hex(ea), comment=comment))

    def _set_inline_comment(self, func: ida_funcs.func_t, ea: int, comment: str) -> bool:
        """Write a Hex-Rays user comment on the AST node at ``ea``.

        Args:
            func: The function containing ``ea``.
            ea: Effective address of the statement to annotate.
            comment: Text to write. Empty string clears the comment.
        """

        try:
            cfunc = ida_hexrays.decompile(func)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile function at %s: %s", hex(func.start_ea), e)
            return False

        if cfunc is None:
            self.logger.error(
                "Decompilation returned no result for function at %s", hex(func.start_ea)
            )
            return False

        itp = ida_hexrays.ITP_SEMI
        pseudocode = cfunc.get_pseudocode()
        for sl in pseudocode:
            item = ida_hexrays.ctree_item_t()

            # Dummy items are needed here to satisfy type check
            # get_line_item() requires output ctree items but we don't need them therefore the dummies
            dummy_head = ida_hexrays.ctree_item_t()
            dummy_anchor = ida_hexrays.ctree_item_t()
            if cfunc.get_line_item(sl.line, 0, False, dummy_head, item, dummy_anchor):
                citem = item.it
                if citem and citem.ea == ea:
                    itp = OP_TO_ITP[citem.op]

        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        return True
