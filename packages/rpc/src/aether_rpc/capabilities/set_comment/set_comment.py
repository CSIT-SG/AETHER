from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_hexrays

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import SetCommentResult
from ..utils import resolve_effective_address

_OP_TO_ITP: defaultdict[int, int] = defaultdict(
    lambda: ida_hexrays.ITP_SEMI,
    {
        ida_hexrays.cit_if:     ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_while:  ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_for:    ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_do:     ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_switch: ida_hexrays.ITP_BLOCK1,
        ida_hexrays.cit_block:  ida_hexrays.ITP_BRACE1,
        ida_hexrays.cit_return: ida_hexrays.ITP_SEMI,
        ida_hexrays.cit_expr:   ida_hexrays.ITP_SEMI,
    },
)

class SetComment(Capability):
    """Attaches or updates a comment at a given address in the IDA decompiler view.

    Handles two distinct comment targets:
    - Function header: the definition line at the top of the pseudocode
    - Inline statement: any address inside the decompiled function body
    """

    @property
    def name(self) -> str:
        return "set_comment"

    def execute(self, address: str | int, comment: str) -> Result[SetCommentResult]:
        """Resolve the address and dispatch to the appropriate comment strategy.

        Args:
            address: Hex or decimal string address of the comment target.
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
            success = self._set_function_header_comment(func, ea, comment)
        else:
            success = self._set_pseudocode_comment(func, ea, comment)

        if not success:
            return Err(result=f"Failed to set comment at {hex(ea)}")

        return Ok(result=SetCommentResult(address=hex(ea), comment=comment))

    def _set_function_header_comment(self, func: ida_funcs.func_t, ea: int, comment: str) -> bool:
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

    def _set_pseudocode_comment(self, func: ida_funcs.func_t, ea: int, comment: str) -> bool:
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
        for i in range(len(pseudocode)):
            sl = pseudocode[i]
            item = ida_hexrays.ctree_item_t()
            dummy_head = ida_hexrays.ctree_item_t()
            dummy_anchor = ida_hexrays.ctree_item_t()
            if cfunc.get_line_item(sl.line, 0, False, dummy_head, item, dummy_anchor):
                citem = item.it
                if citem and citem.ea == ea:
                    itp = _OP_TO_ITP[citem.op]

        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        return True
