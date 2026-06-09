import ida_bytes
import ida_funcs
import ida_hexrays
import idc

from ..base import Capability
from ..utils import refresh_pseudocode, resolve_effective_address


class SetComment(Capability):
    """Attaches or updates a comment at a given address in the IDA decompiler view.

    Handles two distinct comment targets:
    - Function header: the definition line at the top of the pseudocode
    - Inline statement: any address inside the decompiled function body
    """

    @property
    def name(self) -> str:
        return "set_comment"

    def execute(self, address: str | int, comment: str) -> bool:
        """Resolve the address and dispatch to the appropriate comment strategy.

        Args:
            address: Hex or decimal string address of the comment target.
            comment: Text to write. Pass an empty string to clear.
        """

        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return False

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error("Address %s is not inside a function", hex(ea))
            return False

        if ea == func.start_ea:
            success = self._set_function_header_comment(ea, comment)
        else:
            success = self._set_pseudocode_comment(func, ea, comment)

        if success:
            refresh_pseudocode(func.start_ea)

        return success

    def _set_function_header_comment(self, ea: int, comment: str) -> bool:
        """Write a comment that appears above the function signature in pseudocode.

        Args:
            func: The function whose header is being annotated.
            comment: Text to write. Empty string clears the comment.
        """

        ea = ida_bytes.get_item_head(ea)
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            self.logger.error("Failed to decompile function at %s", hex(ea))
            return False

        idc.set_func_cmt(ea, comment, 1)
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

        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = ida_hexrays.ITP_SEMI
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        return True
