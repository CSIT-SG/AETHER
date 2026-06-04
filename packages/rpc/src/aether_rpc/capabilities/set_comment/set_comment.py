import ida_bytes
import ida_funcs
import ida_hexrays

from ..base import Capability
from ..utils import resolve_effective_address


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
            return self._set_disassembly_comment(ea, comment)

        if ea == func.start_ea:
            return self._set_function_comment(func, comment)

        return self._set_pseudocode_comment(func, ea, comment)

    def _set_disassembly_comment(self, ea: int, comment: str) -> bool:
        if not ida_bytes.set_cmt(ea, comment, False):
            self.logger.error("Failed to set disassembly comment at %s", hex(ea))
            return False
        return True

    def _set_function_comment(self, func: ida_funcs.func_t, comment: str) -> bool:
        if not ida_funcs.set_func_cmt(func, comment, False):
            self.logger.error("Failed to set function comment at %s", hex(func.start_ea))
            return False
        return True

    def _set_pseudocode_comment(self, func: ida_funcs.func_t, ea: int, comment: str) -> bool:
        if not ida_hexrays.init_hexrays_plugin():
            self.logger.warning("Hex-Rays unavailable; falling back to disassembly comment at %s", hex(ea))
            return self._set_disassembly_comment(ea, comment)

        try:
            cfunc = ida_hexrays.decompile(func)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile function at %s: %s", hex(func.start_ea), e)
            return False

        if cfunc is None:
            self.logger.error("Decompilation returned no result for function at %s", hex(func.start_ea))
            return False

        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = ida_hexrays.ITP_SEMI
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        return True
