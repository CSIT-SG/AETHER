import ida_funcs
import ida_hexrays

from ..base import Capability
from ..utils import refresh_pseudocode, resolve_effective_address


class RenameLocalVariable(Capability):
    """Renames a local variable inside a decompiled function."""

    @property
    def name(self) -> str:
        return "rename_local_variable"

    def execute(self, function_address: str | int, old_var_name: str, new_var_name: str) -> bool:
        """Rename a local variable in the Hex-Rays decompiled view.

        Args:
            function_address: Hex or decimal string address inside or at the function start.
            old_var_name: Current name of the variable to rename.
            new_var_name: New name to assign.

        Returns:
            True if the rename succeeded, False otherwise.
        """
        ea = resolve_effective_address(function_address)
        if ea is None:
            self.logger.error(f"Invalid address: {function_address}")
            return False

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return False

        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile %r: %s", old_var_name, e)
            return False

        if cfunc is None:
            self.logger.error(f"Failed to decompile function at {hex(func.start_ea)}")
            return False

        lvar = next((v for v in cfunc.get_lvars() if v.name == old_var_name), None)
        if lvar is None:
            self.logger.error("No local variable named %r in function %r", old_var_name, hex(func.start_ea))
            return False

        if not ida_hexrays.rename_lvar(func.start_ea, old_var_name, new_var_name):
            self.logger.error("Failed to rename %r to %r in function %r", old_var_name, new_var_name, hex(func.start_ea))
            return False

        refresh_pseudocode(func.start_ea)

        return True
