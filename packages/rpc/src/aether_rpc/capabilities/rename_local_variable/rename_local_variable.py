import ida_funcs
import ida_hexrays

from ..base import Capability
from ..types import Result
from ..utils import refresh_pseudocode, resolve_effective_address


class RenameLocalVariable(Capability):
    """Renames a local variable inside a decompiled function."""

    @property
    def name(self) -> str:
        return "rename_local_variable"

    def execute(self, function_address: str | int, old_var_name: str, new_var_name: str) -> Result:
        """Rename a local variable in the Hex-Rays decompiled view.

        Args:
            function_address: Hex or decimal string address inside or at the function start.
            old_var_name: Current name of the variable to rename.
            new_var_name: New name to assign.

        Returns:
            Result indicating success or failure of the rename operation.
        """
        ea = resolve_effective_address(function_address)
        if ea is None:
            self.logger.error(f"Invalid address: {function_address}")
            return Result(success=False, result=f"Invalid address: {function_address}")

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return Result(success=False, result=f"No function found at {hex(ea)}")

        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile %r: %s", old_var_name, e)
            return Result(success=False, result=f"Failed to decompile function at {hex(func.start_ea)}")

        if cfunc is None:
            self.logger.error(f"Failed to decompile function at {hex(func.start_ea)}")
            return Result(success=False, result=f"Failed to decompile function at {hex(func.start_ea)}")

        lvar = next((v for v in cfunc.get_lvars() if v.name == old_var_name), None)
        if lvar is None:
            self.logger.error(
                "No local variable named %r in function %r", old_var_name, hex(func.start_ea)
            )
            return Result(
                success=False,
                result=f"No local variable named {old_var_name!r} in function {hex(func.start_ea)}",
            )

        if not ida_hexrays.rename_lvar(func.start_ea, old_var_name, new_var_name):
            self.logger.error(
                "Failed to rename %r to %r in function %r",
                old_var_name,
                new_var_name,
                hex(func.start_ea),
            )
            return Result(
                success=False,
                result=f"Failed to rename {old_var_name!r} to {new_var_name!r} in {hex(func.start_ea)}",
            )

        refresh_pseudocode(func.start_ea)

        self.logger.info(f"Renamed {old_var_name!r} to {new_var_name!r} in {hex(func.start_ea)}")
        return Result(
            success=True,
            result=f"Renamed {old_var_name!r} to {new_var_name!r} in {hex(func.start_ea)}",
        )
