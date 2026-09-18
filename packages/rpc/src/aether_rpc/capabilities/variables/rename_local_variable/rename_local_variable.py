import ida_funcs
import ida_hexrays
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.misc.utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import RenameLocalVarResult


class RenameLocalVariable(Capability):
    """Renames a local variable inside a decompiled function."""

    @property
    def name(self) -> str:
        return "rename_local_variable"

    def execute(
        self, function_address: str | int, old_var_name: str, new_var_name: str
    ) -> Result[RenameLocalVarResult]:
        """Rename a local variable in the Hex-Rays decompiled view.

        Args:
            function_address: Hex or decimal string address inside or at the function start.
            old_var_name: Current name of the variable to rename.
            new_var_name: New name to assign.

        Returns:
            A Result whose ``success`` reports whether the rename succeeded and
            whose ``result`` carries the function address and variable names.
        """
        ea = resolve_effective_address(function_address)
        if ea is None:
            self.logger.error(f"Invalid address: {function_address}")
            return Err(result=f"Invalid address: {function_address}")

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return Err(result=f"No function found at {hex(ea)}")

        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile %r: %s", old_var_name, e)
            return Err(result=f"Failed to decompile function at {hex(func.start_ea)}: {e}")

        if cfunc is None:
            self.logger.error(f"Failed to decompile function at {hex(func.start_ea)}")
            return Err(result=f"Failed to decompile function at {hex(func.start_ea)}")

        lvar = next((v for v in cfunc.get_lvars() if v.name == old_var_name), None)
        if lvar is None:
            self.logger.error(
                "No local variable named %r in function %r", old_var_name, hex(func.start_ea)
            )
            return Err(
                result=f"No local variable named {old_var_name!r} in function {hex(func.start_ea)}"
            )

        if not ida_hexrays.rename_lvar(func.start_ea, old_var_name, new_var_name):
            self.logger.error(
                "Failed to rename %r to %r in function %r",
                old_var_name,
                new_var_name,
                hex(func.start_ea),
            )
            return Err(
                result=f"Failed to rename {old_var_name!r} to {new_var_name!r} in function {hex(func.start_ea)}"
            )

        return Ok(
            result=RenameLocalVarResult(
                function_address=hex(func.start_ea),
                old_var_name=old_var_name,
                new_var_name=new_var_name,
            )
        )
