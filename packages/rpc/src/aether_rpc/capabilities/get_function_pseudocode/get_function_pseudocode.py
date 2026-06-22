import ida_hexrays

from ..base import Capability
from ..types import Result
from ..utils import resolve_function_name


class GetFunctionPseudocode(Capability):
    """Retrieves the Hex-Rays decompiled pseudocode for a function by name."""

    @property
    def name(self) -> str:
        return "get_function_pseudocode"

    def execute(self, function_name: str) -> Result:
        """Decompile a function and return its pseudocode as a string.

        Runs decompilation on the main thread via execute_sync since
        IDA API calls are not safe to invoke from background threads.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            Result whose payload is the decompiled pseudocode, or a failure
            message if the function cannot be resolved or decompiled.
        """

        ea = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return Result(success=False, result=f"Symbol '{function_name}' not found")

        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile %r: %s", function_name, e)
            return Result(success=False, result=f"Failed to decompile {function_name}")

        if cfunc is None:
            self.logger.error("Decompilation returned no result for %r", function_name)
            return Result(
                success=False, result=f"Decompilation returned no result for {function_name}"
            )

        return Result(success=True, result=f"{function_name} @ {hex(ea)}\n{cfunc}")
