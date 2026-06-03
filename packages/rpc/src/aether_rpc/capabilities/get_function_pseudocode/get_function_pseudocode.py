import ida_idaapi
import ida_name

from ..base import Capability
from ..utils import decompile_or_none


class GetFunctionPseudocode(Capability):
    """Retrieves the Hex-Rays decompiled pseudocode for a function by name."""

    @property
    def name(self) -> str:
        return "get_function_pseudocode"

    def execute(self, function_name: str) -> str:
        """Decompile a function and return its pseudocode as a string.

        Runs decompilation on the main thread via execute_sync since
        IDA API calls are not safe to invoke from background threads.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            Pseudocode string, or an error message if the function
            could not be found or decompiled.
        """
        result = {}

        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
        if ea == ida_idaapi.BADADDR:
            return "None"

        result["code"] = decompile_or_none(ea)

        if not result or result["code"] is None:
            self.logger.error(f"Function '{function_name}' not found")
            return f"Function '{function_name}' not found."

        else:
            result["code"] = str(result["code"])

        self.logger.info(f"Pseudocode for '{function_name}' -> {len(result['code'])} chars")
        return result["code"]
