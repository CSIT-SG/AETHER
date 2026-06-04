from typing import Any

import ida_hexrays

from ..base import Capability
from ..utils import resolve_function_name


class GetFunctionPseudocode(Capability):
    """Retrieves the Hex-Rays decompiled pseudocode for a function by name."""

    @property
    def name(self) -> str:
        return "get_function_pseudocode"

    def execute(self, function_name: str) -> dict[str, Any] | None:
        """Decompile a function and return its pseudocode as a string.

        Runs decompilation on the main thread via execute_sync since
        IDA API calls are not safe to invoke from background threads.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            Dictionary containing the function name, start address, and pseudocode string
        """

        ea = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return None

        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile %r: %s", function_name, e)
            return None

        if cfunc is None:
            self.logger.error("Decompilation returned no result for %r", function_name)
            return None

        return {
            "name": function_name,
            "start_address": hex(ea),
            "pseudocode": str(cfunc),
        }
