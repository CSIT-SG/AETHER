from typing import Any

import ida_funcs
import ida_idaapi
import ida_name

from ..base import Capability


class GetFunctionByName(Capability):
    """Retrieves metadata for a function looked up by its symbolic name."""

    @property
    def name(self) -> str:
        return "get_function_by_name"

    def execute(self, function_name: str) -> dict[str, Any] | None:
        """Look up a function by name and return its metadata.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            Dict containing name, start/end address, size, and flags,
            or None if the name cannot be resolved or does not point to a function.
        """
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
        if ea == ida_idaapi.BADADDR:
            self.logger.error(f"Symbol '{function_name}' could not be resolved")
            return None

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"'{function_name}' resolves to {hex(ea)} but is not a valid function")
            return None

        self.logger.info(f"'{function_name}' resolved to function at {hex(func.start_ea)}")
        return {
            "name": function_name,
            "start_address": hex(func.start_ea),
            "end_address": hex(func.end_ea),
            "size_bytes": func.size(),
            "flags": hex(func.flags),
        }
