from aether_rpc.capabilities.types import FunctionMetadata
from aether_rpc.capabilities.utils import get_function, resolve_function_name

from ..base import Capability


class GetFunctionByName(Capability):
    """Retrieves metadata for a function looked up by its symbolic name."""

    @property
    def name(self) -> str:
        return "get_function_by_name"

    def execute(self, function_name: str) -> FunctionMetadata | None:
        """Look up a function by name and return its metadata.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            Dict containing name, start/end address, size, and flags,
            or None if the name cannot be resolved or does not point to a function.
        """
        ea = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return None
        func = get_function(ea)
        if func is None:
            self.logger.error(f"Symbol '{function_name}' at {hex(ea)} is not a function")
        return func
