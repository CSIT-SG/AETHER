from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.utils import get_function
from aether_rpc.capabilities.misc.utils import resolve_function_name
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import FunctionMetadata


class GetFunctionByName(Capability):
    """Retrieves metadata for a function looked up by its symbolic name."""

    @property
    def name(self) -> str:
        return "get_function_by_name"

    def execute(self, function_name: str) -> Result[FunctionMetadata]:
        """Look up a function by name and return its metadata.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            A Result whose ``result`` holds the FunctionMetadata (name, start/end
            address, size, flags) on success, or an error message if the name
            cannot be resolved or does not point to a function.
        """
        ea = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return Err(result=f"Symbol '{function_name}' not found")
        func = get_function(ea)
        if func is None:
            self.logger.error(f"Symbol '{function_name}' at {hex(ea)} is not a function")
            return Err(result=f"Symbol '{function_name}' at {hex(ea)} is not a function")
        return Ok(result=func)
