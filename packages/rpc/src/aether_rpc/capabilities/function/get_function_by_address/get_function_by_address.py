from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.function_utils import get_function
from aether_rpc.capabilities.function.types import FunctionMetadata
from aether_rpc.capabilities.misc.address_utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Ok, Result


class GetFunctionByAddress(Capability):
    """Retrieves metadata for the function that contains a given address."""

    @property
    def name(self) -> str:
        return "get_function_by_address"

    def execute(self, address: str | int) -> Result[FunctionMetadata]:
        """Look up the function enclosing the given address and return its metadata.

        Args:
            address: Hex or decimal string address anywhere within the target function.

        Returns:
            A Result whose ``result`` holds the FunctionMetadata (name, start/end
            address, size, flags) on success, or an error message if the address
            is invalid or no function bounds it.
        """
        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return Err(result=f"Invalid address: {address}")

        func = get_function(ea)
        if func is None:
            self.logger.warning(f"No function found containing address {hex(ea)}")
            return Err(result=f"No function found containing address {hex(ea)}")

        return Ok(result=func)
