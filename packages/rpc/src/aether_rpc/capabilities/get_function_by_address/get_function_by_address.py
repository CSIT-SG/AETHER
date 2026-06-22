from ..base import Capability
from ..result import Result
from ..utils import get_function, resolve_effective_address


class GetFunctionByAddress(Capability):
    """Retrieves metadata for the function that contains a given address."""

    @property
    def name(self) -> str:
        return "get_function_by_address"

    def execute(self, address: str | int) -> Result:
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
            return Result(success=False, result={"error": f"Invalid address: {address}"})

        func = get_function(ea)
        if func is None:
            self.logger.warning(f"No function found containing address {hex(ea)}")
            return Result(
                success=False,
                result={"error": f"No function found containing address {hex(ea)}"},
            )

        return Result(success=True, result=dict(func))
