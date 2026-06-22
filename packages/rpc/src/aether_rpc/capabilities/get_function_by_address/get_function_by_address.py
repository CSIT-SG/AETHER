from ..base import Capability
from ..types import Result
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
            Result whose payload lists the function name, start/end address,
            size, and flags, or a failure message if no function bounds the
            given address.
        """
        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return Result(success=False, result=f"Invalid address: {address}")

        func = get_function(ea)
        if func is None:
            self.logger.warning(f"No function found containing address {hex(ea)}")
            return Result(success=False, result=f"No function found containing address {hex(ea)}")

        return Result(success=True, result="\n".join(f"{key}: {value}" for key, value in func.items()))
