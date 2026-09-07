import ida_funcs
import ida_name
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.misc.utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import RenameFuncResult


class RenameFunction(Capability):
    """Renames a function at a given address."""

    @property
    def name(self) -> str:
        return "rename_function"

    def execute(self, address: str | int, new_name: str) -> Result[RenameFuncResult]:
        """Rename the function at the given address.

        Args:
            address: Hex or decimal string address within the target function.
            new_name: The new name to assign to the function.

        Returns:
            A Result whose ``success`` reports whether the rename succeeded and
            whose ``result`` carries the function address and new name.
        """
        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return Err(result=f"Invalid address: {address}")

        elif (func := ida_funcs.get_func(ea)) is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return Err(result=f"No function found at {hex(ea)}")

        elif ida_name.set_name(func.start_ea, new_name, ida_name.SN_NOWARN):
            self.logger.info(f"Renamed function at {hex(func.start_ea)} to '{new_name}'")
            return Ok(result=RenameFuncResult(address=hex(func.start_ea), new_name=new_name))

        self.logger.error(f"Failed to rename function at {hex(func.start_ea)} to '{new_name}'")
        return Err(result=f"Failed to rename function at {hex(func.start_ea)} to '{new_name}'")
