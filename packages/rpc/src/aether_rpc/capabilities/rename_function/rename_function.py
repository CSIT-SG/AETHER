import ida_funcs
import ida_name

from ..base import Capability
from ..utils import resolve_effective_address


class RenameFunction(Capability):
    """Renames a function at a given address."""

    @property
    def name(self) -> str:
        return "rename_function"

    def execute(self, address: str, new_name: str) -> bool:
        """Rename the function at the given address.

        Args:
            address: Hex or decimal string address within the target function.
            new_name: The new name to assign to the function.

        Returns:
            True if the rename succeeded, False otherwise.
        """
        ea = resolve_effective_address(address)

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return False

        if ida_name.set_name(func.start_ea, new_name, ida_name.SN_NOWARN):
            self.logger.info(f"Renamed function at {hex(func.start_ea)} to '{new_name}'")
            return True

        self.logger.error(f"Failed to rename function at {hex(func.start_ea)} to '{new_name}'")
        return False
