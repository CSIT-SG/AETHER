import ida_funcs
import ida_hexrays
import ida_kernwin

from ..base import Capability
from ..result import Err, Ok, Result
from ..utils import resolve_effective_address


class RefreshPseudocode(Capability):
    """Refreshes the Hex-Rays pseudocode view for a given function if running in UI mode."""

    @property
    def name(self) -> str:
        return "refresh_pseudocode"

    def execute(self, function_address: str | int) -> Result[str]:
        """Force-refresh the IDA visual graph/text views and the pseudocode view.

        Args:
            function_address: Hex or decimal string address inside or at the function start.

        Returns:
            A Result whose ``success`` reports whether the refresh operation was processed,
            and whose ``result`` carries the function address and headless status.
        """
        ea = resolve_effective_address(function_address)
        if ea is None:
            self.logger.error(f"Invalid address: {function_address}")
            return Err(result=f"Invalid address: {function_address}")

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found at {hex(ea)}")
            return Err(result=f"No function found at {hex(ea)}")

        self.logger.info(f"Refreshing UI and pseudocode view for function at {hex(func.start_ea)}")

        ida_kernwin.refresh_idaview_anyway()
        ida_hexrays.open_pseudocode(func.start_ea, ida_hexrays.OPF_REUSE)

        return Ok(result=hex(func.start_ea))
