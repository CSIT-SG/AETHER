import ida_name
import idautils

from aether_rpc.capabilities.types import XrefsResult

from ..base import Capability
from ..result import Err, Ok, Result
from ..utils import collect_xrefs, resolve_effective_address


class GetXrefsTo(Capability):
    """Retrieves all cross-references pointing to a given address or symbol."""

    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def execute(self, location: str | int) -> Result[XrefsResult]:
        """Find all locations that reference the given address or symbol name.

        Args:
            location (str | int): The target to look up cross-references for.
                Accepts a hex address string (e.g. "0x140001000"), a plain
                symbol name (e.g. "assign_buffer"), an IDA auto-generated name
                (e.g. "sub_DEADBEEF"), or an integer effective address.

        Returns:
            Ok[XrefsResult]: A structured object containing:
                - target_address (str): The resolved hex address of the target,
                  e.g. "0x140001000".
                - target_name (str | None): The symbolic name of the target
                  address, or None if no name is defined at that address.
                - count (int): The number of cross-references found.
                - xrefs (list): The collected cross-reference entries pointing
                  to the target.
            Err[str]: An error message string in the following cases:
                - The location could not be resolved to a valid effective
                  address.
                - An exception was raised while collecting cross-references
                  (e.g. an invalid or corrupted address).

        Examples:
            execute("assign_buffer")
            execute("0x140001000")
            execute("sub_DEADBEEF")
        """
        ea = resolve_effective_address(location)
        if ea is None:
            self.logger.error(f"Invalid location: {location}")
            return Err(result=f"Invalid location: {location}")

        try:
            xrefs = [collect_xrefs(x) for x in idautils.XrefsTo(ea)]
        except Exception as e:
            self.logger.exception("Failed to collect xrefs at %s: %s", hex(ea), e)
            return Err(result=f"Failed to collect xrefs at {hex(ea)}: {e}")

        data = XrefsResult(
            target_address=hex(ea),
            target_name=ida_name.get_name(ea) or None,
            count=len(xrefs),
            xrefs=xrefs,
        )

        return Ok(result=data)
