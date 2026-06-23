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
            location: Hex address or symbol name of the target.

        Returns:
            A Result whose ``result`` holds the target address, name, and a list
            of xrefs on success, or an error message if the target could not be
            resolved.
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
