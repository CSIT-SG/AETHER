import ida_name
import idautils

from ..base import Capability
from ..utils import collect_xrefs, resolve_effective_address


class GetXrefsTo(Capability):
    """Retrieves all cross-references pointing to a given address or symbol."""

    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def execute(self, location: str | int) -> dict | None:
        """Find all locations that reference the given address or symbol name.

        Args:
            location: Hex address or symbol name of the target.

        Returns:
            A dictionary containing the target address, name, and a list of xrefs, or an error message if
            the target could not be resolved.
        """
        ea = resolve_effective_address(location)
        if ea is None:
            self.logger.error(f"Invalid location: {location}")
            return None

        xrefs = [collect_xrefs(x) for x in idautils.XrefsTo(ea)]

        return {
            "target_address": hex(ea),
            "target_name": ida_name.get_name(ea) or None,
            "count": len(xrefs),
            "xrefs": xrefs,
        }
