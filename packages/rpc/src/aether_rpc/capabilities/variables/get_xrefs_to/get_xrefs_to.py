from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.misc.utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Result
from aether_rpc.capabilities.types import XrefsResult
from aether_rpc.capabilities.variables.utils import collect_xrefs_result


class GetXrefsTo(Capability):
    """Retrieves all cross-references pointing to a given address or symbol."""

    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def execute(self, location: str | int) -> Result[XrefsResult]:
        """Find all locations that reference the given address or symbol.

        Args:
            location (str | int): Hex address ("0x140001000"), symbol name
                ("assign_buffer", "sub_DEADBEEF"), or effective address.

        Returns:
            Ok[XrefsResult]: target_address, target_name, count, and xrefs —
                the entries pointing at `location`.
            Err[str]: `location` could not be resolved, or IDA raised while
                collecting xrefs.

        Examples:
            execute("assign_buffer")
            execute("0x140001000")
        """
        func_ea: int | None = resolve_effective_address(location)
        if func_ea is None:
            self.logger.error(f"Invalid location: {location}")
            return Err(result=f"Invalid location: {location}")

        return collect_xrefs_result(func_ea, self.logger)
