from typing import Any

import ida_funcs
import idc

from ..base import Capability
from ..utils import resolve_effective_address


class GetFunctionByAddress(Capability):
    """Retrieves metadata for the function that contains a given address."""

    @property
    def name(self) -> str:
        return "get_function_by_address"

    def execute(self, address: str) -> dict[str, Any] | None:
        """Look up the function enclosing the given address and return its metadata.

        Args:
            address: Hex or decimal string address anywhere within the target function.

        Returns:
            Dict containing name, start/end address, size, and flags,
            or None if no function bounds the given address.
        """
        ea = resolve_effective_address(address)

        func = ida_funcs.get_func(ea)
        if func is None:
            self.logger.error(f"No function found bounding address {hex(ea)}")
            return None

        self.logger.info(f"Function resolved at {hex(ea)} -> {idc.get_func_name(func.start_ea)}")
        return {
            "name": idc.get_func_name(func.start_ea),
            "start_address": hex(func.start_ea),
            "end_address": hex(func.end_ea),
            "size_bytes": func.size(),
            "flags": hex(func.flags),
        }
