import idaapi
import idautils
import idc
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.get_functions_called_recursively.constants import (
    FILTERED_FUNCTIONS,
    MAX_DEPTH,
)
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import FunctionTreeNode, FunctionTreeResult
from aether_rpc.capabilities.utils import get_function, resolve_effective_address


class GetFunctionsCalledRecursively(Capability):
    """Get all callees of a function, as a nested call tree."""

    @property
    def name(self) -> str:
        return "get_functions_called_recursively"

    def _is_filtered(self, func_name: str) -> bool:
        return any(filtered.lower() in func_name.lower() for filtered in FILTERED_FUNCTIONS)

    def _count_nodes(self, node: FunctionTreeNode) -> int:
        return 1 + sum(self._count_nodes(c) for c in node["children"])

    def _get_callees(self, func_addr: int) -> list[tuple[str, int]]:
        """Return deduped, unfiltered (name, addr) callees of the function at func_addr."""
        func = idaapi.get_func(func_addr)
        if not func:
            return []

        callee_eas = {
            callee.start_ea
            for ea in idautils.FuncItems(func.start_ea)
            for xref in idautils.XrefsFrom(ea, 0)
            if (callee := idaapi.get_func(xref.to))  # type: ignore
        }

        return [
            (name, ea)
            for ea in sorted(callee_eas)
            if (name := idc.get_name(ea, idaapi.GN_VISIBLE)) and not self._is_filtered(name)
        ]

    def _build_tree(
        self,
        func_addr: int,
        func_name: str,
        depth: int,
        seen: set[str],
        max_depth: int,
    ) -> FunctionTreeNode:
        """Recursively build a call tree rooted at func_addr.

        Stops descending at max_depth. `seen` is shared across the whole
        recursion so each function name appears at most once in the tree
        (this also prevents infinite recursion on call cycles).
        """
        children: list[FunctionTreeNode] = []

        if depth < max_depth:
            try:
                for name, ea in self._get_callees(func_addr):
                    if name in seen:
                        continue
                    seen.add(name)
                    self.logger.info(f"Auto-selected function: {name}")
                    children.append(self._build_tree(ea, name, depth + 1, seen, max_depth))
            except Exception as e:
                self.logger.error(f"Error getting callees for {hex(func_addr)}: {e}")

        return {"function_name": func_name, "address": hex(func_addr), "children": children}

    def execute(self, address: str | int, max_depth: int = MAX_DEPTH) -> Result[FunctionTreeResult]:
        """Look up the function enclosing the given address and return its call tree.

        Args:
            address: Hex or decimal string address anywhere within the target function.
            max_depth: Maximum recursion depth for the call tree. Defaults to MAX_DEPTH.

        Returns:
            A Result whose ``result`` holds the call tree rooted at the starting function,
            or an error message if the address is invalid or no function bounds it.
        """
        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return Err(result=f"Invalid address: {address}")

        if max_depth < 0:
            self.logger.error(f"Invalid max_depth: {max_depth}")
            return Err(result=f"Invalid max_depth: {max_depth} (must be >= 0)")

        func = get_function(ea)
        if func is None:
            self.logger.warning(f"No function found containing address {hex(ea)}")
            return Err(result=f"No function found containing address {hex(ea)}")

        root = self._build_tree(ea, func["name"], depth=0, seen={func["name"]}, max_depth=max_depth)

        return Ok(result=FunctionTreeResult(count=self._count_nodes(root), root=root))
