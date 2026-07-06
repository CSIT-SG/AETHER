import idaapi
import idautils
import idc

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import FunctionCallees, ListFunctionResult, ProcessFunctions
from ..utils import get_function, resolve_effective_address
from .constants import FILTERED_FUNCTIONS, MAX_DEPTH


class GetFunctionsCalledRecursively(Capability):
    """Get all callees of a function."""

    @property
    def name(self) -> str:
        return "get_functions_called_recursively"

    def _is_filtered(self, func_name: str) -> bool:
        return any(filtered.lower() in func_name.lower() for filtered in FILTERED_FUNCTIONS)

    def get_function_callees(
        self, func_addr_str: str, parent_func_name: str | None = None
    ) -> list[FunctionCallees]:
        """Get callees of a function using IDA API. Must be called from main thread."""
        try:
            func_addr = int(func_addr_str, 16)
            func = idaapi.get_func(func_addr)
            if not func:
                return []
            # Dedupe by address while scanning every instruction/xref in the function.
            callee_addrs: set[int] = set()
            for instruction_ea in idautils.FuncItems(func.start_ea):
                for xref in idautils.XrefsFrom(instruction_ea, 0):
                    callee_func = idaapi.get_func(xref.to)  # type: ignore
                    if callee_func:
                        callee_addrs.add(callee_func.start_ea)

            callees: list[FunctionCallees] = []
            for func_ea in sorted(callee_addrs):
                func_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                if not func_name:
                    continue
                if self._is_filtered(func_name):
                    continue
                if parent_func_name and func_name == parent_func_name:
                    continue
                callees.append({"name": func_name, "address": hex(func_ea)})

            return callees

        except Exception as e:
            self.logger.error(f"Error getting callees for {func_addr_str}: {e}")
            return []

    def collect_recursive(self, func_addr: str, func_name: str, current_depth: int) -> None:
        if current_depth >= MAX_DEPTH or func_addr in self.process_functions["processed"]:
            return

        self.process_functions["processed"].add(func_addr)

        # Get callees for this function
        callees = self.get_function_callees(func_addr, func_name)

        for callee_info in callees:
            callee_name, callee_addr = callee_info["name"], callee_info["address"]

            # Check if function not already in selected functions
            if any(
                f["function_name"] == callee_name
                for f in self.process_functions["selected_functions"]
            ):
                continue

            self.process_functions["selected_functions"].append(
                {"function_name": callee_name, "address": callee_addr}
            )
            self.logger.info(f"Auto-selected function: {callee_name}")

            # Recursively process this function's callees
            self.collect_recursive(callee_addr, callee_name, current_depth + 1)

    def execute(self, address: str | int) -> Result[ListFunctionResult]:
        """Look up the function enclosing the given address and return its callees.

        Args:
            address: Hex or decimal string address anywhere within the target function.

        Returns:
            A Result whose ``result`` holds the Functions called by starting function (name, start
            address) on success, or an error message if the address
            is invalid or no function bounds it.
        """
        ea = resolve_effective_address(address)
        if ea is None:
            self.logger.error(f"Invalid address: {address}")
            return Err(result=f"Invalid address: {address}")

        func = get_function(ea)
        if func is None:
            self.logger.warning(f"No function found containing address {hex(ea)}")
            return Err(result=f"No function found containing address {hex(ea)}")

        self.process_functions: ProcessFunctions = {
            "processed": set(),
            "selected_functions": [],
        }

        # Add the starting function

        func_name = func["name"]

        self.process_functions["selected_functions"].append(
            {"function_name": func_name, "address": hex(ea)}
        )

        # Collect functions recursively
        self.collect_recursive(hex(ea), func_name, 0)
        return Ok(
            result=ListFunctionResult(
                count=len(self.process_functions["selected_functions"]),
                functions=self.process_functions["selected_functions"],
            )
        )
