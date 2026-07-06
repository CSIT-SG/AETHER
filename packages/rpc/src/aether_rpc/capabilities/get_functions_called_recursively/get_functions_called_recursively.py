import idaapi
import idautils
import idc

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import ListFunctionResult, ProcessFunctions
from ..utils import get_function, resolve_effective_address
from .constants import FILTERED_FUNCTIONS, MAX_DEPTH


class GetFunctionsCalledRecursively(Capability):
    """Get all callees of a function."""

    @property
    def name(self) -> str:
        return "get_functions_called_recursively"

    def filter_function(self, func_name: str):
        for filtered_name in FILTERED_FUNCTIONS:
            if filtered_name.lower() in func_name.lower():
                return True
        return False

    def get_function_callees(
        self, func_addr_str: str, parent_func_name: str | None = None
    ) -> list[dict[str, str]]:
        """Get callees of a function using IDA API. Must be called from main thread."""
        try:
            func_addr = int(func_addr_str, 16)
            func = idaapi.get_func(func_addr)
            if not func:
                return []
            callee_functions = []
            # Iterate over every instruction in the function
            for instruction_ea in idautils.FuncItems(func.start_ea):
                # Get all references from this single instruction
                for xref in idautils.XrefsFrom(instruction_ea, 0):
                    # Check if the reference destination is a function
                    callee_func = idaapi.get_func(xref.to)
                    if callee_func:
                        # Add the start address of the function to the set
                        callee_functions.append(callee_func.start_ea)
            callees = []
            # Convert to list with names and filter
            for func_ea in sorted(callee_functions):
                func_name = idc.get_name(func_ea, idaapi.GN_VISIBLE)
                if func_name:
                    # Filter out unwanted functions
                    if self.filter_function(func_name):
                        continue

                    # Prevent function from being a child of itself
                    if parent_func_name and func_name == parent_func_name:
                        continue

                    callees.append({"name": func_name, "address": hex(func_ea)})

            return callees

        except Exception as e:
            self.logger.error(f"[AETHER] Error getting callees for {func_addr_str}: {e}")
            return []

    def collect_recursive(self, func_addr, func_name, current_depth):
        if current_depth >= MAX_DEPTH or func_addr in self.process_functions["processed"]:
            return

        self.process_functions["processed"].add(func_addr)

        # Get callees for this function
        callees = self.get_function_callees(func_addr, func_name)

        for callee_info in callees:
            callee_name = callee_info["name"]
            callee_addr = callee_info["address"]

            # Check if function not already in selected functions
            if not any(
                f["function_name"] == callee_name
                for f in self.process_functions["selected_functions"]
            ):
                self.process_functions["selected_functions"].append(
                    {"function_name": callee_name, "address": callee_addr}
                )
                self.logger.info(f"[AETHER] Auto-selected function: {callee_name}")

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

        func_name = func["name"]

        self.process_functions: ProcessFunctions = {
            "processed": set(),
            "selected_functions": [],
        }

        depth = 0

        # Add the starting function

        self.process_functions["selected_functions"].append(
            {"function_name": func_name, "address": hex(ea)}
        )

        # Collect functions recursively
        self.collect_recursive(str(hex(ea)), func_name, depth)
        return Ok(
            result=ListFunctionResult(
                count=len(self.process_functions["selected_functions"]),
                functions=self.process_functions["selected_functions"],
            )
        )
