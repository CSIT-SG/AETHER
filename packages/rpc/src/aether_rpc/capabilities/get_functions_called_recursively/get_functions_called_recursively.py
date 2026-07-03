import idaapi
import idautils
import idc

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import ListFunctionResult
from ..utils import get_function, resolve_effective_address

FILTERED_FUNCTIONS = [
    # Standard C library functions
    "memset", "memcpy", "strcpy", "strcmp", "strlen", "strcat", "sprintf", "printf", "scanf",
    "malloc", "free", "calloc", "realloc", "exit", "abort", "atoi", "atol", "strtol",
    # Windows API common functions
    "GetModuleHandle", "GetProcAddress", "LoadLibrary", "FreeLibrary", "CreateFile",
    "ReadFile", "WriteFile", "CloseHandle", "VirtualAlloc", "VirtualFree",
    # DLL prefixes and common imports
    "ntdll", "kernel32", "user32", "advapi32", "msvcrt", "ws2_32",
    # Dot-prefixed imports
    ".memset", ".memcpy", ".strcpy", ".strcmp", ".strlen", ".strcat", ".sprintf", ".printf"
]

class GetFunctionsCalledRecursively(Capability):
    """Get all callees of a function."""

    @property
    def name(self) -> str:
        return "get_functions_called_recursively"

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

        processed = set()
        selected_functions = []

        depth = 0

        def filter_function(func_name: str):
            for filtered_name in FILTERED_FUNCTIONS:
                if filtered_name.lower() in func_name.lower():
                    return True
            return False

        def get_function_callees(
            func_addr_str: str, parent_func_name: str | None = None
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
                        if filter_function(func_name):
                            continue

                        # Prevent function from being a child of itself
                        if parent_func_name and func_name == parent_func_name:
                            continue

                        callees.append({"name": func_name, "address": hex(func_ea)})

                return callees[:50]  # Limit to 50 callees to avoid overwhelming UI

            except Exception as e:
                print(f"[AETHER] Error getting callees for {func_addr_str}: {e}")
                return []

        def get_default_selection_criteria():
            """Get the default criteria for function selection."""
            return lambda func_name: (
                func_name in ["main", "start", "WinMain"] or func_name.startswith("sub_")
            )

        def collect_recursive(func_addr, func_name, current_depth):
            if current_depth >= 5 or func_addr in processed:
                return

            processed.add(func_addr)

            # Get callees for this function
            callees = get_function_callees(func_addr, func_name)

            # Apply default selection logic
            default_criteria = get_default_selection_criteria()

            for callee_info in callees:
                callee_name = callee_info["name"]
                callee_addr = callee_info["address"]

                # Check if function meets default criteria and not already in selected functions
                if default_criteria(callee_name) and not any(
                    f["name"] == callee_name for f in selected_functions
                ):
                    selected_functions.append({"name": callee_name, "address": callee_addr})
                    print(f"[AETHER] Auto-selected function: {callee_name}")

                    # Recursively process this function's callees
                    collect_recursive(callee_addr, callee_name, current_depth + 1)

        # Add the starting function

        selected_functions.append({"name": func_name, "address": hex(ea)})

        # Collect functions recursively
        collect_recursive(str(hex(ea)), func_name, depth)
        return Ok(
            result=ListFunctionResult(count=len(selected_functions), functions=selected_functions)
        )
