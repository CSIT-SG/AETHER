import ida_funcs
import idautils

from ..base import Capability


class ListFunctions(Capability):
    """Lists all functions present in the binary."""

    @property
    def name(self) -> str:
        return "list_functions"

    def execute(self) -> str:
        """Return the name and address of every function in the binary.

        Runs on the main thread via execute_sync since IDA API calls
        are not safe to invoke from background threads.

        Returns:
            Newline-separated string of function names and addresses.
        """
        functions = []

        for ea in idautils.Functions():
            functions.append({
                "name": ida_funcs.get_func_name(ea),
                "address": hex(ea),
            })

        self.logger.info(f"{len(functions)} functions found")
        return "\n".join(f"{f['name']} {f['address']}" for f in functions)
