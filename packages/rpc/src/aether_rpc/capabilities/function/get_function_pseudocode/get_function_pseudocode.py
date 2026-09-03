import ida_hexrays
import ida_lines
import idaapi
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.types import FunctionPseudocode
from aether_rpc.capabilities.misc.address_utils import resolve_function_name
from aether_rpc.capabilities.result import Err, Ok, Result


class GetFunctionPseudocode(Capability):
    """Retrieves the Hex-Rays decompiled pseudocode for a function by name."""

    @property
    def name(self) -> str:
        return "get_function_pseudocode"

    def execute(self, function_name: str) -> Result[FunctionPseudocode]:
        """Decompile a function and return its pseudocode as a string.

        Runs decompilation on the main thread via execute_sync since
        IDA API calls are not safe to invoke from background threads.

        Args:
            function_name: The symbolic name of the target function.

        Returns:
            A Result whose ``result`` holds the function name, start address, and
            pseudocode string on success, or an error message on failure.
        """

        ea = resolve_function_name(function_name)
        if ea is None:
            self.logger.error(f"Symbol '{function_name}' not found")
            return Err(result=f"Symbol '{function_name}' not found")

        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            self.logger.error("Failed to decompile %r: %s", function_name, e)
            return Err(result=f"Failed to decompile {function_name!r}: {e}")

        if cfunc is None:
            self.logger.error("Decompilation returned no result for %r", function_name)
            return Err(result=f"Decompilation returned no result for {function_name!r}")

        pseudocode = cfunc.get_pseudocode()
        rendered_lines = []

        for sl in pseudocode:
            item = ida_hexrays.ctree_item_t()
            addr_str = ""

            # Dummy items are needed here to satisfy type check
            # get_line_item() requires output ctree items but we don't need them therefore the dummies
            dummy_head = ida_hexrays.ctree_item_t()
            dummy_anchor = ida_hexrays.ctree_item_t()
            if cfunc.get_line_item(sl.line, 0, False, dummy_head, item, dummy_anchor):
                citem = item.it
                line_ea = citem.ea if citem else None
                if line_ea is not None and line_ea != idaapi.BADADDR:
                    addr_str = hex(line_ea)

            line_text = ida_lines.tag_remove(sl.line)
            rendered_lines.append(f"{addr_str.ljust(12)}: {line_text}")

        pseudocode_text = "\n".join(rendered_lines)

        return Ok(
            result=FunctionPseudocode(
                name=function_name,
                start_address=hex(ea),
                pseudocode=pseudocode_text,
            )
        )
