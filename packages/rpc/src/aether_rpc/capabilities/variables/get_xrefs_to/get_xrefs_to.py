import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idautils
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.utils import function_info
from aether_rpc.capabilities.misc.utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import (
    StackVariableInfo,
    StackVariableXrefs,
    XrefEntry,
    XrefsResult,
)
from aether_rpc.capabilities.variables.utils import collect_xrefs
from ida_funcs import func_t


class GetXrefsTo(Capability):
    """Retrieves all cross-references pointing to a given address or symbol."""

    @property
    def name(self) -> str:
        return "get_xrefs_to"

    def collect_stkvar_xrefs(self, stack_vars: StackVariableInfo) -> list[XrefEntry] | None:
        """Collect xrefs to a stack variable's offset range
        and normalize entries to a shape similar to
        collect_xrefs()'s output.

        Args:
            stack_vars: The StackVariableInfo describing the frame, start
                offset, and end offset (bytes) of the variable.

        Returns:
            A list of XrefEntry, or None if the function/frame member
            could not be resolved or no xrefs were found.
        """
        func_ea: int = stack_vars["caller_func_ea"]
        start_off: int = stack_vars["start_off"]
        end_off: int = stack_vars["end_off"]
        xreflist = ida_frame.xreflist_t()

        func: func_t | None = ida_funcs.get_func(func_ea)
        if func is None:
            return None

        ida_frame.build_stkvar_xrefs(xreflist, func, start_off, end_off)
        if len(xreflist) == 0:
            return None
        owner = function_info(func.start_ea)
        result: list[XrefEntry] = [
            XrefEntry(
                from_address=hex(entry.ea),
                type=entry.type,
                is_code=True,
                from_name=ida_name.get_name(entry.ea),
                from_function=owner,
            )
            for entry in xreflist
        ]
        return result

    def resolve_stack_variable(self, func_ea: int, variable: str) -> StackVariableInfo | None:
        """Resolve a Hex-Rays pseudocode local variable to its backing stack
        frame member, if any.

        Args:
            func_ea: Address of the function that owns the variable.
            variable: Name of the pseudocode (decompiler) local variable.

        Returns:
            A StackVariableInfo (including the resolved frame member name,
            and its start/end offsets in bytes) if `variable` is backed by
            a stack frame member, else None.
        """
        pfn = ida_funcs.get_func(func_ea)
        if pfn is None:
            return None

        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return None

        lvar: ida_hexrays.lvar_t | None = None
        for candidate in cfunc.get_lvars():
            if candidate.name == variable:
                lvar = candidate
                break

        if lvar is None or not lvar.is_stk_var():
            return None

        frame_offset: int = lvar.get_stkoff() + cfunc.get_stkoff_delta()

        frame_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame_tif, pfn):
            return None

        frame_udt = ida_typeinf.udt_type_data_t()
        if not frame_tif.get_udt_details(frame_udt):
            return None

        for udm in frame_udt:
            if udm.is_gap():
                continue
            if udm.begin() // 8 == frame_offset:
                return StackVariableInfo(
                    caller_func_ea=func_ea,
                    name=udm.name,
                    start_off=udm.begin() // 8,
                    end_off=udm.end() // 8,
                )

        return None

    def execute(
        self,
        location: str | int,
        variable: str | None = None,
    ) -> Result[XrefsResult]:
        """Find all locations that reference the given address or symbol
        name, optionally alongside cross-references to a local variable's
        backing stack frame member.

        Args:
            location (str | int): The target to look up cross-references
                for. Accepts a hex address string (e.g. "0x140001000"), a
                plain symbol name (e.g. "assign_buffer"), an IDA
                auto-generated name (e.g. "sub_DEADBEEF"), or an integer
                effective address. When `variable` is given, `location`
                must resolve to the function that owns it.
            variable (str | None): The decompiler (Hex-Rays pseudocode)
                name of a local variable (e.g. "v4", "a1", or a renamed
                local) inside the function identified by `location` — not
                the raw stack frame/assembly name (e.g. "var_10"). When it
                resolves to a stack frame member, the result's `stack_info`
                field is populated with that member's own
                cross-references; this does not change what `location` is
                resolved against or what the top-level `xrefs` contains.
                If `variable` can't be resolved to a stack variable,
                `stack_info` is simply `None` and the call still succeeds.

        Returns:
            Ok[XrefsResult]: A structured object containing:
                - target_address (str): The resolved hex address of
                `location`.
                - target_name (str | None): The symbolic name at that
                address, or None if no name is defined there.
                - count (int): The number of cross-references found for
                `location` itself.
                - xrefs (list[XrefEntry]): The collected cross-reference
                entries pointing to `location`.
                - stack_info (StackVariableXrefs | None): When `variable`
                resolves to a stack frame member, its name, frame offsets,
                and its own `xrefs` list; otherwise None.
            Err[str]: An error message string in the following cases:
                - The location could not be resolved.
                - An exception was raised while collecting cross-references.

        Examples:
            execute("assign_buffer")
            execute("0x140001000")
            execute("sub_DEADBEEF")
            execute("assign_buffer", variable="v4")
        """
        func_ea: int | None = resolve_effective_address(location)
        if func_ea is None:
            self.logger.error(f"Invalid location: {location}")
            return Err(result=f"Invalid location: {location}")

        try:
            xrefs = [collect_xrefs(x) for x in idautils.XrefsTo(func_ea)]
        except Exception as e:
            self.logger.exception("Failed to collect xrefs at %s: %s", hex(func_ea), e)
            return Err(result=f"Failed to collect xrefs at {hex(func_ea)}: {e}")

        # are there stack variable xrefs to collect? if so, resolve the stack variable and collect its xrefs
        stack_info: StackVariableXrefs | None = None
        if (
            variable is not None
            and (stack_var_info := self.resolve_stack_variable(func_ea, variable)) is not None
        ):
            stack_xrefs = self.collect_stkvar_xrefs(stack_var_info)
            stack_info = StackVariableXrefs(**stack_var_info, xrefs=stack_xrefs or [])

        data = XrefsResult(
            target_address=hex(func_ea),
            target_name=ida_name.get_name(func_ea) or None,
            count=len(xrefs),
            xrefs=xrefs,
            stack_info=stack_info,
        )

        return Ok(result=data)
