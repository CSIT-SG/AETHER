import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.function.utils import function_info
from aether_rpc.capabilities.misc.utils import resolve_effective_address
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.types import (
    StackVariableInfo,
    StackVariableXrefs,
    StackVariableXrefsResult,
    XrefEntry,
)
from aether_rpc.capabilities.variables.utils import collect_xrefs_result
from ida_funcs import func_t


class GetStackVariableXrefs(Capability):
    """Retrieves cross-references to a local variable's backing stack frame member."""

    @property
    def name(self) -> str:
        return "get_stack_variable_xrefs"

    def collect_stkvar_xrefs(self, stack_vars: StackVariableInfo) -> list[XrefEntry] | None:
        """Collect xrefs to a stack variable's frame offset range, shaped like
        collect_xrefs()'s output. None if the frame member has no xrefs.
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
        """Resolve a Hex-Rays pseudocode local variable to its backing frame
        member (name and byte offsets). None if it has no stack backing.
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
        function_location: str | int,
        local_variable_name: str,
    ) -> Result[StackVariableXrefsResult]:
        """Find references to a local variable's backing stack frame member,
        plus references to the owning function.

        Args:
            function_location (str | int): The function owning the variable —
                hex address, symbol name, or effective address.
            local_variable_name (str): The variable's Hex-Rays pseudocode name
                ("v4", "a1", or a renamed local), not the frame name ("var_10").

        Returns:
            Ok[StackVariableXrefsResult]: target_address, target_name, count
                and xrefs for the function, plus stack_info — the frame
                member's name, byte offsets and its own xrefs, or None when
                the variable has no stack backing (still a success).
            Err[str]: function_location could not be resolved, or IDA raised
                while collecting xrefs.

        Examples:
            execute("assign_buffer", local_variable_name="v4")
        """
        func_ea: int | None = resolve_effective_address(function_location)
        if func_ea is None:
            self.logger.error(f"Invalid location: {function_location}")
            return Err(result=f"Invalid location: {function_location}")

        base = collect_xrefs_result(func_ea, self.logger)
        if isinstance(base, Err):
            return base

        stack_info: StackVariableXrefs | None = None
        if (
            stack_var_info := self.resolve_stack_variable(func_ea, local_variable_name)
        ) is not None:
            stack_xrefs = self.collect_stkvar_xrefs(stack_var_info)
            stack_info = StackVariableXrefs(**stack_var_info, xrefs=stack_xrefs or [])

        return Ok(result=StackVariableXrefsResult(**base.result, stack_info=stack_info))
