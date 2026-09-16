from typing import Any

import ida_frame
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_typeinf
import idaapi
from aether_rpc.capabilities.base import Capability
from aether_rpc.capabilities.misc.utils import resolve_function_name
from aether_rpc.capabilities.result import Err, Ok, Result
from aether_rpc.capabilities.struct.utils import InternalStructInfo, get_struct
from aether_rpc.capabilities.types import AppliedStruct


class ApplyStruct(Capability):
    @property
    def name(self) -> str:
        return "apply_struct"

    def _pointer_to(self, struct: InternalStructInfo) -> ida_typeinf.tinfo_t:
        ptr = ida_typeinf.tinfo_t()
        ptr.create_ptr(struct.tif)
        return ptr

    def _retype_lvar(
        self, lvar: ida_hexrays.lvar_t, func: dict[str, Any], tif: ida_typeinf.tinfo_t
    ) -> bool:
        """Set the saved type of a decompiler variable."""
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = lvar
        info.type = tif
        return bool(ida_hexrays.modify_user_lvar_info(func["ea"], ida_hexrays.MLI_TYPE, info))

    def _resolve_function(self, function_name: str) -> Result[dict[str, Any]]:
        """Collect the address, frame type and frame members of a function."""
        ea = resolve_function_name(function_name)
        if ea is None:
            return Err(result=f"Symbol '{function_name}' not found")

        pfn = ida_funcs.get_func(ea)

        tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(tif, pfn):
            return Err(result=f"Unable to get info for Function {function_name}.")

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return Err(result=f"Unable to get member info for Function {function_name}.")

        return Ok(result={"name": function_name, "ea": ea, "pfn": pfn, "tif": tif, "udt": udt})

    def _find_lvar(
        self, cfunc: ida_hexrays.cfuncptr_t, variable: str
    ) -> tuple[ida_hexrays.lvar_t | None, dict[int, ida_hexrays.lvar_t]]:
        """Find variable among the decompiler variables.

        Also returns every stack-allocated variable keyed by frame offset, which
        the frame member lookup uses to tell which members the decompiler knows
        about. Register-allocated variables are left out: they all report a
        frame offset of -1.
        """
        match: ida_hexrays.lvar_t | None = None
        lvars: dict[int, ida_hexrays.lvar_t] = {}

        for lvar in cfunc.get_lvars():
            if lvar.is_stk_var():
                lvars[lvar.get_stkoff()] = lvar

            if match is None and variable == lvar.name:
                match = lvar

        return match, lvars

    def _apply_to_argument(
        self, lvar: ida_hexrays.lvar_t, func: dict[str, Any], struct: InternalStructInfo
    ) -> Result[AppliedStruct]:
        """Apply the struct to a function argument, by value where it fits."""
        lvar_size = lvar.type().get_size()
        success = self._retype_lvar(lvar, func, struct.tif)
        ida_hexrays.mark_cfunc_dirty(func["ea"])

        cfunc = ida_hexrays.decompile(func["ea"])
        pseudocode = "\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())

        # the argument is passed by reference or is the wrong width, so it is a pointer
        if f"&{lvar.name}" in pseudocode or lvar_size != struct.tif.get_size():
            success = self._retype_lvar(lvar, func, self._pointer_to(struct))

        if not success:
            return Err(
                result=f"Failed to apply Struct {struct.struct_name} on Variable {lvar.name}."
            )

        ida_hexrays.mark_cfunc_dirty(func["ea"])
        return Ok(
            result=AppliedStruct(
                function_name=func["name"],
                struct_id=struct.struct_id,
                struct_name=struct.struct_name,
                variable=lvar.name,
                address=hex(func["ea"]),
            )
        )

    def _apply_to_pointer(
        self, lvar: ida_hexrays.lvar_t, func: dict[str, Any], struct: InternalStructInfo
    ) -> Result[AppliedStruct]:
        """Repoint an already-pointer variable at the struct."""
        if not self._retype_lvar(lvar, func, self._pointer_to(struct)):
            return Err(
                result=f"Failed to apply Struct {struct.struct_name} on Variable {lvar.name}."
            )

        ida_hexrays.mark_cfunc_dirty(func["ea"])
        return Ok(
            result=AppliedStruct(
                function_name=func["name"],
                struct_id=struct.struct_id,
                struct_name=struct.struct_name,
                variable=lvar.name,
                address=hex(func["ea"]),
            )
        )

    def _apply_to_frame_offset(
        self,
        frame_offset: int,
        variable: str,
        func: dict[str, Any],
        struct: InternalStructInfo,
    ) -> Result[AppliedStruct]:
        """Lay the struct over the frame at frame_offset, clearing what it covers."""
        diff = 0x0 - ida_frame.calc_frame_offset(func["pfn"], 0x0)
        lvars_start = ida_frame.frame_off_lvars(func["pfn"])
        savregs_start = ida_frame.frame_off_savregs(func["pfn"])
        struct_size = struct.tif.get_size()

        if not (lvars_start <= frame_offset and frame_offset <= savregs_start - struct_size):
            return Err(
                result=f"Struct {struct.struct_name} is too big to replace Variable {variable} in stack."
            )

        for member in func["udt"]:
            var_start = member.offset // 8
            var_end = var_start + member.type.get_size()

            if not (var_end <= frame_offset or var_start >= frame_offset + struct_size):
                ida_frame.delete_frame_members(func["pfn"], var_start, var_end)

        if not ida_frame.define_stkvar(func["pfn"], variable, frame_offset + diff, struct.tif):
            return Err(
                result=f"Failed to apply Struct {struct.struct_name} on Variable {variable}."
            )

        ida_hexrays.mark_cfunc_dirty(func["ea"])
        return Ok(
            result=AppliedStruct(
                function_name=func["name"],
                struct_id=struct.struct_id,
                struct_name=struct.struct_name,
                variable=variable,
                address=hex(func["ea"]),
            )
        )

    def _apply_to_stack_member(
        self,
        variable: str,
        func: dict[str, Any],
        struct: InternalStructInfo,
        lvars: dict[int, ida_hexrays.lvar_t],
    ) -> Result[AppliedStruct] | None:
        """Apply the struct to a named frame member, or None if there is no such member."""
        for member in func["udt"]:
            if variable != member.name:
                continue

            frame_offset = member.offset // 8
            lvar = lvars.get(frame_offset)

            if lvar is not None and lvar.type().is_ptr():
                if not ida_frame.set_frame_member_type(
                    func["pfn"], frame_offset, self._pointer_to(struct)
                ):
                    return Err(
                        result=f"Failed to apply Struct {struct.struct_name} on Variable {variable}."
                    )

                ida_hexrays.mark_cfunc_dirty(func["ea"])
                return Ok(
                    result=AppliedStruct(
                        function_name=func["name"],
                        struct_id=struct.struct_id,
                        struct_name=struct.struct_name,
                        variable=variable,
                        address=hex(func["ea"]),
                    )
                )

            return self._apply_to_frame_offset(frame_offset, variable, func, struct)

        return None

    def _apply_to_global(
        self, variable: str, func: dict[str, Any], struct: InternalStructInfo
    ) -> Result[AppliedStruct]:
        """Apply the struct to a global symbol."""
        address = ida_name.get_name_ea(idaapi.BADADDR, variable)

        if not ida_typeinf.apply_tinfo(address, struct.tif, ida_typeinf.TINFO_DEFINITE):
            return Err(result=f"Variable {variable} does not exist.")

        ida_hexrays.mark_cfunc_dirty(func["ea"])
        return Ok(
            result=AppliedStruct(
                function_name=func["name"],
                struct_id=struct.struct_id,
                struct_name=struct.struct_name,
                variable=variable,
                address=hex(address),
            )
        )

    def execute(
        self,
        struct: str | int,
        function_name: str,
        variable: str,
    ) -> Result[AppliedStruct]:
        """Apply structure to a variable in a function.

        Args:
            struct: The name or id of the struct to apply.
            function_name: The function containing the target variable.
            variable: The name of the variable to apply struct to.

        Returns:
            A Result whose ``success`` reports whether the applying succeeded and
            ``result`` carries the function name, the id and name of the struct
            applied, the variable the struct was applied to and its address.
        """
        struct_result = get_struct(struct)
        if isinstance(struct_result, Err):
            return Err(result=struct_result.result)

        struct_info = struct_result.result

        func_result = self._resolve_function(function_name)
        if isinstance(func_result, Err):
            return Err(result=func_result.result)

        func = func_result.result

        # a variable the decompiler knows: an argument, a pointer, or a local
        cfunc = ida_hexrays.decompile(func["ea"])
        lvar, lvars = self._find_lvar(cfunc, variable)

        if lvar is not None:
            # trust me its a boolean
            if lvar.is_arg_var:
                return self._apply_to_argument(lvar, func, struct_info)

            if lvar.type().is_ptr():
                return self._apply_to_pointer(lvar, func, struct_info)

            if not lvar.is_stk_var():
                return Err(result=f"Variable {variable} is not a stack variable.")

            return self._apply_to_frame_offset(lvar.get_stkoff(), variable, func, struct_info)

        # a named member of the function's stack frame
        applied = self._apply_to_stack_member(variable, func, struct_info, lvars)
        if applied is not None:
            return applied

        # a global
        return self._apply_to_global(variable, func, struct_info)
