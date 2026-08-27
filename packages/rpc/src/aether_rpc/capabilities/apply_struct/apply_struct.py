import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idaapi

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import AppliedStruct, AppliedStructInStack
from ..utils import get_struct, resolve_function_name


class ApplyStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "apply_struct"

    def execute(
        self,
        struct: str | int,
        function_name: str,
        variable: str,
    ) -> Result[AppliedStructInStack | AppliedStruct]:
        """Apply structure to a variable in a function.

        Args:
            struct: The name or id of the struct to apply.
            function_name: The function containing the target variable.
            variable: The name of the variable to apply struct to.

        Returns:
            A Result whose ``success`` reports whether the applying succeeded and
            If variable in stack:
            ``result`` carries the function name, the id and name of the struct
            applied and the variable the struct was applied to.
            If variable has address (statically allocated or heap):
            ``result`` carries the address, and the id and name of the struct
            applied,
        """
        status, output = get_struct(struct)
        if status:
            struct_name, struct_id, tif, _ = output
        else:
            return Err(result=output)

        ea = resolve_function_name(function_name)
        if ea is None:
            return Err(result=f"Symbol '{function_name}' not found")

        pfn = ida_funcs.get_func(ea)

        func_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(func_tif, pfn):
            return Err(result=f"Unable to get info for Function {function_name}.")

        udt = ida_typeinf.udt_type_data_t()
        if not func_tif.get_udt_details(udt):
            return Err(result=f"Unable to get member info for Function {function_name}.")

        ida_hexrays.mark_cfunc_dirty(ea)
        cfunc = ida_hexrays.decompile(ea)
        address = None
        frame_offset = None
        lvars = {}
        for lvar in cfunc.get_lvars():
            # Attempt to get pseudocode var first
            lvars[lvar.get_stkoff()] = lvar
            if variable != lvar.name:
                continue
            if not lvar.type().is_ptr():
                frame_offset = lvar.get_stkoff()
                break
            new_tif = ida_typeinf.tinfo_t()
            new_tif.create_ptr(tif)

            info = ida_hexrays.lvar_saved_info_t()
            info.ll = lvar
            info.type = new_tif

            if ida_hexrays.modify_user_lvar_info(ea, ida_hexrays.MLI_TYPE, info):
                return Ok(
                    result=AppliedStructInStack(
                        function_name=function_name,
                        struct_id=struct_id,
                        struct_name=struct_name,
                        variable=variable,
                    )
                )
            else:
                return Err(result=f"Failed to apply Struct {struct_name} on Variable {variable}.")

        if frame_offset is None:
            for member in udt:
                if not variable == member.name:
                    continue
                frame_offset = member.offset // 8
                if frame_offset in lvars:
                    if not lvars[frame_offset].type().is_ptr():
                        continue
                    new_tif = ida_typeinf.tinfo_t()
                    new_tif.create_ptr(tif)

                    if ida_frame.set_frame_member_type(pfn, frame_offset, new_tif):
                        return Ok(
                            result=AppliedStructInStack(
                                function_name=function_name,
                                struct_id=struct_id,
                                struct_name=struct_name,
                                variable=variable,
                            )
                        )
                    else:
                        return Err(
                            result=f"Failed to apply Struct {struct_name} on Variable {variable}."
                        )
                break

        if address is None:
            ea = ida_name.get_name_ea(idaapi.BADADDR, variable)
        elif address == "Not Running":
            return Err(result="To apply structs to ptr, please run binary first.")
        else:
            ea = address
        if frame_offset is None:
            # Attempt to get static global var last

            if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                return Ok(
                    result=AppliedStruct(
                        address=hex(ea),
                        struct_id=struct_id,
                        struct_name=struct_name,
                    )
                )
            else:
                return Err(result=f"Variable {variable} does not exist.")

        diff = 0x0 - ida_frame.calc_frame_offset(pfn, 0x0)
        lvars_start = ida_frame.frame_off_lvars(pfn)
        savregs_start = ida_frame.frame_off_savregs(pfn)

        stack_offset = frame_offset + diff

        if not (lvars_start <= frame_offset and frame_offset <= savregs_start - tif.get_size()):
            return Err(
                result=f"Struct {struct_name} is too big to replace Variable {variable} in stack."
            )

        for member in udt:
            var_start = member.offset // 8
            var_end = member.offset // 8 + member.type.get_size()
            if not (var_end <= frame_offset or var_start >= frame_offset + tif.get_size()):
                ida_frame.delete_frame_members(pfn, var_start, var_end)

        if ida_frame.define_stkvar(pfn, variable, stack_offset, tif):
            return Ok(
                result=AppliedStructInStack(
                    function_name=function_name,
                    struct_id=struct_id,
                    struct_name=struct_name,
                    variable=variable,
                )
            )
        else:
            return Err(result=f"Failed to apply Struct {struct_name} on Variable {variable}.")
