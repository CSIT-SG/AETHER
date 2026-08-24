import ida_idaapi
import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import AppliedStruct
from ..utils import get_struct, resolve_effective_address


class ApplyStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "apply_struct"

    def execute(
        self,
        struct: str | int,
        address: int,
    ) -> Result[AppliedStruct]:
        """Apply structure to an address.

        Args:
            struct: The name or id of the struct to apply.
            address: The address to apply the struct to.

        Returns:
            A Result whose ``success`` reports whether the application succeeded and
            whose ``result`` carries the address struct was applied to,
            and the name and id of the struct applied.
        """
        status, output = get_struct(struct)
        if status:
            struct_name, struct_id, tif, _ = output
        else:
            return Err(result=output)

        ea = resolve_effective_address(address)
        if not 0 <= ea <= ida_idaapi.BADADDR:
            return Err(result=f"Invalid address: {address}")

        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
            return Ok(
                result=AppliedStruct(
                    address=hex(ea),
                    struct_id=struct_id,
                    struct_name=struct_name,
                )
            )
        else:
            return Err(result=f"Failed to apply Struct {struct_name} at Address {ea:#x}.")
