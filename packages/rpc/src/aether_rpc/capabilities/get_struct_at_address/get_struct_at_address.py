import ida_idaapi
import ida_nalt
import ida_typeinf

from ..base import Capability
from ..result import Err, Ok, Result
from ..types import AppliedStruct
from ..utils import get_struct_id_by_name, resolve_effective_address


class GetStructAtAddress(Capability):
    """"""

    @property
    def name(self) -> str:
        return "get_struct_at_address"

    def execute(
        self,
        address: str | int,
    ) -> Result[AppliedStruct]:
        """Get the struct applied to specified address

        Args:
            address: The address to find struct at.

        Returns:
            A Result whose ``success`` reports whether the get succeeded and
            whose ``result`` carries the address, id and name of the struct applied
            to specified address.
        """
        ea = resolve_effective_address(address)
        if not 0 <= ea <= ida_idaapi.BADADDR:
            return Err(result=f"Invalid address: {address}")

        tif = ida_typeinf.tinfo_t()

        if ida_nalt.get_tinfo(tif, ea):
            if tif.is_struct():
                struct_name = tif.get_type_name()
                struct_id = get_struct_id_by_name(struct_name)
            else:
                return Err(result=f"Could not find struct at address given: {hex(ea)}")
        else:
            return Err(result=f"Could not find struct at address given: {hex(ea)}")
        return Ok(
            result=AppliedStruct(
                address=hex(ea),
                struct_id=struct_id,
                struct_name=struct_name,
            )
        )
