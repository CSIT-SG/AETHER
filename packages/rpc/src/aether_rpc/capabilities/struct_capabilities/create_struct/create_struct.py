import ida_typeinf


from ...base import Capability
from ...result import Err, Ok, Result
from ...types import StructResult
from ...utils import get_struct_id_by_name


class CreateStruct(Capability):
    """"""

    @property
    def name(self) -> str:
        return "create_struct"

    def execute(self,  struct_name: str):
        """Creates struct.

        Args:
            struct: The name of the struct to be created.

        Returns:
            A Result whose ``success`` reports whether the deletion succeeded and
            whose ``result`` carries the struct id and name.
        """
        # Create an empty struct
        tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()

        # Create the UDT
        if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
            raise RuntimeError("Failed to create struct")

        # Register it as a named type
        idati = ida_typeinf.get_idati()
        if not tif.set_named_type(idati, struct_name, ida_typeinf.NTF_REPLACE):
            return Ok(
                result=StructResult(
                struct_id=tif.get_tid(),
                struct_name=struct_name,
            )
            )
        else:
            return Err(result=f"Failed to create named struct.")